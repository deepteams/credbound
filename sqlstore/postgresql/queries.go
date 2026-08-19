package postgresql

import (
	"fmt"
	"strings"
)

// The statements sqlc cannot generate: the paginated reads, which stream
// through pgx at the consumer's pace (ADR-003), and the conditional upsert
// whose WHERE clause sqlc cannot bind.
//
// Each keyset listing ships in two forms rather than one form with a guard
// around the cursor comparison. A guarded predicate — "(NOT $1 OR created_at <
// $2 …)" — is not something the planner can turn into an index scan, so the
// first page of an unfiltered listing would sort the whole table. Choosing the
// statement in Go instead keeps both forms sargable. The resumed form compares
// the ordering columns as a row constructor — "(created_at, id) < ($2, $3)" —
// which PostgreSQL turns into a single ordered index scan; spelling the same
// predicate out with OR makes it a bitmap scan plus a sort.
//
// Identifier parameters carry an explicit ::uuid cast. The columns are of type
// uuid, and the cast states in the statement itself what is being compared,
// instead of leaving it to the driver to infer.

const (
	usersFirstPage = `SELECT u.id, e.address, u.display_name, u.disabled, u.last_seen_at, u.created_at, u.updated_at
FROM credbound.users u
JOIN credbound.user_emails e ON e.user_id = u.id AND e.is_primary
ORDER BY u.created_at DESC, u.id DESC LIMIT $1`

	usersAfterCursor = `SELECT u.id, e.address, u.display_name, u.disabled, u.last_seen_at, u.created_at, u.updated_at
FROM credbound.users u
JOIN credbound.user_emails e ON e.user_id = u.id AND e.is_primary
WHERE (u.created_at, u.id) < ($1, $2::uuid)
ORDER BY u.created_at DESC, u.id DESC LIMIT $3`

	emailsFirstPage = `SELECT id, user_id, address, is_primary, verified_at, created_at, updated_at
FROM credbound.user_emails
WHERE user_id = $1::uuid
ORDER BY created_at DESC, id DESC LIMIT $2`

	emailsAfterCursor = `SELECT id, user_id, address, is_primary, verified_at, created_at, updated_at
FROM credbound.user_emails
WHERE user_id = $1::uuid AND (created_at, id) < ($2, $3::uuid)
ORDER BY created_at DESC, id DESC LIMIT $4`

	passkeysByUser = `SELECT id, user_id, name, credential_id, credential_json, created_at, last_used_at
FROM credbound.passkeys WHERE user_id = $1::uuid ORDER BY created_at, id`

	patsFirstPage = `SELECT id, user_id, name, prefix, digest, workspace_id, scopes_json, created_at, expires_at, last_used_at, revoked_at
FROM credbound.personal_access_tokens
WHERE user_id = $1::uuid
ORDER BY created_at DESC, id DESC LIMIT $2`

	patsAfterCursor = `SELECT id, user_id, name, prefix, digest, workspace_id, scopes_json, created_at, expires_at, last_used_at, revoked_at
FROM credbound.personal_access_tokens
WHERE user_id = $1::uuid AND (created_at, id) < ($2, $3::uuid)
ORDER BY created_at DESC, id DESC LIMIT $4`

	invitationsFirstPage = `SELECT id, workspace_id, email, role, invited_by, digest, created_at, expires_at, accepted_at, accepted_user_id, revoked_at
FROM credbound.workspace_invitations
WHERE workspace_id = $1::uuid
ORDER BY created_at DESC, id DESC LIMIT $2`

	invitationsAfterCursor = `SELECT id, workspace_id, email, role, invited_by, digest, created_at, expires_at, accepted_at, accepted_user_id, revoked_at
FROM credbound.workspace_invitations
WHERE workspace_id = $1::uuid AND (created_at, id) < ($2, $3::uuid)
ORDER BY created_at DESC, id DESC LIMIT $4`

	membershipsFirstPage = `SELECT workspace_id, user_id, role, status, provisioning_source, created_at, updated_at
FROM credbound.memberships
WHERE workspace_id = $1::uuid
ORDER BY created_at DESC, user_id DESC LIMIT $2`

	membershipsAfterCursor = `SELECT workspace_id, user_id, role, status, provisioning_source, created_at, updated_at
FROM credbound.memberships
WHERE workspace_id = $1::uuid AND (created_at, user_id) < ($2, $3::uuid)
ORDER BY created_at DESC, user_id DESC LIMIT $4`

	ssoIdentitiesFirstPage = `SELECT id, user_id, provider_configuration_id, provider_kind, issuer, subject, email, created_at, last_used_at
FROM credbound.sso_identities
WHERE user_id = $1::uuid
ORDER BY created_at DESC, id DESC LIMIT $2`

	ssoIdentitiesAfterCursor = `SELECT id, user_id, provider_configuration_id, provider_kind, issuer, subject, email, created_at, last_used_at
FROM credbound.sso_identities
WHERE user_id = $1::uuid AND (created_at, id) < ($2, $3::uuid)
ORDER BY created_at DESC, id DESC LIMIT $4`

	workspaceDomainsFirstPage = `SELECT id, workspace_id, domain, challenge, confirmed_at, auto_join, auto_join_role, sso_provider_configuration_id, enforce_sso, created_at, updated_at
FROM credbound.workspace_domains
WHERE workspace_id = $1::uuid
ORDER BY created_at DESC, id DESC LIMIT $2`

	workspaceDomainsAfterCursor = `SELECT id, workspace_id, domain, challenge, confirmed_at, auto_join, auto_join_role, sso_provider_configuration_id, enforce_sso, created_at, updated_at
FROM credbound.workspace_domains
WHERE workspace_id = $1::uuid AND (created_at, id) < ($2, $3::uuid)
ORDER BY created_at DESC, id DESC LIMIT $4`

	// The digest is deliberately not selected: listings never expose it.
	sessionsFirstPage = `SELECT id, user_id, method, level, authenticated_at, second_factor_required, user_agent, ip_address, created_at, last_seen_at, expires_at, revoked_at
FROM credbound.sessions
WHERE user_id = $1::uuid
ORDER BY created_at DESC, id DESC LIMIT $2`

	sessionsAfterCursor = `SELECT id, user_id, method, level, authenticated_at, second_factor_required, user_agent, ip_address, created_at, last_seen_at, expires_at, revoked_at
FROM credbound.sessions
WHERE user_id = $1::uuid AND (created_at, id) < ($2, $3::uuid)
ORDER BY created_at DESC, id DESC LIMIT $4`
)

// workspacesQuery assembles the workspace listing. Both the membership filter
// and the cursor are optional, so the clauses are added in Go: a guard left in
// SQL would cost the planner the index on either half.
func workspacesQuery(userID string, after cursor, limit int) (string, []any) {
	query := `SELECT w.id, w.name, w.created_at, w.updated_at, w.disabled_at, w.require_mfa
FROM credbound.workspaces w`
	args := []any{}
	var clauses []string
	if userID != "" {
		args = append(args, userID)
		clauses = append(clauses, fmt.Sprintf("EXISTS (SELECT 1 FROM credbound.memberships m WHERE m.workspace_id = w.id AND m.user_id = $%d::uuid)", len(args)))
	}
	if after.ID != "" {
		args = append(args, after.Time, after.ID)
		clauses = append(clauses, fmt.Sprintf("(w.created_at, w.id) < ($%d, $%d::uuid)", len(args)-1, len(args)))
	}
	if len(clauses) > 0 {
		query += "\nWHERE " + strings.Join(clauses, " AND ")
	}
	args = append(args, limit)
	return query + fmt.Sprintf("\nORDER BY w.created_at DESC, w.id DESC LIMIT $%d", len(args)), args
}

// auditEventsQuery assembles the audit listing, scoped to a workspace when
// workspaceID is set. Same reasoning as workspacesQuery: optional clauses are
// added rather than guarded.
func auditEventsQuery(workspaceID string, after cursor, limit int) (string, []any) {
	query := `SELECT id, occurred_at, actor_kind, actor_id, action, resource_type, resource_id, workspace_id, outcome, reason, ip_address, user_agent, sequence, previous_hash, hash
FROM credbound.audit_events`
	args := []any{}
	var clauses []string
	if workspaceID != "" {
		args = append(args, workspaceID)
		clauses = append(clauses, fmt.Sprintf("workspace_id = $%d::uuid", len(args)))
	}
	if after.ID != "" {
		args = append(args, after.Time, after.ID)
		clauses = append(clauses, fmt.Sprintf("(occurred_at, id) < ($%d, $%d::uuid)", len(args)-1, len(args)))
	}
	if len(clauses) > 0 {
		query += "\nWHERE " + strings.Join(clauses, " AND ")
	}
	args = append(args, limit)
	return query + fmt.Sprintf("\nORDER BY occurred_at DESC, id DESC LIMIT $%d", len(args)), args
}

// validUUID reports whether value is shaped like a UUID, so a caller-supplied
// identifier can be kept out of a uuid comparison that would otherwise fail
// the statement instead of simply matching nothing.
func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, char := range value {
		switch index {
		case 8, 13, 18, 23:
			if char != '-' {
				return false
			}
		default:
			isDigit := char >= '0' && char <= '9'
			isLower := char >= 'a' && char <= 'f'
			isUpper := char >= 'A' && char <= 'F'
			if !isDigit && !isLower && !isUpper {
				return false
			}
		}
	}
	return true
}
