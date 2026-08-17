// Command genpostgresstore mechanically derives the PostgreSQL store from the
// SQLite implementation and applies the small dialect-specific differences.
package main

import (
	"fmt"
	"go/format"
	"os"
	"strings"
)

func main() {
	const source = "sqlstore/sqlite/store.go"
	const target = "sqlstore/postgresql/store.go"
	raw, err := os.ReadFile(source)
	if err != nil {
		panic(err)
	}
	code := string(raw)
	code = strings.Replace(code, "package sqlite", "package postgresql", 1)
	code = strings.Replace(code, `db "github.com/deepteams/credbound/internal/sqlc/sqlite"`, `db "github.com/deepteams/credbound/internal/sqlc/postgresql"`, 1)
	code = strings.ReplaceAll(code, "credbound.StoreSQLite", "credbound.StorePostgreSQL")
	code = strings.Replace(code, "// Tx is the SQLite transaction capability", "// Tx is the PostgreSQL transaction capability", 1)
	code = strings.Replace(code, "into the live SQLite", "into the live PostgreSQL", 1)
	code = strings.Replace(code, `"github.com/deepteams/credbound"`, `"github.com/deepteams/credbound"
	"github.com/jackc/pgx/v5"`, 1)
	code = strings.Replace(code, "type Store struct {\n\tdb            *sql.DB\n\tqueries", "type RowQuerier interface {\n\tQuery(context.Context, string, ...any) (pgx.Rows, error)\n}\n\ntype Store struct {\n\tdb *sql.DB\n\trows RowQuerier\n\tqueries", 1)
	code = strings.Replace(code, "func New(database *sql.DB, options ...Option)", `// New builds the PostgreSQL store from two views of the same database: a
// *sql.DB used by the sqlc-generated queries for transactional mutations
// (open one with pgx's stdlib.OpenDB or stdlib.OpenDBFromPool), and a pgx
// RowQuerier used to stream paginated reads. In production pass a
// *pgxpool.Pool as the RowQuerier — a single *pgx.Conn is not safe for
// concurrent use.
func New(database *sql.DB, rows RowQuerier, options ...Option)`, 1)
	code = strings.Replace(code, "if database == nil {", "if database == nil || rows == nil {", 1)
	code = strings.Replace(code, "sqlite database is required", "PostgreSQL database/sql and pgx row querier are required", 1)
	code = strings.Replace(code, "&Store{db: database, queries: db.New(database),", "&Store{db: database, rows: rows, queries: db.New(database),", 1)
	code = strings.ReplaceAll(code, "row.Active == 1", "row.Active")
	code = strings.ReplaceAll(code, "row.RequireMfa == 1", "row.RequireMfa")
	code = strings.Replace(code, "var requireMFA int64", "var requireMFA bool", 1)
	code = strings.Replace(code, "value.DisabledAt, value.RequireMFA = timePointer(disabled), requireMFA == 1", "value.DisabledAt, value.RequireMFA = timePointer(disabled), requireMFA", 1)
	code = strings.Replace(code, `// boolValue converts a policy flag to its SQLite representation.
func boolValue(value bool) int64 {
	if value {
		return 1
	}
	return 0
}`, `// boolValue converts a policy flag to its PostgreSQL representation.
func boolValue(value bool) bool { return value }`, 1)
	code = strings.ReplaceAll(code, "row.Disabled == 1", "row.Disabled")
	code = strings.ReplaceAll(code, "row.IsPrimary == 1", "row.IsPrimary")
	code = strings.ReplaceAll(code, "email.IsPrimary == 1", "email.IsPrimary")
	oldDisabled := `disabled := int64(0)
	if user.Disabled {
		disabled = 1
	}`
	code = strings.Replace(code, oldDisabled, `disabled := user.Disabled`, 1)
	oldPrimary := `primary := int64(0)
	if email.Primary {
		primary = 1
	}`
	code = strings.Replace(code, oldPrimary, `primary := email.Primary`, 1)
	code = strings.Replace(code, "var primary int64", "var primary bool", 1)
	code = strings.Replace(code, "primary == 1", "primary", 1)
	code = strings.Replace(code, "ScopesJson: string(scopes)", "ScopesJson: scopes", 1)
	code = strings.Replace(code, "json.Unmarshal([]byte(row.ScopesJson), &scopes)", "json.Unmarshal(row.ScopesJson, &scopes)", 1)
	code = strings.Replace(code, "var scopes string", "var scopes []byte", 1)
	code = strings.Replace(code, "json.Unmarshal([]byte(scopes), &value.Scopes)", "json.Unmarshal(scopes, &value.Scopes)", 1)
	code = strings.Replace(code, `disabledValue := int64(0)
		if disabled {
			disabledValue = 1
		}`, `disabledValue := disabled`, 1)
	code = strings.Replace(code, "var disabled int64", "var disabled bool", 1)
	code = strings.Replace(code, "value.Disabled, value.LastSeenAt = disabled == 1, timePointer(seen)", "value.Disabled, value.LastSeenAt = disabled, timePointer(seen)", 1)
	code = strings.Replace(code, `		if disabled {
			admin, adminErr := q.GetInstanceAdministrator(ctx, userID)`, `		if disabled {
			if _, lockErr := q.LockRootAdministrators(ctx); lockErr != nil {
				return mapError(lockErr)
			}
			if _, lockErr := q.LockUserAdminWorkspaces(ctx, userID); lockErr != nil {
				return mapError(lockErr)
			}
			admin, adminErr := q.GetInstanceAdministrator(ctx, userID)`, 1)
	code = strings.Replace(code, `func (s *Store) UpsertMembership(ctx context.Context, membership credbound.Membership, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		current, err := q.GetMembership`, `func (s *Store) UpsertMembership(ctx context.Context, membership credbound.Membership, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if _, err := q.LockWorkspace(ctx, membership.WorkspaceID); err != nil {
			return mapError(err)
		}
		current, err := q.GetMembership`, 1)
	code = strings.Replace(code, `func (s *Store) RemoveMembership(ctx context.Context, workspaceID, userID string, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		current, err := q.GetMembership`, `func (s *Store) RemoveMembership(ctx context.Context, workspaceID, userID string, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if _, err := q.LockWorkspace(ctx, workspaceID); err != nil {
			return mapError(err)
		}
		current, err := q.GetMembership`, 1)
	code = strings.Replace(code, `func (s *Store) SetInstanceRole(ctx context.Context, admin credbound.InstanceAdministrator, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		current, err := q.GetInstanceAdministrator`, `func (s *Store) SetInstanceRole(ctx context.Context, admin credbound.InstanceAdministrator, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if admin.Role != credbound.InstanceRoleRoot {
			if _, err := q.LockRootAdministrators(ctx); err != nil {
				return mapError(err)
			}
		}
		current, err := q.GetInstanceAdministrator`, 1)
	code = strings.Replace(code, `func (s *Store) RemoveInstanceRole(ctx context.Context, userID string, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		admin, err := q.GetInstanceAdministrator`, `func (s *Store) RemoveInstanceRole(ctx context.Context, userID string, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if _, err := q.LockRootAdministrators(ctx); err != nil {
			return mapError(err)
		}
		admin, err := q.GetInstanceAdministrator`, 1)

	code = strings.Replace(code, `s.db.QueryContext(streamCtx, `+"`"+`SELECT u.id, e.address, u.display_name, u.disabled, u.last_seen_at, u.created_at, u.updated_at
FROM credbound_users u
JOIN credbound_user_emails e ON e.user_id = u.id AND e.is_primary = 1
WHERE (? = '' OR u.created_at < ? OR (u.created_at = ? AND u.id < ?))
ORDER BY u.created_at DESC, u.id DESC LIMIT ?`+"`"+`, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)`, `s.rows.Query(streamCtx, `+"`"+`SELECT u.id, e.address, u.display_name, u.disabled, u.last_seen_at, u.created_at, u.updated_at
FROM credbound_users u
JOIN credbound_user_emails e ON e.user_id = u.id AND e.is_primary
WHERE (NOT $1 OR u.created_at < $2 OR (u.created_at = $3 AND u.id < $4))
ORDER BY u.created_at DESC, u.id DESC LIMIT $5`+"`"+`, cursor.ID != "", cursor.Time, cursor.Time, nullableUUID(cursor.ID), page.Limit+1)`, 1)

	code = strings.Replace(code, `s.db.QueryContext(streamCtx, `+"`"+`SELECT id, user_id, name, credential_id, credential_json, created_at, last_used_at
FROM credbound_passkeys WHERE user_id = ? ORDER BY created_at, id`+"`"+`, userID)`, `s.rows.Query(streamCtx, `+"`"+`SELECT id, user_id, name, credential_id, credential_json, created_at, last_used_at
FROM credbound_passkeys WHERE user_id = $1 ORDER BY created_at, id`+"`"+`, userID)`, 1)
	code = strings.Replace(code, `s.db.QueryContext(streamCtx, `+"`"+`SELECT id, user_id, address, is_primary, verified_at, created_at, updated_at
FROM credbound_user_emails
WHERE user_id = ? AND (? = '' OR created_at < ? OR (created_at = ? AND id < ?))
ORDER BY created_at DESC, id DESC LIMIT ?`+"`"+`, userID, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)`, `s.rows.Query(streamCtx, `+"`"+`SELECT id, user_id, address, is_primary, verified_at, created_at, updated_at
FROM credbound_user_emails
WHERE user_id = $1 AND (NOT $2 OR created_at < $3 OR (created_at = $4 AND id < $5))
ORDER BY created_at DESC, id DESC LIMIT $6`+"`"+`, userID, cursor.ID != "", cursor.Time, cursor.Time, nullableUUID(cursor.ID), page.Limit+1)`, 1)
	code = strings.Replace(code, `s.db.QueryContext(streamCtx, `+"`"+`SELECT id, user_id, name, prefix, digest, workspace_id, scopes_json, created_at, expires_at, last_used_at, revoked_at
FROM credbound_personal_access_tokens
WHERE user_id = ? AND (? = '' OR created_at < ? OR (created_at = ? AND id < ?))
ORDER BY created_at DESC, id DESC LIMIT ?`+"`"+`, userID, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)`, `s.rows.Query(streamCtx, `+"`"+`SELECT id, user_id, name, prefix, digest, workspace_id, scopes_json, created_at, expires_at, last_used_at, revoked_at
FROM credbound_personal_access_tokens
WHERE user_id = $1 AND (NOT $2 OR created_at < $3 OR (created_at = $4 AND id < $5))
ORDER BY created_at DESC, id DESC LIMIT $6`+"`"+`, userID, cursor.ID != "", cursor.Time, cursor.Time, nullableUUID(cursor.ID), page.Limit+1)`, 1)
	code = strings.Replace(code, `s.db.QueryContext(streamCtx, `+"`"+`SELECT id, workspace_id, email, role, invited_by, digest, created_at, expires_at, accepted_at, accepted_user_id, revoked_at
FROM credbound_workspace_invitations
WHERE workspace_id = ? AND (? = '' OR created_at < ? OR (created_at = ? AND id < ?))
ORDER BY created_at DESC, id DESC LIMIT ?`+"`"+`, workspaceID, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)`, `s.rows.Query(streamCtx, `+"`"+`SELECT id, workspace_id, email, role, invited_by, digest, created_at, expires_at, accepted_at, accepted_user_id, revoked_at
FROM credbound_workspace_invitations
WHERE workspace_id = $1 AND (NOT $2 OR created_at < $3 OR (created_at = $4 AND id < $5))
ORDER BY created_at DESC, id DESC LIMIT $6`+"`"+`, workspaceID, cursor.ID != "", cursor.Time, cursor.Time, nullableUUID(cursor.ID), page.Limit+1)`, 1)
	code = strings.Replace(code, `s.db.QueryContext(streamCtx, `+"`"+`SELECT id, user_id, provider_configuration_id, provider_kind, issuer, subject, email, created_at, last_used_at
FROM credbound_sso_identities
WHERE user_id = ? AND (? = '' OR created_at < ? OR (created_at = ? AND id < ?))
ORDER BY created_at DESC, id DESC LIMIT ?`+"`"+`, userID, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)`, `s.rows.Query(streamCtx, `+"`"+`SELECT id, user_id, provider_configuration_id, provider_kind, issuer, subject, email, created_at, last_used_at
FROM credbound_sso_identities
WHERE user_id = $1 AND (NOT $2 OR created_at < $3 OR (created_at = $4 AND id < $5))
ORDER BY created_at DESC, id DESC LIMIT $6`+"`"+`, userID, cursor.ID != "", cursor.Time, cursor.Time, nullableUUID(cursor.ID), page.Limit+1)`, 1)
	code = strings.Replace(code, `query := `+"`"+`SELECT w.id, w.name, w.created_at, w.updated_at, w.disabled_at, w.require_mfa
FROM credbound_workspaces w
WHERE (? = '' OR EXISTS (SELECT 1 FROM credbound_memberships m WHERE m.workspace_id = w.id AND m.user_id = ?))
AND (? = '' OR w.created_at < ? OR (w.created_at = ? AND w.id < ?))
ORDER BY w.created_at DESC, w.id DESC LIMIT ?`+"`", `query := `+"`"+`SELECT w.id, w.name, w.created_at, w.updated_at, w.disabled_at, w.require_mfa
FROM credbound_workspaces w
WHERE (NOT $1 OR EXISTS (SELECT 1 FROM credbound_memberships m WHERE m.workspace_id = w.id AND m.user_id = $2))
AND (NOT $3 OR w.created_at < $4 OR (w.created_at = $5 AND w.id < $6))
ORDER BY w.created_at DESC, w.id DESC LIMIT $7`+"`", 1)
	code = strings.Replace(code, "s.db.QueryContext(streamCtx, query, userID, userID, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)", "s.rows.Query(streamCtx, query, userID != \"\", nullableUUID(userID), cursor.ID != \"\", cursor.Time, cursor.Time, nullableUUID(cursor.ID), page.Limit+1)", 1)
	code = strings.Replace(code, `s.db.QueryContext(streamCtx, `+"`"+`SELECT workspace_id, user_id, role, status, provisioning_source, created_at, updated_at
FROM credbound_memberships
WHERE workspace_id = ? AND (? = '' OR created_at < ? OR (created_at = ? AND user_id < ?))
ORDER BY created_at DESC, user_id DESC LIMIT ?`+"`"+`, workspaceID, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)`, `s.rows.Query(streamCtx, `+"`"+`SELECT workspace_id, user_id, role, status, provisioning_source, created_at, updated_at
FROM credbound_memberships
WHERE workspace_id = $1 AND (NOT $2 OR created_at < $3 OR (created_at = $4 AND user_id < $5))
ORDER BY created_at DESC, user_id DESC LIMIT $6`+"`"+`, workspaceID, cursor.ID != "", cursor.Time, cursor.Time, nullableUUID(cursor.ID), page.Limit+1)`, 1)

	code = strings.Replace(code, `func nullableString(value string) sql.NullString {`, `func nullableUUID(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableString(value string) sql.NullString {`, 1)

	start := strings.Index(code, "func (s *Store) AuditEvents(")
	end := strings.Index(code, "func (s *Store) mutate(")
	if start < 0 || end < 0 || end <= start {
		panic("audit section markers not found")
	}
	code = code[:start] + postgresAuditSection + code[end:]
	code = strings.Replace(code, "s.db.QueryContext(streamCtx, chainedAuditQuery)", "s.rows.Query(streamCtx, chainedAuditQuery)", 1)
	// PostgreSQL objects live in the dedicated `credbound` schema; every raw
	// SQL table reference is schema-qualified instead of prefix-namespaced.
	code = strings.ReplaceAll(code, "credbound_", "credbound.")
	code = "// Code generated by internal/cmd/genpostgresstore; DO NOT EDIT.\n" + code
	formatted, err := format.Source([]byte(code))
	if err != nil {
		panic(fmt.Errorf("format generated PostgreSQL store: %w", err))
	}
	if err := os.MkdirAll("sqlstore/postgresql", 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(target, formatted, 0o644); err != nil {
		panic(err)
	}
	fmt.Println(target)
	generateSession()
	generateSCIM()
	generateOAuth()
}

func generateSession() {
	const source = "sqlstore/sqlite/session.go"
	const target = "sqlstore/postgresql/session.go"
	raw, err := os.ReadFile(source)
	if err != nil {
		panic(err)
	}
	code := string(raw)
	code = strings.Replace(code, "package sqlite", "package postgresql", 1)
	code = strings.Replace(code, `db "github.com/deepteams/credbound/internal/sqlc/sqlite"`, `db "github.com/deepteams/credbound/internal/sqlc/postgresql"`, 1)
	code = strings.Replace(code, "Level: int64(session.Level)", "Level: int16(session.Level)", 1)
	code = strings.Replace(code, "row.SecondFactorRequired == 1", "row.SecondFactorRequired", 1)
	code = strings.Replace(code, "var secondFactor int64", "var secondFactor bool", 1)
	code = strings.Replace(code, "value.SecondFactorRequired = secondFactor == 1", "value.SecondFactorRequired = secondFactor", 1)
	code = strings.Replace(code, `s.db.QueryContext(streamCtx, `+"`"+`SELECT id, user_id, method, level, authenticated_at, second_factor_required, user_agent, ip_address, created_at, last_seen_at, expires_at, revoked_at
FROM credbound_sessions
WHERE user_id = ? AND (? = '' OR created_at < ? OR (created_at = ? AND id < ?))
ORDER BY created_at DESC, id DESC LIMIT ?`+"`"+`, userID, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)`, `s.rows.Query(streamCtx, `+"`"+`SELECT id, user_id, method, level, authenticated_at, second_factor_required, user_agent, ip_address, created_at, last_seen_at, expires_at, revoked_at
FROM credbound_sessions
WHERE user_id = $1 AND (NOT $2 OR created_at < $3 OR (created_at = $4 AND id < $5))
ORDER BY created_at DESC, id DESC LIMIT $6`+"`"+`, userID, cursor.ID != "", cursor.Time, cursor.Time, nullableUUID(cursor.ID), page.Limit+1)`, 1)
	// PostgreSQL objects live in the dedicated `credbound` schema; every raw
	// SQL table reference is schema-qualified instead of prefix-namespaced.
	code = strings.ReplaceAll(code, "credbound_", "credbound.")
	code = "// Code generated by internal/cmd/genpostgresstore; DO NOT EDIT.\n" + code
	formatted, err := format.Source([]byte(code))
	if err != nil {
		panic(fmt.Errorf("format generated PostgreSQL session store: %w", err))
	}
	if err := os.WriteFile(target, formatted, 0o644); err != nil {
		panic(err)
	}
	fmt.Println(target)
}

func generateOAuth() {
	const source = "sqlstore/sqlite/oauth.go"
	const target = "sqlstore/postgresql/oauth.go"
	raw, err := os.ReadFile(source)
	if err != nil {
		panic(err)
	}
	code := string(raw)
	code = strings.Replace(code, "package sqlite", "package postgresql", 1)
	code = strings.Replace(code, `db "github.com/deepteams/credbound/internal/sqlc/sqlite"`, `db "github.com/deepteams/credbound/internal/sqlc/postgresql"`, 1)
	code = strings.Replace(code, "func oauthParam(value any) string { return string(oauthJSON(value)) }", "func oauthParam(value any) []byte { return oauthJSON(value) }", 1)
	code = strings.ReplaceAll(code, "int64(token.RegistrationCount)", "int32(token.RegistrationCount)")
	code = strings.ReplaceAll(code, "int64(previousCount)", "int32(previousCount)")
	code = strings.ReplaceAll(code, "int64(value.RegistrationCount)", "int32(value.RegistrationCount)")
	code = strings.ReplaceAll(code, "int64(value.MaxRegistrations)", "int32(value.MaxRegistrations)")
	code = strings.Replace(code, `"fmt"`, `"fmt"
	"strconv"
	"strings"`, 1)
	code = strings.Replace(code, `func oauthQuery(query string) string { return query }`, `func oauthQuery(query string) string {
	var result strings.Builder
	index := 1
	for _, char := range query {
		if char == '?' {
			result.WriteByte('$')
			result.WriteString(strconv.Itoa(index))
			index++
			continue
		}
		result.WriteRune(char)
	}
	return result.String()
}`, 1)
	code = strings.Replace(code, `var _ = errors.Is
var _ = strings.Builder{}
`, "", 1)
	code = strings.ReplaceAll(code, "(? = '' OR created_at", "(NOT ? OR created_at")
	code = strings.ReplaceAll(code, "(? = '' OR user_id = ?)", "(NOT ? OR user_id = ?)")
	code = strings.ReplaceAll(code, "(? = '' OR workspace_id = ?)", "(NOT ? OR workspace_id = ?)")
	code = strings.Replace(code, `[]any{userID, userID, workspaceID, workspaceID}`, `[]any{userID != "", nullableUUID(userID), workspaceID != "", nullableUUID(workspaceID)}`, 1)
	code = strings.Replace(code, `args = append(args, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)`, `args = append(args, cursor.ID != "", cursor.Time, cursor.Time, nullableUUID(cursor.ID), page.Limit+1)`, 1)
	// PostgreSQL objects live in the dedicated `credbound` schema; every raw
	// SQL table reference is schema-qualified instead of prefix-namespaced.
	code = strings.ReplaceAll(code, "credbound_", "credbound.")
	code = "// Code generated by internal/cmd/genpostgresstore; DO NOT EDIT.\n" + code
	formatted, err := format.Source([]byte(code))
	if err != nil {
		panic(fmt.Errorf("format generated PostgreSQL OAuth store: %w", err))
	}
	if err := os.WriteFile(target, formatted, 0o644); err != nil {
		panic(err)
	}
	fmt.Println(target)
}

func generateSCIM() {
	const source = "sqlstore/sqlite/scim.go"
	const target = "sqlstore/postgresql/scim.go"
	raw, err := os.ReadFile(source)
	if err != nil {
		panic(err)
	}
	code := string(raw)
	code = strings.Replace(code, "package sqlite", "package postgresql", 1)
	code = strings.Replace(code, `db "github.com/deepteams/credbound/internal/sqlc/sqlite"`, `db "github.com/deepteams/credbound/internal/sqlc/postgresql"`, 1)
	code = strings.ReplaceAll(code, "row.Enabled == 1", "row.Enabled")
	code = strings.ReplaceAll(code, "row.TrustDirectoryEmails == 1", "row.TrustDirectoryEmails")
	code = strings.ReplaceAll(code, "row.Active == 1", "row.Active")
	code = strings.ReplaceAll(code, "active == 1", "active")
	code = strings.ReplaceAll(code, "GroupRoleMappingsJson: string(mappings)", "GroupRoleMappingsJson: mappings")
	code = strings.ReplaceAll(code, "EmailsJson: string(emails)", "EmailsJson: emails")
	code = strings.ReplaceAll(code, "ProfileJson: string(profile)", "ProfileJson: profile")
	code = strings.ReplaceAll(code, "MemberIdsJson: string(members)", "MemberIdsJson: members")
	code = strings.Replace(code, "var id, configurationID, userID, userName, displayName, emails, profile string", "var id, configurationID, userID, userName, displayName string\n\tvar emails, profile []byte", 1)
	code = strings.Replace(code, "var active int64", "var active bool", 1)
	code = strings.Replace(code, "var id, configurationID, displayName, members string", "var id, configurationID, displayName string\n\tvar members []byte", 1)
	code = strings.Replace(code, "func sqlBool(value bool) int64 {\n\tif value {\n\t\treturn 1\n\t}\n\treturn 0\n}", "func sqlBool(value bool) bool { return value }", 1)

	oldGroup := `s.db.QueryContext(streamCtx, ` + "`" + `SELECT id, configuration_id, external_id, display_name, member_ids_json, created_at, updated_at, deleted_at
FROM credbound_scim_groups
WHERE configuration_id = ? AND deleted_at IS NULL AND (? = '' OR created_at < ? OR (created_at = ? AND id < ?))
ORDER BY created_at DESC, id DESC LIMIT ?` + "`" + `, configurationID, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)`
	newGroup := `s.rows.Query(streamCtx, ` + "`" + `SELECT id, configuration_id, external_id, display_name, member_ids_json, created_at, updated_at, deleted_at
FROM credbound_scim_groups
WHERE configuration_id = $1 AND deleted_at IS NULL AND (NOT $2 OR created_at < $3 OR (created_at = $4 AND id < $5))
ORDER BY created_at DESC, id DESC LIMIT $6` + "`" + `, configurationID, cursor.ID != "", cursor.Time, cursor.Time, nullableUUID(cursor.ID), page.Limit+1)`
	code = strings.Replace(code, oldGroup, newGroup, 1)

	start := strings.Index(code, "func sqliteSCIMUserListQuery(")
	end := strings.Index(code, "func sqlBool(")
	if start < 0 || end < 0 || end <= start {
		panic("SCIM query helper markers not found")
	}
	code = code[:start] + postgresSCIMUserListQuery + code[end:]
	code = strings.Replace(code, "query, args, err := sqliteSCIMUserListQuery", "query, args, err := postgresSCIMUserListQuery", 1)
	code = strings.Replace(code, "query, args, err := sqliteSCIMGroupListQuery", "query, args, err := postgresSCIMGroupListQuery", 1)
	code = strings.Replace(code, "rows, err := s.db.QueryContext(streamCtx, query, args...)", "rows, err := s.rows.Query(streamCtx, query, args...)", 1)
	code = strings.Replace(code, "rows, err := s.db.QueryContext(streamCtx, query, args...)", "rows, err := s.rows.Query(streamCtx, query, args...)", 1)
	// PostgreSQL objects live in the dedicated `credbound` schema; every raw
	// SQL table reference is schema-qualified instead of prefix-namespaced.
	code = strings.ReplaceAll(code, "credbound_", "credbound.")
	code = "// Code generated by internal/cmd/genpostgresstore; DO NOT EDIT.\n" + code
	formatted, err := format.Source([]byte(code))
	if err != nil {
		panic(fmt.Errorf("format generated PostgreSQL SCIM store: %w", err))
	}
	if err := os.WriteFile(target, formatted, 0o644); err != nil {
		panic(err)
	}
	fmt.Println(target)
}

const postgresSCIMUserListQuery = `func postgresSCIMUserListQuery(configurationID string, filter credbound.SCIMFilter, cursor cursor, limit int) (string, []any, error) {
	query := ` + "`" + `SELECT id, configuration_id, user_id, external_id, normalized_user_name, display_name, emails_json, profile_json, active, created_at, updated_at, deprovisioned_at
FROM credbound_scim_users WHERE configuration_id = $1 AND deprovisioned_at IS NULL` + "`" + `
	args := []any{configurationID}
	next := 2
	add := func(fragment string, value any) {
		query += fmt.Sprintf(fragment, next)
		args = append(args, value)
		next++
	}
	switch filter.Attribute {
	case "":
	case "id":
		add(" AND id::text = $%d", filter.Value)
	case "externalId":
		add(" AND external_id = $%d", filter.Value)
	case "userName":
		add(" AND normalized_user_name = $%d", strings.ToLower(strings.TrimSpace(filter.Value)))
	case "emails.value":
		add(" AND EXISTS (SELECT 1 FROM jsonb_array_elements(emails_json) e WHERE e->>'value' = $%d)", strings.ToLower(strings.TrimSpace(filter.Value)))
	case "active":
		value := false
		if strings.EqualFold(filter.Value, "true") {
			value = true
		} else if !strings.EqualFold(filter.Value, "false") {
			return "", nil, fmt.Errorf("%w: invalid active filter", credbound.ErrInvalidInput)
		}
		add(" AND active = $%d", value)
	default:
		return "", nil, fmt.Errorf("%w: unsupported SCIM user filter", credbound.ErrInvalidInput)
	}
	query += fmt.Sprintf(" AND (NOT $%d OR created_at < $%d OR (created_at = $%d AND id < $%d)) ORDER BY created_at DESC, id DESC LIMIT $%d", next, next+1, next+2, next+3, next+4)
	args = append(args, cursor.ID != "", cursor.Time, cursor.Time, nullableUUID(cursor.ID), limit)
	return query, args, nil
}

func postgresSCIMGroupListQuery(configurationID string, filter credbound.SCIMFilter, cursor cursor, limit int) (string, []any, error) {
	query := ` + "`" + `SELECT id, configuration_id, external_id, display_name, member_ids_json, created_at, updated_at, deleted_at
FROM credbound_scim_groups WHERE configuration_id = $1 AND deleted_at IS NULL` + "`" + `
	args := []any{configurationID}
	next := 2
	switch filter.Attribute {
	case "":
	case "id":
		query += fmt.Sprintf(" AND id::text = $%d", next)
		args, next = append(args, filter.Value), next+1
	case "externalId":
		query += fmt.Sprintf(" AND external_id = $%d", next)
		args, next = append(args, filter.Value), next+1
	case "displayName":
		query += fmt.Sprintf(" AND display_name = $%d", next)
		args, next = append(args, filter.Value), next+1
	default:
		return "", nil, fmt.Errorf("%w: unsupported SCIM group filter", credbound.ErrInvalidInput)
	}
	query += fmt.Sprintf(" AND (NOT $%d OR created_at < $%d OR (created_at = $%d AND id < $%d)) ORDER BY created_at DESC, id DESC LIMIT $%d", next, next+1, next+2, next+3, next+4)
	args = append(args, cursor.ID != "", cursor.Time, cursor.Time, nullableUUID(cursor.ID), limit)
	return query, args, nil
}

`

const postgresAuditSection = `func (s *Store) AuditEvents(ctx context.Context, workspaceID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.AuditEvent], error] {
	query := ` + "`" + `SELECT id, occurred_at, actor_kind, actor_id, action, resource_type, resource_id, workspace_id, outcome, reason, ip_address, user_agent, sequence, previous_hash, hash
FROM credbound_audit_events
WHERE workspace_id = $1 AND (NOT $2 OR occurred_at < $3 OR (occurred_at = $4 AND id < $5))
ORDER BY occurred_at DESC, id DESC LIMIT $6` + "`" + `
	return s.auditEvents(ctx, page, query, []any{workspaceID})
}

func (s *Store) InstanceAuditEvents(ctx context.Context, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.AuditEvent], error] {
	query := ` + "`" + `SELECT id, occurred_at, actor_kind, actor_id, action, resource_type, resource_id, workspace_id, outcome, reason, ip_address, user_agent, sequence, previous_hash, hash
FROM credbound_audit_events
WHERE (NOT $1 OR occurred_at < $2 OR (occurred_at = $3 AND id < $4))
ORDER BY occurred_at DESC, id DESC LIMIT $5` + "`" + `
	return s.auditEvents(ctx, page, query, nil)
}

func (s *Store) auditEvents(ctx context.Context, page credbound.PageRequest, query string, leading []any) iter.Seq2[credbound.PageEvent[credbound.AuditEvent], error] {
	return func(yield func(credbound.PageEvent[credbound.AuditEvent], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.AuditEvent]{}, err)
			return
		}
		args := append(leading, cursor.ID != "", cursor.Time, cursor.Time, nullableUUID(cursor.ID), page.Limit+1)
		rows, err := s.rows.Query(streamCtx, query, args...)
		if err != nil {
			yield(credbound.PageEvent[credbound.AuditEvent]{}, mapError(err))
			return
		}
		defer rows.Close()
		var last credbound.AuditEvent
		count := 0
		for rows.Next() {
			value, err := scanAuditEvent(rows)
			if err != nil {
				yield(credbound.PageEvent[credbound.AuditEvent]{}, err)
				return
			}
			if count == page.Limit {
				yield(credbound.EndEvent[credbound.AuditEvent](credbound.PageEnd{HasMore: true, NextCursor: encodeCursor(last.OccurredAt, last.ID)}), nil)
				return
			}
			last = value
			count++
			if !yield(credbound.ItemEvent(value), nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(credbound.PageEvent[credbound.AuditEvent]{}, err)
			return
		}
		yield(credbound.EndEvent[credbound.AuditEvent](credbound.PageEnd{}), nil)
	}
}

`
