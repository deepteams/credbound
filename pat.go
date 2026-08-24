package credbound

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"
)

// defaultPATPrefix is the marker a PAT carries when Config.PATPrefix is unset.
const defaultPATPrefix = "cbp"

// validTokenMarker reports whether a value can serve as the leading marker of
// a token. The parsers split on "_", so a marker may not contain one; case is
// excluded because a marker is compared verbatim, and accepting several
// spellings of one deployment's tokens is exactly what the token parsers
// refuse.
func validTokenMarker(marker string) bool {
	if len(marker) == 0 || len(marker) > 16 {
		return false
	}
	for _, char := range marker {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

// CreatePAT issues a personal access token with at least 256 bits of entropy
// and returns the raw token exactly once; only its HMAC digest is persisted,
// atomically with the audit event. The authentication it demands follows
// Config.StepUp's PAT scope — a fresh AAL2 step-up by default — and binding the token
// to a workspace additionally requires access to that workspace. Each scope
// is either the "*" wildcard or a workspace permission string: AuthorizePermission denies a scoped authentication any
// permission outside its scopes, and the coarse role-based Authorize
// requires the wildcard, so the scopes chosen here are the ceiling of what
// the token can ever do.
func (m *Manager) CreatePAT(ctx context.Context, actor Authentication, input CreatePATInput) (_ IssuedPAT, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.pat.create", started, err) }()
	if err := m.requireScopedStepUp(ctx, actor, StepUpScopePAT, "auth.pat.create"); err != nil {
		return IssuedPAT{}, err
	}
	name := strings.TrimSpace(input.Name)
	if name == "" || len(name) > 100 {
		return IssuedPAT{}, &ValidationError{Field: "name", Rule: "length", Message: "PAT name is required and limited to 100 characters"}
	}
	if input.ExpiresAt != nil && !input.ExpiresAt.After(m.now()) {
		return IssuedPAT{}, &ValidationError{Field: "expires_at", Rule: "past", Message: "PAT expiration must be in the future"}
	}
	if input.WorkspaceID != (UUID{}) {
		if err := m.AuthorizePermission(ctx, actor, input.WorkspaceID, PermissionWorkspaceAccess); err != nil {
			return IssuedPAT{}, err
		}
	}
	scopes, err := normalizeScopes(input.Scopes)
	if err != nil {
		return IssuedPAT{}, err
	}
	prefixBytes, err := randomBytes(m.random, 6)
	if err != nil {
		return IssuedPAT{}, err
	}
	secret, err := randomBytes(m.random, 32)
	if err != nil {
		return IssuedPAT{}, err
	}
	prefix := hex.EncodeToString(prefixBytes)
	raw := m.patPrefix + "_" + prefix + "_" + base64.RawURLEncoding.EncodeToString(secret)
	id, err := m.newID()
	if err != nil {
		return IssuedPAT{}, err
	}
	now := m.now()
	pat := PAT{
		ID: id, UserID: actor.UserID, Name: name, Prefix: prefix,
		Digest: digest(m.patPepper, raw), WorkspaceID: input.WorkspaceID,
		Scopes: scopes, CreatedAt: now, ExpiresAt: cloneTime(input.ExpiresAt),
	}
	event, err := m.newAudit(ctx, actor.UserID, "pat.create", "pat", id.String(), input.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return IssuedPAT{}, err
	}
	meta, err := m.newEventMeta(EventPATCreated, "auth.pat.create", actor.UserID, input.WorkspaceID, event)
	if err != nil {
		return IssuedPAT{}, err
	}
	change := PATCreation{
		EventMeta: meta, PATID: id, UserID: actor.UserID, PATName: name,
		BoundWorkspaceID: input.WorkspaceID, Scopes: slices.Clone(scopes), ExpiresAt: clonePATExpiration(input.ExpiresAt),
	}
	commit := m.transactionalCommit(event, "pat.creation", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyPATCreation(ctx, tx, change)
	})
	if err := m.store.CreatePAT(ctx, pat, commit); err != nil {
		return IssuedPAT{}, m.mapStoreError(ctx, "auth.pat.create", err)
	}
	pat.Digest = nil
	created := PATCreatedEvent{
		EventMeta: meta, PATID: id, UserID: actor.UserID, PATName: name,
		BoundWorkspaceID: input.WorkspaceID, Scopes: slices.Clone(scopes), ExpiresAt: clonePATExpiration(input.ExpiresAt),
	}
	m.events.emit(ctx, EventPATCreated, func(listener EventListener) error { return listener.OnPATCreated(ctx, created) })
	return IssuedPAT{PAT: pat, Token: raw}, nil
}

// AuthenticatePAT validates a raw PAT, whose marker is Config.PATPrefix, in
// constant time against its
// stored digest and returns a non-interactive AAL1 authentication carrying
// the PAT's workspace binding and scopes; last_used_at is updated atomically
// with the audit event. Malformed, unknown, expired and revoked tokens, as
// well as tokens of disabled users or workspaces, all fail with
// ErrInvalidCredentials. The result never satisfies step-up checks.
func (m *Manager) AuthenticatePAT(ctx context.Context, raw string) (_ Authentication, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.pat.authenticate", started, err) }()
	prefix, validShape := parsePAT(m.patPrefix, raw)
	var pat PAT
	if validShape {
		pat, err = m.store.PATByPrefix(ctx, prefix)
	}
	valid := validShape && err == nil && matchDigestRing(pat.Digest, m.readPATPeppers, raw)
	now := m.now()
	if valid && (pat.RevokedAt != nil || (pat.ExpiresAt != nil && !now.Before(*pat.ExpiresAt))) {
		valid = false
	}
	if !valid {
		actor := UUID{}
		if pat.ID != (UUID{}) {
			actor = pat.UserID
		}
		// A token that matches no record names nobody: the rejection is worth
		// recording as scan evidence, but chaining it would let any
		// unauthenticated caller take the instance-wide chain lock once per
		// request. A rejection that does name an account (wrong digest on a
		// known prefix, revoked, expired, disabled owner) stays chained: it is
		// evidence about someone, so it must stay tamper-evident.
		var audit AuditEvent
		var auditErr error
		if actor == (UUID{}) {
			audit, auditErr = m.recordUnknownPATRejection(ctx)
		} else {
			audit, auditErr = m.recordAuthenticationAudit(ctx, actor, "auth.pat", AuditFailed, "invalid_credentials")
		}
		if auditErr != nil {
			return Authentication{}, auditErr
		}
		if meta, metaErr := m.newEventMeta(EventPATRejected, "auth.pat.authenticate", actor, UUID{}, audit); metaErr == nil {
			rejected := PATRejectedEvent{EventMeta: meta, Reason: "invalid_credentials"}
			m.events.emit(ctx, EventPATRejected, func(listener EventListener) error { return listener.OnPATRejected(ctx, rejected) })
		}
		m.emitAuthenticationFailed(ctx, "auth.pat.authenticate", audit, MethodPAT, actor, "invalid_credentials")
		return Authentication{}, ErrInvalidCredentials
	}
	user, err := m.store.UserByID(ctx, pat.UserID)
	if err != nil || user.Disabled {
		audit, auditErr := m.recordAuthenticationAudit(ctx, pat.UserID, "auth.pat", AuditFailed, "invalid_credentials")
		if auditErr != nil {
			return Authentication{}, auditErr
		}
		if meta, metaErr := m.newEventMeta(EventPATRejected, "auth.pat.authenticate", pat.UserID, pat.WorkspaceID, audit); metaErr == nil {
			rejected := PATRejectedEvent{EventMeta: meta, Reason: "invalid_credentials"}
			m.events.emit(ctx, EventPATRejected, func(listener EventListener) error { return listener.OnPATRejected(ctx, rejected) })
		}
		m.emitAuthenticationFailed(ctx, "auth.pat.authenticate", audit, MethodPAT, pat.UserID, "invalid_credentials")
		return Authentication{}, ErrInvalidCredentials
	}
	if pat.WorkspaceID != (UUID{}) {
		workspaceActor := Authentication{UserID: pat.UserID, WorkspaceID: pat.WorkspaceID}
		if err := m.AuthorizePermission(ctx, workspaceActor, pat.WorkspaceID, PermissionWorkspaceAccess); err != nil {
			return Authentication{}, ErrInvalidCredentials
		}
	}
	authentication := Authentication{
		UserID: pat.UserID, Method: MethodPAT, Level: AAL1, AuthenticatedAt: now,
		WorkspaceID: pat.WorkspaceID, Scopes: slices.Clone(pat.Scopes),
	}
	// Within the configured touch interval the authentication stays
	// read-only: the token was used recently enough that refreshing last-used
	// (and appending its audit event) again would only add write contention,
	// and every store-backed check above already ran, so revocation remains
	// instant. This is the difference between one write per machine request
	// and one per token per interval, on a path where every write serializes
	// on the audit chain.
	if m.patTouchInterval > 0 && pat.LastUsedAt != nil && now.Before(pat.LastUsedAt.Add(m.patTouchInterval)) {
		return authentication, nil
	}
	event, err := m.newAudit(ctx, pat.UserID, "auth.pat", "pat", pat.ID.String(), pat.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return Authentication{}, err
	}
	if err := m.store.TouchPAT(ctx, pat.ID, now, Commit{Audit: event}); err != nil {
		return Authentication{}, m.mapStoreError(ctx, "auth.pat.authenticate", err)
	}
	if meta, metaErr := m.newEventMeta(EventPATAuthenticated, "auth.pat.authenticate", pat.UserID, pat.WorkspaceID, event); metaErr == nil {
		authenticated := PATAuthenticatedEvent{EventMeta: meta, PATID: pat.ID, UserID: pat.UserID}
		m.events.emit(ctx, EventPATAuthenticated, func(listener EventListener) error { return listener.OnPATAuthenticated(ctx, authenticated) })
	}
	m.emitAuthenticationSucceeded(ctx, "auth.pat.authenticate", event, authentication)
	return authentication, nil
}

// RevokePAT revokes one of the actor's own tokens, atomically with the audit
// event. It demands the same authentication as CreatePAT (the PAT scope of
// Config.StepUp, a fresh AAL2 step-up by default), so a token can never become harder to
// revoke than it was to issue; a token belonging to another user is reported
// as ErrNotFound by the store.
func (m *Manager) RevokePAT(ctx context.Context, actor Authentication, patID UUID) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.pat.revoke", started, err) }()
	if err := m.requireScopedStepUp(ctx, actor, StepUpScopePAT, "auth.pat.revoke"); err != nil {
		return err
	}
	if patID == (UUID{}) {
		return fmt.Errorf("%w: PAT id is required", ErrInvalidInput)
	}
	event, err := m.newAudit(ctx, actor.UserID, "pat.revoke", "pat", patID.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventPATRevoked, "auth.pat.revoke", actor.UserID, UUID{}, event)
	if err != nil {
		return err
	}
	change := PATRevocation{EventMeta: meta, PATID: patID, UserID: actor.UserID}
	commit := m.transactionalCommit(event, "pat.revocation", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyPATRevocation(ctx, tx, change)
	})
	if err := m.store.RevokePAT(ctx, actor.UserID, patID, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, "auth.pat.revoke", err)
	}
	revoked := PATRevokedEvent{EventMeta: meta, PATID: patID, UserID: actor.UserID}
	m.events.emit(ctx, EventPATRevoked, func(listener EventListener) error { return listener.OnPATRevoked(ctx, revoked) })
	return nil
}

// PATs streams a user's tokens — metadata, prefix and timestamps, never the
// secret. An empty userID means the actor, which requires an interactive
// authentication and nothing more: what it returns are names, prefixes and
// timestamps, not credentials, and a token-management screen that had to
// re-prompt for a password every StepUpMaxAge would train users to
// re-authenticate on sight. Issuing and revoking stay gated by
// Config.StepUp's PAT scope. Reading another user requires admin users read —
// the same scoping as Sessions, Emails and Passkeys.
func (m *Manager) PATs(ctx context.Context, actor Authentication, userID UUID, page PageRequest) iter.Seq2[PageEvent[PAT], error] {
	if actor.UserID == (UUID{}) {
		return errorSeq[PageEvent[PAT]](ErrUnauthorized)
	}
	if userID == (UUID{}) {
		userID = actor.UserID
	}
	if userID == actor.UserID {
		if err := m.requireInteractive(ctx, actor); err != nil {
			return errorSeq[PageEvent[PAT]](err)
		}
	} else if err := m.AuthorizeAdmin(ctx, actor, PermissionUsersRead); err != nil {
		return errorSeq[PageEvent[PAT]](err)
	}
	page, err := normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[PAT]](err)
	}
	return m.store.PATs(ctx, userID, page)
}

// WorkspacePATs streams the tokens bound to one workspace joined with each
// owner's account profile, so a workspace administrator can render the keys
// page of their tenant — including the key of a colleague who has left —
// without the instance-wide admin users read permission. It requires
// workspace credentials manage in that workspace. Digests are never exposed,
// and a token whose owner vanished mid-stream is skipped rather than failing
// the page, exactly like WorkspaceMembers.
//
// Only workspace-bound tokens appear: a token created without a WorkspaceID
// belongs to its user across the whole instance, not to a tenant, so no
// workspace administrator can see or revoke it.
func (m *Manager) WorkspacePATs(ctx context.Context, actor Authentication, workspaceID UUID, page PageRequest) iter.Seq2[PageEvent[WorkspacePAT], error] {
	if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionWorkspaceCredentialsManage); err != nil {
		return errorSeq[PageEvent[WorkspacePAT]](err)
	}
	page, err := normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[WorkspacePAT]](err)
	}
	return func(yield func(PageEvent[WorkspacePAT], error) bool) {
		for event, err := range m.store.WorkspacePATs(ctx, workspaceID, page) {
			if err != nil {
				yield(PageEvent[WorkspacePAT]{}, err)
				return
			}
			if event.Data == nil {
				if event.End != nil && !yield(PageEvent[WorkspacePAT]{Type: event.Type, End: event.End}, nil) {
					return
				}
				continue
			}
			user, userErr := m.store.UserByID(ctx, event.Data.UserID)
			if userErr != nil {
				if errors.Is(userErr, ErrNotFound) {
					continue
				}
				yield(PageEvent[WorkspacePAT]{}, userErr)
				return
			}
			pat := *event.Data
			pat.Digest = nil
			if !yield(ItemEvent(WorkspacePAT{PAT: pat, User: user}), nil) {
				return
			}
		}
	}
}

// RevokeWorkspacePAT revokes a token bound to the workspace, whoever owns it,
// atomically with the audit event. It is how a tenant disables the key of a
// departed member without instance administration: the actor needs workspace
// credentials manage and the step-up its workspace scope demands
// (Config.StepUp). A token that is not bound to this workspace — another
// tenant's, or an unbound instance-wide one — reports ErrNotFound, so the
// permission can never reach beyond the tenant that granted it.
func (m *Manager) RevokeWorkspacePAT(ctx context.Context, actor Authentication, workspaceID, patID UUID) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.pat.workspace_revoke", started, err) }()
	if err := m.authorizeWorkspaceMutation(ctx, actor, workspaceID, PermissionWorkspaceCredentialsManage, "pat.workspace.revoke"); err != nil {
		return err
	}
	if patID == (UUID{}) {
		return fmt.Errorf("%w: PAT id is required", ErrInvalidInput)
	}
	pat, err := m.store.PATByID(ctx, patID)
	if err != nil {
		return m.mapStoreError(ctx, "auth.pat.workspace_revoke", err)
	}
	// The binding is the whole authorization: an unbound token, or one bound
	// elsewhere, is not this workspace's to revoke and must not even be
	// confirmed to exist.
	if pat.WorkspaceID != workspaceID {
		return ErrNotFound
	}
	event, err := m.newAudit(ctx, actor.UserID, "pat.revoke", "pat", patID.String(), workspaceID, AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventPATRevoked, "auth.pat.workspace_revoke", actor.UserID, workspaceID, event)
	if err != nil {
		return err
	}
	change := PATRevocation{EventMeta: meta, PATID: patID, UserID: pat.UserID}
	commit := m.transactionalCommit(event, "pat.revocation", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyPATRevocation(ctx, tx, change)
	})
	if err := m.store.RevokePAT(ctx, pat.UserID, patID, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, "auth.pat.workspace_revoke", err)
	}
	revoked := PATRevokedEvent{EventMeta: meta, PATID: patID, UserID: pat.UserID}
	m.events.emit(ctx, EventPATRevoked, func(listener EventListener) error { return listener.OnPATRevoked(ctx, revoked) })
	return nil
}

// recordUnknownPATRejection audits a token that matches no record at all —
// the shape parsed, the prefix resolved to nothing. It is the one audit event
// Credbound writes outside the hash chain (Commit.Unchained): it names no
// account, so there is nothing in it for an attacker to tamper with in
// anyone's favour, while chaining it would let any unauthenticated caller
// take the instance-wide chain lock once per request — a throughput ceiling
// for every tenant's mutations and an amplification vector for a caller that
// holds no credential. It still fails closed: an audit that cannot be written
// still refuses the authentication.
func (m *Manager) recordUnknownPATRejection(ctx context.Context) (AuditEvent, error) {
	event, err := m.newAudit(ctx, UUID{}, "auth.pat", "user", UUID{}.String(), UUID{}, AuditFailed, "invalid_credentials")
	if err != nil {
		return AuditEvent{}, err
	}
	if err := m.store.AppendAudit(ctx, Commit{Audit: event, Unchained: true}); err != nil {
		return AuditEvent{}, m.mapStoreError(ctx, "auth.pat", err)
	}
	return event, nil
}

// parsePAT validates the `<marker>_<12 hex>_<43 chars>` PAT shape against the
// marker this deployment issues and returns the prefix the store indexes. The
// marker is a parameter, like it is for the sibling parsers, because it is
// configurable (Config.PATPrefix): a PAT minted by another deployment must not
// even reach a lookup here.
func parsePAT(marker, raw string) (string, bool) {
	parts := strings.SplitN(raw, "_", 3)
	if len(parts) != 3 || parts[0] != marker || len(parts[1]) != 12 || len(parts[2]) != 43 {
		return "", false
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", false
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil || len(decoded) != 32 {
		return "", false
	}
	return parts[1], true
}

// normalizeScopes validates and deduplicates the requested PAT scopes. A
// scope is either the "*" wildcard or a workspace permission string —
// AuthorizePermission enforces the set on every scoped authorization, so a
// name outside the permission grammar would create a token that can never
// authorize anything.
func normalizeScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, &ValidationError{Field: "scopes", Rule: "required", Message: "at least one PAT scope is required"}
	}
	seen := make(map[string]struct{}, len(scopes))
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope != "*" && !workspacePermissionPattern.MatchString(scope) {
			return nil, &ValidationError{Field: "scopes", Rule: "format", Message: "a PAT scope must be \"*\" or a workspace permission"}
		}
		if _, duplicate := seen[scope]; duplicate {
			continue
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	slices.Sort(result)
	return result, nil
}

func normalizePage(page PageRequest) (PageRequest, error) {
	if page.Limit == 0 {
		page.Limit = 50
	}
	if page.Limit < 1 || page.Limit > 100 {
		return PageRequest{}, fmt.Errorf("%w: page limit must be between 1 and 100", ErrInvalidInput)
	}
	return page, nil
}

func errorSeq[T any](err error) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		var zero T
		yield(zero, err)
	}
}
