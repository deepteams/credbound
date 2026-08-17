package credbound

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"iter"
	"slices"
	"strings"
)

func (m *Manager) CreatePAT(ctx context.Context, actor Authentication, input CreatePATInput) (_ IssuedPAT, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.pat.create", started, err) }()
	if err := m.requireStepUp(ctx, actor, "auth.pat.create"); err != nil {
		return IssuedPAT{}, err
	}
	name := strings.TrimSpace(input.Name)
	if name == "" || len(name) > 100 {
		return IssuedPAT{}, fmt.Errorf("%w: PAT name is required and limited to 100 characters", ErrInvalidInput)
	}
	if input.ExpiresAt != nil && !input.ExpiresAt.After(m.now()) {
		return IssuedPAT{}, fmt.Errorf("%w: PAT expiration must be in the future", ErrInvalidInput)
	}
	if input.WorkspaceID != "" {
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
	raw := "cbp_" + prefix + "_" + base64.RawURLEncoding.EncodeToString(secret)
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
	event, err := m.newAudit(ctx, actor.UserID, "pat.create", "pat", id, input.WorkspaceID, AuditSucceeded, "")
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

func (m *Manager) AuthenticatePAT(ctx context.Context, raw string) (_ Authentication, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.pat.authenticate", started, err) }()
	prefix, validShape := parsePAT(raw)
	var pat PAT
	if validShape {
		pat, err = m.store.PATByPrefix(ctx, prefix)
	}
	valid := validShape && err == nil && hmac.Equal(pat.Digest, digest(m.patPepper, raw))
	now := m.now()
	if valid && (pat.RevokedAt != nil || (pat.ExpiresAt != nil && !now.Before(*pat.ExpiresAt))) {
		valid = false
	}
	if !valid {
		actor := ""
		if pat.ID != "" {
			actor = pat.UserID
		}
		audit, auditErr := m.recordAuthenticationAudit(ctx, actor, "auth.pat", AuditFailed, "invalid_credentials")
		if auditErr != nil {
			return Authentication{}, auditErr
		}
		if meta, metaErr := m.newEventMeta(EventPATRejected, "auth.pat.authenticate", actor, "", audit); metaErr == nil {
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
	if pat.WorkspaceID != "" {
		workspaceActor := Authentication{UserID: pat.UserID, WorkspaceID: pat.WorkspaceID}
		if err := m.AuthorizePermission(ctx, workspaceActor, pat.WorkspaceID, PermissionWorkspaceAccess); err != nil {
			return Authentication{}, ErrInvalidCredentials
		}
	}
	event, err := m.newAudit(ctx, pat.UserID, "auth.pat", "pat", pat.ID, pat.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return Authentication{}, err
	}
	if err := m.store.TouchPAT(ctx, pat.ID, now, Commit{Audit: event}); err != nil {
		return Authentication{}, m.mapStoreError(ctx, "auth.pat.authenticate", err)
	}
	authentication := Authentication{
		UserID: pat.UserID, Method: MethodPAT, Level: AAL1, AuthenticatedAt: now,
		WorkspaceID: pat.WorkspaceID, Scopes: slices.Clone(pat.Scopes),
	}
	if meta, metaErr := m.newEventMeta(EventPATAuthenticated, "auth.pat.authenticate", pat.UserID, pat.WorkspaceID, event); metaErr == nil {
		authenticated := PATAuthenticatedEvent{EventMeta: meta, PATID: pat.ID, UserID: pat.UserID}
		m.events.emit(ctx, EventPATAuthenticated, func(listener EventListener) error { return listener.OnPATAuthenticated(ctx, authenticated) })
	}
	m.emitAuthenticationSucceeded(ctx, "auth.pat.authenticate", event, authentication)
	return authentication, nil
}

func (m *Manager) RevokePAT(ctx context.Context, actor Authentication, patID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.pat.revoke", started, err) }()
	if err := m.requireStepUp(ctx, actor, "auth.pat.revoke"); err != nil {
		return err
	}
	if patID == "" {
		return fmt.Errorf("%w: PAT id is required", ErrInvalidInput)
	}
	event, err := m.newAudit(ctx, actor.UserID, "pat.revoke", "pat", patID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventPATRevoked, "auth.pat.revoke", actor.UserID, "", event)
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

func (m *Manager) PATs(ctx context.Context, actor Authentication, page PageRequest) iter.Seq2[PageEvent[PAT], error] {
	if err := m.requireRecentInteractive(ctx, actor); err != nil {
		return errorSeq[PageEvent[PAT]](err)
	}
	page, err := normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[PAT]](err)
	}
	return m.store.PATs(ctx, actor.UserID, page)
}

func parsePAT(raw string) (string, bool) {
	parts := strings.SplitN(raw, "_", 3)
	if len(parts) != 3 || parts[0] != "cbp" || len(parts[1]) != 12 || len(parts[2]) != 43 {
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

func normalizeScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, fmt.Errorf("%w: at least one PAT scope is required", ErrInvalidInput)
	}
	seen := make(map[string]struct{}, len(scopes))
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" || len(scope) > 100 {
			return nil, fmt.Errorf("%w: invalid PAT scope", ErrInvalidInput)
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
