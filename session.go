package credbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"iter"
)

const sessionTokenPrefix = "cbs"

// CreateSession persists a server-side session for the actor: an immutable
// snapshot of the Authentication (method, level, authenticated-at, pending
// second factor) plus the device metadata attached to the context with
// WithRequestMetadata, behind an opaque cbs_ token returned exactly once.
// Only the HMAC digest of the token is stored, atomically with the audit
// event. It requires a SessionStore-capable store (ErrNotSupported
// otherwise), an interactive actor — a PAT-backed Authentication is
// non-interactive and fails with ErrForbidden — and an enabled user.
//
// Sessions never change assurance level in place: after VerifyTOTP or any
// other AAL transition the host calls CreateSession again with the promoted
// Authentication and revokes the previous session, which doubles as fixation
// protection. Expiry is absolute (CreatedAt plus Config.SessionTTL) and is
// never extended by activity.
func (m *Manager) CreateSession(ctx context.Context, actor Authentication, _ CreateSessionInput) (_ IssuedSession, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.session.create", started, err) }()
	if m.sessionStore == nil {
		return IssuedSession{}, ErrNotSupported
	}
	if actor.UserID == "" {
		return IssuedSession{}, ErrUnauthorized
	}
	if !actor.Interactive() {
		return IssuedSession{}, ErrForbidden
	}
	if err := m.requireActiveUser(ctx, actor.UserID); err != nil {
		return IssuedSession{}, err
	}
	id, err := m.newID()
	if err != nil {
		return IssuedSession{}, err
	}
	secret, err := randomBytes(m.random, 32)
	if err != nil {
		return IssuedSession{}, err
	}
	raw := sessionTokenPrefix + "_" + id + "_" + base64.RawURLEncoding.EncodeToString(secret)
	metadata := requestMetadataFromContext(ctx)
	now := m.now()
	session := Session{
		ID: id, UserID: actor.UserID, Method: actor.Method, Level: actor.Level,
		AuthenticatedAt: actor.AuthenticatedAt, SecondFactorRequired: actor.SecondFactorRequired,
		UserAgent: metadata.UserAgent, IPAddress: metadata.IPAddress,
		Digest:    m.tokenDigest("session:" + raw),
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(m.sessionTTL),
	}
	event, err := m.newAudit(ctx, actor.UserID, "session.create", "session", id, "", AuditSucceeded, "")
	if err != nil {
		return IssuedSession{}, err
	}
	meta, err := m.newEventMeta(EventSessionCreated, "auth.session.create", actor.UserID, "", event)
	if err != nil {
		return IssuedSession{}, err
	}
	scrubbed := session
	scrubbed.Digest = nil
	change := SessionCreation{EventMeta: meta, Session: scrubbed, Request: metadata}
	commit := m.transactionalCommit(event, "session.creation", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplySessionCreation(ctx, tx, change)
	})
	if err := m.sessionStore.CreateSession(ctx, session, commit); err != nil {
		return IssuedSession{}, m.mapStoreError(ctx, "auth.session.create", err)
	}
	created := SessionCreatedEvent{EventMeta: meta, Session: scrubbed, Request: metadata}
	m.events.emit(ctx, EventSessionCreated, func(listener EventListener) error { return listener.OnSessionCreated(ctx, created) })
	return IssuedSession{Session: scrubbed, Token: raw}, nil
}

// AuthenticateSession validates a raw cbs_ session token in constant time
// against its stored digest, enforces expiry (ErrExpired) and revocation,
// re-checks that the user is still enabled, touches the session's last-seen
// timestamp atomically with the audit event, and returns the immutable
// Authentication snapshot together with the Session record (Digest scrubbed).
// Malformed and unknown tokens, revoked sessions and sessions of disabled
// users all fail with ErrInvalidCredentials.
//
// The returned Authentication reproduces the snapshot verbatim — including
// AuthenticatedAt — so step-up freshness keeps measuring the original factor
// verification. Validation happens on every request, so it deliberately emits
// no authentication.succeeded (or any other) event; the audit log is the
// record of session activity.
//
// Cost note: every successful validation performs one write transaction (the
// last-seen touch committed with its audit event). High-traffic hosts should
// budget for that, and may cache the (Authentication, Session) result for a
// short, bounded interval per token — accepting that a revocation takes
// effect at the end of the cache window rather than instantly.
func (m *Manager) AuthenticateSession(ctx context.Context, raw string) (_ Authentication, _ Session, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.session.authenticate", started, err) }()
	if m.sessionStore == nil {
		return Authentication{}, Session{}, ErrNotSupported
	}
	sessionID, valid := parseSecretToken(sessionTokenPrefix, raw)
	if !valid {
		return Authentication{}, Session{}, ErrInvalidCredentials
	}
	session, lookupErr := m.sessionStore.SessionByID(ctx, sessionID)
	if lookupErr != nil {
		if errors.Is(lookupErr, ErrNotFound) {
			return Authentication{}, Session{}, ErrInvalidCredentials
		}
		return Authentication{}, Session{}, lookupErr
	}
	// The digest is verified before any state check so a caller who only
	// knows a session identifier — without the secret — cannot distinguish
	// revoked from expired from nonexistent.
	if !m.matchTokenDigest(session.Digest, "session:"+raw) {
		if auditErr := m.appendAuthenticationAudit(ctx, session.UserID, "session.authenticate", AuditFailed, "invalid_credentials"); auditErr != nil {
			return Authentication{}, Session{}, auditErr
		}
		return Authentication{}, Session{}, ErrInvalidCredentials
	}
	if session.RevokedAt != nil {
		if auditErr := m.appendAuthenticationAudit(ctx, session.UserID, "session.authenticate", AuditFailed, "revoked"); auditErr != nil {
			return Authentication{}, Session{}, auditErr
		}
		return Authentication{}, Session{}, ErrInvalidCredentials
	}
	if !m.now().Before(session.ExpiresAt) {
		if auditErr := m.appendAuthenticationAudit(ctx, session.UserID, "session.authenticate", AuditFailed, "expired"); auditErr != nil {
			return Authentication{}, Session{}, auditErr
		}
		return Authentication{}, Session{}, ErrExpired
	}
	user, userErr := m.store.UserByID(ctx, session.UserID)
	if userErr != nil || user.Disabled {
		if userErr != nil && !errors.Is(userErr, ErrNotFound) {
			return Authentication{}, Session{}, userErr
		}
		if auditErr := m.appendAuthenticationAudit(ctx, session.UserID, "session.authenticate", AuditFailed, "user_disabled"); auditErr != nil {
			return Authentication{}, Session{}, auditErr
		}
		return Authentication{}, Session{}, ErrInvalidCredentials
	}
	now := m.now()
	event, err := m.newAudit(ctx, session.UserID, "session.authenticate", "session", session.ID, "", AuditSucceeded, "")
	if err != nil {
		return Authentication{}, Session{}, err
	}
	if err := m.sessionStore.TouchSession(ctx, session.ID, now, Commit{Audit: event}); err != nil {
		return Authentication{}, Session{}, m.mapStoreError(ctx, "auth.session.authenticate", err)
	}
	session.LastSeenAt = now
	session.Digest = nil
	authentication := Authentication{
		UserID: session.UserID, Method: session.Method, Level: session.Level,
		AuthenticatedAt: session.AuthenticatedAt, SecondFactorRequired: session.SecondFactorRequired,
	}
	return authentication, session, nil
}

// SignOut revokes the session identified by possession of its raw token —
// the ordinary logout. Unlike RevokeSession it needs no step-up and no actor:
// holding the single-display token proves ownership exactly as it does for
// AuthenticateSession, so even a password-only (AAL1) deployment can sign out
// immediately. Signing out an already-revoked session succeeds silently
// (logout is idempotent); an expired session is still revoked so its record
// reads as closed. Malformed, unknown, and forged tokens fail with
// ErrInvalidCredentials.
func (m *Manager) SignOut(ctx context.Context, raw string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.session.sign_out", started, err) }()
	if m.sessionStore == nil {
		return ErrNotSupported
	}
	sessionID, valid := parseSecretToken(sessionTokenPrefix, raw)
	if !valid {
		return ErrInvalidCredentials
	}
	session, lookupErr := m.sessionStore.SessionByID(ctx, sessionID)
	if lookupErr != nil {
		if errors.Is(lookupErr, ErrNotFound) {
			return ErrInvalidCredentials
		}
		return lookupErr
	}
	if !m.matchTokenDigest(session.Digest, "session:"+raw) {
		if auditErr := m.appendAuthenticationAudit(ctx, session.UserID, "session.sign_out", AuditFailed, "invalid_credentials"); auditErr != nil {
			return auditErr
		}
		return ErrInvalidCredentials
	}
	if session.RevokedAt != nil {
		return nil
	}
	event, err := m.newAudit(ctx, session.UserID, "session.sign_out", "session", session.ID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventSessionRevoked, "auth.session.sign_out", session.UserID, "", event)
	if err != nil {
		return err
	}
	change := SessionRevocation{EventMeta: meta, SessionID: session.ID, UserID: session.UserID}
	commit := m.transactionalCommit(event, "session.revocation", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplySessionRevocation(ctx, tx, change)
	})
	if err := m.sessionStore.RevokeSession(ctx, session.ID, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, "auth.session.sign_out", err)
	}
	revoked := SessionRevokedEvent{EventMeta: meta, SessionID: session.ID, UserID: session.UserID}
	m.events.emit(ctx, EventSessionRevoked, func(listener EventListener) error { return listener.OnSessionRevoked(ctx, revoked) })
	return nil
}

// Sessions streams a user's sessions — snapshot, device metadata and
// timestamps, never the token digest. The actor lists their own sessions
// (userID empty or equal to the actor) with a recent interactive
// authentication; listing another user's sessions additionally requires a
// fresh AAL2 step-up and admin users read.
func (m *Manager) Sessions(ctx context.Context, actor Authentication, userID string, page PageRequest) iter.Seq2[PageEvent[Session], error] {
	if m.sessionStore == nil {
		return errorSeq[PageEvent[Session]](ErrNotSupported)
	}
	if actor.UserID == "" {
		return errorSeq[PageEvent[Session]](ErrUnauthorized)
	}
	if userID == "" {
		userID = actor.UserID
	}
	if userID == actor.UserID {
		if err := m.requireRecentInteractive(ctx, actor); err != nil {
			return errorSeq[PageEvent[Session]](err)
		}
	} else {
		if err := m.requireStepUp(ctx, actor, "auth.session.list"); err != nil {
			return errorSeq[PageEvent[Session]](err)
		}
		if err := m.AuthorizeAdmin(ctx, actor, PermissionUsersRead); err != nil {
			return errorSeq[PageEvent[Session]](err)
		}
	}
	page, err := normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[Session]](err)
	}
	return m.sessionStore.Sessions(ctx, userID, page)
}

// RevokeSession revokes one of the actor's own sessions, atomically with the
// audit event. Like PAT revocation it requires a fresh AAL2 step-up, and a
// session belonging to another user is reported as ErrNotFound. Bulk and
// administrative revocation go through RevokeUserSessions instead.
func (m *Manager) RevokeSession(ctx context.Context, actor Authentication, sessionID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.session.revoke", started, err) }()
	if m.sessionStore == nil {
		return ErrNotSupported
	}
	if err := m.requireStepUp(ctx, actor, "auth.session.revoke"); err != nil {
		return err
	}
	if sessionID == "" {
		return fmt.Errorf("%w: session id is required", ErrInvalidInput)
	}
	session, err := m.sessionStore.SessionByID(ctx, sessionID)
	if err != nil {
		return err
	}
	if session.UserID != actor.UserID {
		return ErrNotFound
	}
	event, err := m.newAudit(ctx, actor.UserID, "session.revoke", "session", sessionID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventSessionRevoked, "auth.session.revoke", actor.UserID, "", event)
	if err != nil {
		return err
	}
	change := SessionRevocation{EventMeta: meta, SessionID: sessionID, UserID: actor.UserID}
	commit := m.transactionalCommit(event, "session.revocation", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplySessionRevocation(ctx, tx, change)
	})
	if err := m.sessionStore.RevokeSession(ctx, sessionID, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, "auth.session.revoke", err)
	}
	revoked := SessionRevokedEvent{EventMeta: meta, SessionID: sessionID, UserID: actor.UserID}
	m.events.emit(ctx, EventSessionRevoked, func(listener EventListener) error { return listener.OnSessionRevoked(ctx, revoked) })
	return nil
}

// RevokeUserSessions revokes every active session of a user in one atomic
// operation ("log out everywhere"). Its authorization mirrors
// RevokeUserCredentials: a user runs it on their own account with a fresh
// AAL2 step-up; revoking another user's sessions requires an instance
// administrator with admin users write and an admin mutation (fresh AAL2, or
// a trusted local request).
func (m *Manager) RevokeUserSessions(ctx context.Context, actor Authentication, request TrustedRequest, userID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.session.revoke_all", started, err) }()
	if m.sessionStore == nil {
		return ErrNotSupported
	}
	if userID == "" {
		userID = actor.UserID
	}
	if !validUUIDv7(userID) {
		return fmt.Errorf("%w: invalid user id", ErrInvalidInput)
	}
	if userID == actor.UserID {
		if err := m.requireStepUp(ctx, actor, "auth.session.revoke_all"); err != nil {
			return err
		}
	} else {
		if err := m.requireAdminMutation(ctx, actor, request, "auth.session.revoke_all"); err != nil {
			return err
		}
		if err := m.AuthorizeAdmin(ctx, actor, PermissionUsersWrite); err != nil {
			return err
		}
	}
	event, err := m.newAudit(ctx, actor.UserID, "session.revoke_all", "user", userID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventUserSessionsRevoked, "auth.session.revoke_all", actor.UserID, "", event)
	if err != nil {
		return err
	}
	change := UserSessionRevocation{EventMeta: meta, UserID: userID}
	commit := m.transactionalCommit(event, "session.user_revocation", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyUserSessionRevocation(ctx, tx, change)
	})
	if err := m.sessionStore.RevokeUserSessions(ctx, userID, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, "auth.session.revoke_all", err)
	}
	revoked := UserSessionsRevokedEvent{EventMeta: meta, UserID: userID}
	m.events.emit(ctx, EventUserSessionsRevoked, func(listener EventListener) error { return listener.OnUserSessionsRevoked(ctx, revoked) })
	return nil
}
