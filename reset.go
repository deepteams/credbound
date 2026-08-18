package credbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
)

const passwordResetPrefix = "cbr"

// BeginPasswordReset issues a single-use, expiring reset token for the
// account owning the address. The host delivers the token to that address and
// answers the end user identically whether or not the account exists. When the
// address does not belong to an enabled account, the call succeeds with a zero
// IssuedPasswordReset so the host's error path never becomes an enumeration
// oracle: send the email only when Deliverable is true. The library
// performs the same cryptographic work and a comparable store write in both
// cases so timing does not reveal the difference either.
func (m *Manager) BeginPasswordReset(ctx context.Context, email string) (_ IssuedPasswordReset, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.password.reset.begin", started, err) }()
	normalized := normalizeEmail(email)
	// SSO-006: an address under a confirmed EnforceSSO domain is rejected
	// before any lookup or token derivation. The answer depends only on the
	// domain, never on account existence, so it opens no enumeration oracle.
	if err := m.domainRequiresSSO(ctx, normalized, "password.reset.request"); err != nil {
		return IssuedPasswordReset{}, err
	}
	if allowed, err := m.allowEmailIssuance(ctx, normalized, "password.reset.request"); err != nil {
		return IssuedPasswordReset{}, err
	} else if !allowed {
		if auditErr := m.appendAuthenticationAudit(ctx, "", "password.reset.request", AuditFailed, "throttled"); auditErr != nil {
			return IssuedPasswordReset{}, auditErr
		}
		return IssuedPasswordReset{}, nil
	}
	user, lookupErr := m.store.UserByEmail(ctx, normalized)
	// Generate the identifier and secret before deciding the outcome so the
	// work performed is identical for unknown addresses.
	id, err := m.newID()
	if err != nil {
		return IssuedPasswordReset{}, err
	}
	secret, err := randomBytes(m.random, 32)
	if err != nil {
		return IssuedPasswordReset{}, err
	}
	raw := passwordResetPrefix + "_" + id + "_" + base64.RawURLEncoding.EncodeToString(secret)
	tokenDigest := m.tokenDigest("password-reset:" + raw)
	if lookupErr != nil {
		if !errors.Is(lookupErr, ErrNotFound) {
			return IssuedPasswordReset{}, lookupErr
		}
		if auditErr := m.appendAuthenticationAudit(ctx, "", "password.reset.request", AuditFailed, "unknown_email"); auditErr != nil {
			return IssuedPasswordReset{}, auditErr
		}
		return IssuedPasswordReset{}, nil
	}
	if user.Disabled {
		if auditErr := m.appendAuthenticationAudit(ctx, user.ID, "password.reset.request", AuditFailed, "user_disabled"); auditErr != nil {
			return IssuedPasswordReset{}, auditErr
		}
		return IssuedPasswordReset{}, nil
	}
	now := m.now()
	credential := PasswordResetCredential{
		ID: id, UserID: user.ID, Digest: tokenDigest,
		CreatedAt: now, ExpiresAt: now.Add(m.passwordResetTTL),
	}
	event, err := m.newAudit(ctx, user.ID, "password.reset.request", "user", user.ID, "", AuditSucceeded, "")
	if err != nil {
		return IssuedPasswordReset{}, err
	}
	meta, err := m.newEventMeta(EventPasswordResetRequested, "auth.password.reset.begin", user.ID, "", event)
	if err != nil {
		return IssuedPasswordReset{}, err
	}
	if err := m.store.CreatePasswordReset(ctx, credential, Commit{Audit: event}); err != nil {
		return IssuedPasswordReset{}, m.mapStoreError(ctx, "auth.password.reset.begin", err)
	}
	requested := PasswordResetRequestedEvent{EventMeta: meta, UserID: user.ID, ResetID: id, ExpiresAt: credential.ExpiresAt}
	m.events.emit(ctx, EventPasswordResetRequested, func(listener EventListener) error { return listener.OnPasswordResetRequested(ctx, requested) })
	return IssuedPasswordReset{UserID: user.ID, Token: raw, ExpiresAt: credential.ExpiresAt, Deliverable: true}, nil
}

// CompletePasswordReset consumes a reset token and installs the new password.
// For a passwordless member provisioned by SSO JIT or SCIM this installs
// their first password: the verified email proof is the same authority every
// reset rests on. An address under a confirmed EnforceSSO domain is refused
// by BeginPasswordReset up front, and the account's primary address is
// re-checked here so an in-flight token does not outlive an EnforceSSO
// confirmation — consuming it would install an unusable password yet still
// revoke the account's sessions, PATs and grants.
// As required by the recovery policy, it atomically revokes every PAT and
// OAuth grant of the account and clears its login throttle. When the store
// supports sessions (SessionStore) the user's server-side sessions are
// revoked in the same transaction; hosts managing their own sessions must
// still terminate those themselves. The user then signs in again with the
// new password.
func (m *Manager) CompletePasswordReset(ctx context.Context, raw, newPassword string) (_ User, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.password.reset.complete", started, err) }()
	resetID, valid := parseSecretToken(passwordResetPrefix, raw)
	if !valid {
		return User{}, ErrInvalidCredentials
	}
	credential, lookupErr := m.store.PasswordResetByID(ctx, resetID)
	if lookupErr != nil {
		if errors.Is(lookupErr, ErrNotFound) {
			return User{}, ErrInvalidCredentials
		}
		return User{}, lookupErr
	}
	if credential.UsedAt != nil {
		if auditErr := m.appendAuthenticationAudit(ctx, credential.UserID, "password.reset.complete", AuditFailed, "reused"); auditErr != nil {
			return User{}, auditErr
		}
		return User{}, ErrInvalidCredentials
	}
	if !m.now().Before(credential.ExpiresAt) {
		if auditErr := m.appendAuthenticationAudit(ctx, credential.UserID, "password.reset.complete", AuditFailed, "expired"); auditErr != nil {
			return User{}, auditErr
		}
		return User{}, ErrExpired
	}
	if !m.matchTokenDigest(credential.Digest, "password-reset:"+raw) {
		if auditErr := m.appendAuthenticationAudit(ctx, credential.UserID, "password.reset.complete", AuditFailed, "invalid_credentials"); auditErr != nil {
			return User{}, auditErr
		}
		return User{}, ErrInvalidCredentials
	}
	if err := m.validatePassword(ctx, newPassword); err != nil {
		return User{}, err
	}
	user, err := m.store.UserByID(ctx, credential.UserID)
	if err != nil || user.Disabled {
		if auditErr := m.appendAuthenticationAudit(ctx, credential.UserID, "password.reset.complete", AuditFailed, "user_disabled"); auditErr != nil {
			return User{}, auditErr
		}
		return User{}, ErrInvalidCredentials
	}
	// SSO-006: see the doc comment — the policy can be confirmed between
	// issuance and redemption, so the in-flight token is refused rather than
	// left as a working denial-of-access lever.
	if ssoErr := m.domainRequiresSSO(ctx, normalizeEmail(user.Email), "password.reset.complete"); ssoErr != nil {
		return User{}, ssoErr
	}
	hash, err := m.passwords.Hash(newPassword)
	if err != nil {
		return User{}, fmt.Errorf("hash password: %w", err)
	}
	now := m.now()
	event, err := m.newAudit(ctx, user.ID, "password.reset.complete", "user", user.ID, "", AuditSucceeded, "")
	if err != nil {
		return User{}, err
	}
	resetMeta, err := m.newEventMeta(EventPasswordResetCompleted, "auth.password.reset.complete", user.ID, "", event)
	if err != nil {
		return User{}, err
	}
	revokeMeta, err := m.newEventMeta(EventUserCredentialsRevoked, "auth.password.reset.complete", user.ID, "", event)
	if err != nil {
		return User{}, err
	}
	passwordChange := PasswordChange{EventMeta: resetMeta, UserID: user.ID}
	revocation := UserCredentialRevocation{EventMeta: revokeMeta, UserID: user.ID}
	commit := Commit{Audit: event, Transactional: func(ctx context.Context, tx Tx) error {
		if err := m.events.apply(ctx, "password.change", func(hook TransactionHook) error {
			return hook.ApplyPasswordChange(ctx, tx, passwordChange)
		}); err != nil {
			return err
		}
		return m.events.apply(ctx, "user.credentials.revocation", func(hook TransactionHook) error {
			return hook.ApplyUserCredentialRevocation(ctx, tx, revocation)
		})
	}}
	if err := m.store.CompletePasswordReset(ctx, resetID, PasswordCredential{UserID: user.ID, Hash: hash, UpdatedAt: now}, now, commit); err != nil {
		if errors.Is(err, ErrConflict) {
			return User{}, ErrInvalidCredentials
		}
		return User{}, m.mapStoreError(ctx, "auth.password.reset.complete", err)
	}
	completed := PasswordResetCompletedEvent{EventMeta: resetMeta, UserID: user.ID}
	m.events.emit(ctx, EventPasswordResetCompleted, func(listener EventListener) error { return listener.OnPasswordResetCompleted(ctx, completed) })
	revoked := UserCredentialsRevokedEvent{EventMeta: revokeMeta, UserID: user.ID}
	m.events.emit(ctx, EventUserCredentialsRevoked, func(listener EventListener) error { return listener.OnUserCredentialsRevoked(ctx, revoked) })
	return user, nil
}
