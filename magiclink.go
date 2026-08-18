package credbound

import (
	"context"
	"encoding/base64"
	"errors"
)

const emailAuthenticationPrefix = "cbl"

// BeginEmailAuthentication issues a single-use, short-lived magic-link token
// for the account owning the verified address. The host delivers the token to
// that address and answers the end user identically whether or not the account
// exists. When the address does not belong to a verified email of an enabled
// account, the call succeeds with a zero IssuedEmailAuthentication (empty
// Token) so the host's error path never becomes an enumeration oracle: send
// the email only when Token is non-empty.
func (m *Manager) BeginEmailAuthentication(ctx context.Context, email string) (_ IssuedEmailAuthentication, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.email_link.begin", started, err) }()
	normalized := normalizeEmail(email)
	// SSO-006: an address under a confirmed EnforceSSO domain is rejected
	// before any lookup or token derivation. The answer depends only on the
	// domain, never on account existence, so it opens no enumeration oracle.
	if err := m.domainRequiresSSO(ctx, normalized, "email_authentication.request"); err != nil {
		return IssuedEmailAuthentication{}, err
	}
	if allowed, err := m.allowEmailIssuance(ctx, normalized, "email_authentication.request"); err != nil {
		return IssuedEmailAuthentication{}, err
	} else if !allowed {
		if auditErr := m.appendAuthenticationAudit(ctx, "", "email_authentication.request", AuditFailed, "throttled"); auditErr != nil {
			return IssuedEmailAuthentication{}, auditErr
		}
		return IssuedEmailAuthentication{}, nil
	}
	user, lookupErr := m.store.UserByEmail(ctx, normalized)
	// Generate the identifier and secret before deciding the outcome so the
	// work performed is identical for unknown addresses.
	id, err := m.newID()
	if err != nil {
		return IssuedEmailAuthentication{}, err
	}
	secret, err := randomBytes(m.random, 32)
	if err != nil {
		return IssuedEmailAuthentication{}, err
	}
	raw := emailAuthenticationPrefix + "_" + id + "_" + base64.RawURLEncoding.EncodeToString(secret)
	tokenDigest := m.tokenDigest("email-authentication:" + raw)
	if lookupErr != nil {
		if !errors.Is(lookupErr, ErrNotFound) {
			return IssuedEmailAuthentication{}, lookupErr
		}
		if auditErr := m.appendAuthenticationAudit(ctx, "", "email_authentication.request", AuditFailed, "unknown_email"); auditErr != nil {
			return IssuedEmailAuthentication{}, auditErr
		}
		return IssuedEmailAuthentication{}, nil
	}
	if user.Disabled {
		if auditErr := m.appendAuthenticationAudit(ctx, user.ID, "email_authentication.request", AuditFailed, "user_disabled"); auditErr != nil {
			return IssuedEmailAuthentication{}, auditErr
		}
		return IssuedEmailAuthentication{}, nil
	}
	emailID, err := m.verifiedEmailID(ctx, user.ID, normalized)
	if errors.Is(err, ErrNotFound) {
		if auditErr := m.appendAuthenticationAudit(ctx, user.ID, "email_authentication.request", AuditFailed, "unverified_email"); auditErr != nil {
			return IssuedEmailAuthentication{}, auditErr
		}
		return IssuedEmailAuthentication{}, nil
	}
	if err != nil {
		return IssuedEmailAuthentication{}, err
	}
	now := m.now()
	credential := EmailAuthenticationCredential{
		ID: id, UserID: user.ID, EmailID: emailID, Digest: tokenDigest,
		CreatedAt: now, ExpiresAt: now.Add(m.emailAuthTTL),
	}
	event, err := m.newAudit(ctx, user.ID, "email_authentication.request", "user", user.ID, "", AuditSucceeded, "")
	if err != nil {
		return IssuedEmailAuthentication{}, err
	}
	meta, err := m.newEventMeta(EventEmailAuthenticationRequested, "auth.email_link.begin", user.ID, "", event)
	if err != nil {
		return IssuedEmailAuthentication{}, err
	}
	if err := m.store.CreateEmailAuthentication(ctx, credential, Commit{Audit: event}); err != nil {
		return IssuedEmailAuthentication{}, m.mapStoreError(ctx, "auth.email_link.begin", err)
	}
	requested := EmailAuthenticationRequestedEvent{EventMeta: meta, UserID: user.ID, EmailID: emailID, ExpiresAt: credential.ExpiresAt}
	m.events.emit(ctx, EventEmailAuthenticationRequested, func(listener EventListener) error { return listener.OnEmailAuthenticationRequested(ctx, requested) })
	return IssuedEmailAuthentication{UserID: user.ID, EmailID: emailID, Token: raw, ExpiresAt: credential.ExpiresAt}, nil
}

// CompleteEmailAuthentication consumes a magic-link token and returns an AAL1
// interactive authentication. Like a password login, it reports whether an
// active TOTP factor still has to be verified before AAL2 operations.
func (m *Manager) CompleteEmailAuthentication(ctx context.Context, raw string) (_ Authentication, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.email_link.complete", started, err) }()
	tokenID, valid := parseSecretToken(emailAuthenticationPrefix, raw)
	if !valid {
		return Authentication{}, ErrInvalidCredentials
	}
	credential, lookupErr := m.store.EmailAuthenticationByID(ctx, tokenID)
	if lookupErr != nil {
		if errors.Is(lookupErr, ErrNotFound) {
			return Authentication{}, ErrInvalidCredentials
		}
		return Authentication{}, lookupErr
	}
	if credential.UsedAt != nil {
		if auditErr := m.appendAuthenticationAudit(ctx, credential.UserID, "auth.email_link", AuditFailed, "reused"); auditErr != nil {
			return Authentication{}, auditErr
		}
		return Authentication{}, ErrInvalidCredentials
	}
	if !m.now().Before(credential.ExpiresAt) {
		if auditErr := m.appendAuthenticationAudit(ctx, credential.UserID, "auth.email_link", AuditFailed, "expired"); auditErr != nil {
			return Authentication{}, auditErr
		}
		return Authentication{}, ErrExpired
	}
	if !m.matchTokenDigest(credential.Digest, "email-authentication:"+raw) {
		if auditErr := m.appendAuthenticationAudit(ctx, credential.UserID, "auth.email_link", AuditFailed, "invalid_credentials"); auditErr != nil {
			return Authentication{}, auditErr
		}
		return Authentication{}, ErrInvalidCredentials
	}
	user, err := m.store.UserByID(ctx, credential.UserID)
	if err != nil || user.Disabled {
		if auditErr := m.appendAuthenticationAudit(ctx, credential.UserID, "auth.email_link", AuditFailed, "user_disabled"); auditErr != nil {
			return Authentication{}, auditErr
		}
		return Authentication{}, ErrInvalidCredentials
	}
	factor, factorErr := m.store.TOTPByUserID(ctx, user.ID)
	requiresSecondFactor := factorErr == nil && factor.Active
	if factorErr != nil && !errors.Is(factorErr, ErrNotFound) {
		return Authentication{}, factorErr
	}
	now := m.now()
	event, err := m.newAudit(ctx, user.ID, "auth.email_link", "user", user.ID, "", AuditSucceeded, "")
	if err != nil {
		return Authentication{}, err
	}
	if err := m.store.ConsumeEmailAuthentication(ctx, tokenID, user.ID, now, Commit{Audit: event}); err != nil {
		if errors.Is(err, ErrConflict) {
			return Authentication{}, ErrInvalidCredentials
		}
		return Authentication{}, m.mapStoreError(ctx, "auth.email_link.complete", err)
	}
	authentication := Authentication{
		UserID:               user.ID,
		Method:               MethodEmail,
		Level:                AAL1,
		AuthenticatedAt:      now,
		SecondFactorRequired: requiresSecondFactor,
	}
	m.emitAuthenticationSucceeded(ctx, "auth.email_link.complete", event, authentication)
	return authentication, nil
}

// verifiedEmailID resolves the verified address record used by a magic link.
func (m *Manager) verifiedEmailID(ctx context.Context, userID, address string) (string, error) {
	for email, err := range m.userEmails(ctx, userID) {
		if err != nil {
			return "", err
		}
		if email.Address == address && email.VerifiedAt != nil {
			return email.ID, nil
		}
	}
	return "", ErrNotFound
}
