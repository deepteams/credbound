package credbound

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const emailOTPOperation = "email_otp"

// BeginEmailOTP issues a single-use, short-lived numeric code for the account
// owning the verified address, together with a sealed continuation that the
// host passes back to CompleteEmailOTP with the code the user typed. The
// continuation is AEAD-sealed and tamper-proof, so it may safely round-trip
// through the client (a cookie or hidden form field); what matters is that it
// come back with the code, not where it was kept.
// Binding the code to the continuation keeps its short length safe: a code is
// only ever compared against the single credential it was issued for, and
// failed attempts count toward the account lockout.
//
// The call answers identically whether or not the address is eligible: for an
// unknown, disabled, or unverified address it still returns a well-formed
// continuation with an empty Code and Deliverable false, so the host sends no
// email but responds to the end user exactly as in the success case, and the
// later completion fails like any wrong code. Send the email only when
// Deliverable is true.
func (m *Manager) BeginEmailOTP(ctx context.Context, email string) (_ IssuedEmailOTP, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.email_otp.begin", started, err) }()
	normalized := normalizeEmail(email)
	// SSO-006: an address under a confirmed EnforceSSO domain is rejected
	// before any lookup or code derivation. The answer depends only on the
	// domain, never on account existence, so it opens no enumeration oracle.
	if err := m.domainRequiresSSO(ctx, normalized, "email_otp.request"); err != nil {
		return IssuedEmailOTP{}, err
	}
	if allowed, err := m.allowEmailIssuance(ctx, normalized, "email_otp.request"); err != nil {
		return IssuedEmailOTP{}, err
	} else if !allowed {
		if auditErr := m.appendAuthenticationAudit(ctx, "", "email_otp.request", AuditFailed, "throttled"); auditErr != nil {
			return IssuedEmailOTP{}, auditErr
		}
		return IssuedEmailOTP{}, nil
	}
	user, lookupErr := m.store.UserByEmail(ctx, normalized)
	// Generate the identifier and code before deciding the outcome so the
	// work performed is identical for unknown addresses.
	id, err := m.newID()
	if err != nil {
		return IssuedEmailOTP{}, err
	}
	code, err := m.newEmailOTPCode()
	if err != nil {
		return IssuedEmailOTP{}, err
	}
	now := m.now()
	expiresAt := now.Add(m.emailAuthTTL)
	// The continuation outlives the code by a small grace period so an
	// attempt with an expired code is still audited as "expired" instead of
	// failing opaquely at the continuation boundary.
	continuation, err := m.encodeContinuation(ceremonyContinuation{
		UserID: id, Operation: emailOTPOperation, Name: id, ExpiresAt: expiresAt.Add(time.Minute),
	})
	if err != nil {
		return IssuedEmailOTP{}, err
	}
	if lookupErr != nil {
		if !errors.Is(lookupErr, ErrNotFound) {
			return IssuedEmailOTP{}, lookupErr
		}
		if auditErr := m.appendAuthenticationAudit(ctx, "", "email_otp.request", AuditFailed, "unknown_email"); auditErr != nil {
			return IssuedEmailOTP{}, auditErr
		}
		return IssuedEmailOTP{Continuation: continuation, ExpiresAt: expiresAt}, nil
	}
	if user.Disabled {
		if auditErr := m.appendAuthenticationAudit(ctx, user.ID, "email_otp.request", AuditFailed, "user_disabled"); auditErr != nil {
			return IssuedEmailOTP{}, auditErr
		}
		return IssuedEmailOTP{Continuation: continuation, ExpiresAt: expiresAt}, nil
	}
	emailID, err := m.verifiedEmailID(ctx, user.ID, normalized)
	if errors.Is(err, ErrNotFound) {
		if auditErr := m.appendAuthenticationAudit(ctx, user.ID, "email_otp.request", AuditFailed, "unverified_email"); auditErr != nil {
			return IssuedEmailOTP{}, auditErr
		}
		return IssuedEmailOTP{Continuation: continuation, ExpiresAt: expiresAt}, nil
	}
	if err != nil {
		return IssuedEmailOTP{}, err
	}
	credential := EmailAuthenticationCredential{
		ID: id, UserID: user.ID, EmailID: emailID,
		Digest:    m.tokenDigest("email-otp:" + id + ":" + code),
		CreatedAt: now, ExpiresAt: expiresAt,
	}
	event, err := m.newAudit(ctx, user.ID, "email_otp.request", "user", user.ID, "", AuditSucceeded, "")
	if err != nil {
		return IssuedEmailOTP{}, err
	}
	meta, err := m.newEventMeta(EventEmailAuthenticationRequested, "auth.email_otp.begin", user.ID, "", event)
	if err != nil {
		return IssuedEmailOTP{}, err
	}
	if err := m.store.CreateEmailAuthentication(ctx, credential, Commit{Audit: event}); err != nil {
		return IssuedEmailOTP{}, m.mapStoreError(ctx, "auth.email_otp.begin", err)
	}
	requested := EmailAuthenticationRequestedEvent{EventMeta: meta, UserID: user.ID, EmailID: emailID, ExpiresAt: expiresAt}
	m.events.emit(ctx, EventEmailAuthenticationRequested, func(listener EventListener) error { return listener.OnEmailAuthenticationRequested(ctx, requested) })
	return IssuedEmailOTP{UserID: user.ID, EmailID: emailID, Code: code, Continuation: continuation, ExpiresAt: expiresAt, Deliverable: true}, nil
}

// CompleteEmailOTP consumes an email OTP and returns an AAL1 interactive
// authentication. Like a password login, it reports whether an active TOTP
// factor still has to be verified before AAL2 operations. A wrong code counts
// toward the account lockout exactly like a wrong password.
func (m *Manager) CompleteEmailOTP(ctx context.Context, continuation, code string) (_ Authentication, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.email_otp.complete", started, err) }()
	state, err := m.decodeContinuation(continuation, emailOTPOperation)
	if err != nil {
		return Authentication{}, err
	}
	credential, lookupErr := m.store.EmailAuthenticationByID(ctx, state.Name)
	if lookupErr != nil {
		if errors.Is(lookupErr, ErrNotFound) {
			// Either a decoy continuation issued for an ineligible address or
			// a forged reference; both fail exactly like a wrong code.
			if auditErr := m.appendAuthenticationAudit(ctx, "", "auth.email_otp", AuditFailed, "invalid_credentials"); auditErr != nil {
				return Authentication{}, auditErr
			}
			return Authentication{}, ErrInvalidCredentials
		}
		return Authentication{}, lookupErr
	}
	if credential.UsedAt != nil {
		if auditErr := m.appendAuthenticationAudit(ctx, credential.UserID, "auth.email_otp", AuditFailed, "reused"); auditErr != nil {
			return Authentication{}, auditErr
		}
		return Authentication{}, ErrInvalidCredentials
	}
	if !m.now().Before(credential.ExpiresAt) {
		if auditErr := m.appendAuthenticationAudit(ctx, credential.UserID, "auth.email_otp", AuditFailed, "expired"); auditErr != nil {
			return Authentication{}, auditErr
		}
		return Authentication{}, ErrExpired
	}
	user, err := m.store.UserByID(ctx, credential.UserID)
	if err != nil || user.Disabled {
		if auditErr := m.appendAuthenticationAudit(ctx, credential.UserID, "auth.email_otp", AuditFailed, "user_disabled"); auditErr != nil {
			return Authentication{}, auditErr
		}
		return Authentication{}, ErrInvalidCredentials
	}
	if err := m.requireUnlocked(ctx, user.ID, "auth.email_otp"); err != nil {
		return Authentication{}, err
	}
	if !m.matchTokenDigest(credential.Digest, "email-otp:"+credential.ID+":"+code) {
		audit, auditErr := m.recordAuthenticationFailure(ctx, user.ID, "auth.email_otp", true)
		if auditErr != nil {
			return Authentication{}, auditErr
		}
		m.emitAuthenticationFailed(ctx, "auth.email_otp.complete", audit, MethodEmail, user.ID, "invalid_credentials")
		return Authentication{}, ErrInvalidCredentials
	}
	factor, factorErr := m.store.TOTPByUserID(ctx, user.ID)
	requiresSecondFactor := factorErr == nil && factor.Active
	if factorErr != nil && !errors.Is(factorErr, ErrNotFound) {
		return Authentication{}, factorErr
	}
	now := m.now()
	event, err := m.newAudit(ctx, user.ID, "auth.email_otp", "user", user.ID, "", AuditSucceeded, "")
	if err != nil {
		return Authentication{}, err
	}
	// Like a password success, the consumption completes the sign-in only
	// when no second factor is pending: while one is, the code is spent but
	// the lockout and last_seen stay untouched, so redeeming fresh codes
	// cannot reset the counter between TOTP guesses — VerifyTOTP clears them
	// atomically on success.
	if err := m.store.ConsumeEmailAuthentication(ctx, credential.ID, user.ID, now, !requiresSecondFactor, Commit{Audit: event}); err != nil {
		if errors.Is(err, ErrConflict) {
			return Authentication{}, ErrInvalidCredentials
		}
		return Authentication{}, m.mapStoreError(ctx, "auth.email_otp.complete", err)
	}
	authentication := Authentication{
		UserID:               user.ID,
		Method:               MethodEmail,
		Level:                AAL1,
		AuthenticatedAt:      now,
		SecondFactorRequired: requiresSecondFactor,
	}
	m.emitAuthenticationSucceeded(ctx, "auth.email_otp.complete", event, authentication)
	return authentication, nil
}

// newEmailOTPCode draws a uniformly distributed 8-digit code through rejection
// sampling so no residue class is more likely than another.
func (m *Manager) newEmailOTPCode() (string, error) {
	const modulus = 100_000_000
	// Largest multiple of the modulus representable in 32 bits; values at or
	// above it are redrawn to avoid modulo bias.
	const limit = (1 << 32) / modulus * modulus
	for {
		b, err := randomBytes(m.random, 4)
		if err != nil {
			return "", err
		}
		value := binary.BigEndian.Uint32(b)
		if uint64(value) < uint64(limit) {
			return fmt.Sprintf("%08d", value%modulus), nil
		}
	}
}
