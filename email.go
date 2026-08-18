package credbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"iter"
	"strings"
)

const emailVerificationPrefix = "cbe"

// BeginEmailAddition attaches a new, unverified address to the actor's
// account and returns the raw verification token exactly once for the host
// to deliver to that address; only its HMAC is persisted. It requires a
// recent interactive authentication, and a globally taken address fails with
// ErrConflict. The address becomes usable for sign-in only after
// ConfirmEmail.
func (m *Manager) BeginEmailAddition(ctx context.Context, actor Authentication, address string) (_ IssuedEmailVerification, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.email.add.begin", started, err) }()
	if err := m.requireRecentInteractive(ctx, actor); err != nil {
		return IssuedEmailVerification{}, err
	}
	address, err = validEmail(address)
	if err != nil {
		return IssuedEmailVerification{}, err
	}
	id, err := m.newID()
	if err != nil {
		return IssuedEmailVerification{}, err
	}
	secret, err := randomBytes(m.random, 32)
	if err != nil {
		return IssuedEmailVerification{}, err
	}
	raw := emailVerificationPrefix + "_" + id + "_" + base64.RawURLEncoding.EncodeToString(secret)
	now := m.now()
	email := EmailAddress{ID: id, UserID: actor.UserID, Address: address, CreatedAt: now, UpdatedAt: now}
	verification := EmailVerificationCredential{
		EmailID: id, Digest: m.tokenDigest("email-verification:" + raw), ExpiresAt: now.Add(m.emailVerificationTTL),
	}
	event, err := m.newAudit(ctx, actor.UserID, "email.add", "email", id, "", AuditSucceeded, "")
	if err != nil {
		return IssuedEmailVerification{}, err
	}
	meta, err := m.newEventMeta(EventEmailAdded, "auth.email.add.begin", actor.UserID, "", event)
	if err != nil {
		return IssuedEmailVerification{}, err
	}
	change := EmailAddition{EventMeta: meta, Email: email}
	commit := m.transactionalCommit(event, "email.add", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyEmailAddition(ctx, tx, change)
	})
	if err := m.store.SaveEmail(ctx, email, verification, commit); err != nil {
		return IssuedEmailVerification{}, m.mapStoreError(ctx, "auth.email.add.begin", err)
	}
	added := EmailAddedEvent{EventMeta: meta, Email: email}
	m.events.emit(ctx, EventEmailAdded, func(listener EventListener) error { return listener.OnEmailAdded(ctx, added) })
	return IssuedEmailVerification{Email: email, Token: raw}, nil
}

// ResendEmailVerification re-issues a verification token for an unverified
// address without requiring authentication, so a user whose signup token
// expired or was lost is not locked out of their own account. The host answers
// the end user identically whether or not the address exists or is already
// verified: the call succeeds with a zero IssuedEmailVerification (empty Token)
// in those cases, so the error path is not an enumeration oracle — send the
// email only when Token is non-empty. It performs the same cryptographic work
// and a comparable store write in every case so timing does not reveal the
// difference. Re-issuing a token invalidates the previous one (the stored
// digest is replaced). An address under a confirmed EnforceSSO domain is
// refused before any lookup, exactly like signup.
func (m *Manager) ResendEmailVerification(ctx context.Context, address string) (_ IssuedEmailVerification, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.email.verification.resend", started, err) }()
	normalized := normalizeEmail(address)
	if err := m.domainRequiresSSO(ctx, normalized, "email.verification.resend"); err != nil {
		return IssuedEmailVerification{}, err
	}
	email, lookupErr := m.store.EmailByAddress(ctx, normalized)
	// Derive a fresh identifier and secret before deciding the outcome so an
	// unknown or already-verified address performs the same work as a pending
	// one and timing reveals nothing.
	decoyID, err := m.newID()
	if err != nil {
		return IssuedEmailVerification{}, err
	}
	secret, err := randomBytes(m.random, 32)
	if err != nil {
		return IssuedEmailVerification{}, err
	}
	emailID := decoyID
	pending := lookupErr == nil && email.VerifiedAt == nil
	if pending {
		emailID = email.ID
	}
	raw := emailVerificationPrefix + "_" + emailID + "_" + base64.RawURLEncoding.EncodeToString(secret)
	tokenDigest := m.tokenDigest("email-verification:" + raw)
	if lookupErr != nil {
		if !errors.Is(lookupErr, ErrNotFound) {
			return IssuedEmailVerification{}, lookupErr
		}
		if auditErr := m.appendAuthenticationAudit(ctx, "", "email.verification.resend", AuditFailed, "unknown_email"); auditErr != nil {
			return IssuedEmailVerification{}, auditErr
		}
		return IssuedEmailVerification{}, nil
	}
	if !pending {
		if auditErr := m.appendAuthenticationAudit(ctx, email.UserID, "email.verification.resend", AuditFailed, "already_verified"); auditErr != nil {
			return IssuedEmailVerification{}, auditErr
		}
		return IssuedEmailVerification{}, nil
	}
	now := m.now()
	verification := EmailVerificationCredential{
		EmailID: email.ID, Digest: tokenDigest, ExpiresAt: now.Add(m.emailVerificationTTL),
	}
	event, err := m.newAudit(ctx, email.UserID, "email.verification.resend", "email", email.ID, "", AuditSucceeded, "")
	if err != nil {
		return IssuedEmailVerification{}, err
	}
	meta, err := m.newEventMeta(EventEmailVerificationResent, "auth.email.verification.resend", email.UserID, "", event)
	if err != nil {
		return IssuedEmailVerification{}, err
	}
	if err := m.store.ReissueEmailVerification(ctx, email.ID, verification, Commit{Audit: event}); err != nil {
		return IssuedEmailVerification{}, m.mapStoreError(ctx, "auth.email.verification.resend", err)
	}
	email.UpdatedAt = now
	resent := EmailVerificationResentEvent{EventMeta: meta, Email: email}
	m.events.emit(ctx, EventEmailVerificationResent, func(listener EventListener) error { return listener.OnEmailVerificationResent(ctx, resent) })
	return IssuedEmailVerification{Email: email, Token: raw}, nil
}

// ConfirmEmail marks the pending address verified by proving possession of
// the verification token. Possession of the token is the authorization — no
// actor is required. An unknown or mismatched token fails with
// ErrInvalidCredentials, a stale one with ErrExpired, and an already
// verified address with ErrConflict.
func (m *Manager) ConfirmEmail(ctx context.Context, raw string) (_ EmailAddress, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.email.add.confirm", started, err) }()
	emailID, valid := parseEmailVerification(raw)
	if !valid {
		return EmailAddress{}, ErrInvalidCredentials
	}
	email, verification, lookupErr := m.store.EmailVerificationByID(ctx, emailID)
	if lookupErr != nil {
		if errors.Is(lookupErr, ErrNotFound) {
			return EmailAddress{}, ErrInvalidCredentials
		}
		return EmailAddress{}, lookupErr
	}
	if email.VerifiedAt != nil {
		return EmailAddress{}, ErrConflict
	}
	if !m.now().Before(verification.ExpiresAt) {
		if auditErr := m.appendAuthenticationAudit(ctx, email.UserID, "email.verify", AuditFailed, "expired"); auditErr != nil {
			return EmailAddress{}, auditErr
		}
		return EmailAddress{}, ErrExpired
	}
	if !m.matchTokenDigest(verification.Digest, "email-verification:"+raw) {
		if auditErr := m.appendAuthenticationAudit(ctx, email.UserID, "email.verify", AuditFailed, "invalid_credentials"); auditErr != nil {
			return EmailAddress{}, auditErr
		}
		return EmailAddress{}, ErrInvalidCredentials
	}
	verifiedAt := m.now()
	event, err := m.newAudit(ctx, email.UserID, "email.verify", "email", email.ID, "", AuditSucceeded, "")
	if err != nil {
		return EmailAddress{}, err
	}
	email.VerifiedAt = &verifiedAt
	email.UpdatedAt = verifiedAt
	meta, err := m.newEventMeta(EventEmailConfirmed, "auth.email.add.confirm", email.UserID, "", event)
	if err != nil {
		return EmailAddress{}, err
	}
	change := EmailConfirmation{EventMeta: meta, Email: email}
	commit := m.transactionalCommit(event, "email.confirm", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyEmailConfirmation(ctx, tx, change)
	})
	if err := m.store.VerifyEmail(ctx, email.ID, verifiedAt, commit); err != nil {
		return EmailAddress{}, m.mapStoreError(ctx, "auth.email.add.confirm", err)
	}
	confirmed := EmailConfirmedEvent{EventMeta: meta, Email: email}
	m.events.emit(ctx, EventEmailConfirmed, func(listener EventListener) error { return listener.OnEmailConfirmed(ctx, confirmed) })
	return email, nil
}

// SetPrimaryEmail makes one of the actor's verified addresses the primary
// address, atomically with the audit event. It requires a fresh AAL2
// step-up; an unverified address is rejected by the store.
func (m *Manager) SetPrimaryEmail(ctx context.Context, actor Authentication, emailID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.email.primary.set", started, err) }()
	if err := m.requireStepUp(ctx, actor, "auth.email.primary.set"); err != nil {
		return err
	}
	if !validUUIDv7(emailID) {
		return fmt.Errorf("%w: invalid email id", ErrInvalidInput)
	}
	event, err := m.newAudit(ctx, actor.UserID, "email.primary.set", "email", emailID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventPrimaryEmailChanged, "auth.email.primary.set", actor.UserID, "", event)
	if err != nil {
		return err
	}
	change := PrimaryEmailChange{EventMeta: meta, UserID: actor.UserID, EmailID: emailID}
	commit := m.transactionalCommit(event, "email.primary.change", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyPrimaryEmailChange(ctx, tx, change)
	})
	if err := m.store.SetPrimaryEmail(ctx, actor.UserID, emailID, commit); err != nil {
		return m.mapStoreError(ctx, "auth.email.primary.set", err)
	}
	changed := PrimaryEmailChangedEvent{EventMeta: meta, UserID: actor.UserID, EmailID: emailID}
	m.events.emit(ctx, EventPrimaryEmailChanged, func(listener EventListener) error { return listener.OnPrimaryEmailChanged(ctx, changed) })
	return nil
}

// RemoveEmail deletes one of the actor's addresses, atomically with the
// audit event. It requires a fresh AAL2 step-up; the primary address and the
// last verified address cannot be removed.
func (m *Manager) RemoveEmail(ctx context.Context, actor Authentication, emailID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.email.remove", started, err) }()
	if err := m.requireStepUp(ctx, actor, "auth.email.remove"); err != nil {
		return err
	}
	if !validUUIDv7(emailID) {
		return fmt.Errorf("%w: invalid email id", ErrInvalidInput)
	}
	event, err := m.newAudit(ctx, actor.UserID, "email.remove", "email", emailID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventEmailRemoved, "auth.email.remove", actor.UserID, "", event)
	if err != nil {
		return err
	}
	change := EmailRemoval{EventMeta: meta, UserID: actor.UserID, EmailID: emailID}
	commit := m.transactionalCommit(event, "email.remove", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyEmailRemoval(ctx, tx, change)
	})
	if err := m.store.RemoveEmail(ctx, actor.UserID, emailID, commit); err != nil {
		return m.mapStoreError(ctx, "auth.email.remove", err)
	}
	removed := EmailRemovedEvent{EventMeta: meta, UserID: actor.UserID, EmailID: emailID}
	m.events.emit(ctx, EventEmailRemoved, func(listener EventListener) error { return listener.OnEmailRemoved(ctx, removed) })
	return nil
}

// Emails streams a user's email addresses. An empty userID means the actor,
// which requires a recent interactive authentication; reading another user
// requires admin users read.
func (m *Manager) Emails(ctx context.Context, actor Authentication, userID string, page PageRequest) iter.Seq2[PageEvent[EmailAddress], error] {
	if actor.UserID == "" {
		return errorSeq[PageEvent[EmailAddress]](ErrUnauthorized)
	}
	if userID == "" {
		userID = actor.UserID
	}
	if userID == actor.UserID {
		if err := m.requireRecentInteractive(ctx, actor); err != nil {
			return errorSeq[PageEvent[EmailAddress]](err)
		}
	} else if err := m.AuthorizeAdmin(ctx, actor, PermissionUsersRead); err != nil {
		return errorSeq[PageEvent[EmailAddress]](err)
	}
	page, err := normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[EmailAddress]](err)
	}
	return m.store.Emails(ctx, userID, page)
}

func parseEmailVerification(raw string) (string, bool) {
	return parseSecretToken(emailVerificationPrefix, raw)
}

// parseSecretToken validates the shared `<prefix>_<uuidv7>_<43 chars>` token
// shape and returns the embedded identifier.
func parseSecretToken(prefix, raw string) (string, bool) {
	parts := strings.SplitN(raw, "_", 3)
	if len(parts) != 3 || parts[0] != prefix || !validUUIDv7(parts[1]) || len(parts[2]) != 43 {
		return "", false
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(secret) != 32 {
		return "", false
	}
	return parts[1], true
}
