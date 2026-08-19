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
	raw := emailVerificationPrefix + "_" + id.String() + "_" + base64.RawURLEncoding.EncodeToString(secret)
	now := m.now()
	email := EmailAddress{ID: id, UserID: actor.UserID, Address: address, CreatedAt: now, UpdatedAt: now}
	verification := EmailVerificationCredential{
		EmailID: id, Digest: m.tokenDigest("email-verification:" + raw), ExpiresAt: now.Add(m.emailVerificationTTL),
	}
	event, err := m.newAudit(ctx, actor.UserID, "email.add", "email", id.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return IssuedEmailVerification{}, err
	}
	meta, err := m.newEventMeta(EventEmailAdded, "auth.email.add.begin", actor.UserID, UUID{}, event)
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
	return IssuedEmailVerification{Email: email, Token: raw, Deliverable: true}, nil
}

// ResendEmailVerification re-issues a verification token for an unverified
// address without requiring authentication, so a user whose signup token
// expired or was lost is not locked out of their own account. The host answers
// the end user identically whether or not the address exists or is already
// verified: the call succeeds with a zero IssuedEmailVerification in those
// cases, so the error path is not an enumeration oracle — send the email only
// when Deliverable is true. It performs the same cryptographic work
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
	if allowed, err := m.allowEmailIssuance(ctx, normalized, "email.verification.resend"); err != nil {
		return IssuedEmailVerification{}, err
	} else if !allowed {
		if auditErr := m.appendAuthenticationAudit(ctx, UUID{}, "email.verification.resend", AuditFailed, "throttled"); auditErr != nil {
			return IssuedEmailVerification{}, auditErr
		}
		return IssuedEmailVerification{}, nil
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
	raw := emailVerificationPrefix + "_" + emailID.String() + "_" + base64.RawURLEncoding.EncodeToString(secret)
	tokenDigest := m.tokenDigest("email-verification:" + raw)
	if lookupErr != nil {
		if !errors.Is(lookupErr, ErrNotFound) {
			return IssuedEmailVerification{}, lookupErr
		}
		if auditErr := m.appendAuthenticationAudit(ctx, UUID{}, "email.verification.resend", AuditFailed, "unknown_email"); auditErr != nil {
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
	event, err := m.newAudit(ctx, email.UserID, "email.verification.resend", "email", email.ID.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return IssuedEmailVerification{}, err
	}
	meta, err := m.newEventMeta(EventEmailVerificationResent, "auth.email.verification.resend", email.UserID, UUID{}, event)
	if err != nil {
		return IssuedEmailVerification{}, err
	}
	if err := m.store.ReissueEmailVerification(ctx, email.ID, verification, Commit{Audit: event}); err != nil {
		return IssuedEmailVerification{}, m.mapStoreError(ctx, "auth.email.verification.resend", err)
	}
	email.UpdatedAt = now
	resent := EmailVerificationResentEvent{EventMeta: meta, Email: email}
	m.events.emit(ctx, EventEmailVerificationResent, func(listener EventListener) error { return listener.OnEmailVerificationResent(ctx, resent) })
	return IssuedEmailVerification{Email: email, Token: raw, Deliverable: true}, nil
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
	event, err := m.newAudit(ctx, email.UserID, "email.verify", "email", email.ID.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return EmailAddress{}, err
	}
	email.VerifiedAt = &verifiedAt
	email.UpdatedAt = verifiedAt
	meta, err := m.newEventMeta(EventEmailConfirmed, "auth.email.add.confirm", email.UserID, UUID{}, event)
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
func (m *Manager) SetPrimaryEmail(ctx context.Context, actor Authentication, emailID UUID) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.email.primary.set", started, err) }()
	if err := m.requireStepUp(ctx, actor, "auth.email.primary.set"); err != nil {
		return err
	}
	if !validUUIDv7(emailID) {
		return fmt.Errorf("%w: invalid email id", ErrInvalidInput)
	}
	event, err := m.newAudit(ctx, actor.UserID, "email.primary.set", "email", emailID.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventPrimaryEmailChanged, "auth.email.primary.set", actor.UserID, UUID{}, event)
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
func (m *Manager) RemoveEmail(ctx context.Context, actor Authentication, emailID UUID) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.email.remove", started, err) }()
	if err := m.requireStepUp(ctx, actor, "auth.email.remove"); err != nil {
		return err
	}
	if !validUUIDv7(emailID) {
		return fmt.Errorf("%w: invalid email id", ErrInvalidInput)
	}
	event, err := m.newAudit(ctx, actor.UserID, "email.remove", "email", emailID.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventEmailRemoved, "auth.email.remove", actor.UserID, UUID{}, event)
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
func (m *Manager) Emails(ctx context.Context, actor Authentication, userID UUID, page PageRequest) iter.Seq2[PageEvent[EmailAddress], error] {
	if actor.UserID == (UUID{}) {
		return errorSeq[PageEvent[EmailAddress]](ErrUnauthorized)
	}
	if userID == (UUID{}) {
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

// userEmails streams every email address of the user, following the store's
// cursor across all pages. Internal predicates must range over this — not a
// single fixed-limit page — so an account holding more addresses than one
// page never has an address silently skipped.
func (m *Manager) userEmails(ctx context.Context, userID UUID) iter.Seq2[EmailAddress, error] {
	return func(yield func(EmailAddress, error) bool) {
		cursor := ""
		for {
			next, more := "", false
			for event, err := range m.store.Emails(ctx, userID, PageRequest{Cursor: cursor, Limit: 100}) {
				if err != nil {
					yield(EmailAddress{}, err)
					return
				}
				if event.Data != nil && !yield(*event.Data, nil) {
					return
				}
				if event.End != nil {
					next, more = event.End.NextCursor, event.End.HasMore
				}
			}
			if !more || next == "" {
				return
			}
			cursor = next
		}
	}
}

// allowEmailIssuance enforces the per-address issuance cooldown. The store
// key is a fixed-size HMAC of the (normalized) address, so anonymous hostile
// input of any length or shape creates only one bounded, opaque row — the
// store never learns which addresses were tried — and every claim prunes
// entries older than the cooldown, so the bookkeeping tracks the current
// window instead of growing with every address ever submitted. It returns
// true when issuance is permitted — always so when the cooldown is disabled or
// the store lacks the capability — and false when the address is still within
// its cooldown window for that purpose. It is keyed by address alone, so it
// never distinguishes existing from unknown accounts.
func (m *Manager) allowEmailIssuance(ctx context.Context, address, purpose string) (bool, error) {
	if m.emailIssuanceCooldown <= 0 || m.emailThrottle == nil {
		return true, nil
	}
	key := base64.RawURLEncoding.EncodeToString(m.tokenDigest("email-issuance:" + address))
	now := m.now()
	return m.emailThrottle.ClaimEmailIssuance(ctx, key, purpose, now, now.Add(-m.emailIssuanceCooldown))
}

func parseEmailVerification(raw string) (UUID, bool) {
	return parseSecretToken(emailVerificationPrefix, raw)
}

// parseSecretToken validates the shared `<prefix>_<uuidv7>_<43 chars>` token
// shape and returns the embedded identifier.
// parseSecretToken splits a single-display token into the record it addresses
// and validates its shape. The identifier travels as canonical text inside the
// token, so this is where it is parsed back: a token whose identifier is
// malformed, or not one Credbound minted, is rejected here rather than reaching
// a store lookup.
func parseSecretToken(prefix, raw string) (UUID, bool) {
	parts := strings.SplitN(raw, "_", 3)
	if len(parts) != 3 || parts[0] != prefix || len(parts[2]) != 43 {
		return UUID{}, false
	}
	id, err := ParseUUID(parts[1])
	if err != nil || !validUUIDv7(id) {
		return UUID{}, false
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(secret) != 32 {
		return UUID{}, false
	}
	return id, true
}
