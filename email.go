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
