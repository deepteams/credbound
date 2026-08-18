package credbound

import (
	"context"
	"fmt"
)

// RevokeUserCredentials revokes every active PAT of a user and, when the
// store has the OAuth capability, every OAuth grant with its tokens, in one
// atomic operation. When the store supports sessions (SessionStore) the
// user's server-side sessions are revoked in the same transaction. A user
// runs it on their own account after a suspected compromise; revoking
// another account requires an instance administrator. Sessions the host
// service manages itself remain host-owned and must be invalidated by the
// host alongside this call.
func (m *Manager) RevokeUserCredentials(ctx context.Context, actor Authentication, request TrustedRequest, userID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.credentials.revoke", started, err) }()
	if userID == "" {
		userID = actor.UserID
	}
	if !validUUIDv7(userID) {
		return fmt.Errorf("%w: invalid user id", ErrInvalidInput)
	}
	if userID == actor.UserID {
		if err := m.requireStepUp(ctx, actor, "auth.credentials.revoke"); err != nil {
			return err
		}
	} else {
		if err := m.requireAdminMutation(ctx, actor, request, "auth.credentials.revoke"); err != nil {
			return err
		}
		if err := m.AuthorizeAdmin(ctx, actor, PermissionUsersWrite); err != nil {
			return err
		}
	}
	event, err := m.newAudit(ctx, actor.UserID, "user.credentials.revoke", "user", userID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventUserCredentialsRevoked, "auth.credentials.revoke", actor.UserID, "", event)
	if err != nil {
		return err
	}
	change := UserCredentialRevocation{EventMeta: meta, UserID: userID}
	commit := m.transactionalCommit(event, "user.credentials.revocation", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyUserCredentialRevocation(ctx, tx, change)
	})
	if err := m.store.RevokeUserCredentials(ctx, userID, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, "auth.credentials.revoke", err)
	}
	revoked := UserCredentialsRevokedEvent{EventMeta: meta, UserID: userID}
	m.events.emit(ctx, EventUserCredentialsRevoked, func(listener EventListener) error { return listener.OnUserCredentialsRevoked(ctx, revoked) })
	return nil
}

// AdminResetSecondFactor is the total-loss recovery path: when a user has
// lost every second factor (TOTP device, recovery codes, passkeys), an
// instance administrator removes them all and revokes the user's
// server-side sessions in one atomic operation, so the account falls back
// to its first factor and the user re-enrolls from a fresh sign-in. The
// actor needs admin users write and an admin mutation (fresh AAL2, or a
// trusted local request); the target must exist and cannot be the actor —
// an administrator's own factors are removed through DisableTOTP and
// DeletePasskey, which re-prove possession. Hosts should notify the
// affected user out of band through SecondFactorResetEvent.
func (m *Manager) AdminResetSecondFactor(ctx context.Context, actor Authentication, request TrustedRequest, userID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "admin.second_factor.reset", started, err) }()
	if !validUUIDv7(userID) {
		return fmt.Errorf("%w: invalid user id", ErrInvalidInput)
	}
	if userID == actor.UserID {
		return fmt.Errorf("%w: an administrator cannot reset their own second factor", ErrInvalidInput)
	}
	if err := m.requireAdminMutation(ctx, actor, request, "admin.second_factor.reset"); err != nil {
		return err
	}
	if err := m.AuthorizeAdmin(ctx, actor, PermissionUsersWrite); err != nil {
		return err
	}
	event, err := m.newAudit(ctx, actor.UserID, "user.second_factor.reset", "user", userID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventSecondFactorReset, "admin.second_factor.reset", actor.UserID, "", event)
	if err != nil {
		return err
	}
	change := SecondFactorReset{EventMeta: meta, UserID: userID}
	commit := m.transactionalCommit(event, "user.second_factor.reset", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplySecondFactorReset(ctx, tx, change)
	})
	if err := m.store.ResetSecondFactor(ctx, userID, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, "admin.second_factor.reset", err)
	}
	reset := SecondFactorResetEvent{EventMeta: meta, UserID: userID}
	m.events.emit(ctx, EventSecondFactorReset, func(listener EventListener) error { return listener.OnSecondFactorReset(ctx, reset) })
	return nil
}

// AnonymizeUser is the right-to-erasure primitive: an instance administrator
// pseudonymizes a user by scrubbing their mutable personal data — display
// name, email addresses (replaced with unique tombstones), SSO and PAT names,
// and session IP/User-Agent — while disabling the account, revoking its PATs,
// sessions and OAuth grants, and removing its second factors, all in one
// transaction. The append-only, hash-chained audit log is deliberately
// preserved: it retains a pseudonymous user id and the request IP/User-Agent
// under the host's security-log retention basis, since scrubbing it would
// break VerifyAuditChain. The actor needs admin users write and an admin
// mutation (fresh AAL2, or a trusted local request); anonymizing the last
// enabled root or the sole admin of a workspace fails with ErrConflict, as
// disabling them would. Hosts erase their own application-owned data — and any
// business records referencing the user — separately, per ExportUserData and
// their retention policy. It is irreversible.
func (m *Manager) AnonymizeUser(ctx context.Context, actor Authentication, request TrustedRequest, userID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "admin.user.anonymize", started, err) }()
	if !validUUIDv7(userID) {
		return fmt.Errorf("%w: invalid user id", ErrInvalidInput)
	}
	if err := m.requireAdminMutation(ctx, actor, request, "admin.user.anonymize"); err != nil {
		return err
	}
	if err := m.AuthorizeAdmin(ctx, actor, PermissionUsersWrite); err != nil {
		return err
	}
	event, err := m.newAudit(ctx, actor.UserID, "user.anonymize", "user", userID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventUserAnonymized, "admin.user.anonymize", actor.UserID, "", event)
	if err != nil {
		return err
	}
	change := UserAnonymization{EventMeta: meta, UserID: userID}
	commit := m.transactionalCommit(event, "user.anonymize", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyUserAnonymization(ctx, tx, change)
	})
	if err := m.store.AnonymizeUser(ctx, userID, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, "admin.user.anonymize", err)
	}
	anonymized := UserAnonymizedEvent{EventMeta: meta, UserID: userID}
	m.events.emit(ctx, EventUserAnonymized, func(listener EventListener) error { return listener.OnUserAnonymized(ctx, anonymized) })
	return nil
}
