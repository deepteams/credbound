package credbound

import (
	"context"
	"fmt"
)

// RevokeUserCredentials revokes every active PAT of a user and, when the
// store has the OAuth capability, every OAuth grant with its tokens, in one
// atomic operation. A user runs it on their own account after a suspected
// compromise; revoking another account requires an instance administrator.
// Interactive sessions are owned by the host service and must be invalidated
// by the host alongside this call.
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
