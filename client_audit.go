package credbound

import (
	"context"
	"fmt"
	"strings"
)

// RecordAudit appends a host-supplied event to the audit log. Credbound
// derives the actor, UUIDv7 and timestamp itself so a consuming service can
// neither impersonate an actor nor backdate an entry. A workspace-scoped
// event requires workspace access in that workspace; a global event requires
// admin access. The entry commits atomically with the ApplyClientAudit hook
// and fails closed with ErrAuditUnavailable.
func (m *Manager) RecordAudit(ctx context.Context, actor Authentication, input AuditInput) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "audit.record", started, err) }()
	if actor.UserID == "" {
		return ErrUnauthorized
	}
	input.Action = strings.TrimSpace(input.Action)
	input.ResourceType = strings.TrimSpace(input.ResourceType)
	input.ResourceID = strings.TrimSpace(input.ResourceID)
	input.Reason = strings.TrimSpace(input.Reason)
	if !validAuditName(input.Action) || !validAuditName(input.ResourceType) || input.ResourceID == "" || len(input.ResourceID) > 200 || len(input.Reason) > 500 {
		return fmt.Errorf("%w: invalid audit event", ErrInvalidInput)
	}
	if input.Outcome != AuditSucceeded && input.Outcome != AuditFailed {
		return fmt.Errorf("%w: invalid audit outcome", ErrInvalidInput)
	}
	if input.WorkspaceID != "" {
		if err := m.AuthorizePermission(ctx, actor, input.WorkspaceID, PermissionWorkspaceAccess); err != nil {
			return err
		}
	} else if err := m.AuthorizeAdmin(ctx, actor, PermissionAdminAccess); err != nil {
		return err
	}
	event, err := m.newAudit(ctx, actor.UserID, input.Action, input.ResourceType, input.ResourceID, input.WorkspaceID, input.Outcome, input.Reason)
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventClientAuditRecorded, "audit.record", actor.UserID, input.WorkspaceID, event)
	if err != nil {
		return err
	}
	change := ClientAuditRecord{EventMeta: meta, Audit: event}
	commit := m.transactionalCommit(event, "client_audit.record", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyClientAudit(ctx, tx, change)
	})
	if err := m.store.AppendAudit(ctx, commit); err != nil {
		return m.mapStoreError(ctx, "audit.record", err)
	}
	recorded := ClientAuditRecordedEvent{EventMeta: meta, Audit: event}
	m.events.emit(ctx, EventClientAuditRecorded, func(listener EventListener) error { return listener.OnClientAuditRecorded(ctx, recorded) })
	return nil
}

func validAuditName(value string) bool {
	if value == "" || len(value) > 100 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}
