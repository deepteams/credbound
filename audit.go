package credbound

import (
	"context"
	"iter"
)

func (m *Manager) AuditEvents(ctx context.Context, actor Authentication, workspaceID string, page PageRequest) iter.Seq2[PageEvent[AuditEvent], error] {
	if err := m.requireStepUp(ctx, actor, "audit.workspace.list"); err != nil {
		return errorSeq[PageEvent[AuditEvent]](err)
	}
	if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionWorkspaceAuditRead); err != nil {
		return errorSeq[PageEvent[AuditEvent]](err)
	}
	page, err := normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[AuditEvent]](err)
	}
	return m.store.AuditEvents(ctx, workspaceID, page)
}

func (m *Manager) InstanceAuditEvents(ctx context.Context, actor Authentication, page PageRequest) iter.Seq2[PageEvent[AuditEvent], error] {
	if err := m.AuthorizeAdmin(ctx, actor, PermissionAuditRead); err != nil {
		return errorSeq[PageEvent[AuditEvent]](err)
	}
	page, err := normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[AuditEvent]](err)
	}
	return m.store.InstanceAuditEvents(ctx, page)
}
