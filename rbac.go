package credbound

import (
	"context"
	"errors"
	"fmt"
)

func (m *Manager) Authorize(ctx context.Context, authn Authentication, workspaceID string, minimumRole Role) error {
	if authn.UserID == "" {
		return ErrUnauthorized
	}
	if workspaceID == "" {
		return fmt.Errorf("%w: workspace id is required", ErrInvalidInput)
	}
	user, err := m.store.UserByID(ctx, authn.UserID)
	if err != nil || user.Disabled {
		return ErrForbidden
	}
	required, err := m.workspaceRoles.normalize(minimumRole)
	if err != nil {
		return err
	}
	if authn.WorkspaceID != "" && authn.WorkspaceID != workspaceID {
		m.emitAuthorizationDenied(ctx, authn, workspaceID, required)
		return ErrForbidden
	}
	workspace, err := m.store.WorkspaceByID(ctx, workspaceID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrForbidden
		}
		return err
	}
	if workspace.DisabledAt != nil {
		return ErrForbidden
	}
	if workspace.RequireMFA && authn.Interactive() && authn.Level < AAL2 {
		return ErrStepUpRequired
	}
	membership, err := m.store.Membership(ctx, workspaceID, authn.UserID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			m.emitAuthorizationDenied(ctx, authn, workspaceID, required)
			return ErrForbidden
		}
		return err
	}
	if membership.Status != MembershipActive || !m.workspaceRoles.includes(membership.Role, required) {
		m.emitAuthorizationDenied(ctx, authn, workspaceID, required)
		return ErrForbidden
	}
	return nil
}

func (m *Manager) AuthorizePermission(ctx context.Context, authn Authentication, workspaceID string, permission WorkspacePermission) error {
	if authn.UserID == "" {
		return ErrUnauthorized
	}
	if workspaceID == "" || !workspacePermissionPattern.MatchString(string(permission)) {
		return fmt.Errorf("%w: workspace id and permission are required", ErrInvalidInput)
	}
	user, err := m.store.UserByID(ctx, authn.UserID)
	if err != nil || user.Disabled {
		return ErrForbidden
	}
	if authn.WorkspaceID != "" && authn.WorkspaceID != workspaceID {
		m.emitAuthorizationDenied(ctx, authn, workspaceID, Role(""))
		return ErrForbidden
	}
	workspace, err := m.store.WorkspaceByID(ctx, workspaceID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrForbidden
		}
		return err
	}
	if workspace.DisabledAt != nil {
		return ErrForbidden
	}
	if workspace.RequireMFA && authn.Interactive() && authn.Level < AAL2 {
		return ErrStepUpRequired
	}
	membership, err := m.store.Membership(ctx, workspaceID, authn.UserID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrForbidden
		}
		return err
	}
	if membership.Status != MembershipActive || !m.workspaceRoles.allows(membership.Role, permission) {
		return ErrForbidden
	}
	return nil
}

func (m *Manager) GrantRole(ctx context.Context, actor Authentication, workspaceID, userID string, role Role) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "rbac.role.grant", started, err) }()
	if err := m.requireStepUp(ctx, actor, "rbac.role.grant"); err != nil {
		return err
	}
	if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionWorkspaceRBACWrite); err != nil {
		return err
	}
	role, err = m.workspaceRoles.normalize(role)
	if err != nil {
		return err
	}
	if _, err := m.store.UserByID(ctx, userID); err != nil {
		return err
	}
	previousRole := Role("")
	status := MembershipActive
	createdAt := m.now()
	if previous, lookupErr := m.store.Membership(ctx, workspaceID, userID); lookupErr == nil {
		if previous.ProvisioningSource != "" && previous.ProvisioningSource != ProvisioningSourceLocal {
			return ErrConflict
		}
		previousRole = previous.Role
		status = previous.Status
		createdAt = previous.CreatedAt
	} else if !errors.Is(lookupErr, ErrNotFound) {
		return lookupErr
	}
	now := m.now()
	membership := Membership{WorkspaceID: workspaceID, UserID: userID, Role: role, Status: status, ProvisioningSource: ProvisioningSourceLocal, UpdatedAt: now, CreatedAt: createdAt}
	event, err := m.newAudit(ctx, actor.UserID, "membership.role.set", "user", userID, workspaceID, AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventRoleGranted, "rbac.role.grant", actor.UserID, workspaceID, event)
	if err != nil {
		return err
	}
	change := RoleGrant{EventMeta: meta, UserID: userID, Role: role, PreviousRole: previousRole}
	commit := m.transactionalCommit(event, "role.grant", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyRoleGrant(ctx, tx, change)
	})
	if err := m.store.UpsertMembership(ctx, membership, commit); err != nil {
		return m.mapStoreError(ctx, "rbac.role.grant", err)
	}
	granted := RoleGrantedEvent{EventMeta: meta, UserID: userID, Role: role, PreviousRole: previousRole}
	m.events.emit(ctx, EventRoleGranted, func(listener EventListener) error { return listener.OnRoleGranted(ctx, granted) })
	return nil
}

func (m *Manager) emitAuthorizationDenied(ctx context.Context, authn Authentication, workspaceID string, required Role) {
	meta, err := m.newEventMeta(EventAuthorizationDenied, "rbac.authorize", authn.UserID, workspaceID, AuditEvent{})
	if err != nil {
		return
	}
	event := AuthorizationDeniedEvent{EventMeta: meta, UserID: authn.UserID, RequiredRole: required}
	m.events.emit(ctx, EventAuthorizationDenied, func(listener EventListener) error {
		return listener.OnAuthorizationDenied(ctx, event)
	})
}
