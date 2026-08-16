package credbound

import (
	"context"
	"errors"
	"fmt"
)

var defaultAdminPermissions = map[InstanceRole][]Permission{
	InstanceRoleRoot: {
		PermissionAdminAccess, PermissionAuditRead,
		PermissionSettingsRead, PermissionSettingsWrite,
		PermissionUsersRead, PermissionUsersWrite,
		PermissionWorkspacesRead, PermissionWorkspacesWrite,
		PermissionRBACRead, PermissionRBACWrite,
		PermissionInstanceRolesRead, PermissionInstanceRolesWrite,
	},
	InstanceRoleDeveloper: {
		PermissionAdminAccess, PermissionAuditRead,
		PermissionSettingsRead, PermissionSettingsWrite,
		PermissionUsersRead, PermissionWorkspacesRead, PermissionRBACRead,
	},
	InstanceRoleSupport: {
		PermissionAdminAccess, PermissionAuditRead,
		PermissionUsersRead, PermissionUsersWrite, PermissionWorkspacesRead,
	},
	InstanceRoleMarketing: {
		PermissionAdminAccess, PermissionSettingsRead,
		PermissionUsersRead, PermissionWorkspacesRead,
	},
	InstanceRoleSales: {
		PermissionAdminAccess, PermissionUsersRead, PermissionWorkspacesRead,
	},
}

func buildAdminPermissions(overrides map[InstanceRole][]Permission) (map[InstanceRole]map[Permission]struct{}, error) {
	result := make(map[InstanceRole]map[Permission]struct{}, len(defaultAdminPermissions))
	for role, defaults := range defaultAdminPermissions {
		allowed := make(map[Permission]struct{}, len(defaults))
		for _, permission := range defaults {
			allowed[permission] = struct{}{}
		}
		selected := defaults
		if configured, ok := overrides[role]; ok {
			selected = configured
		}
		result[role] = make(map[Permission]struct{}, len(selected))
		for _, permission := range selected {
			if _, ok := allowed[permission]; !ok {
				return nil, fmt.Errorf("%w: role %s cannot be granted permission %s", ErrInvalidInput, role, permission)
			}
			result[role][permission] = struct{}{}
		}
	}
	for role := range overrides {
		if _, ok := defaultAdminPermissions[role]; !ok {
			return nil, fmt.Errorf("%w: unknown instance role %s", ErrInvalidInput, role)
		}
	}
	return result, nil
}

func (m *Manager) AuthorizeAdmin(ctx context.Context, actor Authentication, permission Permission) error {
	if actor.UserID == "" {
		return ErrUnauthorized
	}
	user, userErr := m.store.UserByID(ctx, actor.UserID)
	admin, err := m.store.InstanceAdministrator(ctx, actor.UserID)
	allowed := userErr == nil && !user.Disabled && err == nil && m.hasAdminPermission(admin.Role, permission)
	outcome := AuditFailed
	reason := "forbidden"
	if allowed {
		outcome = AuditSucceeded
		reason = ""
	}
	event, eventErr := m.newAudit(actor.UserID, "admin.access", "permission", string(permission), "", outcome, reason)
	if eventErr != nil {
		return eventErr
	}
	if auditErr := m.store.AppendAudit(ctx, Commit{Audit: event}); auditErr != nil {
		return m.mapStoreError(ctx, "admin.access", auditErr)
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if userErr != nil && !errors.Is(userErr, ErrNotFound) {
		return userErr
	}
	if !allowed {
		return ErrForbidden
	}
	return nil
}

func (m *Manager) RequireAdminMutation(actor Authentication, request TrustedRequest) error {
	if actor.UserID == "" || !actor.Interactive() {
		return ErrUnauthorized
	}
	if request.Local {
		return nil
	}
	return m.RequireStepUp(actor)
}

func (m *Manager) requireAdminMutation(ctx context.Context, actor Authentication, request TrustedRequest, operation string) error {
	if actor.UserID == "" || !actor.Interactive() {
		return ErrUnauthorized
	}
	if request.Local {
		return nil
	}
	return m.requireStepUp(ctx, actor, operation)
}

func (m *Manager) SetInstanceRole(ctx context.Context, actor Authentication, request TrustedRequest, userID string, role InstanceRole) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "admin.instance_role.set", started, err) }()
	if err := m.AuthorizeAdmin(ctx, actor, PermissionInstanceRolesWrite); err != nil {
		return err
	}
	if err := m.requireAdminMutation(ctx, actor, request, "admin.instance_role.set"); err != nil {
		return err
	}
	if _, ok := defaultAdminPermissions[role]; !ok {
		return fmt.Errorf("%w: unknown instance role", ErrInvalidInput)
	}
	if userID == "" {
		return fmt.Errorf("%w: user id is required", ErrInvalidInput)
	}
	if userID == actor.UserID && role != InstanceRoleRoot {
		return fmt.Errorf("%w: a root administrator cannot downgrade itself", ErrForbidden)
	}
	if _, err := m.store.UserByID(ctx, userID); err != nil {
		return err
	}
	previousRole := InstanceRole("")
	if previous, lookupErr := m.store.InstanceAdministrator(ctx, userID); lookupErr == nil {
		previousRole = previous.Role
	} else if !errors.Is(lookupErr, ErrNotFound) {
		return lookupErr
	}
	now := m.now()
	admin := InstanceAdministrator{UserID: userID, Role: role, CreatedAt: now, UpdatedAt: now}
	event, err := m.newAudit(actor.UserID, "admin.instance_role.set", "user", userID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventInstanceRoleChanged, "admin.instance_role.set", actor.UserID, "", event)
	if err != nil {
		return err
	}
	change := InstanceRoleChange{EventMeta: meta, UserID: userID, Role: role, PreviousRole: previousRole}
	commit := m.transactionalCommit(event, "instance_role.change", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyInstanceRoleChange(ctx, tx, change)
	})
	if err := m.store.SetInstanceRole(ctx, admin, commit); err != nil {
		return m.mapStoreError(ctx, "admin.instance_role.set", err)
	}
	changed := InstanceRoleChangedEvent{EventMeta: meta, UserID: userID, Role: role, PreviousRole: previousRole}
	m.events.emit(ctx, EventInstanceRoleChanged, func(listener EventListener) error { return listener.OnInstanceRoleChanged(ctx, changed) })
	return nil
}

func (m *Manager) RemoveInstanceRole(ctx context.Context, actor Authentication, request TrustedRequest, userID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "admin.instance_role.remove", started, err) }()
	if err := m.AuthorizeAdmin(ctx, actor, PermissionInstanceRolesWrite); err != nil {
		return err
	}
	if err := m.requireAdminMutation(ctx, actor, request, "admin.instance_role.remove"); err != nil {
		return err
	}
	if userID == actor.UserID {
		return fmt.Errorf("%w: a root administrator cannot remove itself", ErrForbidden)
	}
	event, err := m.newAudit(actor.UserID, "admin.instance_role.remove", "user", userID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventInstanceRoleRemoved, "admin.instance_role.remove", actor.UserID, "", event)
	if err != nil {
		return err
	}
	change := InstanceRoleRemoval{EventMeta: meta, UserID: userID}
	commit := m.transactionalCommit(event, "instance_role.remove", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyInstanceRoleRemoval(ctx, tx, change)
	})
	if err := m.store.RemoveInstanceRole(ctx, userID, commit); err != nil {
		return m.mapStoreError(ctx, "admin.instance_role.remove", err)
	}
	removed := InstanceRoleRemovedEvent{EventMeta: meta, UserID: userID}
	m.events.emit(ctx, EventInstanceRoleRemoved, func(listener EventListener) error { return listener.OnInstanceRoleRemoved(ctx, removed) })
	return nil
}

func (m *Manager) hasAdminPermission(role InstanceRole, permission Permission) bool {
	permissions, ok := m.adminPermissions[role]
	if !ok {
		return false
	}
	_, ok = permissions[permission]
	return ok
}
