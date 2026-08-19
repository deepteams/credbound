package credbound

import (
	"context"
	"errors"
	"fmt"
	"iter"
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

// AuthorizeAdmin checks that the actor is an enabled user holding an
// instance role that maps to the permission. Every check — allowed or denied
// — appends an audit event and fails with ErrAuditUnavailable when that
// audit cannot be persisted; a missing role or permission fails with
// ErrForbidden. Instance roles never grant workspace data access by
// themselves, and a scope-narrowed or workspace-bound credential (a PAT or
// OAuth token) is refused outright — instance administration is not a
// delegable, workspace-scoped capability.
//
// Deliberate exception: a workspace-unbound PAT holding the "*" scope is an
// unrestricted credential of its owner and passes this check, so when the
// owner is an instance administrator such a PAT can perform administration
// reads — listing every user and workspace, reading the instance audit log.
// Mutations stay out of reach: RequireAdminMutation additionally demands an
// interactive fresh AAL2 authentication (or a trusted local request), which
// no PAT satisfies. Mint "*" PATs for automation deliberately.
func (m *Manager) AuthorizeAdmin(ctx context.Context, actor Authentication, permission Permission) error {
	if actor.UserID == (UUID{}) {
		return ErrUnauthorized
	}
	// Instance administration is neither workspace-scoped nor delegable to a
	// narrowed token: a workspace-bound or scope-limited credential (a PAT or
	// OAuth token) can never exercise it, even when its owner holds an
	// instance role. Without this the scope ceiling and workspace binding that
	// Authorize/AuthorizePermission enforce would be bypassed for every admin
	// read. A "*"-scoped credential is unrestricted and still allowed.
	instanceCredential := actor.WorkspaceID == (UUID{}) && (len(actor.Scopes) == 0 || actor.HasScope("*"))
	user, userErr := m.store.UserByID(ctx, actor.UserID)
	admin, err := m.store.InstanceAdministrator(ctx, actor.UserID)
	allowed := instanceCredential && userErr == nil && !user.Disabled && err == nil && m.hasAdminPermission(admin.Role, permission)
	outcome := AuditFailed
	reason := "forbidden"
	if allowed {
		outcome = AuditSucceeded
		reason = ""
	}
	event, eventErr := m.newAudit(ctx, actor.UserID, "admin.access", "permission", string(permission), UUID{}, outcome, reason)
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

// RequireAdminMutation gates administrative writes: the actor must be
// interactive, and either the request was verified as loopback by the server
// adapter (TrustedRequest.Local) or RequireStepUp must pass. It complements
// AuthorizeAdmin, which checks the permission itself.
func (m *Manager) RequireAdminMutation(actor Authentication, request TrustedRequest) error {
	if actor.UserID == (UUID{}) || !actor.Interactive() {
		return ErrUnauthorized
	}
	if request.Local {
		return nil
	}
	return m.RequireStepUp(actor)
}

func (m *Manager) requireAdminMutation(ctx context.Context, actor Authentication, request TrustedRequest, operation string) error {
	if actor.UserID == (UUID{}) || !actor.Interactive() {
		return ErrUnauthorized
	}
	if request.Local {
		return nil
	}
	return m.requireStepUp(ctx, actor, operation)
}

// InstanceAdministrator returns one user's instance-administration role. It
// requires admin instance-roles read; an unknown or role-less user reports
// ErrNotFound.
func (m *Manager) InstanceAdministrator(ctx context.Context, actor Authentication, userID UUID) (InstanceAdministrator, error) {
	if err := m.AuthorizeAdmin(ctx, actor, PermissionInstanceRolesRead); err != nil {
		return InstanceAdministrator{}, err
	}
	if !validUUIDv7(userID) {
		return InstanceAdministrator{}, fmt.Errorf("%w: invalid user id", ErrInvalidInput)
	}
	return m.store.InstanceAdministrator(ctx, userID)
}

// InstanceAdministrators streams every instance role assignment, oldest
// first, so an administration interface can render the governance roster.
// It requires admin instance-roles read.
func (m *Manager) InstanceAdministrators(ctx context.Context, actor Authentication) iter.Seq2[InstanceAdministrator, error] {
	if err := m.AuthorizeAdmin(ctx, actor, PermissionInstanceRolesRead); err != nil {
		return errorSeq[InstanceAdministrator](err)
	}
	return m.store.InstanceAdministrators(ctx)
}

// SetInstanceRole grants or changes a user's instance-administration role,
// atomically with the audit event. The actor needs admin instance-roles
// write (root only by default) and an admin mutation (fresh AAL2, or a
// trusted local request). A root cannot downgrade itself, and only the five
// built-in roles are accepted.
func (m *Manager) SetInstanceRole(ctx context.Context, actor Authentication, request TrustedRequest, userID UUID, role InstanceRole) (err error) {
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
	if userID == (UUID{}) {
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
	event, err := m.newAudit(ctx, actor.UserID, "admin.instance_role.set", "user", userID.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventInstanceRoleChanged, "admin.instance_role.set", actor.UserID, UUID{}, event)
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

// RemoveInstanceRole withdraws a user's instance-administration role,
// atomically with the audit event, under the same authorization as
// SetInstanceRole. An administrator cannot remove its own role, and the
// store protects the last root.
func (m *Manager) RemoveInstanceRole(ctx context.Context, actor Authentication, request TrustedRequest, userID UUID) (err error) {
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
	event, err := m.newAudit(ctx, actor.UserID, "admin.instance_role.remove", "user", userID.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventInstanceRoleRemoved, "admin.instance_role.remove", actor.UserID, UUID{}, event)
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
