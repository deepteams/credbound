package credbound

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"strings"
)

// CreateWorkspace creates a workspace and makes the actor its admin member,
// atomically with the audit event. It requires a fresh AAL2 step-up from an
// enabled user.
func (m *Manager) CreateWorkspace(ctx context.Context, actor Authentication, input CreateWorkspaceInput) (_ Workspace, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "workspace.create", started, err) }()
	if err := m.requireStepUp(ctx, actor, "workspace.create"); err != nil {
		return Workspace{}, err
	}
	user, err := m.store.UserByID(ctx, actor.UserID)
	if err != nil || user.Disabled {
		return Workspace{}, ErrForbidden
	}
	name := strings.TrimSpace(input.Name)
	if name == "" || len(name) > 200 {
		return Workspace{}, &ValidationError{Field: "name", Rule: "length", Message: "workspace name must contain between 1 and 200 characters"}
	}
	id, err := m.newID()
	if err != nil {
		return Workspace{}, err
	}
	now := m.now()
	workspace := Workspace{ID: id, Name: name, RequireMFA: input.RequireMFA, CreatedAt: now, UpdatedAt: now}
	owner := Membership{WorkspaceID: id, UserID: actor.UserID, Role: RoleAdmin, Status: MembershipActive, ProvisioningSource: ProvisioningSourceLocal, CreatedAt: now, UpdatedAt: now}
	audit, err := m.newAudit(ctx, actor.UserID, "workspace.create", "workspace", id, id, AuditSucceeded, "")
	if err != nil {
		return Workspace{}, err
	}
	meta, err := m.newEventMeta(EventWorkspaceCreated, "workspace.create", actor.UserID, id, audit)
	if err != nil {
		return Workspace{}, err
	}
	change := WorkspaceCreateChange{EventMeta: meta, Workspace: workspace, Owner: owner}
	commit := m.transactionalCommit(audit, "workspace.create", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyWorkspaceCreate(ctx, tx, change)
	})
	if err := m.store.CreateWorkspace(ctx, workspace, owner, commit); err != nil {
		return Workspace{}, m.mapStoreError(ctx, "workspace.create", err)
	}
	event := WorkspaceCreatedEvent{EventMeta: meta, Workspace: workspace, Owner: owner}
	m.events.emit(ctx, EventWorkspaceCreated, func(listener EventListener) error { return listener.OnWorkspaceCreated(ctx, event) })
	return workspace, nil
}

// UpdateWorkspace renames the workspace and optionally toggles its MFA
// policy, atomically with the audit event. The actor needs a fresh AAL2
// step-up and workspace settings write as an active member.
func (m *Manager) UpdateWorkspace(ctx context.Context, actor Authentication, workspaceID string, input UpdateWorkspaceInput) (_ Workspace, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "workspace.update", started, err) }()
	if err := m.authorizeWorkspaceMutation(ctx, actor, workspaceID, PermissionWorkspaceSettingsWrite, "workspace.update"); err != nil {
		return Workspace{}, err
	}
	return m.updateWorkspace(ctx, actor, workspaceID, input, "workspace.update")
}

// AdminUpdateWorkspace is the instance-administration variant of
// UpdateWorkspace: it requires admin workspaces write and an admin mutation
// (fresh AAL2, or a trusted local request) instead of a membership, and is
// audited like every administrative access.
func (m *Manager) AdminUpdateWorkspace(ctx context.Context, actor Authentication, request TrustedRequest, workspaceID string, input UpdateWorkspaceInput) (_ Workspace, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "admin.workspace.update", started, err) }()
	if err := m.AuthorizeAdmin(ctx, actor, PermissionWorkspacesWrite); err != nil {
		return Workspace{}, err
	}
	if err := m.requireAdminMutation(ctx, actor, request, "admin.workspace.update"); err != nil {
		return Workspace{}, err
	}
	return m.updateWorkspace(ctx, actor, workspaceID, input, "admin.workspace.update")
}

func (m *Manager) updateWorkspace(ctx context.Context, actor Authentication, workspaceID string, input UpdateWorkspaceInput, operation string) (Workspace, error) {
	if !validUUIDv7(workspaceID) {
		return Workspace{}, fmt.Errorf("%w: invalid workspace id", ErrInvalidInput)
	}
	name := strings.TrimSpace(input.Name)
	if name == "" || len(name) > 200 {
		return Workspace{}, &ValidationError{Field: "name", Rule: "length", Message: "workspace name must contain between 1 and 200 characters"}
	}
	previous, err := m.store.WorkspaceByID(ctx, workspaceID)
	if err != nil {
		return Workspace{}, err
	}
	workspace := previous
	workspace.Name = name
	if input.RequireMFA != nil {
		workspace.RequireMFA = *input.RequireMFA
	}
	workspace.UpdatedAt = m.now()
	audit, err := m.newAudit(ctx, actor.UserID, operation, "workspace", workspaceID, workspaceID, AuditSucceeded, "")
	if err != nil {
		return Workspace{}, err
	}
	meta, err := m.newEventMeta(EventWorkspaceUpdated, operation, actor.UserID, workspaceID, audit)
	if err != nil {
		return Workspace{}, err
	}
	change := WorkspaceChange{EventMeta: meta, Workspace: workspace, Previous: previous}
	commit := m.transactionalCommit(audit, operation, func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyWorkspaceChange(ctx, tx, change)
	})
	if err := m.store.UpdateWorkspace(ctx, workspace, commit); err != nil {
		return Workspace{}, m.mapStoreError(ctx, operation, err)
	}
	m.emitWorkspaceChange(ctx, EventWorkspaceUpdated, change)
	return workspace, nil
}

// DisableWorkspace disables the workspace so every tenant-scoped capability
// is denied until it is re-enabled; the store cascade also revokes the
// workspace-bound PAT and OAuth credentials. The actor needs a fresh AAL2
// step-up and workspace settings write. Disabling an already disabled
// workspace is a no-op.
func (m *Manager) DisableWorkspace(ctx context.Context, actor Authentication, workspaceID string) error {
	return m.setWorkspaceDisabled(ctx, actor, TrustedRequest{}, workspaceID, true, false)
}

// EnableWorkspace restores a disabled workspace. The actor must still be an
// active member holding workspace settings write with a fresh AAL2 step-up —
// the only tenant mutation a disabled workspace accepts.
func (m *Manager) EnableWorkspace(ctx context.Context, actor Authentication, workspaceID string) error {
	return m.setWorkspaceDisabled(ctx, actor, TrustedRequest{}, workspaceID, false, false)
}

// AdminDisableWorkspace is the instance-administration variant of
// DisableWorkspace: it requires admin workspaces write and an admin mutation
// (fresh AAL2, or a trusted local request) instead of a membership.
func (m *Manager) AdminDisableWorkspace(ctx context.Context, actor Authentication, request TrustedRequest, workspaceID string) error {
	return m.setWorkspaceDisabled(ctx, actor, request, workspaceID, true, true)
}

// AdminEnableWorkspace is the instance-administration variant of
// EnableWorkspace: it requires admin workspaces write and an admin mutation
// (fresh AAL2, or a trusted local request) instead of a membership.
func (m *Manager) AdminEnableWorkspace(ctx context.Context, actor Authentication, request TrustedRequest, workspaceID string) error {
	return m.setWorkspaceDisabled(ctx, actor, request, workspaceID, false, true)
}

func (m *Manager) setWorkspaceDisabled(ctx context.Context, actor Authentication, request TrustedRequest, workspaceID string, disabled, administrative bool) (err error) {
	operation := "workspace.enable"
	name := EventWorkspaceEnabled
	action := "workspace.enable"
	if disabled {
		operation, name, action = "workspace.disable", EventWorkspaceDisabled, "workspace.disable"
	}
	if administrative {
		operation = "admin." + operation
		action = operation
	}
	started := m.now()
	defer func() { m.observe(ctx, operation, started, err) }()
	if administrative {
		if err := m.AuthorizeAdmin(ctx, actor, PermissionWorkspacesWrite); err != nil {
			return err
		}
		if err := m.requireAdminMutation(ctx, actor, request, operation); err != nil {
			return err
		}
		if !validUUIDv7(workspaceID) {
			return fmt.Errorf("%w: invalid workspace id", ErrInvalidInput)
		}
	} else if err := m.authorizeWorkspaceMutation(ctx, actor, workspaceID, PermissionWorkspaceSettingsWrite, operation); err != nil {
		return err
	}
	previous, err := m.store.WorkspaceByID(ctx, workspaceID)
	if err != nil {
		return err
	}
	if (previous.DisabledAt != nil) == disabled {
		return nil
	}
	now := m.now()
	workspace := previous
	workspace.DisabledAt = nil
	if disabled {
		workspace.DisabledAt = cloneTime(&now)
	}
	workspace.UpdatedAt = now
	audit, err := m.newAudit(ctx, actor.UserID, action, "workspace", workspaceID, workspaceID, AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(name, operation, actor.UserID, workspaceID, audit)
	if err != nil {
		return err
	}
	change := WorkspaceChange{EventMeta: meta, Workspace: workspace, Previous: previous}
	commit := m.transactionalCommit(audit, action, func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyWorkspaceChange(ctx, tx, change)
	})
	if err := m.store.SetWorkspaceDisabled(ctx, workspaceID, disabled, now, commit); err != nil {
		return m.mapStoreError(ctx, operation, err)
	}
	m.emitWorkspaceChange(ctx, name, change)
	return nil
}

// DisableUser disables a global account so it can no longer authenticate or
// authorize anywhere, atomically with the audit event. The actor needs admin
// users write and an admin mutation (fresh AAL2, or a trusted local
// request); the store protects the last enabled root administrator. The
// store cascade revokes the user's credentials and, when the store supports
// sessions (SessionStore), their server-side sessions in the same
// transaction; re-enabling never restores them. Disabling an already
// disabled user is a no-op.
func (m *Manager) DisableUser(ctx context.Context, actor Authentication, request TrustedRequest, userID string) error {
	return m.setUserDisabled(ctx, actor, request, userID, true)
}

// EnableUser re-enables a disabled global account under the same
// authorization as DisableUser.
func (m *Manager) EnableUser(ctx context.Context, actor Authentication, request TrustedRequest, userID string) error {
	return m.setUserDisabled(ctx, actor, request, userID, false)
}

func (m *Manager) setUserDisabled(ctx context.Context, actor Authentication, request TrustedRequest, userID string, disabled bool) (err error) {
	operation := "admin.user.enable"
	name := EventUserEnabled
	action := "user.enable"
	if disabled {
		operation, name, action = "admin.user.disable", EventUserDisabled, "user.disable"
	}
	started := m.now()
	defer func() { m.observe(ctx, operation, started, err) }()
	if err := m.AuthorizeAdmin(ctx, actor, PermissionUsersWrite); err != nil {
		return err
	}
	if err := m.requireAdminMutation(ctx, actor, request, operation); err != nil {
		return err
	}
	if !validUUIDv7(userID) {
		return fmt.Errorf("%w: invalid user id", ErrInvalidInput)
	}
	user, err := m.store.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.Disabled == disabled {
		return nil
	}
	audit, err := m.newAudit(ctx, actor.UserID, action, "user", userID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(name, operation, actor.UserID, "", audit)
	if err != nil {
		return err
	}
	change := UserStatusChange{EventMeta: meta, UserID: userID, Disabled: disabled}
	commit := m.transactionalCommit(audit, action, func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyUserStatusChange(ctx, tx, change)
	})
	if err := m.store.SetUserDisabled(ctx, userID, disabled, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, operation, err)
	}
	event := UserStatusEvent{EventMeta: meta, UserID: userID, Disabled: disabled}
	m.events.emit(ctx, name, func(listener EventListener) error { return listener.OnUserStatusChanged(ctx, event) })
	return nil
}

// UpdateUser changes the actor's own display name. It requires a recent
// interactive authentication (any assurance level within the step-up window),
// mirroring ChangePassword. Updating another account is an administrative
// mutation, see AdminUpdateUser. It returns the updated user.
func (m *Manager) UpdateUser(ctx context.Context, actor Authentication, input UpdateUserInput) (user User, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.user.profile.update", started, err) }()
	if err := m.requireRecentInteractive(ctx, actor); err != nil {
		return User{}, err
	}
	return m.updateUserProfile(ctx, actor, actor.UserID, input, "user.profile.update")
}

// AdminUpdateUser changes any account's display name. The actor needs admin
// users write and an admin mutation (fresh AAL2, or a trusted local
// request), like every other administrative user lifecycle operation. It
// returns the updated user.
func (m *Manager) AdminUpdateUser(ctx context.Context, actor Authentication, request TrustedRequest, userID string, input UpdateUserInput) (user User, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "admin.user.profile.update", started, err) }()
	if err := m.AuthorizeAdmin(ctx, actor, PermissionUsersWrite); err != nil {
		return User{}, err
	}
	if err := m.requireAdminMutation(ctx, actor, request, "admin.user.profile.update"); err != nil {
		return User{}, err
	}
	return m.updateUserProfile(ctx, actor, userID, input, "admin.user.profile.update")
}

func (m *Manager) updateUserProfile(ctx context.Context, actor Authentication, userID string, input UpdateUserInput, operation string) (User, error) {
	if !validUUIDv7(userID) {
		return User{}, fmt.Errorf("%w: invalid user id", ErrInvalidInput)
	}
	displayName := strings.TrimSpace(input.DisplayName)
	if displayName == "" || len(displayName) > 200 {
		return User{}, &ValidationError{Field: "display_name", Rule: "length", Message: "display name must contain between 1 and 200 characters"}
	}
	user, err := m.store.UserByID(ctx, userID)
	if err != nil {
		return User{}, err
	}
	previousProfile := user.DisplayName
	user.DisplayName = displayName
	user.UpdatedAt = m.now()
	audit, err := m.newAudit(ctx, actor.UserID, operation, "user", userID, "", AuditSucceeded, "")
	if err != nil {
		return User{}, err
	}
	meta, err := m.newEventMeta(EventUserProfileUpdated, operation, actor.UserID, "", audit)
	if err != nil {
		return User{}, err
	}
	change := UserProfileChange{EventMeta: meta, User: user, PreviousProfile: previousProfile}
	commit := m.transactionalCommit(audit, operation, func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyUserProfileChange(ctx, tx, change)
	})
	if err := m.store.UpdateUser(ctx, user, commit); err != nil {
		return User{}, m.mapStoreError(ctx, operation, err)
	}
	m.emitUserProfileChange(ctx, change)
	return user, nil
}

// AddMembership adds an existing user to the workspace with the given role,
// atomically with the audit event. The actor needs a fresh AAL2 step-up plus
// workspace users write and RBAC write. An existing membership — local or
// SCIM-managed — fails with ErrConflict.
func (m *Manager) AddMembership(ctx context.Context, actor Authentication, workspaceID, userID string, role Role) (Membership, error) {
	return m.upsertLocalMembership(ctx, actor, workspaceID, userID, role, MembershipActive, true)
}

// SetMembershipStatus suspends or reactivates a local membership, atomically
// with the audit event; the store cascade revokes workspace-bound
// credentials on suspension. The actor needs a fresh AAL2 step-up and
// workspace users write. SCIM-managed memberships fail with ErrConflict, and
// the store protects the last active workspace administrator.
func (m *Manager) SetMembershipStatus(ctx context.Context, actor Authentication, workspaceID, userID string, status MembershipStatus) (Membership, error) {
	if status != MembershipActive && status != MembershipSuspended {
		return Membership{}, fmt.Errorf("%w: invalid membership status", ErrInvalidInput)
	}
	// Authorize before the lookup so an unauthenticated caller cannot use the
	// status endpoint to enumerate workspace memberships.
	if err := m.authorizeWorkspaceMutation(ctx, actor, workspaceID, PermissionWorkspaceUsersWrite, "membership.status.set"); err != nil {
		return Membership{}, err
	}
	current, err := m.store.Membership(ctx, workspaceID, userID)
	if err != nil {
		return Membership{}, err
	}
	return m.upsertLocalMembership(ctx, actor, workspaceID, userID, current.Role, status, false)
}

func (m *Manager) upsertLocalMembership(ctx context.Context, actor Authentication, workspaceID, userID string, role Role, status MembershipStatus, add bool) (_ Membership, err error) {
	operation := "membership.status.set"
	name := EventMembershipStatusChanged
	if add {
		operation, name = "membership.add", EventMembershipAdded
	}
	started := m.now()
	defer func() { m.observe(ctx, operation, started, err) }()
	if err := m.authorizeWorkspaceMutation(ctx, actor, workspaceID, PermissionWorkspaceUsersWrite, operation); err != nil {
		return Membership{}, err
	}
	if add {
		if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionWorkspaceRBACWrite); err != nil {
			return Membership{}, err
		}
	}
	role, err = m.workspaceRoles.normalize(role)
	if err != nil {
		return Membership{}, err
	}
	if _, err := m.store.UserByID(ctx, userID); err != nil {
		return Membership{}, err
	}
	var previous *Membership
	if current, lookupErr := m.store.Membership(ctx, workspaceID, userID); lookupErr == nil {
		if current.ProvisioningSource != ProvisioningSourceLocal {
			return Membership{}, ErrConflict
		}
		if add {
			return Membership{}, ErrConflict
		}
		previous = &current
	} else if !errors.Is(lookupErr, ErrNotFound) {
		return Membership{}, lookupErr
	} else if !add {
		return Membership{}, ErrNotFound
	}
	now := m.now()
	membership := Membership{WorkspaceID: workspaceID, UserID: userID, Role: role, Status: status, ProvisioningSource: ProvisioningSourceLocal, CreatedAt: now, UpdatedAt: now}
	if previous != nil {
		membership.CreatedAt = previous.CreatedAt
	}
	audit, err := m.newAudit(ctx, actor.UserID, operation, "membership", userID, workspaceID, AuditSucceeded, "")
	if err != nil {
		return Membership{}, err
	}
	meta, err := m.newEventMeta(name, operation, actor.UserID, workspaceID, audit)
	if err != nil {
		return Membership{}, err
	}
	change := MembershipChange{EventMeta: meta, Membership: membership, Previous: previous}
	commit := m.transactionalCommit(audit, operation, func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyMembershipChange(ctx, tx, change)
	})
	if err := m.store.UpsertMembership(ctx, membership, commit); err != nil {
		return Membership{}, m.mapStoreError(ctx, operation, err)
	}
	m.emitMembershipChange(ctx, name, change)
	return membership, nil
}

// RemoveMembership removes a local membership, atomically with the audit
// event; the store cascade revokes the member's workspace-bound credentials.
// The actor needs a fresh AAL2 step-up and workspace users write.
// SCIM-managed memberships fail with ErrConflict, and the store protects the
// last active workspace administrator.
func (m *Manager) RemoveMembership(ctx context.Context, actor Authentication, workspaceID, userID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "membership.remove", started, err) }()
	if err := m.authorizeWorkspaceMutation(ctx, actor, workspaceID, PermissionWorkspaceUsersWrite, "membership.remove"); err != nil {
		return err
	}
	previous, err := m.store.Membership(ctx, workspaceID, userID)
	if err != nil {
		return err
	}
	if previous.ProvisioningSource != ProvisioningSourceLocal {
		return ErrConflict
	}
	audit, err := m.newAudit(ctx, actor.UserID, "membership.remove", "membership", userID, workspaceID, AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventMembershipRemoved, "membership.remove", actor.UserID, workspaceID, audit)
	if err != nil {
		return err
	}
	change := MembershipChange{EventMeta: meta, Membership: previous, Previous: &previous, Removed: true}
	commit := m.transactionalCommit(audit, "membership.remove", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyMembershipChange(ctx, tx, change)
	})
	if err := m.store.RemoveMembership(ctx, workspaceID, userID, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, "membership.remove", err)
	}
	m.emitMembershipChange(ctx, EventMembershipRemoved, change)
	return nil
}

// User returns one account by ID. An empty userID means the actor, which
// requires a recent interactive authentication; reading another user
// requires admin users read — the same scoping as Emails and Passkeys.
func (m *Manager) User(ctx context.Context, actor Authentication, userID string) (User, error) {
	if actor.UserID == "" {
		return User{}, ErrUnauthorized
	}
	if userID == "" {
		userID = actor.UserID
	}
	if userID == actor.UserID {
		if err := m.requireRecentInteractive(ctx, actor); err != nil {
			return User{}, err
		}
	} else {
		if !validUUIDv7(userID) {
			return User{}, fmt.Errorf("%w: invalid user id", ErrInvalidInput)
		}
		if err := m.AuthorizeAdmin(ctx, actor, PermissionUsersRead); err != nil {
			return User{}, err
		}
	}
	return m.store.UserByID(ctx, userID)
}

// Workspace returns one workspace by ID. The actor needs workspace access in
// it; admin workspaces read reaches any workspace of the instance.
func (m *Manager) Workspace(ctx context.Context, actor Authentication, workspaceID string) (Workspace, error) {
	if !validUUIDv7(workspaceID) {
		return Workspace{}, fmt.Errorf("%w: invalid workspace id", ErrInvalidInput)
	}
	if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionWorkspaceAccess); err != nil {
		if adminErr := m.AuthorizeAdmin(ctx, actor, PermissionWorkspacesRead); adminErr != nil {
			return Workspace{}, err
		}
	}
	return m.store.WorkspaceByID(ctx, workspaceID)
}

// Membership returns one membership by workspace and user. An empty userID
// means the actor's own membership, which needs workspace access; reading
// another member requires workspace users read in that workspace.
func (m *Manager) Membership(ctx context.Context, actor Authentication, workspaceID, userID string) (Membership, error) {
	if !validUUIDv7(workspaceID) {
		return Membership{}, fmt.Errorf("%w: invalid workspace id", ErrInvalidInput)
	}
	if userID == "" {
		userID = actor.UserID
	}
	permission := PermissionWorkspaceUsersRead
	if userID == actor.UserID {
		permission = PermissionWorkspaceAccess
	} else if !validUUIDv7(userID) {
		return Membership{}, fmt.Errorf("%w: invalid user id", ErrInvalidInput)
	}
	if err := m.AuthorizePermission(ctx, actor, workspaceID, permission); err != nil {
		return Membership{}, err
	}
	return m.store.Membership(ctx, workspaceID, userID)
}

// Users streams every global account. It requires admin users read; the
// authorization itself is audited like every administrative access.
func (m *Manager) Users(ctx context.Context, actor Authentication, page PageRequest) iter.Seq2[PageEvent[User], error] {
	if err := m.AuthorizeAdmin(ctx, actor, PermissionUsersRead); err != nil {
		return errorSeq[PageEvent[User]](err)
	}
	page, err := normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[User]](err)
	}
	return m.store.Users(ctx, page)
}

// Workspaces streams every workspace of the instance. It requires admin
// workspaces read.
func (m *Manager) Workspaces(ctx context.Context, actor Authentication, page PageRequest) iter.Seq2[PageEvent[Workspace], error] {
	if err := m.AuthorizeAdmin(ctx, actor, PermissionWorkspacesRead); err != nil {
		return errorSeq[PageEvent[Workspace]](err)
	}
	page, err := normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[Workspace]](err)
	}
	return m.store.Workspaces(ctx, page)
}

// UserWorkspaces streams the workspaces the actor belongs to. It only
// requires an authenticated, enabled actor.
func (m *Manager) UserWorkspaces(ctx context.Context, actor Authentication, page PageRequest) iter.Seq2[PageEvent[Workspace], error] {
	if actor.UserID == "" {
		return errorSeq[PageEvent[Workspace]](ErrUnauthorized)
	}
	user, err := m.store.UserByID(ctx, actor.UserID)
	if err != nil || user.Disabled {
		return errorSeq[PageEvent[Workspace]](ErrForbidden)
	}
	page, err = normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[Workspace]](err)
	}
	return m.store.UserWorkspaces(ctx, actor.UserID, page)
}

// Memberships streams the memberships of a workspace. The actor needs
// workspace users read in that workspace.
func (m *Manager) Memberships(ctx context.Context, actor Authentication, workspaceID string, page PageRequest) iter.Seq2[PageEvent[Membership], error] {
	if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionWorkspaceUsersRead); err != nil {
		return errorSeq[PageEvent[Membership]](err)
	}
	page, err := normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[Membership]](err)
	}
	return m.store.Memberships(ctx, workspaceID, page)
}

func (m *Manager) authorizeWorkspaceMutation(ctx context.Context, actor Authentication, workspaceID string, permission WorkspacePermission, operation string) error {
	if err := m.requireStepUp(ctx, actor, operation); err != nil {
		return err
	}
	if !validUUIDv7(workspaceID) {
		return fmt.Errorf("%w: invalid workspace id", ErrInvalidInput)
	}
	user, err := m.store.UserByID(ctx, actor.UserID)
	if err != nil || user.Disabled {
		return ErrForbidden
	}
	if actor.WorkspaceID != "" && actor.WorkspaceID != workspaceID {
		return ErrForbidden
	}
	workspace, err := m.store.WorkspaceByID(ctx, workspaceID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrForbidden
		}
		return err
	}
	// A disabled workspace rejects every tenant mutation except the operation
	// that restores it. The restoring actor must still be an active member with
	// the settings permission and a fresh AAL2 authentication.
	if workspace.DisabledAt != nil && operation != "workspace.enable" {
		return ErrForbidden
	}
	membership, err := m.store.Membership(ctx, workspaceID, actor.UserID)
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

func (m *Manager) emitWorkspaceChange(ctx context.Context, name EventName, change WorkspaceChange) {
	event := WorkspaceChangedEvent{EventMeta: change.EventMeta, Workspace: change.Workspace, Previous: change.Previous}
	m.events.emit(ctx, name, func(listener EventListener) error { return listener.OnWorkspaceChanged(ctx, event) })
}

func (m *Manager) emitUserProfileChange(ctx context.Context, change UserProfileChange) {
	event := UserProfileUpdatedEvent{EventMeta: change.EventMeta, UserID: change.User.ID, DisplayName: change.User.DisplayName, PreviousProfile: change.PreviousProfile}
	m.events.emit(ctx, EventUserProfileUpdated, func(listener EventListener) error { return listener.OnUserProfileUpdated(ctx, event) })
}

func (m *Manager) emitMembershipChange(ctx context.Context, name EventName, change MembershipChange) {
	event := MembershipChangedEvent{EventMeta: change.EventMeta, Membership: change.Membership, Previous: change.Previous, Removed: change.Removed}
	m.events.emit(ctx, name, func(listener EventListener) error { return listener.OnMembershipChanged(ctx, event) })
}
