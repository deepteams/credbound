package credbound

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"iter"
	"strings"
)

const invitationPrefix = "cbi"

// InviteToWorkspace invites an email address into a workspace with a
// pre-assigned role and returns the single-use token once. The invitee either
// accepts it from an existing authenticated account owning that address, or
// registers a new account with it.
func (m *Manager) InviteToWorkspace(ctx context.Context, actor Authentication, workspaceID string, input InviteToWorkspaceInput) (_ IssuedWorkspaceInvitation, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "workspace.invitation.create", started, err) }()
	if err := m.requireStepUp(ctx, actor, "workspace.invitation.create"); err != nil {
		return IssuedWorkspaceInvitation{}, err
	}
	if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionWorkspaceUsersWrite); err != nil {
		return IssuedWorkspaceInvitation{}, err
	}
	email, err := validEmail(input.Email)
	if err != nil {
		return IssuedWorkspaceInvitation{}, err
	}
	role, err := m.workspaceRoles.normalize(input.Role)
	if err != nil {
		return IssuedWorkspaceInvitation{}, err
	}
	if user, lookupErr := m.store.UserByEmail(ctx, email); lookupErr == nil {
		if _, membershipErr := m.store.Membership(ctx, workspaceID, user.ID); membershipErr == nil {
			return IssuedWorkspaceInvitation{}, fmt.Errorf("%w: the user is already a member", ErrConflict)
		} else if !errors.Is(membershipErr, ErrNotFound) {
			return IssuedWorkspaceInvitation{}, membershipErr
		}
	} else if !errors.Is(lookupErr, ErrNotFound) {
		return IssuedWorkspaceInvitation{}, lookupErr
	}
	if _, pendingErr := m.store.PendingWorkspaceInvitation(ctx, workspaceID, email); pendingErr == nil {
		return IssuedWorkspaceInvitation{}, fmt.Errorf("%w: a pending invitation already exists", ErrConflict)
	} else if !errors.Is(pendingErr, ErrNotFound) {
		return IssuedWorkspaceInvitation{}, pendingErr
	}
	id, err := m.newID()
	if err != nil {
		return IssuedWorkspaceInvitation{}, err
	}
	secret, err := randomBytes(m.random, 32)
	if err != nil {
		return IssuedWorkspaceInvitation{}, err
	}
	raw := invitationPrefix + "_" + id + "_" + base64.RawURLEncoding.EncodeToString(secret)
	now := m.now()
	invitation := WorkspaceInvitation{
		ID: id, WorkspaceID: workspaceID, Email: email, Role: role, InvitedBy: actor.UserID,
		Digest: digest(m.secretKey, "workspace-invitation:"+raw), CreatedAt: now, ExpiresAt: now.Add(m.invitationTTL),
	}
	event, err := m.newAudit(ctx, actor.UserID, "workspace.invitation.create", "workspace_invitation", id, workspaceID, AuditSucceeded, "")
	if err != nil {
		return IssuedWorkspaceInvitation{}, err
	}
	meta, err := m.newEventMeta(EventWorkspaceInvitationCreated, "workspace.invitation.create", actor.UserID, workspaceID, event)
	if err != nil {
		return IssuedWorkspaceInvitation{}, err
	}
	change := WorkspaceInvitationChange{EventMeta: meta, Invitation: scrubInvitation(invitation)}
	commit := m.transactionalCommit(event, "workspace.invitation.create", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyWorkspaceInvitationChange(ctx, tx, change)
	})
	if err := m.store.CreateWorkspaceInvitation(ctx, invitation, commit); err != nil {
		return IssuedWorkspaceInvitation{}, m.mapStoreError(ctx, "workspace.invitation.create", err)
	}
	created := WorkspaceInvitationEvent{EventMeta: meta, Invitation: scrubInvitation(invitation)}
	m.events.emit(ctx, EventWorkspaceInvitationCreated, func(listener EventListener) error { return listener.OnWorkspaceInvitationCreated(ctx, created) })
	return IssuedWorkspaceInvitation{Invitation: scrubInvitation(invitation), Token: raw}, nil
}

// AcceptInvitation lets an authenticated user who owns the invited address as
// a verified email join the workspace with the invited role.
func (m *Manager) AcceptInvitation(ctx context.Context, actor Authentication, raw string) (_ Membership, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "workspace.invitation.accept", started, err) }()
	if err := m.requireRecentInteractive(ctx, actor); err != nil {
		return Membership{}, err
	}
	invitation, err := m.usableInvitation(ctx, raw, "workspace.invitation.accept")
	if err != nil {
		return Membership{}, err
	}
	owned, err := m.ownsVerifiedEmail(ctx, actor.UserID, invitation.Email)
	if err != nil {
		return Membership{}, err
	}
	if !owned {
		if auditErr := m.appendAuthenticationAudit(ctx, actor.UserID, "workspace.invitation.accept", AuditFailed, "email_mismatch"); auditErr != nil {
			return Membership{}, auditErr
		}
		return Membership{}, ErrForbidden
	}
	if _, membershipErr := m.store.Membership(ctx, invitation.WorkspaceID, actor.UserID); membershipErr == nil {
		return Membership{}, fmt.Errorf("%w: the user is already a member", ErrConflict)
	} else if !errors.Is(membershipErr, ErrNotFound) {
		return Membership{}, membershipErr
	}
	now := m.now()
	membership := Membership{
		WorkspaceID: invitation.WorkspaceID, UserID: actor.UserID, Role: invitation.Role,
		Status: MembershipActive, ProvisioningSource: ProvisioningSourceLocal, CreatedAt: now, UpdatedAt: now,
	}
	event, err := m.newAudit(ctx, actor.UserID, "workspace.invitation.accept", "workspace_invitation", invitation.ID, invitation.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return Membership{}, err
	}
	invitationMeta, err := m.newEventMeta(EventWorkspaceInvitationAccepted, "workspace.invitation.accept", actor.UserID, invitation.WorkspaceID, event)
	if err != nil {
		return Membership{}, err
	}
	membershipMeta, err := m.newEventMeta(EventMembershipAdded, "workspace.invitation.accept", actor.UserID, invitation.WorkspaceID, event)
	if err != nil {
		return Membership{}, err
	}
	accepted := invitation
	accepted.AcceptedAt = &now
	accepted.AcceptedUserID = actor.UserID
	invitationChange := WorkspaceInvitationChange{EventMeta: invitationMeta, Invitation: accepted}
	membershipChange := MembershipChange{EventMeta: membershipMeta, Membership: membership}
	commit := Commit{Audit: event, Transactional: func(ctx context.Context, tx Tx) error {
		if err := m.events.apply(ctx, "membership.change", func(hook TransactionHook) error {
			return hook.ApplyMembershipChange(ctx, tx, membershipChange)
		}); err != nil {
			return err
		}
		return m.events.apply(ctx, "workspace.invitation.accept", func(hook TransactionHook) error {
			return hook.ApplyWorkspaceInvitationChange(ctx, tx, invitationChange)
		})
	}}
	if err := m.store.AcceptWorkspaceInvitation(ctx, invitation.ID, actor.UserID, now, membership, commit); err != nil {
		return Membership{}, m.mapStoreError(ctx, "workspace.invitation.accept", err)
	}
	m.emitMembershipChange(ctx, EventMembershipAdded, membershipChange)
	acceptedEvent := WorkspaceInvitationEvent{EventMeta: invitationMeta, Invitation: accepted}
	m.events.emit(ctx, EventWorkspaceInvitationAccepted, func(listener EventListener) error { return listener.OnWorkspaceInvitationAccepted(ctx, acceptedEvent) })
	return membership, nil
}

// RegisterFromInvitation creates the invited account in one atomic operation:
// the invitee chooses their own password, the invited address is the verified
// primary email (delivery of the token proved control of the mailbox), and
// the invited role becomes their membership.
func (m *Manager) RegisterFromInvitation(ctx context.Context, raw string, input RegisterFromInvitationInput) (_ Authentication, _ User, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "workspace.invitation.register", started, err) }()
	invitation, err := m.usableInvitation(ctx, raw, "workspace.invitation.register")
	if err != nil {
		return Authentication{}, User{}, err
	}
	displayName := strings.TrimSpace(input.DisplayName)
	if displayName == "" {
		return Authentication{}, User{}, fmt.Errorf("%w: display name is required", ErrInvalidInput)
	}
	if err := m.validatePassword(input.Password); err != nil {
		return Authentication{}, User{}, err
	}
	if _, lookupErr := m.store.UserByEmail(ctx, invitation.Email); lookupErr == nil {
		return Authentication{}, User{}, fmt.Errorf("%w: an account with this email already exists", ErrConflict)
	} else if !errors.Is(lookupErr, ErrNotFound) {
		return Authentication{}, User{}, lookupErr
	}
	hash, err := m.passwords.Hash(input.Password)
	if err != nil {
		return Authentication{}, User{}, fmt.Errorf("hash password: %w", err)
	}
	userID, err := m.newID()
	if err != nil {
		return Authentication{}, User{}, err
	}
	emailID, err := m.newID()
	if err != nil {
		return Authentication{}, User{}, err
	}
	now := m.now()
	user := User{ID: userID, Email: invitation.Email, DisplayName: displayName, LastSeenAt: cloneTime(&now), CreatedAt: now, UpdatedAt: now}
	primaryEmail := EmailAddress{ID: emailID, UserID: userID, Address: invitation.Email, Primary: true, VerifiedAt: cloneTime(&now), CreatedAt: now, UpdatedAt: now}
	membership := Membership{
		WorkspaceID: invitation.WorkspaceID, UserID: userID, Role: invitation.Role,
		Status: MembershipActive, ProvisioningSource: ProvisioningSourceLocal, CreatedAt: now, UpdatedAt: now,
	}
	event, err := m.newAudit(ctx, userID, "workspace.invitation.register", "workspace_invitation", invitation.ID, invitation.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return Authentication{}, User{}, err
	}
	userMeta, err := m.newEventMeta(EventUserCreated, "workspace.invitation.register", userID, invitation.WorkspaceID, event)
	if err != nil {
		return Authentication{}, User{}, err
	}
	invitationMeta, err := m.newEventMeta(EventWorkspaceInvitationAccepted, "workspace.invitation.register", userID, invitation.WorkspaceID, event)
	if err != nil {
		return Authentication{}, User{}, err
	}
	accepted := invitation
	accepted.AcceptedAt = &now
	accepted.AcceptedUserID = userID
	userChange := UserCreateChange{EventMeta: userMeta, User: user, Email: primaryEmail, Membership: membership}
	invitationChange := WorkspaceInvitationChange{EventMeta: invitationMeta, Invitation: accepted}
	commit := Commit{Audit: event, Transactional: func(ctx context.Context, tx Tx) error {
		if err := m.events.apply(ctx, "user.create", func(hook TransactionHook) error {
			return hook.ApplyUserCreate(ctx, tx, userChange)
		}); err != nil {
			return err
		}
		return m.events.apply(ctx, "workspace.invitation.accept", func(hook TransactionHook) error {
			return hook.ApplyWorkspaceInvitationChange(ctx, tx, invitationChange)
		})
	}}
	if err := m.store.RegisterInvitedUser(ctx, invitation.ID, user, primaryEmail, PasswordCredential{UserID: userID, Hash: hash, UpdatedAt: now}, membership, now, commit); err != nil {
		return Authentication{}, User{}, m.mapStoreError(ctx, "workspace.invitation.register", err)
	}
	createdEvent := UserCreatedEvent{EventMeta: userMeta, User: user, Email: primaryEmail, Membership: membership}
	m.events.emit(ctx, EventUserCreated, func(listener EventListener) error { return listener.OnUserCreated(ctx, createdEvent) })
	acceptedEvent := WorkspaceInvitationEvent{EventMeta: invitationMeta, Invitation: accepted}
	m.events.emit(ctx, EventWorkspaceInvitationAccepted, func(listener EventListener) error { return listener.OnWorkspaceInvitationAccepted(ctx, acceptedEvent) })
	authentication := Authentication{UserID: userID, Method: MethodPassword, Level: AAL1, AuthenticatedAt: now}
	m.emitAuthenticationSucceeded(ctx, "workspace.invitation.register", event, authentication)
	return authentication, user, nil
}

// RevokeInvitation withdraws a pending invitation so its token can no longer
// be accepted.
func (m *Manager) RevokeInvitation(ctx context.Context, actor Authentication, workspaceID, invitationID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "workspace.invitation.revoke", started, err) }()
	if err := m.requireStepUp(ctx, actor, "workspace.invitation.revoke"); err != nil {
		return err
	}
	if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionWorkspaceUsersWrite); err != nil {
		return err
	}
	if !validUUIDv7(invitationID) {
		return fmt.Errorf("%w: invalid invitation id", ErrInvalidInput)
	}
	now := m.now()
	invitation, err := m.store.WorkspaceInvitationByID(ctx, invitationID)
	if err != nil {
		return err
	}
	if invitation.WorkspaceID != workspaceID {
		return ErrNotFound
	}
	event, err := m.newAudit(ctx, actor.UserID, "workspace.invitation.revoke", "workspace_invitation", invitationID, workspaceID, AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventWorkspaceInvitationRevoked, "workspace.invitation.revoke", actor.UserID, workspaceID, event)
	if err != nil {
		return err
	}
	revoked := scrubInvitation(invitation)
	revoked.RevokedAt = &now
	change := WorkspaceInvitationChange{EventMeta: meta, Invitation: revoked}
	commit := m.transactionalCommit(event, "workspace.invitation.revoke", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyWorkspaceInvitationChange(ctx, tx, change)
	})
	if err := m.store.RevokeWorkspaceInvitation(ctx, workspaceID, invitationID, now, commit); err != nil {
		return m.mapStoreError(ctx, "workspace.invitation.revoke", err)
	}
	revokedEvent := WorkspaceInvitationEvent{EventMeta: meta, Invitation: revoked}
	m.events.emit(ctx, EventWorkspaceInvitationRevoked, func(listener EventListener) error { return listener.OnWorkspaceInvitationRevoked(ctx, revokedEvent) })
	return nil
}

// WorkspaceInvitations streams the workspace's invitations without their
// digests.
func (m *Manager) WorkspaceInvitations(ctx context.Context, actor Authentication, workspaceID string, page PageRequest) iter.Seq2[PageEvent[WorkspaceInvitation], error] {
	if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionWorkspaceUsersRead); err != nil {
		return errorSeq[PageEvent[WorkspaceInvitation]](err)
	}
	page, err := normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[WorkspaceInvitation]](err)
	}
	return func(yield func(PageEvent[WorkspaceInvitation], error) bool) {
		for event, err := range m.store.WorkspaceInvitations(ctx, workspaceID, page) {
			if event.Data != nil {
				scrubbed := scrubInvitation(*event.Data)
				event.Data = &scrubbed
			}
			if !yield(event, err) {
				return
			}
		}
	}
}

// usableInvitation validates the token shape, digest, expiry and state, and
// checks that the workspace is still enabled.
func (m *Manager) usableInvitation(ctx context.Context, raw, action string) (WorkspaceInvitation, error) {
	invitationID, valid := parseSecretToken(invitationPrefix, raw)
	if !valid {
		return WorkspaceInvitation{}, ErrInvalidCredentials
	}
	invitation, lookupErr := m.store.WorkspaceInvitationByID(ctx, invitationID)
	if lookupErr != nil {
		if errors.Is(lookupErr, ErrNotFound) {
			return WorkspaceInvitation{}, ErrInvalidCredentials
		}
		return WorkspaceInvitation{}, lookupErr
	}
	if invitation.RevokedAt != nil || invitation.AcceptedAt != nil {
		if auditErr := m.appendAuthenticationAudit(ctx, "", action, AuditFailed, "invalid_credentials"); auditErr != nil {
			return WorkspaceInvitation{}, auditErr
		}
		return WorkspaceInvitation{}, ErrInvalidCredentials
	}
	if !m.now().Before(invitation.ExpiresAt) {
		if auditErr := m.appendAuthenticationAudit(ctx, "", action, AuditFailed, "expired"); auditErr != nil {
			return WorkspaceInvitation{}, auditErr
		}
		return WorkspaceInvitation{}, ErrExpired
	}
	if !hmac.Equal(invitation.Digest, digest(m.secretKey, "workspace-invitation:"+raw)) {
		if auditErr := m.appendAuthenticationAudit(ctx, "", action, AuditFailed, "invalid_credentials"); auditErr != nil {
			return WorkspaceInvitation{}, auditErr
		}
		return WorkspaceInvitation{}, ErrInvalidCredentials
	}
	workspace, err := m.store.WorkspaceByID(ctx, invitation.WorkspaceID)
	if err != nil {
		return WorkspaceInvitation{}, err
	}
	if workspace.DisabledAt != nil {
		return WorkspaceInvitation{}, ErrForbidden
	}
	invitation.Digest = nil
	return invitation, nil
}

// ownsVerifiedEmail reports whether the user owns the address as a verified
// email.
func (m *Manager) ownsVerifiedEmail(ctx context.Context, userID, address string) (bool, error) {
	for event, err := range m.store.Emails(ctx, userID, PageRequest{Limit: 100}) {
		if err != nil {
			return false, err
		}
		if event.Data != nil && event.Data.Address == address && event.Data.VerifiedAt != nil {
			return true, nil
		}
	}
	return false, nil
}

func scrubInvitation(invitation WorkspaceInvitation) WorkspaceInvitation {
	invitation.Digest = nil
	return invitation
}
