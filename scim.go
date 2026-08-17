package credbound

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"
	"time"
)

// CreateSCIMConfiguration creates the provisioning domain of a workspace
// with its first bearer credential and returns the raw token exactly once;
// only its HMAC is persisted, atomically with the audit event. The actor
// needs a fresh AAL2 step-up and workspace RBAC write. Returns
// ErrNotSupported when the store lacks the SCIM capability.
func (m *Manager) CreateSCIMConfiguration(ctx context.Context, actor Authentication, workspaceID string, input CreateSCIMConfigurationInput) (_ IssuedSCIMCredential, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "scim.configuration.create", started, err) }()
	if m.scimStore == nil {
		return IssuedSCIMCredential{}, ErrNotSupported
	}
	if err := m.requireStepUp(ctx, actor, "scim.configuration.create"); err != nil {
		return IssuedSCIMCredential{}, err
	}
	if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionWorkspaceRBACWrite); err != nil {
		return IssuedSCIMCredential{}, err
	}
	defaultRole, mappings, err := m.validateSCIMRoleConfiguration(input.DefaultRole, input.GroupRoleMappings)
	if err != nil {
		return IssuedSCIMCredential{}, err
	}
	if input.CredentialExpiresAt != nil && !input.CredentialExpiresAt.After(m.now()) {
		return IssuedSCIMCredential{}, fmt.Errorf("%w: SCIM credential expiration must be in the future", ErrInvalidInput)
	}
	configurationID, err := m.newID()
	if err != nil {
		return IssuedSCIMCredential{}, err
	}
	credential, raw, err := m.newSCIMCredential(configurationID, input.CredentialExpiresAt)
	if err != nil {
		return IssuedSCIMCredential{}, err
	}
	now := m.now()
	configuration := SCIMConfiguration{
		ID: configurationID, WorkspaceID: workspaceID, Enabled: true, DefaultRole: defaultRole,
		TrustDirectoryEmails: input.TrustDirectoryEmails, GroupRoleMappings: mappings,
		CreatedAt: now, UpdatedAt: now,
	}
	audit, err := m.newAudit(ctx, actor.UserID, "scim.configuration.create", "scim_configuration", configuration.ID, workspaceID, AuditSucceeded, "")
	if err != nil {
		return IssuedSCIMCredential{}, err
	}
	meta, err := m.newEventMeta(EventSCIMConfigurationCreated, "scim.configuration.create", actor.UserID, workspaceID, audit)
	if err != nil {
		return IssuedSCIMCredential{}, err
	}
	change := SCIMConfigurationChange{EventMeta: meta, Configuration: cloneSCIMConfiguration(configuration)}
	commit := m.transactionalCommit(audit, "scim.configuration.create", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplySCIMConfigurationCreate(ctx, tx, change)
	})
	if err := m.scimStore.CreateSCIMConfiguration(ctx, configuration, credential, commit); err != nil {
		return IssuedSCIMCredential{}, m.mapStoreError(ctx, "scim.configuration.create", err)
	}
	event := SCIMConfigurationCreatedEvent{EventMeta: meta, Configuration: cloneSCIMConfiguration(configuration)}
	m.events.emit(ctx, EventSCIMConfigurationCreated, func(listener EventListener) error {
		return listener.OnSCIMConfigurationCreated(ctx, event)
	})
	publicCredential := cloneSCIMCredential(credential)
	publicCredential.Digest = nil
	return IssuedSCIMCredential{Configuration: cloneSCIMConfiguration(configuration), Credential: publicCredential, Token: raw}, nil
}

// UpdateSCIMConfiguration replaces the role policy of the configuration and
// immediately recomputes the roles of every membership it manages; the
// configuration change, the recomputed memberships and the audit record
// commit atomically. The actor needs a fresh AAL2 step-up and workspace RBAC
// write in the configuration's workspace. An ambiguous group mapping fails
// with ErrConflict; ErrNotSupported without the SCIM capability.
func (m *Manager) UpdateSCIMConfiguration(ctx context.Context, actor Authentication, configurationID string, input UpdateSCIMConfigurationInput) (_ SCIMConfiguration, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "scim.configuration.update", started, err) }()
	configuration, err := m.requireSCIMAdmin(ctx, actor, configurationID, "scim.configuration.update")
	if err != nil {
		return SCIMConfiguration{}, err
	}
	defaultRole, mappings, err := m.validateSCIMRoleConfiguration(input.DefaultRole, input.GroupRoleMappings)
	if err != nil {
		return SCIMConfiguration{}, err
	}
	configuration.DefaultRole = defaultRole
	configuration.TrustDirectoryEmails = input.TrustDirectoryEmails
	configuration.GroupRoleMappings = mappings
	configuration.UpdatedAt = m.now()
	groups, err := m.allSCIMGroups(ctx, configuration.ID)
	if err != nil {
		return SCIMConfiguration{}, err
	}
	users, err := m.allSCIMUsers(ctx, configuration.ID)
	if err != nil {
		return SCIMConfiguration{}, err
	}
	memberships := make([]Membership, 0, len(users))
	for _, user := range users {
		membership, lookupErr := m.store.Membership(ctx, configuration.WorkspaceID, user.UserID)
		if lookupErr != nil {
			return SCIMConfiguration{}, lookupErr
		}
		if membership.ProvisioningSource != configuration.ID {
			return SCIMConfiguration{}, ErrConflict
		}
		role, roleErr := m.scimRoleForUser(configuration, groups, user.ID)
		if roleErr != nil {
			return SCIMConfiguration{}, roleErr
		}
		membership.Role, membership.UpdatedAt = role, configuration.UpdatedAt
		memberships = append(memberships, membership)
	}
	audit, err := m.newAudit(ctx, actor.UserID, "scim.configuration.update", "scim_configuration", configurationID, configuration.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return SCIMConfiguration{}, err
	}
	if err := m.scimStore.UpdateSCIMConfiguration(ctx, configuration, memberships, Commit{Audit: audit}); err != nil {
		return SCIMConfiguration{}, m.mapStoreError(ctx, "scim.configuration.update", err)
	}
	return cloneSCIMConfiguration(configuration), nil
}

// RotateSCIMCredential issues an additional bearer credential for the
// configuration and returns the raw token exactly once; existing credentials
// stay valid until individually revoked. The actor needs a fresh AAL2
// step-up and workspace RBAC write; ErrNotSupported without the SCIM
// capability.
func (m *Manager) RotateSCIMCredential(ctx context.Context, actor Authentication, configurationID string, expiresAt *time.Time) (_ IssuedSCIMCredential, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "scim.credential.rotate", started, err) }()
	configuration, err := m.requireSCIMAdmin(ctx, actor, configurationID, "scim.credential.rotate")
	if err != nil {
		return IssuedSCIMCredential{}, err
	}
	if expiresAt != nil && !expiresAt.After(m.now()) {
		return IssuedSCIMCredential{}, fmt.Errorf("%w: SCIM credential expiration must be in the future", ErrInvalidInput)
	}
	credential, raw, err := m.newSCIMCredential(configurationID, expiresAt)
	if err != nil {
		return IssuedSCIMCredential{}, err
	}
	audit, err := m.newAudit(ctx, actor.UserID, "scim.credential.rotate", "scim_configuration", configurationID, configuration.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return IssuedSCIMCredential{}, err
	}
	if err := m.scimStore.SaveSCIMCredential(ctx, credential, Commit{Audit: audit}); err != nil {
		return IssuedSCIMCredential{}, m.mapStoreError(ctx, "scim.credential.rotate", err)
	}
	publicCredential := cloneSCIMCredential(credential)
	publicCredential.Digest = nil
	return IssuedSCIMCredential{Configuration: configuration, Credential: publicCredential, Token: raw}, nil
}

// RevokeSCIMCredential revokes one bearer credential of the configuration,
// atomically with the audit event. The actor needs a fresh AAL2 step-up and
// workspace RBAC write; ErrNotSupported without the SCIM capability.
func (m *Manager) RevokeSCIMCredential(ctx context.Context, actor Authentication, configurationID, credentialID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "scim.credential.revoke", started, err) }()
	configuration, err := m.requireSCIMAdmin(ctx, actor, configurationID, "scim.credential.revoke")
	if err != nil {
		return err
	}
	audit, err := m.newAudit(ctx, actor.UserID, "scim.credential.revoke", "scim_credential", credentialID, configuration.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return err
	}
	if err := m.scimStore.RevokeSCIMCredential(ctx, configurationID, credentialID, m.now(), Commit{Audit: audit}); err != nil {
		return m.mapStoreError(ctx, "scim.credential.revoke", err)
	}
	return nil
}

// DisableSCIMConfiguration turns provisioning off for the workspace and
// revokes all the configuration's active credentials, atomically with the
// audit event. The actor needs a fresh AAL2 step-up and workspace RBAC
// write; ErrNotSupported without the SCIM capability.
func (m *Manager) DisableSCIMConfiguration(ctx context.Context, actor Authentication, configurationID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "scim.configuration.disable", started, err) }()
	configuration, err := m.requireSCIMAdmin(ctx, actor, configurationID, "scim.configuration.disable")
	if err != nil {
		return err
	}
	audit, err := m.newAudit(ctx, actor.UserID, "scim.configuration.disable", "scim_configuration", configurationID, configuration.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return err
	}
	if err := m.scimStore.DisableSCIMConfiguration(ctx, configurationID, m.now(), Commit{Audit: audit}); err != nil {
		return m.mapStoreError(ctx, "scim.configuration.disable", err)
	}
	return nil
}

// AuthenticateSCIM validates a raw cbs_ bearer token in constant time and
// returns the SCIMAuthentication service capability scoped to its
// configuration and workspace; the credential's last use is recorded
// atomically with the audit event. Malformed, unknown, expired and revoked
// tokens, disabled configurations and disabled workspaces all fail with
// ErrInvalidCredentials; ErrNotSupported without the SCIM capability.
func (m *Manager) AuthenticateSCIM(ctx context.Context, raw string) (_ SCIMAuthentication, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "scim.authenticate", started, err) }()
	if m.scimStore == nil {
		return SCIMAuthentication{}, ErrNotSupported
	}
	prefix, validShape := parseSCIMToken(raw)
	var configuration SCIMConfiguration
	var credential SCIMCredential
	if validShape {
		configuration, credential, err = m.scimStore.SCIMConfigurationByCredentialPrefix(ctx, prefix)
	}
	now := m.now()
	valid := validShape && err == nil && configuration.Enabled && credential.RevokedAt == nil &&
		(credential.ExpiresAt == nil || now.Before(*credential.ExpiresAt)) &&
		hmac.Equal(credential.Digest, digest(m.patPepper, "scim\x00"+raw))
	if !valid {
		return SCIMAuthentication{}, ErrInvalidCredentials
	}
	workspace, workspaceErr := m.store.WorkspaceByID(ctx, configuration.WorkspaceID)
	if workspaceErr != nil || workspace.DisabledAt != nil {
		return SCIMAuthentication{}, ErrInvalidCredentials
	}
	audit, err := m.newServiceAudit(ctx, credential.ID, "auth.scim", "scim_configuration", configuration.ID, configuration.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return SCIMAuthentication{}, err
	}
	if err := m.scimStore.TouchSCIMCredential(ctx, credential.ID, now, Commit{Audit: audit}); err != nil {
		return SCIMAuthentication{}, m.mapStoreError(ctx, "scim.authenticate", err)
	}
	return SCIMAuthentication{
		ConfigurationID: configuration.ID, WorkspaceID: configuration.WorkspaceID,
		CredentialID: credential.ID, AuthenticatedAt: now,
	}, nil
}

// ProvisionSCIMUser creates a passwordless global account, its primary
// email, a directory-owned membership with the configuration's default role
// and the SCIM link, all atomically with the transactional hook and audit.
// The principal is a SCIMAuthentication from AuthenticateSCIM; the primary
// address is marked verified only under TrustDirectoryEmails. A taken
// address or userName fails with ErrConflict.
func (m *Manager) ProvisionSCIMUser(ctx context.Context, principal SCIMAuthentication, input SCIMUserInput) (_ SCIMUser, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "scim.user.provision", started, err) }()
	configuration, err := m.scimConfigurationForPrincipal(ctx, principal)
	if err != nil {
		return SCIMUser{}, err
	}
	input, primaryEmail, err := normalizeSCIMUserInput(input, true)
	if err != nil {
		return SCIMUser{}, err
	}
	userID, err := m.newID()
	if err != nil {
		return SCIMUser{}, err
	}
	emailID, err := m.newID()
	if err != nil {
		return SCIMUser{}, err
	}
	linkID, err := m.newID()
	if err != nil {
		return SCIMUser{}, err
	}
	now := m.now()
	var verifiedAt *time.Time
	if configuration.TrustDirectoryEmails {
		verifiedAt = cloneTime(&now)
	}
	user := User{ID: userID, Email: primaryEmail, DisplayName: input.DisplayName, CreatedAt: now, UpdatedAt: now}
	email := EmailAddress{ID: emailID, UserID: userID, Address: primaryEmail, Primary: true, VerifiedAt: verifiedAt, CreatedAt: now, UpdatedAt: now}
	status := MembershipSuspended
	if input.Active {
		status = MembershipActive
	}
	membership := Membership{
		WorkspaceID: configuration.WorkspaceID, UserID: userID, Role: configuration.DefaultRole,
		Status: status, ProvisioningSource: configuration.ID, CreatedAt: now, UpdatedAt: now,
	}
	link := SCIMUser{
		ID: linkID, ConfigurationID: configuration.ID, UserID: userID, ExternalID: input.ExternalID,
		Schemas: slices.Clone(input.Schemas), UserName: input.UserName, DisplayName: input.DisplayName, Emails: cloneSCIMEmails(input.Emails), Attributes: cloneRawAttributes(input.Attributes),
		Active: input.Active, CreatedAt: now, UpdatedAt: now,
	}
	audit, err := m.newServiceAudit(ctx, principal.CredentialID, "scim.user.provision", "scim_user", link.ID, configuration.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return SCIMUser{}, err
	}
	meta, err := m.newEventMeta(EventSCIMUserProvisioned, "scim.user.provision", principal.CredentialID, configuration.WorkspaceID, audit)
	if err != nil {
		return SCIMUser{}, err
	}
	change := SCIMUserChange{EventMeta: meta, User: cloneSCIMUser(link)}
	commit := m.transactionalCommit(audit, "scim.user.provision", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplySCIMUserProvision(ctx, tx, change)
	})
	if err := m.scimStore.CreateSCIMUser(ctx, user, email, membership, link, commit); err != nil {
		return SCIMUser{}, m.mapStoreError(ctx, "scim.user.provision", err)
	}
	m.emitSCIMUser(ctx, EventSCIMUserProvisioned, meta, link)
	return cloneSCIMUser(link), nil
}

// AdoptSCIMUser explicitly places an existing local membership under
// directory management, creating the SCIM link atomically with the audit
// event. Unlike the provisioning operations it is run by a workspace
// administrator: the actor needs a fresh AAL2 step-up and workspace RBAC
// write. A membership already managed by SCIM fails with ErrConflict.
func (m *Manager) AdoptSCIMUser(ctx context.Context, actor Authentication, configurationID, userID string, input SCIMUserInput) (_ SCIMUser, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "scim.user.adopt", started, err) }()
	configuration, err := m.requireSCIMAdmin(ctx, actor, configurationID, "scim.user.adopt")
	if err != nil {
		return SCIMUser{}, err
	}
	input, _, err = normalizeSCIMUserInput(input, false)
	if err != nil {
		return SCIMUser{}, err
	}
	if _, err := m.store.UserByID(ctx, userID); err != nil {
		return SCIMUser{}, err
	}
	membership, err := m.store.Membership(ctx, configuration.WorkspaceID, userID)
	if err != nil {
		return SCIMUser{}, err
	}
	if membership.ProvisioningSource != ProvisioningSourceLocal {
		return SCIMUser{}, ErrConflict
	}
	linkID, err := m.newID()
	if err != nil {
		return SCIMUser{}, err
	}
	now := m.now()
	link := SCIMUser{
		ID: linkID, ConfigurationID: configuration.ID, UserID: userID, ExternalID: input.ExternalID,
		Schemas: slices.Clone(input.Schemas), UserName: input.UserName, DisplayName: input.DisplayName, Emails: cloneSCIMEmails(input.Emails), Attributes: cloneRawAttributes(input.Attributes),
		Active: input.Active, CreatedAt: now, UpdatedAt: now,
	}
	membership.ProvisioningSource = configuration.ID
	membership.Status = MembershipSuspended
	if input.Active {
		membership.Status = MembershipActive
	}
	membership.UpdatedAt = now
	audit, err := m.newAudit(ctx, actor.UserID, "scim.user.adopt", "scim_user", link.ID, configuration.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return SCIMUser{}, err
	}
	meta, err := m.newEventMeta(EventSCIMUserProvisioned, "scim.user.adopt", actor.UserID, configuration.WorkspaceID, audit)
	if err != nil {
		return SCIMUser{}, err
	}
	change := SCIMUserChange{EventMeta: meta, User: cloneSCIMUser(link)}
	commit := m.transactionalCommit(audit, "scim.user.adopt", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplySCIMUserProvision(ctx, tx, change)
	})
	if err := m.scimStore.AdoptSCIMUser(ctx, membership, link, commit); err != nil {
		return SCIMUser{}, m.mapStoreError(ctx, "scim.user.adopt", err)
	}
	m.emitSCIMUser(ctx, EventSCIMUserProvisioned, meta, link)
	return cloneSCIMUser(link), nil
}

// ReplaceSCIMUser replaces the SCIM representation of a managed user and
// synchronizes the membership status from Active — false suspends, true
// reactivates — atomically with the transactional hook and audit. The
// membership must be managed by the principal's configuration
// (ErrConflict otherwise); the global account is never disabled.
func (m *Manager) ReplaceSCIMUser(ctx context.Context, principal SCIMAuthentication, id string, input SCIMUserInput) (_ SCIMUser, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "scim.user.replace", started, err) }()
	configuration, err := m.scimConfigurationForPrincipal(ctx, principal)
	if err != nil {
		return SCIMUser{}, err
	}
	input, _, err = normalizeSCIMUserInput(input, false)
	if err != nil {
		return SCIMUser{}, err
	}
	current, err := m.scimStore.SCIMUser(ctx, configuration.ID, id)
	if err != nil {
		return SCIMUser{}, err
	}
	membership, err := m.store.Membership(ctx, configuration.WorkspaceID, current.UserID)
	if err != nil {
		return SCIMUser{}, err
	}
	if membership.ProvisioningSource != configuration.ID {
		return SCIMUser{}, ErrConflict
	}
	now := m.now()
	updated := current
	updated.ExternalID, updated.UserName, updated.DisplayName = input.ExternalID, input.UserName, input.DisplayName
	updated.Schemas, updated.Emails, updated.Attributes = slices.Clone(input.Schemas), cloneSCIMEmails(input.Emails), cloneRawAttributes(input.Attributes)
	updated.Active, updated.UpdatedAt = input.Active, now
	updated.DeprovisionedAt = nil
	membership.Status = MembershipSuspended
	if input.Active {
		membership.Status = MembershipActive
	}
	membership.UpdatedAt = now
	name := EventSCIMUserUpdated
	if !current.Active && input.Active {
		name = EventSCIMUserActivated
	} else if current.Active && !input.Active {
		name = EventSCIMUserSuspended
	}
	return m.commitSCIMUserUpdate(ctx, principal, configuration, updated, membership, name, false)
}

// DeprovisionSCIMUser logically deprovisions a managed user: it suspends the
// membership and revokes the user's workspace-scoped PATs while keeping the
// global account and the SCIM link for auditing and restoration, atomically
// with the transactional hook and audit. Deprovisioning an unknown or
// already deprovisioned user is a no-op.
func (m *Manager) DeprovisionSCIMUser(ctx context.Context, principal SCIMAuthentication, id string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "scim.user.deprovision", started, err) }()
	configuration, err := m.scimConfigurationForPrincipal(ctx, principal)
	if err != nil {
		return err
	}
	current, err := m.scimStore.SCIMUser(ctx, configuration.ID, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	if current.DeprovisionedAt != nil {
		return nil
	}
	membership, err := m.store.Membership(ctx, configuration.WorkspaceID, current.UserID)
	if err != nil {
		return err
	}
	if membership.ProvisioningSource != configuration.ID {
		return ErrConflict
	}
	now := m.now()
	current.Active, current.UpdatedAt, current.DeprovisionedAt = false, now, cloneTime(&now)
	membership.Status, membership.UpdatedAt = MembershipSuspended, now
	_, err = m.commitSCIMUserUpdate(ctx, principal, configuration, current, membership, EventSCIMUserDeprovisioned, true)
	return err
}

// SCIMUser reads one managed user of the principal's configuration.
func (m *Manager) SCIMUser(ctx context.Context, principal SCIMAuthentication, id string) (SCIMUser, error) {
	configuration, err := m.scimConfigurationForPrincipal(ctx, principal)
	if err != nil {
		return SCIMUser{}, err
	}
	value, err := m.scimStore.SCIMUser(ctx, configuration.ID, id)
	return cloneSCIMUser(value), err
}

// SCIMUsers streams the managed users of the principal's configuration,
// optionally narrowed by a supported equality filter (id, externalId,
// userName, emails.value, active); unsupported filters fail with
// ErrInvalidInput.
func (m *Manager) SCIMUsers(ctx context.Context, principal SCIMAuthentication, filter SCIMFilter, page PageRequest) iter.Seq2[PageEvent[SCIMUser], error] {
	configuration, err := m.scimConfigurationForPrincipal(ctx, principal)
	if err != nil {
		return errorSeq[PageEvent[SCIMUser]](err)
	}
	page, err = normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[SCIMUser]](err)
	}
	if !validSCIMFilter(filter, true) {
		return errorSeq[PageEvent[SCIMUser]](fmt.Errorf("%w: unsupported SCIM user filter", ErrInvalidInput))
	}
	return m.scimStore.SCIMUsers(ctx, configuration.ID, filter, page)
}

// UpsertSCIMGroup creates (empty id) or replaces a directory group and
// recomputes the roles of every membership the change affects through the
// configured group-role mappings, atomically with the transactional hook and
// audit. An unknown or deprovisioned member fails with ErrInvalidInput and
// an ambiguous mapping fails closed with ErrConflict.
func (m *Manager) UpsertSCIMGroup(ctx context.Context, principal SCIMAuthentication, id string, input SCIMGroupInput) (_ SCIMGroup, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "scim.group.upsert", started, err) }()
	configuration, err := m.scimConfigurationForPrincipal(ctx, principal)
	if err != nil {
		return SCIMGroup{}, err
	}
	input, err = normalizeSCIMGroupInput(input)
	if err != nil {
		return SCIMGroup{}, err
	}
	created := false
	current, lookupErr := m.scimStore.SCIMGroup(ctx, configuration.ID, id)
	if id == "" {
		created = true
		id, err = m.newID()
		if err != nil {
			return SCIMGroup{}, err
		}
		current = SCIMGroup{ID: id, ConfigurationID: configuration.ID, CreatedAt: m.now()}
	} else if lookupErr != nil {
		return SCIMGroup{}, lookupErr
	}
	for _, memberID := range input.MemberIDs {
		member, memberErr := m.scimStore.SCIMUser(ctx, configuration.ID, memberID)
		if memberErr != nil || member.DeprovisionedAt != nil {
			return SCIMGroup{}, fmt.Errorf("%w: unknown SCIM group member", ErrInvalidInput)
		}
	}
	group := current
	group.ExternalID, group.DisplayName = input.ExternalID, input.DisplayName
	group.MemberIDs, group.UpdatedAt, group.DeletedAt = slices.Clone(input.MemberIDs), m.now(), nil
	membersChanged := !slices.Equal(current.MemberIDs, group.MemberIDs)
	memberships, err := m.scimMembershipsForGroupChange(ctx, configuration, &group, false, current.MemberIDs)
	if err != nil {
		return SCIMGroup{}, err
	}
	name := EventSCIMGroupUpdated
	if created {
		name = EventSCIMGroupCreated
	}
	audit, err := m.newServiceAudit(ctx, principal.CredentialID, "scim.group.upsert", "scim_group", group.ID, configuration.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return SCIMGroup{}, err
	}
	meta, err := m.newEventMeta(name, "scim.group.upsert", principal.CredentialID, configuration.WorkspaceID, audit)
	if err != nil {
		return SCIMGroup{}, err
	}
	change := SCIMGroupChange{EventMeta: meta, Group: cloneSCIMGroup(group)}
	commit := m.transactionalCommit(audit, "scim.group.upsert", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplySCIMGroupUpsert(ctx, tx, change)
	})
	if err := m.scimStore.UpsertSCIMGroup(ctx, group, memberships, commit); err != nil {
		return SCIMGroup{}, m.mapStoreError(ctx, "scim.group.upsert", err)
	}
	m.emitSCIMGroup(ctx, name, meta, group)
	if membersChanged {
		if membersMeta, metaErr := m.newEventMeta(EventSCIMGroupMembersChanged, "scim.group.upsert", principal.CredentialID, configuration.WorkspaceID, audit); metaErr == nil {
			m.emitSCIMGroup(ctx, EventSCIMGroupMembersChanged, membersMeta, group)
		}
	}
	return cloneSCIMGroup(group), nil
}

// DeleteSCIMGroup logically deletes a directory group and recomputes the
// roles of its former members, atomically with the transactional hook and
// audit. Deleting an unknown group is a no-op.
func (m *Manager) DeleteSCIMGroup(ctx context.Context, principal SCIMAuthentication, id string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "scim.group.delete", started, err) }()
	configuration, err := m.scimConfigurationForPrincipal(ctx, principal)
	if err != nil {
		return err
	}
	group, err := m.scimStore.SCIMGroup(ctx, configuration.ID, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	memberships, err := m.scimMembershipsForGroupChange(ctx, configuration, &group, true, group.MemberIDs)
	if err != nil {
		return err
	}
	now := m.now()
	group.DeletedAt, group.UpdatedAt = cloneTime(&now), now
	audit, err := m.newServiceAudit(ctx, principal.CredentialID, "scim.group.delete", "scim_group", group.ID, configuration.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventSCIMGroupDeleted, "scim.group.delete", principal.CredentialID, configuration.WorkspaceID, audit)
	if err != nil {
		return err
	}
	change := SCIMGroupChange{EventMeta: meta, Group: cloneSCIMGroup(group)}
	commit := m.transactionalCommit(audit, "scim.group.delete", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplySCIMGroupDelete(ctx, tx, change)
	})
	if err := m.scimStore.DeleteSCIMGroup(ctx, group, memberships, commit); err != nil {
		return m.mapStoreError(ctx, "scim.group.delete", err)
	}
	m.emitSCIMGroup(ctx, EventSCIMGroupDeleted, meta, group)
	return nil
}

// SCIMGroup reads one directory group of the principal's configuration.
func (m *Manager) SCIMGroup(ctx context.Context, principal SCIMAuthentication, id string) (SCIMGroup, error) {
	configuration, err := m.scimConfigurationForPrincipal(ctx, principal)
	if err != nil {
		return SCIMGroup{}, err
	}
	value, err := m.scimStore.SCIMGroup(ctx, configuration.ID, id)
	return cloneSCIMGroup(value), err
}

// SCIMGroups streams the directory groups of the principal's configuration,
// optionally narrowed by a supported equality filter (id, externalId,
// displayName); unsupported filters fail with ErrInvalidInput.
func (m *Manager) SCIMGroups(ctx context.Context, principal SCIMAuthentication, filter SCIMFilter, page PageRequest) iter.Seq2[PageEvent[SCIMGroup], error] {
	configuration, err := m.scimConfigurationForPrincipal(ctx, principal)
	if err != nil {
		return errorSeq[PageEvent[SCIMGroup]](err)
	}
	page, err = normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[SCIMGroup]](err)
	}
	if !validSCIMFilter(filter, false) {
		return errorSeq[PageEvent[SCIMGroup]](fmt.Errorf("%w: unsupported SCIM group filter", ErrInvalidInput))
	}
	return m.scimStore.SCIMGroups(ctx, configuration.ID, filter, page)
}

func (m *Manager) commitSCIMUserUpdate(ctx context.Context, principal SCIMAuthentication, configuration SCIMConfiguration, user SCIMUser, membership Membership, name EventName, revokeWorkspacePATs bool) (SCIMUser, error) {
	action := "scim.user.update"
	if name == EventSCIMUserDeprovisioned {
		action = "scim.user.deprovision"
	}
	audit, err := m.newServiceAudit(ctx, principal.CredentialID, action, "scim_user", user.ID, configuration.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return SCIMUser{}, err
	}
	meta, err := m.newEventMeta(name, action, principal.CredentialID, configuration.WorkspaceID, audit)
	if err != nil {
		return SCIMUser{}, err
	}
	change := SCIMUserChange{EventMeta: meta, User: cloneSCIMUser(user)}
	commit := m.transactionalCommit(audit, action, func(ctx context.Context, tx Tx, hook TransactionHook) error {
		if name == EventSCIMUserDeprovisioned {
			return hook.ApplySCIMUserDeprovision(ctx, tx, change)
		}
		return hook.ApplySCIMUserUpdate(ctx, tx, change)
	})
	if err := m.scimStore.UpdateSCIMUser(ctx, user, membership, revokeWorkspacePATs, commit); err != nil {
		return SCIMUser{}, m.mapStoreError(ctx, action, err)
	}
	m.emitSCIMUser(ctx, name, meta, user)
	return cloneSCIMUser(user), nil
}

func (m *Manager) scimMembershipsForGroupChange(ctx context.Context, configuration SCIMConfiguration, replacement *SCIMGroup, deleted bool, priorMembers []string) ([]Membership, error) {
	groups, err := m.allSCIMGroups(ctx, configuration.ID)
	if err != nil {
		return nil, err
	}
	found := false
	for index := range groups {
		if groups[index].ID == replacement.ID {
			found = true
			if deleted {
				groups = slices.Delete(groups, index, index+1)
			} else {
				groups[index] = cloneSCIMGroup(*replacement)
			}
			break
		}
	}
	if !found && !deleted {
		groups = append(groups, cloneSCIMGroup(*replacement))
	}
	affected := append(slices.Clone(priorMembers), replacement.MemberIDs...)
	slices.Sort(affected)
	affected = slices.Compact(affected)
	result := make([]Membership, 0, len(affected))
	for _, linkID := range affected {
		link, err := m.scimStore.SCIMUser(ctx, configuration.ID, linkID)
		if err != nil {
			return nil, err
		}
		membership, err := m.store.Membership(ctx, configuration.WorkspaceID, link.UserID)
		if err != nil {
			return nil, err
		}
		if membership.ProvisioningSource != configuration.ID {
			return nil, ErrConflict
		}
		role, err := m.scimRoleForUser(configuration, groups, linkID)
		if err != nil {
			return nil, err
		}
		membership.Role, membership.UpdatedAt = role, m.now()
		result = append(result, membership)
	}
	return result, nil
}

func (m *Manager) scimRoleForUser(configuration SCIMConfiguration, groups []SCIMGroup, linkID string) (Role, error) {
	selectedRole, selectedPriority, selected := configuration.DefaultRole, 0, false
	for _, group := range groups {
		if group.DeletedAt != nil || !slices.Contains(group.MemberIDs, linkID) {
			continue
		}
		for _, mapping := range configuration.GroupRoleMappings {
			if mapping.ExternalID != group.ExternalID {
				continue
			}
			if !selected || mapping.Priority > selectedPriority {
				selectedRole, selectedPriority, selected = mapping.Role, mapping.Priority, true
			} else if mapping.Priority == selectedPriority && mapping.Role != selectedRole {
				return "", fmt.Errorf("%w: ambiguous SCIM group role mapping", ErrConflict)
			}
		}
	}
	return selectedRole, nil
}

func (m *Manager) allSCIMGroups(ctx context.Context, configurationID string) ([]SCIMGroup, error) {
	var result []SCIMGroup
	cursor := ""
	for {
		var end *PageEnd
		for event, err := range m.scimStore.SCIMGroups(ctx, configurationID, SCIMFilter{}, PageRequest{Cursor: cursor, Limit: 50}) {
			if err != nil {
				return nil, err
			}
			if event.Data != nil {
				result = append(result, cloneSCIMGroup(*event.Data))
			}
			if event.End != nil {
				end = event.End
			}
		}
		if end == nil || !end.HasMore {
			return result, nil
		}
		cursor = end.NextCursor
	}
}

func (m *Manager) allSCIMUsers(ctx context.Context, configurationID string) ([]SCIMUser, error) {
	var result []SCIMUser
	cursor := ""
	for {
		var end *PageEnd
		for event, err := range m.scimStore.SCIMUsers(ctx, configurationID, SCIMFilter{}, PageRequest{Cursor: cursor, Limit: 50}) {
			if err != nil {
				return nil, err
			}
			if event.Data != nil {
				result = append(result, cloneSCIMUser(*event.Data))
			}
			if event.End != nil {
				end = event.End
			}
		}
		if end == nil || !end.HasMore {
			return result, nil
		}
		cursor = end.NextCursor
	}
}

func (m *Manager) requireSCIMAdmin(ctx context.Context, actor Authentication, configurationID, operation string) (SCIMConfiguration, error) {
	if m.scimStore == nil {
		return SCIMConfiguration{}, ErrNotSupported
	}
	if err := m.requireStepUp(ctx, actor, operation); err != nil {
		return SCIMConfiguration{}, err
	}
	configuration, err := m.scimStore.SCIMConfiguration(ctx, configurationID)
	if err != nil {
		return SCIMConfiguration{}, err
	}
	if err := m.AuthorizePermission(ctx, actor, configuration.WorkspaceID, PermissionWorkspaceRBACWrite); err != nil {
		return SCIMConfiguration{}, err
	}
	return cloneSCIMConfiguration(configuration), nil
}

func (m *Manager) scimConfigurationForPrincipal(ctx context.Context, principal SCIMAuthentication) (SCIMConfiguration, error) {
	if m.scimStore == nil {
		return SCIMConfiguration{}, ErrNotSupported
	}
	if principal.ConfigurationID == "" || principal.CredentialID == "" || principal.WorkspaceID == "" {
		return SCIMConfiguration{}, ErrUnauthorized
	}
	configuration, err := m.scimStore.SCIMConfiguration(ctx, principal.ConfigurationID)
	if err != nil {
		return SCIMConfiguration{}, err
	}
	if !configuration.Enabled || configuration.WorkspaceID != principal.WorkspaceID {
		return SCIMConfiguration{}, ErrUnauthorized
	}
	return cloneSCIMConfiguration(configuration), nil
}

func (m *Manager) validateSCIMRoleConfiguration(defaultRole Role, mappings []SCIMGroupRoleMapping) (Role, []SCIMGroupRoleMapping, error) {
	if defaultRole == "" {
		defaultRole = RoleMember
	}
	defaultRole, err := m.workspaceRoles.normalize(defaultRole)
	if err != nil {
		return "", nil, err
	}
	result := slices.Clone(mappings)
	seen := make(map[string]struct{}, len(result))
	for index := range result {
		result[index].ExternalID = strings.TrimSpace(result[index].ExternalID)
		if result[index].ExternalID == "" || len(result[index].ExternalID) > 255 {
			return "", nil, fmt.Errorf("%w: invalid SCIM group mapping", ErrInvalidInput)
		}
		if _, duplicate := seen[result[index].ExternalID]; duplicate {
			return "", nil, fmt.Errorf("%w: duplicate SCIM group mapping", ErrInvalidInput)
		}
		seen[result[index].ExternalID] = struct{}{}
		role, err := m.workspaceRoles.normalize(result[index].Role)
		if err != nil {
			return "", nil, err
		}
		result[index].Role = role
	}
	return defaultRole, result, nil
}

func (m *Manager) newSCIMCredential(configurationID string, expiresAt *time.Time) (SCIMCredential, string, error) {
	prefixBytes, err := randomBytes(m.random, 6)
	if err != nil {
		return SCIMCredential{}, "", err
	}
	secret, err := randomBytes(m.random, 32)
	if err != nil {
		return SCIMCredential{}, "", err
	}
	id, err := m.newID()
	if err != nil {
		return SCIMCredential{}, "", err
	}
	prefix := hex.EncodeToString(prefixBytes)
	raw := "cbs_" + prefix + "_" + base64.RawURLEncoding.EncodeToString(secret)
	return SCIMCredential{
		ID: id, ConfigurationID: configurationID, Prefix: prefix,
		Digest: digest(m.patPepper, "scim\x00"+raw), CreatedAt: m.now(), ExpiresAt: cloneTime(expiresAt),
	}, raw, nil
}

func parseSCIMToken(raw string) (string, bool) {
	parts := strings.SplitN(raw, "_", 3)
	if len(parts) != 3 || parts[0] != "cbs" || len(parts[1]) != 12 || len(parts[2]) != 43 {
		return "", false
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", false
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil || len(decoded) != 32 {
		return "", false
	}
	return parts[1], true
}

func normalizeSCIMUserInput(input SCIMUserInput, requireEmail bool) (SCIMUserInput, string, error) {
	input.Schemas = slices.Clone(input.Schemas)
	input.Attributes = cloneRawAttributes(input.Attributes)
	input.ExternalID = strings.TrimSpace(input.ExternalID)
	input.UserName = strings.ToLower(strings.TrimSpace(input.UserName))
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	if input.UserName == "" || len(input.UserName) > 320 || len(input.ExternalID) > 255 {
		return SCIMUserInput{}, "", fmt.Errorf("%w: SCIM userName is required", ErrInvalidInput)
	}
	if input.DisplayName == "" {
		input.DisplayName = input.UserName
	}
	if len(input.DisplayName) > 255 {
		return SCIMUserInput{}, "", fmt.Errorf("%w: SCIM displayName is too long", ErrInvalidInput)
	}
	seen := make(map[string]struct{}, len(input.Emails))
	primary := ""
	primaryCount := 0
	for index := range input.Emails {
		email, err := validEmail(input.Emails[index].Value)
		if err != nil {
			return SCIMUserInput{}, "", err
		}
		if _, duplicate := seen[email]; duplicate {
			return SCIMUserInput{}, "", fmt.Errorf("%w: duplicate SCIM email", ErrInvalidInput)
		}
		seen[email] = struct{}{}
		input.Emails[index].Value = email
		input.Emails[index].Type = strings.TrimSpace(input.Emails[index].Type)
		if input.Emails[index].Primary {
			primary, primaryCount = email, primaryCount+1
		}
	}
	if primaryCount > 1 {
		return SCIMUserInput{}, "", fmt.Errorf("%w: multiple primary SCIM emails", ErrInvalidInput)
	}
	if primary == "" && len(input.Emails) > 0 {
		input.Emails[0].Primary, primary = true, input.Emails[0].Value
	}
	if requireEmail && primary == "" {
		return SCIMUserInput{}, "", fmt.Errorf("%w: a SCIM email is required", ErrInvalidInput)
	}
	return input, primary, nil
}

func normalizeSCIMGroupInput(input SCIMGroupInput) (SCIMGroupInput, error) {
	input.ExternalID = strings.TrimSpace(input.ExternalID)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	if input.DisplayName == "" || len(input.DisplayName) > 255 || len(input.ExternalID) > 255 {
		return SCIMGroupInput{}, fmt.Errorf("%w: invalid SCIM group", ErrInvalidInput)
	}
	input.MemberIDs = slices.Clone(input.MemberIDs)
	for _, memberID := range input.MemberIDs {
		if !validUUIDv7(memberID) {
			return SCIMGroupInput{}, fmt.Errorf("%w: invalid SCIM group member", ErrInvalidInput)
		}
	}
	slices.Sort(input.MemberIDs)
	input.MemberIDs = slices.Compact(input.MemberIDs)
	return input, nil
}

func validSCIMFilter(filter SCIMFilter, user bool) bool {
	if filter.Attribute == "" {
		return true
	}
	if !user {
		return filter.Attribute == "id" || filter.Attribute == "externalId" || filter.Attribute == "displayName"
	}
	switch filter.Attribute {
	case "id", "externalId", "userName", "emails.value", "active":
		return true
	default:
		return false
	}
}

func (m *Manager) newServiceAudit(ctx context.Context, actor, action, resourceType, resourceID, workspaceID string, outcome AuditOutcome, reason string) (AuditEvent, error) {
	event, err := m.newAudit(ctx, actor, action, resourceType, resourceID, workspaceID, outcome, reason)
	if err == nil {
		event.ActorKind = ActorService
	}
	return event, err
}

func (m *Manager) emitSCIMUser(ctx context.Context, name EventName, meta EventMeta, value SCIMUser) {
	event := SCIMUserEvent{EventMeta: meta, User: cloneSCIMUser(value)}
	m.events.emit(ctx, name, func(listener EventListener) error {
		switch name {
		case EventSCIMUserProvisioned:
			return listener.OnSCIMUserProvisioned(ctx, event)
		case EventSCIMUserActivated:
			return listener.OnSCIMUserActivated(ctx, event)
		case EventSCIMUserSuspended:
			return listener.OnSCIMUserSuspended(ctx, event)
		case EventSCIMUserDeprovisioned:
			return listener.OnSCIMUserDeprovisioned(ctx, event)
		default:
			return listener.OnSCIMUserUpdated(ctx, event)
		}
	})
}

func (m *Manager) emitSCIMGroup(ctx context.Context, name EventName, meta EventMeta, value SCIMGroup) {
	event := SCIMGroupEvent{EventMeta: meta, Group: cloneSCIMGroup(value)}
	m.events.emit(ctx, name, func(listener EventListener) error {
		switch name {
		case EventSCIMGroupCreated:
			return listener.OnSCIMGroupCreated(ctx, event)
		case EventSCIMGroupDeleted:
			return listener.OnSCIMGroupDeleted(ctx, event)
		case EventSCIMGroupMembersChanged:
			return listener.OnSCIMGroupMembersChanged(ctx, event)
		default:
			return listener.OnSCIMGroupUpdated(ctx, event)
		}
	})
}

func cloneSCIMConfiguration(value SCIMConfiguration) SCIMConfiguration {
	value.GroupRoleMappings = slices.Clone(value.GroupRoleMappings)
	return value
}

func cloneSCIMCredential(value SCIMCredential) SCIMCredential {
	value.Digest = slices.Clone(value.Digest)
	value.ExpiresAt, value.LastUsedAt, value.RevokedAt = cloneTime(value.ExpiresAt), cloneTime(value.LastUsedAt), cloneTime(value.RevokedAt)
	return value
}

func cloneSCIMEmails(values []SCIMEmail) []SCIMEmail { return slices.Clone(values) }

func cloneSCIMUser(value SCIMUser) SCIMUser {
	value.Schemas = slices.Clone(value.Schemas)
	value.Emails = cloneSCIMEmails(value.Emails)
	value.Attributes = cloneRawAttributes(value.Attributes)
	value.DeprovisionedAt = cloneTime(value.DeprovisionedAt)
	return value
}

func cloneRawAttributes(values map[string]json.RawMessage) map[string]json.RawMessage {
	if values == nil {
		return nil
	}
	result := make(map[string]json.RawMessage, len(values))
	for key, value := range values {
		result[key] = slices.Clone(value)
	}
	return result
}

func cloneSCIMGroup(value SCIMGroup) SCIMGroup {
	value.MemberIDs = slices.Clone(value.MemberIDs)
	value.DeletedAt = cloneTime(value.DeletedAt)
	return value
}
