package credbound_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
)

type coreOnlyStore struct{ credbound.Store }

// TestSCIMAPIsRequireStoreCapability pins SCIM-001: every SCIM API answers
// ErrNotSupported when the configured store does not implement SCIMStore.
func TestSCIMAPIsRequireStoreCapability(t *testing.T) {
	base := memory.New()
	manager, err := credbound.New(credbound.Config{
		Store: coreOnlyStore{Store: base}, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC) }, Random: &counterReader{next: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	actor := credbound.Authentication{}
	principal := credbound.SCIMAuthentication{}
	operations := []func() error{
		func() error {
			_, err := manager.CreateSCIMConfiguration(ctx, actor, credbound.MustParseUUID("0198b463-0000-7000-8000-21a3230e0377"), credbound.CreateSCIMConfigurationInput{})
			return err
		},
		func() error {
			_, err := manager.UpdateSCIMConfiguration(ctx, actor, credbound.MustParseUUID("0198b463-0000-7000-8000-b7d64a922100"), credbound.UpdateSCIMConfigurationInput{})
			return err
		},
		func() error {
			_, err := manager.RotateSCIMCredential(ctx, actor, credbound.MustParseUUID("0198b463-0000-7000-8000-b7d64a922100"), nil)
			return err
		},
		func() error {
			return manager.RevokeSCIMCredential(ctx, actor, credbound.MustParseUUID("0198b463-0000-7000-8000-b7d64a922100"), credbound.MustParseUUID("0198b463-0000-7000-8000-e265b6f56460"))
		},
		func() error {
			return manager.DisableSCIMConfiguration(ctx, actor, credbound.MustParseUUID("0198b463-0000-7000-8000-b7d64a922100"))
		},
		func() error { _, err := manager.AuthenticateSCIM(ctx, "token"); return err },
		func() error {
			_, err := manager.ProvisionSCIMUser(ctx, principal, credbound.SCIMUserInput{})
			return err
		},
		func() error {
			_, err := manager.AdoptSCIMUser(ctx, actor, credbound.MustParseUUID("0198b463-0000-7000-8000-b7d64a922100"), credbound.MustParseUUID("0198b463-0000-7000-8000-04f8996da763"), credbound.SCIMUserInput{})
			return err
		},
		func() error {
			_, err := manager.ReplaceSCIMUser(ctx, principal, credbound.MustParseUUID("0198b463-0000-7000-8000-04f8996da763"), credbound.SCIMUserInput{})
			return err
		},
		func() error {
			return manager.DeprovisionSCIMUser(ctx, principal, credbound.MustParseUUID("0198b463-0000-7000-8000-04f8996da763"))
		},
		func() error {
			_, err := manager.SCIMUser(ctx, principal, credbound.MustParseUUID("0198b463-0000-7000-8000-04f8996da763"))
			return err
		},
		func() error {
			_, err := manager.UpsertSCIMGroup(ctx, principal, credbound.MustParseUUID("0198b463-0000-7000-8000-ad936fcbed63"), credbound.SCIMGroupInput{})
			return err
		},
		func() error {
			return manager.DeleteSCIMGroup(ctx, principal, credbound.MustParseUUID("0198b463-0000-7000-8000-ad936fcbed63"))
		},
		func() error {
			_, err := manager.SCIMGroup(ctx, principal, credbound.MustParseUUID("0198b463-0000-7000-8000-ad936fcbed63"))
			return err
		},
	}
	for index, operation := range operations {
		if err := operation(); !errors.Is(err, credbound.ErrNotSupported) {
			t.Fatalf("SCIM API %d = %v", index, err)
		}
	}
	if _, err := firstSCIMError(manager.SCIMUsers(ctx, principal, credbound.SCIMFilter{}, credbound.PageRequest{})); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("SCIM users = %v", err)
	}
	if _, err := firstSCIMError(manager.SCIMGroups(ctx, principal, credbound.SCIMFilter{}, credbound.PageRequest{})); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("SCIM groups = %v", err)
	}
}

type coreStoreOnly struct{ credbound.Store }

// TestExtensibleWorkspaceRoles pins that the host service can register
// additional workspace roles and permissions alongside the provided admin and
// member roles (RBAC-001), and that the permission-based authorization
// resolves inheritance, gives admin every registered permission, rejects
// cyclic or dangling catalogs, and fails closed on an unknown role (RBAC-003).
func TestExtensibleWorkspaceRoles(t *testing.T) {
	store := memory.New()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	manager, err := credbound.New(credbound.Config{
		Store: store, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return now }, Random: &counterReader{next: 0x41},
		WorkspaceRoles: []credbound.RoleDefinition{
			{Role: "viewer", Permissions: []credbound.WorkspacePermission{"documents.read"}},
			{Role: "editor", Permissions: []credbound.WorkspacePermission{"documents.write"}, Inherits: []credbound.Role{"viewer"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	root, workspace, err := manager.Bootstrap(context.Background(), credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	member, err := manager.CreateUser(context.Background(), aal2(root.UserID, now), workspace.ID, credbound.CreateUserInput{
		Email: "editor@example.com", DisplayName: "Editor", Password: "another secure password", Role: "editor",
	})
	if err != nil {
		t.Fatal(err)
	}
	authn := credbound.Authentication{UserID: member.ID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: now}
	if err := manager.AuthorizePermission(context.Background(), authn, workspace.ID, "documents.read"); err != nil {
		t.Fatalf("inherited permission = %v", err)
	}
	if err := manager.AuthorizePermission(context.Background(), authn, workspace.ID, "documents.write"); err != nil {
		t.Fatalf("direct permission = %v", err)
	}
	if err := manager.Authorize(context.Background(), authn, workspace.ID, credbound.RoleMember); err != nil {
		t.Fatalf("custom role did not inherit member: %v", err)
	}
	if err := manager.AuthorizePermission(context.Background(), root, workspace.ID, "documents.write"); err != nil {
		t.Fatalf("admin did not receive application permission: %v", err)
	}
	if err := manager.GrantRole(context.Background(), aal2(root.UserID, now), workspace.ID, member.ID, "unknown"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("unknown role = %v", err)
	}

	for name, roles := range map[string][]credbound.RoleDefinition{
		"cycle":               {{Role: "one", Inherits: []credbound.Role{"two"}}, {Role: "two", Inherits: []credbound.Role{"one"}}},
		"unknown inheritance": {{Role: "one", Inherits: []credbound.Role{"missing"}}},
		"invalid permission":  {{Role: "one", Permissions: []credbound.WorkspacePermission{"Invalid Permission"}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := credbound.New(credbound.Config{
				Store: memory.New(), Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
				SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32), WorkspaceRoles: roles,
			})
			if !errors.Is(err, credbound.ErrInvalidInput) {
				t.Fatalf("invalid catalog = %v", err)
			}
		})
	}
}

// TestSCIMLifecycleRolesGroupsAndDeprovision walks the provisioning
// lifecycle — passwordless creation, explicit adoption of a local user,
// group-driven role mapping, and logical deprovisioning that leaves the
// global account enabled (SCIM-003, SCIM-005).
func TestSCIMLifecycleRolesGroupsAndDeprovision(t *testing.T) {
	f := newFixture(t)
	root, workspace := f.bootstrap(t)
	// Rebuild with a custom role while retaining the freshly bootstrapped store.
	manager, err := credbound.New(credbound.Config{
		Store: f.store, Passwords: f.passwords, TOTP: fakeTOTP{}, Passkeys: f.passkeys,
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return f.now }, Random: &counterReader{next: 0x55},
		WorkspaceRoles: []credbound.RoleDefinition{{Role: "editor", Permissions: []credbound.WorkspacePermission{"documents.write"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	admin := aal2(root.UserID, f.now)
	localUser, err := manager.CreateUser(context.Background(), admin, workspace.ID, credbound.CreateUserInput{
		Email: "adopt@example.com", DisplayName: "Adopt", Password: "another secure password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := manager.CreateSCIMConfiguration(context.Background(), admin, workspace.ID, credbound.CreateSCIMConfigurationInput{
		DefaultRole:       credbound.RoleMember,
		GroupRoleMappings: []credbound.SCIMGroupRoleMapping{{ExternalID: "directory-editors", Role: "editor", Priority: 10}},
	})
	if err != nil {
		t.Fatal(err)
	}
	updatedConfiguration, err := manager.UpdateSCIMConfiguration(context.Background(), admin, issued.Configuration.ID, credbound.UpdateSCIMConfigurationInput{
		DefaultRole:       credbound.RoleMember,
		GroupRoleMappings: []credbound.SCIMGroupRoleMapping{{ExternalID: "directory-editors", Role: "editor", Priority: 20}},
	})
	if err != nil || len(updatedConfiguration.GroupRoleMappings) != 1 || updatedConfiguration.GroupRoleMappings[0].Priority != 20 {
		t.Fatalf("updated SCIM configuration = %#v, %v", updatedConfiguration, err)
	}
	adopted, err := manager.AdoptSCIMUser(context.Background(), admin, issued.Configuration.ID, localUser.ID, credbound.SCIMUserInput{
		ExternalID: "adopted-user", UserName: "adopt@example.com", DisplayName: "Adopted", Active: true,
	})
	if err != nil || adopted.UserID != localUser.ID {
		t.Fatalf("adopted SCIM user = %#v, %v", adopted, err)
	}
	if _, err := manager.AdoptSCIMUser(context.Background(), admin, issued.Configuration.ID, localUser.ID, credbound.SCIMUserInput{
		ExternalID: "adopted-twice", UserName: "adopt2@example.com", Active: true,
	}); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("second adoption = %v", err)
	}
	// The token is displayed only this once, the response never carries the
	// persisted digest, and both identifiers are UUIDv7 (SCIM-002, SCIM-006).
	if issued.Token == "" || issued.Credential.Digest != nil || !uuidV7.MatchString(issued.Configuration.ID.String()) || !uuidV7.MatchString(issued.Credential.ID.String()) {
		t.Fatalf("unsafe issued SCIM credential: %#v", issued)
	}
	if _, err := manager.AuthenticateSCIM(context.Background(), issued.Token+"x"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("invalid SCIM token = %v", err)
	}
	principal, err := manager.AuthenticateSCIM(context.Background(), issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	link, err := manager.ProvisionSCIMUser(context.Background(), principal, credbound.SCIMUserInput{
		ExternalID: "directory-user-1", UserName: " USER@Example.com ", DisplayName: "Directory User",
		Emails: []credbound.SCIMEmail{{Value: " USER@Example.com ", Primary: true}}, Active: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The user's SCIM identifier is distinct from the global User.ID (SCIM-002).
	if link.UserName != "user@example.com" || link.UserID == (credbound.UUID{}) || link.ID == link.UserID {
		t.Fatalf("invalid SCIM link: %#v", link)
	}
	if value, err := f.store.SCIMUserByExternalID(context.Background(), issued.Configuration.ID, link.ExternalID); err != nil || value.ID != link.ID {
		t.Fatalf("memory external SCIM lookup = %#v, %v", value, err)
	}
	if value, err := f.store.SCIMUserByUserName(context.Background(), issued.Configuration.ID, strings.ToUpper(link.UserName)); err != nil || value.ID != link.ID {
		t.Fatalf("memory username SCIM lookup = %#v, %v", value, err)
	}
	// The membership names the SCIM configuration as its provisioning source
	// (SCIM-004).
	membership, err := f.store.Membership(context.Background(), workspace.ID, link.UserID)
	if err != nil || membership.Role != credbound.RoleMember || membership.Status != credbound.MembershipActive || membership.ProvisioningSource != issued.Configuration.ID.String() {
		t.Fatalf("provisioned membership = %#v, %v", membership, err)
	}
	if _, err := f.store.PasswordByUserID(context.Background(), link.UserID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("SCIM created a password: %v", err)
	}
	if _, err := f.store.UserByEmail(context.Background(), "user@example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("untrusted SCIM email was accepted for login: %v", err)
	}

	page := collectSCIMPage(t, manager.SCIMUsers(context.Background(), principal, credbound.SCIMFilter{Attribute: "externalId", Value: "directory-user-1"}, credbound.PageRequest{Limit: 50}))
	if len(page.items) != 1 || page.items[0].ID != link.ID {
		t.Fatalf("filtered SCIM users = %#v", page)
	}
	group, err := manager.UpsertSCIMGroup(context.Background(), principal, credbound.UUID{}, credbound.SCIMGroupInput{
		ExternalID: "directory-editors", DisplayName: "Editors", MemberIDs: []credbound.UUID{link.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if value, err := f.store.SCIMGroupByExternalID(context.Background(), issued.Configuration.ID, group.ExternalID); err != nil || value.ID != group.ID {
		t.Fatalf("memory external SCIM group lookup = %#v, %v", value, err)
	}
	membership, _ = f.store.Membership(context.Background(), workspace.ID, link.UserID)
	if membership.Role != "editor" {
		t.Fatalf("group mapping role = %q", membership.Role)
	}
	updatedConfiguration, err = manager.UpdateSCIMConfiguration(context.Background(), admin, issued.Configuration.ID, credbound.UpdateSCIMConfigurationInput{
		DefaultRole:       credbound.RoleMember,
		GroupRoleMappings: []credbound.SCIMGroupRoleMapping{{ExternalID: "directory-editors", Role: credbound.RoleAdmin, Priority: 30}},
	})
	if err != nil || updatedConfiguration.GroupRoleMappings[0].Role != credbound.RoleAdmin {
		t.Fatalf("remapped SCIM configuration = %#v, %v", updatedConfiguration, err)
	}
	membership, _ = f.store.Membership(context.Background(), workspace.ID, link.UserID)
	if membership.Role != credbound.RoleAdmin {
		t.Fatalf("configuration update did not remap membership: %#v", membership)
	}
	groups := collectSCIMPage(t, manager.SCIMGroups(context.Background(), principal, credbound.SCIMFilter{Attribute: "externalId", Value: "directory-editors"}, credbound.PageRequest{Limit: 50}))
	if len(groups.items) != 1 || groups.items[0].ID != group.ID {
		t.Fatalf("filtered SCIM groups = %#v", groups)
	}
	// An ordinary local mutation cannot overwrite the SCIM-managed membership
	// (SCIM-004, TENANT-003).
	if err := manager.GrantRole(context.Background(), admin, workspace.ID, link.UserID, credbound.RoleAdmin); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("ordinary RBAC overrode SCIM source: %v", err)
	}

	pat := credbound.PAT{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-000000000001"), UserID: link.UserID, Name: "workspace", Prefix: "scimuser0001", Digest: []byte("digest"), WorkspaceID: workspace.ID, CreatedAt: f.now}
	audit := credbound.AuditEvent{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-000000000002"), OccurredAt: f.now, ActorKind: credbound.ActorSystem, Action: "test.pat", ResourceType: "pat", ResourceID: pat.ID.String(), WorkspaceID: workspace.ID, Outcome: credbound.AuditSucceeded}
	if err := f.store.CreatePAT(context.Background(), pat, credbound.Commit{Audit: audit}); err != nil {
		t.Fatal(err)
	}
	if err := manager.DeprovisionSCIMUser(context.Background(), principal, link.ID); err != nil {
		t.Fatal(err)
	}
	membership, _ = f.store.Membership(context.Background(), workspace.ID, link.UserID)
	if membership.Status != credbound.MembershipSuspended {
		t.Fatalf("deprovisioned membership = %#v", membership)
	}
	storedPAT, err := f.store.PATByPrefix(context.Background(), pat.Prefix)
	if err != nil || storedPAT.RevokedAt == nil {
		t.Fatalf("workspace PAT was not revoked: %#v, %v", storedPAT, err)
	}
	global, err := f.store.UserByID(context.Background(), link.UserID)
	if err != nil || global.Disabled {
		t.Fatalf("workspace deprovision disabled global user: %#v, %v", global, err)
	}
	if err := manager.AuthorizePermission(context.Background(), credbound.Authentication{UserID: link.UserID}, workspace.ID, "documents.write"); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("suspended membership authorized: %v", err)
	}
	if err := manager.DeprovisionSCIMUser(context.Background(), principal, link.ID); err != nil {
		t.Fatalf("idempotent deprovision = %v", err)
	}

	// SCIM-006: rotation issues a fresh secret and revocation ends it
	// immediately.
	rotated, err := manager.RotateSCIMCredential(context.Background(), admin, issued.Configuration.ID, nil)
	if err != nil || rotated.Token == issued.Token {
		t.Fatalf("rotated credential = %#v, %v", rotated, err)
	}
	if err := manager.RevokeSCIMCredential(context.Background(), admin, issued.Configuration.ID, rotated.Credential.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AuthenticateSCIM(context.Background(), rotated.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("revoked SCIM credential = %v", err)
	}
	// The administration reads inventory the workspace's configurations and
	// the configuration's credentials — digests omitted, revocation visible.
	configurations := 0
	for configuration, err := range manager.SCIMConfigurations(context.Background(), admin, workspace.ID) {
		if err != nil {
			t.Fatal(err)
		}
		if configuration.ID != issued.Configuration.ID {
			t.Fatalf("inventoried SCIM configuration = %#v", configuration)
		}
		configurations++
	}
	if configurations != 1 {
		t.Fatalf("SCIM configurations = %d, want 1", configurations)
	}
	credentials := map[credbound.UUID]credbound.SCIMCredential{}
	for credential, err := range manager.SCIMCredentials(context.Background(), admin, issued.Configuration.ID) {
		if err != nil {
			t.Fatal(err)
		}
		if credential.Digest != nil {
			t.Fatalf("credential inventory leaked a digest: %#v", credential)
		}
		credentials[credential.ID] = credential
	}
	if len(credentials) != 2 || credentials[rotated.Credential.ID].RevokedAt == nil {
		t.Fatalf("SCIM credential inventory = %#v", credentials)
	}
	for _, err := range manager.SCIMCredentials(context.Background(), credbound.Authentication{UserID: link.UserID}, issued.Configuration.ID) {
		if !errors.Is(err, credbound.ErrForbidden) {
			t.Fatalf("non-admin SCIM credential inventory = %v", err)
		}
	}
	for _, err := range manager.SCIMConfigurations(context.Background(), credbound.Authentication{UserID: link.UserID}, workspace.ID) {
		if !errors.Is(err, credbound.ErrForbidden) {
			t.Fatalf("non-admin SCIM configuration inventory = %v", err)
		}
	}
	for _, err := range manager.SCIMConfigurations(context.Background(), admin, credbound.MustParseUUID("00000000-0000-4000-8000-000000000000")) {
		if !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("invalid workspace id inventory = %v", err)
		}
	}
	if err := manager.DisableSCIMConfiguration(context.Background(), admin, issued.Configuration.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AuthenticateSCIM(context.Background(), rotated.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("disabled configuration token = %v", err)
	}
}

// TestSCIMValidationConflictsAndStateTransitions pins the suspend and
// reactivate transitions of Replace (SCIM-003) together with the fail-closed
// group paths: an unknown member or an ambiguous role mapping is refused
// (SCIM-005).
func TestSCIMValidationConflictsAndStateTransitions(t *testing.T) {
	f := newFixture(t)
	root, workspace := f.bootstrap(t)
	admin := aal2(root.UserID, f.now)
	past := f.now.Add(-time.Minute)
	if _, err := f.manager.CreateSCIMConfiguration(context.Background(), admin, workspace.ID, credbound.CreateSCIMConfigurationInput{CredentialExpiresAt: &past}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("past credential expiration = %v", err)
	}
	if _, err := f.manager.CreateSCIMConfiguration(context.Background(), admin, workspace.ID, credbound.CreateSCIMConfigurationInput{DefaultRole: "missing"}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("unknown default role = %v", err)
	}
	if _, err := f.manager.CreateSCIMConfiguration(context.Background(), admin, workspace.ID, credbound.CreateSCIMConfigurationInput{
		GroupRoleMappings: []credbound.SCIMGroupRoleMapping{{ExternalID: "duplicate", Role: credbound.RoleAdmin}, {ExternalID: "duplicate", Role: credbound.RoleMember}},
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("duplicate group mapping = %v", err)
	}
	issued, err := f.manager.CreateSCIMConfiguration(context.Background(), admin, workspace.ID, credbound.CreateSCIMConfigurationInput{
		GroupRoleMappings: []credbound.SCIMGroupRoleMapping{
			{ExternalID: "admins", Role: credbound.RoleAdmin, Priority: 10},
			{ExternalID: "members", Role: credbound.RoleMember, Priority: 10},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := f.manager.AuthenticateSCIM(context.Background(), issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.UpdateSCIMConfiguration(context.Background(), admin, issued.Configuration.ID, credbound.UpdateSCIMConfigurationInput{DefaultRole: "missing"}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid SCIM configuration update = %v", err)
	}
	if err := f.manager.RevokeSCIMCredential(context.Background(), admin, issued.Configuration.ID, credbound.MustParseUUID("0198b463-0000-7000-8000-000000000099")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing SCIM credential revocation = %v", err)
	}
	if _, err := f.manager.SCIMUser(context.Background(), credbound.SCIMAuthentication{}, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6")); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("forged empty principal = %v", err)
	}
	for name, input := range map[string]credbound.SCIMUserInput{
		"missing email":     {UserName: "missing@example.com", Active: true},
		"long username":     {UserName: strings.Repeat("a", 321), Emails: []credbound.SCIMEmail{{Value: "long@example.com"}}, Active: true},
		"long display name": {UserName: "long-display@example.com", DisplayName: strings.Repeat("a", 256), Emails: []credbound.SCIMEmail{{Value: "long-display@example.com"}}, Active: true},
		"duplicate email":   {UserName: "duplicate@example.com", Emails: []credbound.SCIMEmail{{Value: "duplicate@example.com"}, {Value: "DUPLICATE@example.com"}}, Active: true},
		"primary emails":    {UserName: "primary@example.com", Emails: []credbound.SCIMEmail{{Value: "primary@example.com", Primary: true}, {Value: "other-primary@example.com", Primary: true}}, Active: true},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.manager.ProvisionSCIMUser(context.Background(), principal, input); !errors.Is(err, credbound.ErrInvalidInput) {
				t.Fatalf("invalid SCIM user input = %v", err)
			}
		})
	}
	if _, err := f.manager.ProvisionSCIMUser(context.Background(), principal, credbound.SCIMUserInput{UserName: "00000000-0000-4000-8000-000000000000", Emails: []credbound.SCIMEmail{{Value: "not-an-email"}}, Active: true}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid SCIM user = %v", err)
	}
	link, err := f.manager.ProvisionSCIMUser(context.Background(), principal, credbound.SCIMUserInput{
		ExternalID: "transition", UserName: "transition@example.com", Emails: []credbound.SCIMEmail{{Value: "transition@example.com"}}, Active: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]credbound.SCIMUserInput{
		"username": {ExternalID: "other", UserName: link.UserName, Emails: []credbound.SCIMEmail{{Value: "other@example.com"}}, Active: true},
		"external": {ExternalID: link.ExternalID, UserName: "other@example.com", Emails: []credbound.SCIMEmail{{Value: "other@example.com"}}, Active: true},
		"email":    {ExternalID: "email-conflict", UserName: "email-conflict@example.com", Emails: []credbound.SCIMEmail{{Value: "root@example.com"}}, Active: true},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.manager.ProvisionSCIMUser(context.Background(), principal, input); !errors.Is(err, credbound.ErrConflict) {
				t.Fatalf("duplicate provision = %v", err)
			}
		})
	}
	updated, err := f.manager.ReplaceSCIMUser(context.Background(), principal, link.ID, credbound.SCIMUserInput{
		ExternalID: link.ExternalID, UserName: link.UserName, DisplayName: "Suspended", Emails: link.Emails, Active: false,
	})
	if err != nil || updated.Active {
		t.Fatalf("suspend = %#v, %v", updated, err)
	}
	updated, err = f.manager.ReplaceSCIMUser(context.Background(), principal, link.ID, credbound.SCIMUserInput{
		ExternalID: link.ExternalID, UserName: link.UserName, DisplayName: "Reactivated", Emails: link.Emails, Active: true,
	})
	if err != nil || !updated.Active {
		t.Fatalf("reactivate = %#v, %v", updated, err)
	}
	for _, filter := range []credbound.SCIMFilter{
		{Attribute: "id", Value: link.ID.String()}, {Attribute: "userName", Value: link.UserName},
		{Attribute: "emails.value", Value: link.Emails[0].Value}, {Attribute: "active", Value: "true"},
	} {
		if page := collectSCIMPage(t, f.manager.SCIMUsers(context.Background(), principal, filter, credbound.PageRequest{Limit: 1})); len(page.items) != 1 {
			t.Fatalf("filter %#v = %#v", filter, page)
		}
	}
	if _, err := firstSCIMError(f.manager.SCIMUsers(context.Background(), principal, credbound.SCIMFilter{Attribute: "title", Value: "x"}, credbound.PageRequest{Limit: 50})); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("unsupported user filter = %v", err)
	}
	if _, err := firstSCIMError(f.manager.SCIMUsers(context.Background(), principal, credbound.SCIMFilter{}, credbound.PageRequest{Limit: 101})); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid user page = %v", err)
	}
	if _, err := f.manager.ReplaceSCIMUser(context.Background(), principal, credbound.MustParseUUID("0198b463-0000-7000-8000-000000000098"), credbound.SCIMUserInput{UserName: "missing@example.com", Active: true}); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("replace missing SCIM user = %v", err)
	}
	if err := f.manager.DeprovisionSCIMUser(context.Background(), principal, credbound.MustParseUUID("0198b463-0000-7000-8000-000000000098")); err != nil {
		t.Fatalf("deprovision missing SCIM user = %v", err)
	}
	for name, input := range map[string]credbound.SCIMGroupInput{
		"empty name":     {},
		"invalid member": {DisplayName: "Invalid", MemberIDs: []credbound.UUID{credbound.MustParseUUID("00000000-0000-4000-8000-000000000000")}},
		"unknown member": {DisplayName: "Unknown", MemberIDs: []credbound.UUID{credbound.MustParseUUID("0198b463-0000-7000-8000-000000000097")}},
	} {
		t.Run("group_"+name, func(t *testing.T) {
			if _, err := f.manager.UpsertSCIMGroup(context.Background(), principal, credbound.UUID{}, input); !errors.Is(err, credbound.ErrInvalidInput) {
				t.Fatalf("invalid SCIM group input = %v", err)
			}
		})
	}
	if _, err := firstSCIMError(f.manager.SCIMGroups(context.Background(), principal, credbound.SCIMFilter{Attribute: "active", Value: "true"}, credbound.PageRequest{Limit: 50})); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("unsupported group filter = %v", err)
	}
	if _, err := firstSCIMError(f.manager.SCIMGroups(context.Background(), principal, credbound.SCIMFilter{}, credbound.PageRequest{Limit: 101})); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid group page = %v", err)
	}
	admins, err := f.manager.UpsertSCIMGroup(context.Background(), principal, credbound.UUID{}, credbound.SCIMGroupInput{ExternalID: "admins", DisplayName: "Admins", MemberIDs: []credbound.UUID{link.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.UpsertSCIMGroup(context.Background(), principal, credbound.UUID{}, credbound.SCIMGroupInput{ExternalID: "members", DisplayName: "Members", MemberIDs: []credbound.UUID{link.ID}}); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("ambiguous group roles = %v", err)
	}
	if err := f.manager.DeleteSCIMGroup(context.Background(), principal, admins.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.DeleteSCIMGroup(context.Background(), principal, admins.ID); err != nil {
		t.Fatalf("idempotent group deletion = %v", err)
	}
	if _, err := f.manager.RotateSCIMCredential(context.Background(), admin, issued.Configuration.ID, &past); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("past rotated credential = %v", err)
	}
	for _, token := range []string{"", "cbs_bad", "cbs_zzzzzzzzzzzz_" + strings.Repeat("a", 43), "cbs_000000000000_short"} {
		if _, err := f.manager.AuthenticateSCIM(context.Background(), token); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("malformed token %q = %v", token, err)
		}
	}
	withoutSCIM, err := credbound.New(credbound.Config{
		Store: coreStoreOnly{Store: f.store}, Passwords: f.passwords, TOTP: fakeTOTP{}, Passkeys: f.passkeys,
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return f.now }, Random: &counterReader{next: 0x77},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutSCIM.CreateSCIMConfiguration(context.Background(), admin, workspace.ID, credbound.CreateSCIMConfigurationInput{}); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("unsupported SCIM configuration = %v", err)
	}
	if _, err := withoutSCIM.AuthenticateSCIM(context.Background(), issued.Token); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("unsupported SCIM authentication = %v", err)
	}
	if _, err := withoutSCIM.RotateSCIMCredential(context.Background(), admin, issued.Configuration.ID, nil); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("unsupported SCIM rotation = %v", err)
	}
	if _, err := withoutSCIM.UpdateSCIMConfiguration(context.Background(), admin, issued.Configuration.ID, credbound.UpdateSCIMConfigurationInput{}); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("unsupported SCIM update = %v", err)
	}
	if err := withoutSCIM.RevokeSCIMCredential(context.Background(), admin, issued.Configuration.ID, issued.Credential.ID); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("unsupported SCIM credential revocation = %v", err)
	}
	if err := withoutSCIM.DisableSCIMConfiguration(context.Background(), admin, issued.Configuration.ID); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("unsupported SCIM disable = %v", err)
	}
	if _, err := firstSCIMError(withoutSCIM.SCIMUsers(context.Background(), principal, credbound.SCIMFilter{}, credbound.PageRequest{Limit: 50})); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("unsupported SCIM list = %v", err)
	}
}

type scimPage[T any] struct {
	items []T
	end   *credbound.PageEnd
}

func collectSCIMPage[T any](t *testing.T, sequence func(func(credbound.PageEvent[T], error) bool)) scimPage[T] {
	t.Helper()
	var result scimPage[T]
	for event, err := range sequence {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			result.items = append(result.items, *event.Data)
		}
		if event.End != nil {
			result.end = event.End
		}
	}
	return result
}

func firstSCIMError[T any](sequence func(func(credbound.PageEvent[T], error) bool)) (credbound.PageEvent[T], error) {
	for event, err := range sequence {
		return event, err
	}
	return credbound.PageEvent[T]{}, nil
}
