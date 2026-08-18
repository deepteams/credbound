package sqlite_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

// TestSCIMStoreContractAndAtomicDeprovision pins SCIM-008: every
// provisioning mutation commits atomically with its transactional hook and
// its service audit — a rejected hook rolls the whole configuration back,
// and deprovisioning revokes the workspace PAT in the same commit.
func TestSCIMStoreContractAndAtomicDeprovision(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	root := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	workspace := credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
	rootMembership := credbound.Membership{WorkspaceID: workspace.ID, UserID: root.ID, Role: credbound.RoleAdmin, CreatedAt: f.now, UpdatedAt: f.now}
	admin := credbound.InstanceAdministrator{UserID: root.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.Bootstrap(ctx, root, f.email(root), credbound.PasswordCredential{UserID: root.ID, Hash: "hash", UpdatedAt: f.now}, workspace, rootMembership, admin, f.event(root.ID, "bootstrap", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	configuration := credbound.SCIMConfiguration{
		ID: f.id(), WorkspaceID: workspace.ID, Enabled: true, DefaultRole: credbound.RoleMember, TrustDirectoryEmails: true,
		GroupRoleMappings: []credbound.SCIMGroupRoleMapping{{ExternalID: "editors", Role: "editor", Priority: 10}}, CreatedAt: f.now, UpdatedAt: f.now,
	}
	credential := credbound.SCIMCredential{ID: f.id(), ConfigurationID: configuration.ID, Prefix: "abcdef012345", Digest: []byte("digest"), CreatedAt: f.now}
	configurationCommit := f.event(root.ID, "scim.configuration.create", configuration.ID, workspace.ID)
	configurationCommit.Audit.ActorKind = credbound.ActorUser
	if err := f.store.CreateSCIMConfiguration(ctx, configuration, credential, configurationCommit); err != nil {
		t.Fatal(err)
	}
	storedConfiguration, storedCredential, err := f.store.SCIMConfigurationByCredentialPrefix(ctx, credential.Prefix)
	if err != nil || storedConfiguration.ID != configuration.ID || len(storedConfiguration.GroupRoleMappings) != 1 || storedCredential.ID != credential.ID {
		t.Fatalf("SCIM configuration = %#v %#v, %v", storedConfiguration, storedCredential, err)
	}
	if direct, err := f.store.SCIMConfiguration(ctx, configuration.ID); err != nil || direct.ID != configuration.ID {
		t.Fatalf("direct SCIM configuration = %#v, %v", direct, err)
	}
	configuration.TrustDirectoryEmails = false
	configuration.UpdatedAt = configuration.UpdatedAt.Add(time.Second)
	if err := f.store.UpdateSCIMConfiguration(ctx, configuration, nil, f.event(root.ID, "scim.configuration.update", configuration.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if updated, err := f.store.SCIMConfiguration(ctx, configuration.ID); err != nil || updated.TrustDirectoryEmails || !updated.UpdatedAt.Equal(configuration.UpdatedAt) {
		t.Fatalf("updated SCIM configuration = %#v, %v", updated, err)
	}
	rotated := credbound.SCIMCredential{ID: f.id(), ConfigurationID: configuration.ID, Prefix: "abcdef012346", Digest: []byte("rotated"), CreatedAt: f.now}
	if err := f.store.SaveSCIMCredential(ctx, rotated, f.event(root.ID, "scim.credential.rotate", rotated.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.TouchSCIMCredential(ctx, rotated.ID, f.now, f.event(rotated.ID, "auth.scim", rotated.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RevokeSCIMCredential(ctx, configuration.ID, rotated.ID, f.now, f.event(root.ID, "scim.credential.revoke", rotated.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if _, revoked, err := f.store.SCIMConfigurationByCredentialPrefix(ctx, rotated.Prefix); err != nil || revoked.RevokedAt == nil {
		t.Fatalf("revoked SCIM credential = %#v, %v", revoked, err)
	}
	adoptedMembership := rootMembership
	adoptedMembership.Status, adoptedMembership.ProvisioningSource, adoptedMembership.UpdatedAt = credbound.MembershipActive, configuration.ID, f.now
	adopted := credbound.SCIMUser{ID: f.id(), ConfigurationID: configuration.ID, UserID: root.ID, ExternalID: "adopted-root", UserName: "root@example.com", DisplayName: "Root", Active: true, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.AdoptSCIMUser(ctx, adoptedMembership, adopted, f.event(root.ID, "scim.user.adopt", adopted.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	configuration.DefaultRole = credbound.RoleAdmin
	adoptedMembership.Role = credbound.RoleAdmin
	if err := f.store.UpdateSCIMConfiguration(ctx, configuration, []credbound.Membership{adoptedMembership}, f.event(root.ID, "scim.configuration.remap", configuration.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if remapped, err := f.store.Membership(ctx, workspace.ID, root.ID); err != nil || remapped.Role != credbound.RoleAdmin {
		t.Fatalf("remapped SCIM membership = %#v, %v", remapped, err)
	}

	user := credbound.User{ID: f.id(), Email: "scim@example.com", DisplayName: "SCIM", CreatedAt: f.now, UpdatedAt: f.now}
	email := f.email(user)
	membership := credbound.Membership{
		WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleMember, Status: credbound.MembershipActive,
		ProvisioningSource: configuration.ID, CreatedAt: f.now, UpdatedAt: f.now,
	}
	link := credbound.SCIMUser{
		ID: f.id(), ConfigurationID: configuration.ID, UserID: user.ID, ExternalID: "external-user", UserName: "scim@example.com", DisplayName: "SCIM",
		Schemas: []string{"urn:example:profile"}, Emails: []credbound.SCIMEmail{{Value: "scim@example.com", Primary: true}},
		Attributes: map[string]json.RawMessage{"title": json.RawMessage(`"Engineer"`)}, Active: true, CreatedAt: f.now, UpdatedAt: f.now,
	}
	userCommit := f.event(credential.ID, "scim.user.provision", link.ID, workspace.ID)
	userCommit.Audit.ActorKind = credbound.ActorService
	if err := f.store.CreateSCIMUser(ctx, user, email, membership, link, userCommit); err != nil {
		t.Fatal(err)
	}
	for name, lookup := range map[string]func() (credbound.SCIMUser, error){
		"id": func() (credbound.SCIMUser, error) { return f.store.SCIMUser(ctx, configuration.ID, link.ID) },
		"external": func() (credbound.SCIMUser, error) {
			return f.store.SCIMUserByExternalID(ctx, configuration.ID, link.ExternalID)
		},
		"username": func() (credbound.SCIMUser, error) {
			return f.store.SCIMUserByUserName(ctx, configuration.ID, strings.ToUpper(link.UserName))
		},
	} {
		value, err := lookup()
		if err != nil || value.ID != link.ID {
			t.Fatalf("SCIM user lookup %s = %#v, %v", name, value, err)
		}
	}
	if _, err := f.store.PasswordByUserID(ctx, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("SCIM password = %v", err)
	}
	storedMembership, err := f.store.Membership(ctx, workspace.ID, user.ID)
	if err != nil || storedMembership.Status != credbound.MembershipActive || storedMembership.ProvisioningSource != configuration.ID {
		t.Fatalf("SCIM membership = %#v, %v", storedMembership, err)
	}
	users := collectStorePage(t, f.store.SCIMUsers(ctx, configuration.ID, credbound.SCIMFilter{Attribute: "emails.value", Value: user.Email}, credbound.PageRequest{Limit: 50}))
	if len(users.items) != 1 || users.items[0].ID != link.ID || string(users.items[0].Attributes["title"]) != `"Engineer"` || len(users.items[0].Schemas) != 1 {
		t.Fatalf("SCIM users = %#v", users)
	}
	for _, filter := range []credbound.SCIMFilter{
		{}, {Attribute: "id", Value: link.ID}, {Attribute: "externalId", Value: link.ExternalID},
		{Attribute: "userName", Value: strings.ToUpper(link.UserName)}, {Attribute: "active", Value: "true"},
	} {
		if page := collectStorePage(t, f.store.SCIMUsers(ctx, configuration.ID, filter, credbound.PageRequest{Limit: 50})); len(page.items) == 0 {
			t.Fatalf("SCIM filter %#v returned no users", filter)
		}
	}
	for _, filter := range []credbound.SCIMFilter{{Attribute: "active", Value: "maybe"}, {Attribute: "unknown", Value: "x"}} {
		if err := firstStoreError(f.store.SCIMUsers(ctx, configuration.ID, filter, credbound.PageRequest{Limit: 50})); !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("invalid SCIM user filter %#v = %v", filter, err)
		}
	}
	if err := firstStoreError(f.store.SCIMUsers(ctx, configuration.ID, credbound.SCIMFilter{}, credbound.PageRequest{Cursor: "%%%", Limit: 50})); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid SCIM user cursor = %v", err)
	}

	group := credbound.SCIMGroup{
		ID: f.id(), ConfigurationID: configuration.ID, ExternalID: "editors", DisplayName: "Editors", MemberIDs: []string{link.ID}, CreatedAt: f.now, UpdatedAt: f.now,
	}
	membership.Role = "editor"
	if err := f.store.UpsertSCIMGroup(ctx, group, []credbound.Membership{membership}, f.event(credential.ID, "scim.group.upsert", group.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	groups := collectStorePage(t, f.store.SCIMGroups(ctx, configuration.ID, credbound.SCIMFilter{Attribute: "displayName", Value: "Editors"}, credbound.PageRequest{Limit: 50}))
	if len(groups.items) != 1 || len(groups.items[0].MemberIDs) != 1 {
		t.Fatalf("SCIM groups = %#v", groups)
	}
	for _, filter := range []credbound.SCIMFilter{{}, {Attribute: "id", Value: group.ID}, {Attribute: "externalId", Value: group.ExternalID}} {
		if page := collectStorePage(t, f.store.SCIMGroups(ctx, configuration.ID, filter, credbound.PageRequest{Limit: 50})); len(page.items) != 1 {
			t.Fatalf("SCIM group filter %#v = %#v", filter, page)
		}
	}
	if err := firstStoreError(f.store.SCIMGroups(ctx, configuration.ID, credbound.SCIMFilter{Attribute: "unknown", Value: "x"}, credbound.PageRequest{Limit: 50})); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid SCIM group filter = %v", err)
	}
	if err := firstStoreError(f.store.SCIMGroups(ctx, configuration.ID, credbound.SCIMFilter{}, credbound.PageRequest{Cursor: "%%%", Limit: 50})); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid SCIM group cursor = %v", err)
	}
	if direct, err := f.store.SCIMGroup(ctx, configuration.ID, group.ID); err != nil || direct.ID != group.ID {
		t.Fatalf("direct SCIM group = %#v, %v", direct, err)
	}
	if byExternal, err := f.store.SCIMGroupByExternalID(ctx, configuration.ID, group.ExternalID); err != nil || byExternal.ID != group.ID {
		t.Fatalf("external SCIM group = %#v, %v", byExternal, err)
	}

	pat := credbound.PAT{ID: f.id(), UserID: user.ID, Name: "workspace", Prefix: "patprefix0001", Digest: []byte("digest"), WorkspaceID: workspace.ID, CreatedAt: f.now}
	if err := f.store.CreatePAT(ctx, pat, f.event(user.ID, "pat.create", pat.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	link.Active = false
	link.UpdatedAt = f.now
	membership.Status = credbound.MembershipSuspended
	if err := f.store.UpdateSCIMUser(ctx, link, membership, true, f.event(credential.ID, "scim.user.deprovision", link.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	storedPAT, err := f.store.PATByPrefix(ctx, pat.Prefix)
	if err != nil || storedPAT.RevokedAt == nil {
		t.Fatalf("revoked PAT = %#v, %v", storedPAT, err)
	}

	rejected := configuration
	rejected.ID = f.id()
	rejectedCredential := credential
	rejectedCredential.ID, rejectedCredential.ConfigurationID, rejectedCredential.Prefix = f.id(), rejected.ID, "abcdef012346"
	commit := f.event(root.ID, "scim.configuration.reject", rejected.ID, workspace.ID)
	commit.Transactional = func(context.Context, credbound.Tx) error { return errors.New("host rejected") }
	if err := f.store.CreateSCIMConfiguration(ctx, rejected, rejectedCredential, commit); err == nil {
		t.Fatal("rejected SCIM configuration committed")
	}
	if _, err := f.store.SCIMConfiguration(ctx, rejected.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("rejected SCIM configuration = %v", err)
	}

	audits := collectStorePage(t, f.store.AuditEvents(ctx, workspace.ID, credbound.PageRequest{Limit: 50}))
	serviceActorSeen := false
	for _, event := range audits.items {
		if event.Action == "scim.user.provision" && event.ActorKind == credbound.ActorService {
			serviceActorSeen = true
		}
	}
	if !serviceActorSeen {
		t.Fatalf("service actor missing from audit: %#v", audits.items)
	}
	group.DeletedAt = &f.now
	if err := f.store.DeleteSCIMGroup(ctx, group, []credbound.Membership{membership}, f.event(credential.ID, "scim.group.delete", group.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.SCIMGroup(ctx, configuration.ID, group.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("deleted SCIM group = %v", err)
	}
	if err := f.store.DisableSCIMConfiguration(ctx, configuration.ID, f.now, f.event(root.ID, "scim.configuration.disable", configuration.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if disabled, err := f.store.SCIMConfiguration(ctx, configuration.ID); err != nil || disabled.Enabled {
		t.Fatalf("disabled SCIM configuration = %#v, %v", disabled, err)
	}
}

type storePage[T any] struct {
	items []T
	end   *credbound.PageEnd
}

func collectStorePage[T any](t *testing.T, sequence func(func(credbound.PageEvent[T], error) bool)) storePage[T] {
	t.Helper()
	var result storePage[T]
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

func firstStoreError[T any](sequence func(func(credbound.PageEvent[T], error) bool)) error {
	for _, err := range sequence {
		return err
	}
	return nil
}

// TestAnonymizeUserScrubsSCIMAndInvitations pins the privacy reach of the
// erasure primitive beyond the core account: the personal attributes of the
// user's SCIM profiles are scrubbed and the profile deprovisioned, and the
// address on invitations the user accepted is tombstoned, while another
// user's records stay untouched. The PrivacyStore reads expose both record
// families for the DSAR export.
func TestAnonymizeUserScrubsSCIMAndInvitations(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	root := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	workspace := credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
	rootMembership := credbound.Membership{WorkspaceID: workspace.ID, UserID: root.ID, Role: credbound.RoleAdmin, Status: credbound.MembershipActive, CreatedAt: f.now, UpdatedAt: f.now}
	admin := credbound.InstanceAdministrator{UserID: root.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.Bootstrap(ctx, root, f.email(root), credbound.PasswordCredential{UserID: root.ID, Hash: "hash", UpdatedAt: f.now}, workspace, rootMembership, admin, f.event(root.ID, "bootstrap", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	configuration := credbound.SCIMConfiguration{ID: f.id(), WorkspaceID: workspace.ID, Enabled: true, DefaultRole: credbound.RoleMember, CreatedAt: f.now, UpdatedAt: f.now}
	credential := credbound.SCIMCredential{ID: f.id(), ConfigurationID: configuration.ID, Prefix: "abcdef012345", Digest: []byte("digest"), CreatedAt: f.now}
	if err := f.store.CreateSCIMConfiguration(ctx, configuration, credential, f.event(root.ID, "scim.configuration.create", configuration.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	user := credbound.User{ID: f.id(), Email: "worker@example.com", DisplayName: "Worker", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleMember, Status: credbound.MembershipActive, ProvisioningSource: configuration.ID, CreatedAt: f.now, UpdatedAt: f.now}
	link := credbound.SCIMUser{
		ID: f.id(), ConfigurationID: configuration.ID, UserID: user.ID, ExternalID: "worker", UserName: "worker@example.com", DisplayName: "Worker",
		Emails:     []credbound.SCIMEmail{{Value: "worker@example.com", Primary: true}},
		Attributes: map[string]json.RawMessage{"title": json.RawMessage(`"Engineer"`)}, Active: true, CreatedAt: f.now, UpdatedAt: f.now,
	}
	if err := f.store.CreateSCIMUser(ctx, user, f.email(user), membership, link, f.event(credential.ID, "scim.user.provision", link.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	invitation := credbound.WorkspaceInvitation{ID: f.id(), WorkspaceID: workspace.ID, Email: "worker@example.com", Role: credbound.RoleMember, InvitedBy: root.ID, Digest: []byte("digest"), CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	if err := f.store.CreateWorkspaceInvitation(ctx, invitation, f.event(root.ID, "invite.create", invitation.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.AcceptWorkspaceInvitation(ctx, invitation.ID, user.ID, f.now, membership, f.event(user.ID, "invite.accept", invitation.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	pending := credbound.WorkspaceInvitation{ID: f.id(), WorkspaceID: workspace.ID, Email: "other@example.com", Role: credbound.RoleMember, InvitedBy: root.ID, Digest: []byte("digest"), CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	if err := f.store.CreateWorkspaceInvitation(ctx, pending, f.event(root.ID, "invite.other", pending.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}

	if err := f.store.AnonymizeUser(ctx, user.ID, f.now, f.event(root.ID, "user.anonymize", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	scrubbed, err := f.store.SCIMUser(ctx, configuration.ID, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	if scrubbed.UserName != "anonymized-"+link.ID || scrubbed.DisplayName != "" || scrubbed.ExternalID != "" ||
		len(scrubbed.Emails) != 0 || len(scrubbed.Attributes) != 0 || scrubbed.Active || scrubbed.DeprovisionedAt == nil {
		t.Fatalf("SCIM profile kept personal data: %#v", scrubbed)
	}
	links := 0
	for value, err := range f.store.SCIMUsersByUser(ctx, user.ID) {
		if err != nil {
			t.Fatal(err)
		}
		if value.ID != link.ID {
			t.Fatalf("unexpected SCIM link: %#v", value)
		}
		links++
	}
	if links != 1 {
		t.Fatalf("SCIM links = %d, want 1", links)
	}
	accepted := 0
	for value, err := range f.store.AcceptedWorkspaceInvitations(ctx, user.ID) {
		if err != nil {
			t.Fatal(err)
		}
		if value.ID != invitation.ID || value.Email != "anonymized-"+invitation.ID+"@invalid" {
			t.Fatalf("accepted invitation kept its address: %#v", value)
		}
		accepted++
	}
	if accepted != 1 {
		t.Fatalf("accepted invitations = %d, want 1", accepted)
	}
	untouched, err := f.store.WorkspaceInvitationByID(ctx, pending.ID)
	if err != nil || untouched.Email != "other@example.com" {
		t.Fatalf("unrelated invitation mutated: %#v, %v", untouched, err)
	}
}
