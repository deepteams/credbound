package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/deepteams/credbound"
)

func TestSCIMConflictsNotFoundAndPagination(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	configuration := credbound.SCIMConfiguration{ID: f.id(), WorkspaceID: f.workspace.ID, Enabled: true, DefaultRole: credbound.RoleMember, CreatedAt: f.now, UpdatedAt: f.now}
	credential := credbound.SCIMCredential{ID: f.id(), ConfigurationID: configuration.ID, Prefix: "credential01", Digest: []byte("digest"), CreatedAt: f.now}
	if err := f.store.CreateSCIMConfiguration(ctx, configuration, credential, f.event("scim.configuration")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateSCIMConfiguration(ctx, configuration, credential, f.event("scim.configuration.duplicate")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate configuration = %v", err)
	}
	if _, err := f.store.SCIMConfiguration(ctx, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing configuration = %v", err)
	}
	if _, _, err := f.store.SCIMConfigurationByCredentialPrefix(ctx, "missing"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing credential prefix = %v", err)
	}
	if err := f.store.SaveSCIMCredential(ctx, credential, f.event("scim.credential.duplicate_id")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate credential id = %v", err)
	}
	missingConfiguration := configuration
	missingConfiguration.ID, missingConfiguration.WorkspaceID = f.id(), credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6")
	missingCredential := credential
	missingCredential.ID, missingCredential.ConfigurationID, missingCredential.Prefix = f.id(), missingConfiguration.ID, "credential02"
	if err := f.store.CreateSCIMConfiguration(ctx, missingConfiguration, missingCredential, f.event("scim.configuration.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing workspace = %v", err)
	}
	if err := f.store.SaveSCIMCredential(ctx, missingCredential, f.event("scim.credential.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing configuration credential = %v", err)
	}
	duplicatePrefix := missingCredential
	duplicatePrefix.ConfigurationID, duplicatePrefix.Prefix = configuration.ID, credential.Prefix
	if err := f.store.SaveSCIMCredential(ctx, duplicatePrefix, f.event("scim.credential.duplicate")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate credential prefix = %v", err)
	}
	if err := f.store.TouchSCIMCredential(ctx, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6"), f.now, f.event("scim.credential.touch")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing credential touch = %v", err)
	}
	if err := f.store.DisableSCIMConfiguration(ctx, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6"), f.now, f.event("scim.configuration.disable")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing configuration disable = %v", err)
	}
	missingUpdate := configuration
	missingUpdate.ID = credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6")
	if err := f.store.UpdateSCIMConfiguration(ctx, missingUpdate, nil, f.event("scim.configuration.update_missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing configuration update = %v", err)
	}
	if err := f.store.RevokeSCIMCredential(ctx, configuration.ID, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6"), f.now, f.event("scim.credential.revoke_missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing credential revoke = %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := f.store.UpdateSCIMConfiguration(cancelled, configuration, nil, f.event("scim.configuration.update_cancelled")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled configuration update = %v", err)
	}
	if err := f.store.RevokeSCIMCredential(cancelled, configuration.ID, credential.ID, f.now, f.event("scim.credential.revoke_cancelled")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled credential revoke = %v", err)
	}

	makeUser := func(emailAddress, externalID string) (credbound.User, credbound.EmailAddress, credbound.Membership, credbound.SCIMUser) {
		user := credbound.User{ID: f.id(), Email: emailAddress, DisplayName: emailAddress, CreatedAt: f.now, UpdatedAt: f.now}
		email := f.email(user)
		membership := credbound.Membership{WorkspaceID: f.workspace.ID, UserID: user.ID, Role: credbound.RoleMember, Status: credbound.MembershipActive, ProvisioningSource: configuration.ID.String(), CreatedAt: f.now, UpdatedAt: f.now}
		link := credbound.SCIMUser{ID: f.id(), ConfigurationID: configuration.ID, UserID: user.ID, ExternalID: externalID, UserName: emailAddress, Active: true, CreatedAt: f.now, UpdatedAt: f.now}
		return user, email, membership, link
	}
	user1, email1, membership1, link1 := makeUser("one@example.com", "one")
	if err := f.store.CreateSCIMUser(ctx, user1, email1, membership1, link1, f.event("scim.user.one")); err != nil {
		t.Fatal(err)
	}
	missingAdoption := link1
	missingAdoption.ID, missingAdoption.UserID = f.id(), f.id()
	if err := f.store.AdoptSCIMUser(ctx, membership1, missingAdoption, f.event("scim.user.adopt_missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing SCIM adoption user = %v", err)
	}
	wrongConfiguration := link1
	wrongConfiguration.ID, wrongConfiguration.ConfigurationID = f.id(), credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6")
	if err := f.store.CreateSCIMUser(ctx, user1, email1, membership1, wrongConfiguration, f.event("scim.user.configuration_missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing SCIM user configuration = %v", err)
	}
	if err := f.store.CreateSCIMUser(ctx, user1, email1, membership1, link1, f.event("scim.user.duplicate")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate SCIM user = %v", err)
	}
	user2, email2, membership2, link2 := makeUser("two@example.com", "two")
	if err := f.store.CreateSCIMUser(ctx, user2, email2, membership2, link2, f.event("scim.user.two")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.SCIMUser(ctx, configuration.ID, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing SCIM user = %v", err)
	}
	if _, err := f.store.SCIMUserByExternalID(ctx, configuration.ID, "missing"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing external SCIM user = %v", err)
	}
	if _, err := f.store.SCIMUserByUserName(ctx, configuration.ID, "missing"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing username SCIM user = %v", err)
	}
	conflicting := link2
	conflicting.UserName = link1.UserName
	if err := f.store.UpdateSCIMUser(ctx, conflicting, membership2, false, f.event("scim.user.conflict")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("conflicting SCIM update = %v", err)
	}
	missingLink := link2
	missingLink.ID = credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6")
	if err := f.store.UpdateSCIMUser(ctx, missingLink, membership2, false, f.event("scim.user.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing SCIM update = %v", err)
	}
	first := collectMemoryPage(t, f.store.SCIMUsers(ctx, configuration.ID, credbound.SCIMFilter{}, credbound.PageRequest{Limit: 1}))
	if len(first.items) != 1 || first.end == nil || !first.end.HasMore || first.end.NextCursor == "" {
		t.Fatalf("first SCIM page = %#v", first)
	}
	second := collectMemoryPage(t, f.store.SCIMUsers(ctx, configuration.ID, credbound.SCIMFilter{}, credbound.PageRequest{Limit: 1, Cursor: first.end.NextCursor}))
	if len(second.items) != 1 || second.end == nil || second.end.HasMore {
		t.Fatalf("second SCIM page = %#v", second)
	}

	if err := f.store.UpsertSCIMGroup(ctx, credbound.SCIMGroup{ID: f.id(), ConfigurationID: credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6")}, nil, f.event("scim.group.missing_configuration")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing group configuration = %v", err)
	}
	group1 := credbound.SCIMGroup{ID: f.id(), ConfigurationID: configuration.ID, ExternalID: "group", DisplayName: "Group", CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.UpsertSCIMGroup(ctx, group1, nil, f.event("scim.group.one")); err != nil {
		t.Fatal(err)
	}
	group2 := group1
	group2.ID = f.id()
	if err := f.store.UpsertSCIMGroup(ctx, group2, nil, f.event("scim.group.conflict")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate group external id = %v", err)
	}
	if _, err := f.store.SCIMGroup(ctx, configuration.ID, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing SCIM group = %v", err)
	}
	if _, err := f.store.SCIMGroupByExternalID(ctx, configuration.ID, "missing"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing external group = %v", err)
	}
	if err := f.store.DeleteSCIMGroup(ctx, group2, nil, f.event("scim.group.delete_missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing group delete = %v", err)
	}
}

type memoryPage[T any] struct {
	items []T
	end   *credbound.PageEnd
}

func collectMemoryPage[T any](t *testing.T, sequence func(func(credbound.PageEvent[T], error) bool)) memoryPage[T] {
	t.Helper()
	var result memoryPage[T]
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
