package memory

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

// TestRecordAuthenticationContract pins the unguarded finalization used by
// the non-password factors: it stamps the user's last-seen time, clears the
// login throttle in the same commit, and reports ErrNotFound for an unknown
// user.
func TestRecordAuthenticationContract(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	if _, err := f.store.RecordLoginFailure(ctx, f.user.ID, f.now, 5, f.now.Add(time.Hour), f.event("auth.failure")); err != nil {
		t.Fatal(err)
	}
	seen := f.now.Add(time.Minute)
	if err := f.store.RecordAuthentication(ctx, f.user.ID, seen, f.event("auth.totp")); err != nil {
		t.Fatal(err)
	}
	user, err := f.store.UserByID(ctx, f.user.ID)
	if err != nil || user.LastSeenAt == nil || !user.LastSeenAt.Equal(seen) {
		t.Fatalf("last seen = %#v, %v", user, err)
	}
	if _, err := f.store.LoginThrottleByUserID(ctx, f.user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("throttle survived the completed sign-in: %v", err)
	}
	if err := f.store.RecordAuthentication(ctx, f.id(), seen, f.event("auth.totp.unknown")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown user finalization error = %v", err)
	}
}

// TestAnonymizeUserRefusesToOrphanWorkspace pins the workspace guard: a user
// who is the only enabled active admin of a workspace cannot be anonymized,
// since disabling them would leave the workspace without administration.
func TestAnonymizeUserRefusesToOrphanWorkspace(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	owner := credbound.User{ID: f.id(), Email: "owner@example.com", DisplayName: "Owner", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: f.workspace.ID, UserID: owner.ID, Role: credbound.RoleMember, Status: credbound.MembershipActive, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateUser(ctx, owner, f.email(owner), credbound.PasswordCredential{UserID: owner.ID, Hash: "hash", UpdatedAt: f.now}, membership, f.event("user.create")); err != nil {
		t.Fatal(err)
	}
	solo := credbound.Workspace{ID: f.id(), Name: "Solo", CreatedAt: f.now, UpdatedAt: f.now}
	soloMembership := credbound.Membership{WorkspaceID: solo.ID, UserID: owner.ID, Role: credbound.RoleAdmin, Status: credbound.MembershipActive, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateWorkspace(ctx, solo, soloMembership, f.event("workspace.create")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.AnonymizeUser(ctx, owner.ID, f.now, f.event("user.anonymize.orphan")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("orphaning anonymize error = %v", err)
	}
	untouched, err := f.store.UserByID(ctx, owner.ID)
	if err != nil || untouched.Disabled || untouched.DisplayName == "" {
		t.Fatalf("refused anonymize mutated the user: %#v, %v", untouched, err)
	}
	// With a second enabled admin in place the same anonymization proceeds.
	backup := credbound.User{ID: f.id(), Email: "backup@example.com", DisplayName: "Backup", CreatedAt: f.now, UpdatedAt: f.now}
	backupMembership := credbound.Membership{WorkspaceID: solo.ID, UserID: backup.ID, Role: credbound.RoleAdmin, Status: credbound.MembershipActive, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateUser(ctx, backup, f.email(backup), credbound.PasswordCredential{UserID: backup.ID, Hash: "hash", UpdatedAt: f.now}, backupMembership, f.event("user.create.backup")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.AnonymizeUser(ctx, owner.ID, f.now, f.event("user.anonymize")); err != nil {
		t.Fatal(err)
	}
	anonymized, err := f.store.UserByID(ctx, owner.ID)
	if err != nil || !anonymized.Disabled || anonymized.DisplayName != "" {
		t.Fatalf("anonymize did not scrub the user: %#v, %v", anonymized, err)
	}
}

// TestAnonymizeUserScrubsSCIMAndInvitations pins the privacy reach of the
// erasure primitive beyond the core account: the personal attributes of the
// user's SCIM profiles are scrubbed and the profile deprovisioned, and the
// address on invitations the user accepted is tombstoned, while another
// user's records stay untouched. The PrivacyStore reads expose both record
// families for the DSAR export.
func TestAnonymizeUserScrubsSCIMAndInvitations(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	configuration := credbound.SCIMConfiguration{ID: f.id(), WorkspaceID: f.workspace.ID, Enabled: true, DefaultRole: credbound.RoleMember, CreatedAt: f.now, UpdatedAt: f.now}
	credential := credbound.SCIMCredential{ID: f.id(), ConfigurationID: configuration.ID, Prefix: "credential01", Digest: []byte("digest"), CreatedAt: f.now}
	if err := f.store.CreateSCIMConfiguration(ctx, configuration, credential, f.event("scim.configuration")); err != nil {
		t.Fatal(err)
	}
	user := credbound.User{ID: f.id(), Email: "worker@example.com", DisplayName: "Worker", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: f.workspace.ID, UserID: user.ID, Role: credbound.RoleMember, Status: credbound.MembershipActive, ProvisioningSource: configuration.ID, CreatedAt: f.now, UpdatedAt: f.now}
	link := credbound.SCIMUser{
		ID: f.id(), ConfigurationID: configuration.ID, UserID: user.ID, ExternalID: "worker", UserName: "worker@example.com", DisplayName: "Worker",
		Emails:     []credbound.SCIMEmail{{Value: "worker@example.com", Primary: true}},
		Attributes: map[string]json.RawMessage{"title": json.RawMessage(`"Engineer"`)}, Active: true, CreatedAt: f.now, UpdatedAt: f.now,
	}
	if err := f.store.CreateSCIMUser(ctx, user, f.email(user), membership, link, f.event("scim.user.create")); err != nil {
		t.Fatal(err)
	}
	invitation := credbound.WorkspaceInvitation{ID: f.id(), WorkspaceID: f.workspace.ID, Email: "worker@example.com", Role: credbound.RoleMember, InvitedBy: f.user.ID, Digest: []byte("digest"), CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	if err := f.store.CreateWorkspaceInvitation(ctx, invitation, f.event("invite.create")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.AcceptWorkspaceInvitation(ctx, invitation.ID, user.ID, f.now, membership, f.event("invite.accept")); err != nil {
		t.Fatal(err)
	}
	pending := credbound.WorkspaceInvitation{ID: f.id(), WorkspaceID: f.workspace.ID, Email: "other@example.com", Role: credbound.RoleMember, InvitedBy: f.user.ID, Digest: []byte("digest"), CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	if err := f.store.CreateWorkspaceInvitation(ctx, pending, f.event("invite.other")); err != nil {
		t.Fatal(err)
	}

	if err := f.store.AnonymizeUser(ctx, user.ID, f.now, f.event("user.anonymize")); err != nil {
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
