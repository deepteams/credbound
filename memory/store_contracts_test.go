package memory

import (
	"context"
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
