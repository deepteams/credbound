package credbound_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

func TestIdentityWorkspaceAndMembershipLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	authn, original := f.bootstrap(t)
	root := aal2(authn.UserID, f.now)

	workspace, err := f.manager.CreateWorkspace(ctx, root, credbound.CreateWorkspaceInput{Name: " Product "})
	if err != nil || workspace.Name != "Product" || !uuidV7.MatchString(workspace.ID) {
		t.Fatalf("workspace = %#v, %v", workspace, err)
	}
	if err := f.manager.RemoveMembership(ctx, root, workspace.ID, root.UserID); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("last workspace admin removal = %v", err)
	}
	workspace, err = f.manager.UpdateWorkspace(ctx, root, workspace.ID, credbound.UpdateWorkspaceInput{Name: "Platform"})
	if err != nil || workspace.Name != "Platform" {
		t.Fatalf("updated workspace = %#v, %v", workspace, err)
	}

	user, err := f.manager.CreateUser(ctx, root, original.ID, credbound.CreateUserInput{
		Email: "developer@example.com", DisplayName: "Developer", Password: "correct horse battery", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	membership, err := f.manager.AddMembership(ctx, root, workspace.ID, user.ID, credbound.RoleMember)
	if err != nil || membership.Status != credbound.MembershipActive {
		t.Fatalf("membership = %#v, %v", membership, err)
	}
	membership, err = f.manager.SetMembershipStatus(ctx, root, workspace.ID, user.ID, credbound.MembershipSuspended)
	if err != nil || membership.Status != credbound.MembershipSuspended {
		t.Fatalf("suspended membership = %#v, %v", membership, err)
	}
	if _, err := f.manager.SetMembershipStatus(ctx, root, workspace.ID, user.ID, credbound.MembershipActive); err != nil {
		t.Fatal(err)
	}
	if got := collectLifecyclePage(t, f.manager.Memberships(ctx, root, workspace.ID, credbound.PageRequest{})); len(got) != 2 {
		t.Fatalf("memberships = %#v", got)
	}
	if err := f.manager.DisableWorkspace(ctx, root, workspace.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.AuthorizePermission(ctx, root, workspace.ID, credbound.PermissionWorkspaceAccess); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("disabled workspace authorization = %v", err)
	}
	if _, err := f.manager.UpdateWorkspace(ctx, root, workspace.ID, credbound.UpdateWorkspaceInput{Name: "Forbidden while disabled"}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("disabled workspace mutation = %v", err)
	}
	if err := f.manager.EnableWorkspace(ctx, root, workspace.ID); err != nil {
		t.Fatal(err)
	}
	workspace, err = f.manager.AdminUpdateWorkspace(ctx, root, credbound.TrustedRequest{Local: true}, workspace.ID, credbound.UpdateWorkspaceInput{Name: "Platform Admin"})
	if err != nil || workspace.Name != "Platform Admin" {
		t.Fatalf("administrative workspace update = %#v, %v", workspace, err)
	}
	if err := f.manager.AdminDisableWorkspace(ctx, root, credbound.TrustedRequest{Local: true}, workspace.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.AdminDisableWorkspace(ctx, root, credbound.TrustedRequest{Local: true}, workspace.ID); err != nil {
		t.Fatalf("idempotent administrative disable = %v", err)
	}
	if err := f.manager.AdminEnableWorkspace(ctx, root, credbound.TrustedRequest{Local: true}, workspace.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.AdminEnableWorkspace(ctx, root, credbound.TrustedRequest{Local: true}, workspace.ID); err != nil {
		t.Fatalf("idempotent administrative enable = %v", err)
	}
	if err := f.manager.RemoveMembership(ctx, root, workspace.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.AddMembership(ctx, root, workspace.ID, user.ID, credbound.RoleAdmin); err != nil {
		t.Fatal(err)
	}

	if err := f.manager.SetInstanceRole(ctx, root, credbound.TrustedRequest{Local: true}, user.ID, credbound.InstanceRoleRoot); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.DisableUser(ctx, root, credbound.TrustedRequest{Local: true}, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.UpdateWorkspace(ctx, aal2(user.ID, f.now), workspace.ID, credbound.UpdateWorkspaceInput{Name: "Forbidden for disabled user"}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("disabled user mutation = %v", err)
	}
	assertLifecycleError(t, f.manager.UserWorkspaces(ctx, aal2(user.ID, f.now), credbound.PageRequest{}), credbound.ErrForbidden)
	if _, err := f.manager.AuthenticatePassword(ctx, user.Email, "correct horse battery"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("disabled user authentication = %v", err)
	}
	if err := f.manager.DisableUser(ctx, root, credbound.TrustedRequest{Local: true}, root.UserID); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("last enabled root disable = %v", err)
	}
	if err := f.manager.EnableUser(ctx, root, credbound.TrustedRequest{Local: true}, user.ID); err != nil {
		t.Fatal(err)
	}

	if users := collectLifecyclePage(t, f.manager.Users(ctx, root, credbound.PageRequest{Limit: 1})); len(users) != 1 {
		t.Fatalf("user first page = %#v", users)
	}
	if workspaces := collectLifecyclePage(t, f.manager.Workspaces(ctx, root, credbound.PageRequest{})); len(workspaces) != 2 {
		t.Fatalf("workspaces = %#v", workspaces)
	}
	userAuth, err := f.manager.AuthenticatePassword(ctx, user.Email, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if workspaces := collectLifecyclePage(t, f.manager.UserWorkspaces(ctx, userAuth, credbound.PageRequest{})); len(workspaces) != 2 {
		t.Fatalf("user workspaces = %#v", workspaces)
	}
}

func TestIdentityLifecycleRejectsInvalidAndUnauthorizedMutations(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	authn, workspace := f.bootstrap(t)
	root := aal2(authn.UserID, f.now)
	if _, err := f.manager.CreateWorkspace(ctx, authn, credbound.CreateWorkspaceInput{Name: "No step-up"}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("workspace without step-up = %v", err)
	}
	if _, err := f.manager.CreateWorkspace(ctx, root, credbound.CreateWorkspaceInput{Name: " "}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("blank workspace = %v", err)
	}
	if _, err := f.manager.UpdateWorkspace(ctx, root, "invalid", credbound.UpdateWorkspaceInput{Name: "Name"}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid workspace id = %v", err)
	}
	if _, err := f.manager.UpdateWorkspace(ctx, authn, workspace.ID, credbound.UpdateWorkspaceInput{Name: "Name"}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("workspace update without step-up = %v", err)
	}
	if _, err := f.manager.UpdateWorkspace(ctx, root, "0198b463-0000-7000-8000-00000000ffff", credbound.UpdateWorkspaceInput{Name: "Name"}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("missing workspace update = %v", err)
	}
	if _, err := f.manager.AdminUpdateWorkspace(ctx, credbound.Authentication{}, credbound.TrustedRequest{}, workspace.ID, credbound.UpdateWorkspaceInput{Name: "Name"}); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("unauthorized administrative workspace update = %v", err)
	}
	if _, err := f.manager.AdminUpdateWorkspace(ctx, authn, credbound.TrustedRequest{}, workspace.ID, credbound.UpdateWorkspaceInput{Name: "Name"}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("administrative workspace update without step-up = %v", err)
	}
	if _, err := f.manager.AdminUpdateWorkspace(ctx, root, credbound.TrustedRequest{Local: true}, "invalid", credbound.UpdateWorkspaceInput{Name: "Name"}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("administrative invalid workspace id = %v", err)
	}
	if err := f.manager.AdminDisableWorkspace(ctx, credbound.Authentication{}, credbound.TrustedRequest{}, workspace.ID); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("unauthorized administrative workspace disable = %v", err)
	}
	if err := f.manager.AdminDisableWorkspace(ctx, root, credbound.TrustedRequest{Local: true}, "invalid"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("administrative invalid workspace disable = %v", err)
	}
	bound := root
	bound.WorkspaceID = "0198b463-0000-7000-8000-0000000000ff"
	if _, err := f.manager.UpdateWorkspace(ctx, bound, workspace.ID, credbound.UpdateWorkspaceInput{Name: "Name"}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("cross-workspace mutation = %v", err)
	}
	if _, err := f.manager.UpdateWorkspace(ctx, root, workspace.ID, credbound.UpdateWorkspaceInput{Name: ""}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("blank update = %v", err)
	}
	if _, err := f.manager.AddMembership(ctx, root, workspace.ID, "invalid", credbound.RoleMember); !errors.Is(err, credbound.ErrNotFound) && !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid member = %v", err)
	}
	if _, err := f.manager.AddMembership(ctx, root, workspace.ID, root.UserID, credbound.RoleMember); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate member = %v", err)
	}
	if _, err := f.manager.AddMembership(ctx, root, workspace.ID, root.UserID, "unknown"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("unknown role = %v", err)
	}
	if _, err := f.manager.SetMembershipStatus(ctx, root, workspace.ID, root.UserID, "unknown"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("unknown membership status = %v", err)
	}
	if _, err := f.manager.SetMembershipStatus(ctx, credbound.Authentication{}, workspace.ID, root.UserID, credbound.MembershipActive); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("unauthorized membership status = %v", err)
	}
	if _, err := f.manager.SetMembershipStatus(ctx, root, workspace.ID, "0198b463-0000-7000-8000-00000000fffe", credbound.MembershipActive); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing membership status = %v", err)
	}
	if err := f.manager.RemoveMembership(ctx, credbound.Authentication{}, workspace.ID, root.UserID); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("unauthorized membership removal = %v", err)
	}
	if err := f.manager.RemoveMembership(ctx, root, workspace.ID, "0198b463-0000-7000-8000-00000000fffe"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing membership removal = %v", err)
	}
	if err := f.manager.DisableUser(ctx, credbound.Authentication{}, credbound.TrustedRequest{}, root.UserID); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("unauthorized user disable = %v", err)
	}
	if err := f.manager.DisableUser(ctx, authn, credbound.TrustedRequest{}, root.UserID); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("user disable without step-up = %v", err)
	}
	if err := f.manager.DisableUser(ctx, root, credbound.TrustedRequest{Local: true}, "0198b463-0000-7000-8000-00000000fffd"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing user disable = %v", err)
	}
	if err := f.manager.DisableUser(ctx, root, credbound.TrustedRequest{Local: true}, "invalid"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid user id = %v", err)
	}
	if err := f.manager.EnableUser(ctx, root, credbound.TrustedRequest{Local: true}, root.UserID); err != nil {
		t.Fatalf("idempotent user enable = %v", err)
	}
	soleAdmin, err := f.manager.CreateUser(ctx, root, workspace.ID, credbound.CreateUserInput{
		Email: "sole-admin@example.com", DisplayName: "Sole Admin", Password: "correct horse battery", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.CreateWorkspace(ctx, aal2(soleAdmin.ID, f.now), credbound.CreateWorkspaceInput{Name: "Sole Admin Workspace"}); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.DisableUser(ctx, root, credbound.TrustedRequest{Local: true}, soleAdmin.ID); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("disable last enabled workspace admin = %v", err)
	}
	assertLifecycleError(t, f.manager.Users(ctx, credbound.Authentication{}, credbound.PageRequest{}), credbound.ErrUnauthorized)
	assertLifecycleError(t, f.manager.Users(ctx, root, credbound.PageRequest{Limit: 101}), credbound.ErrInvalidInput)
	assertLifecycleError(t, f.manager.Workspaces(ctx, credbound.Authentication{}, credbound.PageRequest{}), credbound.ErrUnauthorized)
	assertLifecycleError(t, f.manager.Workspaces(ctx, root, credbound.PageRequest{Limit: 101}), credbound.ErrInvalidInput)
	assertLifecycleError(t, f.manager.UserWorkspaces(ctx, credbound.Authentication{}, credbound.PageRequest{}), credbound.ErrUnauthorized)
	assertLifecycleError(t, f.manager.UserWorkspaces(ctx, root, credbound.PageRequest{Limit: 101}), credbound.ErrInvalidInput)
	assertLifecycleError(t, f.manager.Memberships(ctx, credbound.Authentication{}, workspace.ID, credbound.PageRequest{}), credbound.ErrUnauthorized)
	assertLifecycleError(t, f.manager.Memberships(ctx, root, workspace.ID, credbound.PageRequest{Limit: 101}), credbound.ErrInvalidInput)
}

func collectLifecyclePage[T any](t *testing.T, sequence func(func(credbound.PageEvent[T], error) bool)) []T {
	t.Helper()
	var values []T
	for event, err := range sequence {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			values = append(values, *event.Data)
		}
	}
	return values
}

func assertLifecycleError[T any](t *testing.T, sequence func(func(credbound.PageEvent[T], error) bool), target error) {
	t.Helper()
	for _, err := range sequence {
		if !errors.Is(err, target) {
			t.Fatalf("stream error = %v, want %v", err, target)
		}
		return
	}
	t.Fatal("stream did not yield an error")
}

type userProfileRecorder struct {
	credbound.UnimplementedEventListener
	t     *testing.T
	calls []credbound.UserProfileUpdatedEvent
}

func (r *userProfileRecorder) OnUserProfileUpdated(_ context.Context, event credbound.UserProfileUpdatedEvent) error {
	r.t.Helper()
	if event.UserID == "" || event.DisplayName == "" {
		r.t.Fatalf("profile event carries no identity: %#v", event)
	}
	r.calls = append(r.calls, event)
	return nil
}

func TestUpdateUserProfile(t *testing.T) {
	f := newFixture(t)
	recorder := &userProfileRecorder{t: t}
	f.manager.AddEventListener(recorder)
	ctx := context.Background()
	authn, workspace := f.bootstrap(t)
	root := aal2(authn.UserID, f.now)

	member, err := f.manager.CreateUser(ctx, root, workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "correct horse battery", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	memberInteractive := credbound.Authentication{UserID: member.ID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: f.now}

	if _, err := f.manager.UpdateUser(ctx, credbound.Authentication{}, credbound.UpdateUserInput{DisplayName: "Nobody"}); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous profile update = %v", err)
	}
	pat := credbound.Authentication{UserID: member.ID, Method: credbound.MethodPAT, WorkspaceID: "", AuthenticatedAt: f.now}
	if _, err := f.manager.UpdateUser(ctx, pat, credbound.UpdateUserInput{DisplayName: "Nobody"}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("PAT profile update = %v", err)
	}
	if _, err := f.manager.UpdateUser(ctx, aal2(member.ID, f.now.Add(-time.Hour)), credbound.UpdateUserInput{DisplayName: "Stale"}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("stale profile update = %v", err)
	}
	if _, err := f.manager.UpdateUser(ctx, memberInteractive, credbound.UpdateUserInput{DisplayName: " "}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("blank display name = %v", err)
	}
	if _, err := f.manager.UpdateUser(ctx, memberInteractive, credbound.UpdateUserInput{DisplayName: strings.Repeat("x", 201)}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("overlong display name = %v", err)
	}

	t0 := f.now
	updated, err := f.manager.UpdateUser(ctx, memberInteractive, credbound.UpdateUserInput{DisplayName: "  New Member "})
	if err != nil || updated.DisplayName != "New Member" || updated.ID != member.ID {
		t.Fatalf("self profile update = %#v, %v", updated, err)
	}
	if !updated.UpdatedAt.Equal(t0) {
		t.Fatalf("updated timestamp = %v, want clock value %v", updated.UpdatedAt, t0)
	}
	if stored, err := f.store.UserByID(ctx, member.ID); err != nil || stored.DisplayName != "New Member" {
		t.Fatalf("stored profile = %#v, %v", stored, err)
	}
	if got := len(recorder.calls); got != 1 || recorder.calls[0].DisplayName != "New Member" || recorder.calls[0].PreviousProfile != "Member" {
		t.Fatalf("profile events = %#v", recorder.calls)
	}

	// The member must not be able to rename any other account.
	if _, err := f.manager.AdminUpdateUser(ctx, memberInteractive, credbound.TrustedRequest{Local: true}, authn.UserID, credbound.UpdateUserInput{DisplayName: "Hijack"}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("non-admin administrative profile update = %v", err)
	}
	if _, err := f.manager.AdminUpdateUser(ctx, aal2(member.ID, f.now), credbound.TrustedRequest{}, authn.UserID, credbound.UpdateUserInput{DisplayName: "Hijack"}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("untrusted non-admin profile update = %v", err)
	}

	// The trusted-local exception (ADMIN-006) admits the AAL1 root without a
	// fresh step-up, mirroring the administrative lifecycle contract.
	adminUpdated, err := f.manager.AdminUpdateUser(ctx, aal1(authn.UserID, t0), credbound.TrustedRequest{Local: true}, authn.UserID, credbound.UpdateUserInput{DisplayName: "Instance Root"})
	if err != nil || adminUpdated.DisplayName != "Instance Root" {
		t.Fatalf("administrative profile update = %#v, %v", adminUpdated, err)
	}
	// Without the trusted-local exception the same AAL1 root still demands a
	// fresh AAL2 step-up (ADMIN-005).
	if _, err := f.manager.AdminUpdateUser(ctx, aal1(authn.UserID, f.now), credbound.TrustedRequest{}, authn.UserID, credbound.UpdateUserInput{DisplayName: "Step-up"}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("untrusted AAL1 administrative profile update = %v", err)
	}
	if _, err := f.manager.AdminUpdateUser(ctx, root, credbound.TrustedRequest{Local: true}, "bad-id", credbound.UpdateUserInput{DisplayName: "X"}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid target identifier = %v", err)
	}
	if _, err := f.manager.AdminUpdateUser(ctx, root, credbound.TrustedRequest{Local: true}, "0198b463-0000-7000-8000-00000000babe", credbound.UpdateUserInput{DisplayName: "Missing"}); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing target = %v", err)
	}

	// Both mutations are auditable: the self update by the member, the
	// administrative one by the root actor.
	audit := collectAuditPage(t, f.manager.InstanceAuditEvents(ctx, root, credbound.PageRequest{}))
	var foundSelf, foundAdmin bool
	for _, item := range audit.items {
		if item.Action == "user.profile.update" && item.ActorID == member.ID && item.ResourceID == member.ID && item.Outcome == credbound.AuditSucceeded {
			foundSelf = true
		}
		if item.Action == "admin.user.profile.update" && item.ActorID == authn.UserID && item.ResourceID == authn.UserID && item.Outcome == credbound.AuditSucceeded {
			foundAdmin = true
		}
	}
	if !foundSelf || !foundAdmin {
		t.Fatalf("profile audit trail missing: self=%v admin=%v", foundSelf, foundAdmin)
	}
}

func aal1(userID string, at time.Time) credbound.Authentication {
	return credbound.Authentication{UserID: userID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: at}
}
