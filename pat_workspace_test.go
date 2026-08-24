package credbound_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/credboundtest"
)

// collectWorkspacePATs drains the key list of a workspace, returning its rows
// or the first error the listing reported.
func collectWorkspacePATs(sequence func(func(credbound.PageEvent[credbound.WorkspacePAT], error) bool)) ([]credbound.WorkspacePAT, error) {
	var rows []credbound.WorkspacePAT
	for event, err := range sequence {
		if err != nil {
			return nil, err
		}
		if event.Data != nil {
			rows = append(rows, *event.Data)
		}
	}
	return rows, nil
}

// TestWorkspacePATAdministration pins the tenant-scoped key page: a workspace
// administrator with no instance role sees and revokes the workspace-bound
// tokens of every member — the departed-colleague case — while an unbound
// token stays the property of its owner alone and another tenant's
// administrator sees nothing.
func TestWorkspacePATAdministration(t *testing.T) {
	ctx := context.Background()
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager := credboundtest.NewManager(t, credboundtest.WithClock(clock))
	root, workspace := credboundtest.Bootstrap(t, manager)
	rootStepUp := credboundtest.AAL2(root.UserID, clock.Now())

	// A workspace administrator who holds no instance-administration role at
	// all: the whole point is that the keys page works without one.
	admin, err := manager.CreateUser(ctx, rootStepUp, workspace.ID, credbound.CreateUserInput{
		Email: "admin@example.com", DisplayName: "Workspace Admin", Password: "another strong password", Role: credbound.RoleAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}
	member, err := manager.CreateUser(ctx, rootStepUp, workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Departed Member", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	adminStepUp := credboundtest.AAL2(admin.ID, clock.Now())
	memberStepUp := credboundtest.AAL2(member.ID, clock.Now())

	bound, err := manager.CreatePAT(ctx, memberStepUp, credbound.CreatePATInput{Name: "router key", WorkspaceID: workspace.ID, Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	unbound, err := manager.CreatePAT(ctx, memberStepUp, credbound.CreatePATInput{Name: "personal", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}

	rows, err := collectWorkspacePATs(manager.WorkspacePATs(ctx, adminStepUp, workspace.ID, credbound.PageRequest{Limit: 50}))
	if err != nil {
		t.Fatalf("workspace key listing: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("workspace keys = %d rows, want the bound token only: %#v", len(rows), rows)
	}
	if rows[0].PAT.ID != bound.PAT.ID || rows[0].PAT.Digest != nil {
		t.Fatalf("workspace key row = %#v", rows[0].PAT)
	}
	// The owner is joined, which is what makes the page readable without the
	// instance-wide admin users read permission.
	if rows[0].User.ID != member.ID || rows[0].User.DisplayName != "Departed Member" || rows[0].User.Email != "member@example.com" {
		t.Fatalf("owner profile = %#v", rows[0].User)
	}

	// An unbound token is not the tenant's to revoke, and its existence is
	// not even confirmed.
	if err := manager.RevokeWorkspacePAT(ctx, adminStepUp, workspace.ID, unbound.PAT.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("revoking an unbound token = %v", err)
	}
	if _, err := manager.AuthenticatePAT(ctx, unbound.Token); err != nil {
		t.Fatalf("unbound token after the refused revocation = %v", err)
	}

	if err := manager.RevokeWorkspacePAT(ctx, adminStepUp, workspace.ID, bound.PAT.ID); err != nil {
		t.Fatalf("workspace revocation = %v", err)
	}
	if _, err := manager.AuthenticatePAT(ctx, bound.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("revoked workspace key = %v", err)
	}

	// An ordinary member holds neither the listing nor the revocation.
	if _, err := collectWorkspacePATs(manager.WorkspacePATs(ctx, memberStepUp, workspace.ID, credbound.PageRequest{Limit: 50})); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("member listing the workspace keys = %v", err)
	}
	if err := manager.RevokeWorkspacePAT(ctx, memberStepUp, workspace.ID, unbound.PAT.ID); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("member revoking a workspace key = %v", err)
	}

	// The permission never reaches beyond the workspace that granted it.
	other, err := manager.CreateWorkspace(ctx, adminStepUp, credbound.CreateWorkspaceInput{Name: "Other"})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RevokeWorkspacePAT(ctx, credboundtest.AAL2(admin.ID, clock.Now()), other.ID, bound.PAT.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("cross-workspace revocation = %v", err)
	}
}

// TestPATListingHasNoFreshnessWindow pins that reading one's own tokens is a
// plain interactive read: the management screen keeps working long past
// StepUpMaxAge, while a non-interactive credential and an anonymous caller are
// still refused.
func TestPATListingHasNoFreshnessWindow(t *testing.T) {
	ctx := context.Background()
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager := credboundtest.NewManager(t, credboundtest.WithClock(clock))
	root, _ := credboundtest.Bootstrap(t, manager)
	issued, err := manager.CreatePAT(ctx, credboundtest.AAL2(root.UserID, clock.Now()), credbound.CreatePATInput{Name: "ci", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}

	// The sign-in context ages well past the step-up window; the listing must
	// not start refusing it.
	clock.Advance(24 * time.Hour)
	page := collectPage(t, manager.PATs(ctx, root, credbound.UUID{}, credbound.PageRequest{Limit: 50}))
	if len(page.items) != 1 || page.items[0].ID != issued.PAT.ID || page.items[0].Digest != nil {
		t.Fatalf("stale-but-interactive listing = %#v", page.items)
	}

	patAuth, err := manager.AuthenticatePAT(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	for _, err := range manager.PATs(ctx, patAuth, credbound.UUID{}, credbound.PageRequest{Limit: 50}) {
		if !errors.Is(err, credbound.ErrStepUpRequired) {
			t.Fatalf("PAT listing its own siblings = %v", err)
		}
		break
	}
	for _, err := range manager.PATs(ctx, credbound.Authentication{}, credbound.UUID{}, credbound.PageRequest{Limit: 50}) {
		if !errors.Is(err, credbound.ErrUnauthorized) {
			t.Fatalf("anonymous listing = %v", err)
		}
		break
	}
}
