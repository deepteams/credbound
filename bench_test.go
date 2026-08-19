package credbound_test

import (
	"context"
	"testing"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/credboundtest"
)

// These benchmarks measure the hot paths a host calls on every request —
// credential authentication and the first page of a listing — over the
// in-memory store and the fast test hasher, so what they report is the
// library's own overhead rather than Argon2 or a database round trip.

func benchmarkManager(b *testing.B) (*credbound.Manager, credbound.Authentication, credbound.Workspace) {
	b.Helper()
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager := credboundtest.NewManager(b, credboundtest.WithClock(clock))
	root, workspace, err := manager.Bootstrap(context.Background(), credbound.BootstrapInput{
		Email:         credboundtest.BootstrapEmail,
		DisplayName:   credboundtest.BootstrapDisplayName,
		Password:      credboundtest.BootstrapPassword,
		WorkspaceName: credboundtest.BootstrapWorkspaceName,
	})
	if err != nil {
		b.Fatal(err)
	}
	return manager, root, workspace
}

func BenchmarkAuthenticatePassword(b *testing.B) {
	manager, _, _ := benchmarkManager(b)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := manager.AuthenticatePassword(ctx, credboundtest.BootstrapEmail, credboundtest.BootstrapPassword); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthenticatePAT(b *testing.B) {
	manager, root, workspace := benchmarkManager(b)
	ctx := context.Background()
	issued, err := manager.CreatePAT(ctx, credboundtest.AAL2(root.UserID, credboundtest.DefaultStartTime), credbound.CreatePATInput{
		Name: "ci", WorkspaceID: workspace.ID, Scopes: []string{"read"},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := manager.AuthenticatePAT(ctx, issued.Token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthenticateSession(b *testing.B) {
	manager, root, _ := benchmarkManager(b)
	ctx := context.Background()
	issued, err := manager.CreateSession(ctx, credboundtest.AAL2(root.UserID, credboundtest.DefaultStartTime), credbound.CreateSessionInput{})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := manager.AuthenticateSession(ctx, issued.Token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUsersFirstPage(b *testing.B) {
	manager, root, workspace := benchmarkManager(b)
	ctx := context.Background()
	actor := credboundtest.AAL2(root.UserID, credboundtest.DefaultStartTime)
	for index := range 200 {
		if _, err := manager.CreateUser(ctx, actor, workspace.ID, credbound.CreateUserInput{
			Email:       "user" + string(rune('a'+index%26)) + string(rune('a'+index/26)) + "@example.com",
			DisplayName: "User",
			Password:    "member correct horse battery",
			Role:        credbound.RoleMember,
		}); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		count := 0
		for event, err := range manager.Users(ctx, actor, credbound.PageRequest{Limit: 50}) {
			if err != nil {
				b.Fatal(err)
			}
			if event.Data != nil {
				count++
			}
		}
		if count != 50 {
			b.Fatalf("page returned %d users", count)
		}
	}
}
