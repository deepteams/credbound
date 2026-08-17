package postgresql_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/migrations"
	postgresstore "github.com/deepteams/credbound/sqlstore/postgresql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPostgreSQLMigrationsAndStore(t *testing.T) {
	dsn := os.Getenv("CREDBOUND_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("CREDBOUND_POSTGRES_DSN is not set")
	}
	ctx := context.Background()
	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	// Every Credbound object lives in the dedicated `credbound` schema, so
	// isolation is a fresh schema created by the first migration.
	if _, err := admin.Exec(ctx, `DROP SCHEMA IF EXISTS credbound CASCADE`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), `DROP SCHEMA IF EXISTS credbound CASCADE`) })

	testConfig := adminConfig.Copy()
	database := stdlib.OpenDB(*testConfig)
	t.Cleanup(func() { database.Close() })
	rows, err := pgx.ConnectConfig(ctx, testConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rows.Close(context.Background()) })

	applyPostgreSQLMigrations(t, database)
	store, err := postgresstore.New(database, rows, postgresstore.WithStreamTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	user := credbound.User{ID: pgID(1), Email: "root@example.com", DisplayName: "Root", CreatedAt: now, UpdatedAt: now}
	email := credbound.EmailAddress{ID: pgID(2), UserID: user.ID, Address: user.Email, Primary: true, VerifiedAt: &now, CreatedAt: now, UpdatedAt: now}
	workspace := credbound.Workspace{ID: pgID(3), Name: "Main", CreatedAt: now, UpdatedAt: now}
	membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleAdmin, Status: credbound.MembershipActive, CreatedAt: now, UpdatedAt: now}
	administrator := credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: now, UpdatedAt: now}
	commit := pgCommit(now, pgID(4), user.ID, "instance.bootstrap", workspace.ID, workspace.ID)
	if err := store.Bootstrap(ctx, user, email, credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: now}, workspace, membership, administrator, commit); err != nil {
		t.Fatal(err)
	}
	if got, err := store.UserByID(ctx, user.ID); err != nil || got.Email != user.Email {
		t.Fatalf("user = %#v, %v", got, err)
	}
	if got, err := store.WorkspaceByID(ctx, workspace.ID); err != nil || got.Name != workspace.Name {
		t.Fatalf("workspace = %#v, %v", got, err)
	}
	issuer := credbound.OAuthIssuer{ID: pgID(5), Issuer: "https://auth.example.com", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateOAuthIssuer(ctx, issuer, pgCommit(now, pgID(6), user.ID, "oauth.issuer.created", issuer.ID, "")); err != nil {
		t.Fatal(err)
	}
	if got, err := store.OAuthIssuerByURL(ctx, issuer.Issuer); err != nil || got.ID != issuer.ID {
		t.Fatalf("issuer = %#v, %v", got, err)
	}
	page := credbound.PageRequest{Limit: 50}
	users := assertPostgreSQLSequence(t, store.Users(ctx, page))
	if users != 1 {
		t.Fatalf("users = %d", users)
	}
	assertPostgreSQLSequence(t, store.Emails(ctx, user.ID, page))
	assertPostgreSQLSequence(t, store.PATs(ctx, user.ID, page))
	assertPostgreSQLSequence(t, store.SSOIdentities(ctx, user.ID, page))
	assertPostgreSQLSequence(t, store.Workspaces(ctx, page))
	assertPostgreSQLSequence(t, store.UserWorkspaces(ctx, user.ID, page))
	assertPostgreSQLSequence(t, store.Memberships(ctx, workspace.ID, page))
	assertPostgreSQLSequence(t, store.AuditEvents(ctx, workspace.ID, page))
	assertPostgreSQLSequence(t, store.InstanceAuditEvents(ctx, page))
	assertPostgreSQLSequence(t, store.OAuthIssuers(ctx, page))
	assertPostgreSQLSequence(t, store.OAuthProtectedResources(ctx, workspace.ID, page))
	assertPostgreSQLSequence(t, store.OAuthClients(ctx, issuer.ID, page))
	assertPostgreSQLSequence(t, store.OAuthGrants(ctx, "", "", page))
	assertPostgreSQLSequence(t, store.OAuthGrants(ctx, user.ID, workspace.ID, page))
	configurationID := pgID(7)
	assertPostgreSQLSequence(t, store.SCIMUsers(ctx, configurationID, credbound.SCIMFilter{}, page))
	assertPostgreSQLSequence(t, store.SCIMGroups(ctx, configurationID, credbound.SCIMFilter{}, page))
	assertPostgreSQLSequence(t, store.SCIMUsers(ctx, configurationID, credbound.SCIMFilter{Attribute: "id", Value: "not-a-uuid"}, page))
	assertPostgreSQLSequence(t, store.SCIMGroups(ctx, configurationID, credbound.SCIMFilter{Attribute: "id", Value: "not-a-uuid"}, page))
	if _, err := database.ExecContext(ctx, `UPDATE credbound_audit_events SET reason = 'tampered' WHERE id = $1`, commit.Audit.ID); err == nil {
		t.Fatal("append-only audit update unexpectedly succeeded")
	}

	second := credbound.User{ID: pgID(8), Email: "second@example.com", DisplayName: "Second", CreatedAt: now, UpdatedAt: now}
	secondEmail := credbound.EmailAddress{ID: pgID(9), UserID: second.ID, Address: second.Email, Primary: true, VerifiedAt: &now, CreatedAt: now, UpdatedAt: now}
	secondMembership := credbound.Membership{WorkspaceID: workspace.ID, UserID: second.ID, Role: credbound.RoleAdmin, Status: credbound.MembershipActive, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateUser(ctx, second, secondEmail, credbound.PasswordCredential{UserID: second.ID, Hash: "hash", UpdatedAt: now}, secondMembership, pgCommit(now, pgID(10), user.ID, "user.created", second.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	assertConcurrentPostgreSQLInvariant(t,
		func() error {
			value := membership
			value.Role, value.UpdatedAt = credbound.RoleMember, now.Add(time.Second)
			return store.UpsertMembership(ctx, value, pgCommit(now.Add(time.Second), pgID(11), user.ID, "membership.demote", user.ID, workspace.ID))
		},
		func() error {
			value := secondMembership
			value.Role, value.UpdatedAt = credbound.RoleMember, now.Add(time.Second)
			return store.UpsertMembership(ctx, value, pgCommit(now.Add(time.Second), pgID(12), user.ID, "membership.demote", second.ID, workspace.ID))
		},
	)

	secondRoot := credbound.InstanceAdministrator{UserID: second.ID, Role: credbound.InstanceRoleRoot, CreatedAt: now, UpdatedAt: now}
	if err := store.SetInstanceRole(ctx, secondRoot, pgCommit(now.Add(2*time.Second), pgID(13), user.ID, "admin.root.add", second.ID, "")); err != nil {
		t.Fatal(err)
	}
	assertConcurrentPostgreSQLInvariant(t,
		func() error {
			value := administrator
			value.Role, value.UpdatedAt = credbound.InstanceRoleDeveloper, now.Add(3*time.Second)
			return store.SetInstanceRole(ctx, value, pgCommit(now.Add(3*time.Second), pgID(14), user.ID, "admin.root.demote", user.ID, ""))
		},
		func() error {
			value := secondRoot
			value.Role, value.UpdatedAt = credbound.InstanceRoleDeveloper, now.Add(3*time.Second)
			return store.SetInstanceRole(ctx, value, pgCommit(now.Add(3*time.Second), pgID(15), user.ID, "admin.root.demote", second.ID, ""))
		},
	)
}

func assertPostgreSQLSequence[T any](t *testing.T, sequence func(func(credbound.PageEvent[T], error) bool)) int {
	t.Helper()
	count := 0
	for event, err := range sequence {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			count++
		}
	}
	return count
}

func assertConcurrentPostgreSQLInvariant(t *testing.T, left, right func() error) {
	t.Helper()
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, mutation := range []func() error{left, right} {
		go func() {
			<-start
			results <- mutation()
		}()
	}
	close(start)
	succeeded, conflicted := 0, 0
	for range 2 {
		switch err := <-results; {
		case err == nil:
			succeeded++
		case errors.Is(err, credbound.ErrConflict):
			conflicted++
		default:
			t.Fatalf("concurrent invariant mutation = %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent invariant results: succeeded=%d conflicted=%d", succeeded, conflicted)
	}
}

func applyPostgreSQLMigrations(t *testing.T, database *sql.DB) {
	t.Helper()
	entries, err := fs.ReadDir(migrations.PostgreSQL(), ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		raw, err := fs.ReadFile(migrations.PostgreSQL(), entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		up := strings.Split(string(raw), "-- +goose Down")[0]
		if _, err := database.Exec(up); err != nil {
			t.Fatalf("apply %s: %v", entry.Name(), err)
		}
	}
}

func pgID(value int) string { return fmt.Sprintf("0198b463-0000-7000-8000-%012x", value) }

func pgCommit(at time.Time, id, actor, action, resource, workspace string) credbound.Commit {
	return credbound.Commit{Audit: credbound.AuditEvent{
		ID: id, OccurredAt: at, ActorID: actor, Action: action, ResourceType: "test", ResourceID: resource, WorkspaceID: workspace, Outcome: credbound.AuditSucceeded,
	}}
}
