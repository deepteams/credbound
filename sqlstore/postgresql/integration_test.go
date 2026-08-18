package postgresql_test

import (
	"context"
	"database/sql"
	"encoding/json"
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

// TestPostgreSQLMigrationsAndStore applies the shipped migrations to a real
// PostgreSQL and exercises the store against the resulting schema, proving
// the engine is supported on par with SQLite (DATA-001).
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
	// The audit trail is append-only: the migration installs BEFORE
	// UPDATE/DELETE triggers on credbound.audit_events that raise "credbound
	// audit events are immutable". Requiring that exact message — on the real
	// table — keeps a typo'd table name (whose error is a relation-not-found)
	// from passing as immutability.
	if _, err := database.ExecContext(ctx, `UPDATE credbound.audit_events SET reason = 'tampered' WHERE id = $1`, commit.Audit.ID); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("append-only audit update = %v, want the immutability trigger error", err)
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM credbound.audit_events WHERE id = $1`, commit.Audit.ID); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("append-only audit delete = %v, want the immutability trigger error", err)
	}
	var auditReason string
	if err := database.QueryRowContext(ctx, `SELECT reason FROM credbound.audit_events WHERE id = $1`, commit.Audit.ID).Scan(&auditReason); err != nil || auditReason == "tampered" {
		t.Fatalf("audit row after tamper attempts = %q, %v", auditReason, err)
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

	// Credential-currency guards: a finalization whose verified hash moved is
	// refused, the current hash finalizes and clears the throttle, and session
	// creation validates the credential fingerprint inside the transaction.
	if _, err := store.RecordLoginFailure(ctx, second.ID, now, 5, now.Add(time.Hour), pgCommit(now, pgID(16), second.ID, "auth.failure", second.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordPasswordAuthentication(ctx, second.ID, "stale", now, pgCommit(now, pgID(17), second.ID, "auth.password.stale", second.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("stale finalization error = %v", err)
	}
	if _, err := store.LoginThrottleByUserID(ctx, second.ID); err != nil {
		t.Fatalf("throttle vanished on refused finalization: %v", err)
	}
	if err := store.RecordPasswordAuthentication(ctx, second.ID, "hash", now, pgCommit(now, pgID(18), second.ID, "auth.password", second.ID, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoginThrottleByUserID(ctx, second.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("throttle survived a completed sign-in: %v", err)
	}
	staleSession := credbound.Session{
		ID: pgID(19), UserID: second.ID, Method: credbound.MethodPassword, Level: credbound.AAL1,
		AuthenticatedAt: now, UserAgent: "agent", IPAddress: "203.0.113.7", Digest: []byte("digest"),
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}
	if err := store.CreateSession(ctx, staleSession, credbound.CredentialFingerprint("previous"), pgCommit(now, pgID(20), second.ID, "session.create.stale", staleSession.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("stale session error = %v", err)
	}

	// The race the guard exists for: a password change and a session creation
	// carrying the old credential's fingerprint run concurrently. Whatever the
	// interleaving, the invariant holds — either the session is refused, or it
	// was created before the change and the change's sweep revoked it.
	raceSession := staleSession
	raceSession.ID = pgID(21)
	changeAt := now.Add(4 * time.Second)
	results := make(chan error, 1)
	go func() {
		results <- store.ChangePassword(ctx, credbound.PasswordCredential{UserID: second.ID, Hash: "hash2", UpdatedAt: changeAt}, changeAt, pgCommit(changeAt, pgID(22), second.ID, "password.change", second.ID, ""))
	}()
	createErr := store.CreateSession(ctx, raceSession, credbound.CredentialFingerprint("hash"), pgCommit(now, pgID(23), second.ID, "session.create.race", raceSession.ID, ""))
	if err := <-results; err != nil {
		t.Fatalf("racing password change = %v", err)
	}
	switch {
	case errors.Is(createErr, credbound.ErrConflict):
		// The change won: the stale fingerprint was refused.
	case createErr == nil:
		created, err := store.SessionByID(ctx, raceSession.ID)
		if err != nil {
			t.Fatal(err)
		}
		if created.RevokedAt == nil {
			t.Fatal("stale session survived the racing password change unrevoked")
		}
	default:
		t.Fatalf("racing session creation = %v", createErr)
	}

	// Privacy contract: anonymization scrubs the personal attributes of the
	// user's SCIM profiles (marking them deprovisioned) and tombstones the
	// address on invitations the user accepted, and the PrivacyStore reads
	// expose both record families for the DSAR export — the same behavior the
	// memory and SQLite suites pin.
	configuration := credbound.SCIMConfiguration{ID: pgID(24), WorkspaceID: workspace.ID, Enabled: true, DefaultRole: credbound.RoleMember, CreatedAt: now, UpdatedAt: now}
	scimCredential := credbound.SCIMCredential{ID: pgID(25), ConfigurationID: configuration.ID, Prefix: "abcdef012345", Digest: []byte("digest"), CreatedAt: now}
	if err := store.CreateSCIMConfiguration(ctx, configuration, scimCredential, pgCommit(now, pgID(26), user.ID, "scim.configuration.create", configuration.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	worker := credbound.User{ID: pgID(27), Email: "worker@example.com", DisplayName: "Worker", CreatedAt: now, UpdatedAt: now}
	workerMembership := credbound.Membership{WorkspaceID: workspace.ID, UserID: worker.ID, Role: credbound.RoleMember, Status: credbound.MembershipActive, ProvisioningSource: configuration.ID, CreatedAt: now, UpdatedAt: now}
	link := credbound.SCIMUser{
		ID: pgID(28), ConfigurationID: configuration.ID, UserID: worker.ID, ExternalID: "worker", UserName: "worker@example.com", DisplayName: "Worker",
		Emails:     []credbound.SCIMEmail{{Value: "worker@example.com", Primary: true}},
		Attributes: map[string]json.RawMessage{"title": json.RawMessage(`"Engineer"`)}, Active: true, CreatedAt: now, UpdatedAt: now,
	}
	workerEmail := credbound.EmailAddress{ID: pgID(29), UserID: worker.ID, Address: worker.Email, Primary: true, VerifiedAt: &now, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateSCIMUser(ctx, worker, workerEmail, workerMembership, link, pgCommit(now, pgID(30), scimCredential.ID, "scim.user.provision", link.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	invitation := credbound.WorkspaceInvitation{ID: pgID(31), WorkspaceID: workspace.ID, Email: "worker@example.com", Role: credbound.RoleMember, InvitedBy: user.ID, Digest: []byte("digest"), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := store.CreateWorkspaceInvitation(ctx, invitation, pgCommit(now, pgID(32), user.ID, "invite.create", invitation.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptWorkspaceInvitation(ctx, invitation.ID, worker.ID, now, workerMembership, pgCommit(now, pgID(33), worker.ID, "invite.accept", invitation.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := store.AnonymizeUser(ctx, worker.ID, now, pgCommit(now, pgID(34), user.ID, "user.anonymize", worker.ID, "")); err != nil {
		t.Fatal(err)
	}
	scrubbed, err := store.SCIMUser(ctx, configuration.ID, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	if scrubbed.UserName != "anonymized-"+link.ID || scrubbed.DisplayName != "" || scrubbed.ExternalID != "" ||
		len(scrubbed.Emails) != 0 || len(scrubbed.Attributes) != 0 || scrubbed.Active || scrubbed.DeprovisionedAt == nil {
		t.Fatalf("SCIM profile kept personal data: %#v", scrubbed)
	}
	links := 0
	for value, err := range store.SCIMUsersByUser(ctx, worker.ID) {
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
	for value, err := range store.AcceptedWorkspaceInvitations(ctx, worker.ID) {
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
