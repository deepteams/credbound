package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	db "github.com/deepteams/credbound/internal/sqlc/sqlite"
	"github.com/deepteams/credbound/migrations"
	_ "modernc.org/sqlite"
)

type edgeFixture struct {
	db        *sql.DB
	store     *Store
	user      credbound.User
	workspace credbound.Workspace
	now       time.Time
	next      int
}

func newEdgeFixture(t *testing.T) *edgeFixture {
	t.Helper()
	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared&_pragma=foreign_keys(1)&_texttotime=1"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrationFS := migrations.SQLite()
	entries, err := fs.ReadDir(migrationFS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		migration, err := fs.ReadFile(migrationFS, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(strings.Split(string(migration), "-- +goose Down")[0]); err != nil {
			t.Fatalf("apply %s: %v", entry.Name(), err)
		}
	}
	store, err := New(database, WithStreamTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	f := &edgeFixture{db: database, store: store, now: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC), next: 1}
	f.user = credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	f.workspace = credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: f.workspace.ID, UserID: f.user.ID, Role: credbound.RoleAdmin, CreatedAt: f.now, UpdatedAt: f.now}
	admin := credbound.InstanceAdministrator{UserID: f.user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}
	if err := store.Bootstrap(context.Background(), f.user, f.email(f.user), credbound.PasswordCredential{UserID: f.user.ID, Hash: "hash", UpdatedAt: f.now}, f.workspace, membership, admin, f.event("bootstrap")); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *edgeFixture) id() string {
	id := fmt.Sprintf("0198b463-0000-7000-8000-%012x", f.next)
	f.next++
	return id
}

func (f *edgeFixture) event(action string) credbound.Commit {
	event := credbound.AuditEvent{ID: f.id(), OccurredAt: f.now, ActorID: f.user.ID, Action: action, ResourceType: "test", ResourceID: action, Outcome: credbound.AuditSucceeded}
	f.now = f.now.Add(time.Millisecond)
	return credbound.Commit{Audit: event}
}

func (f *edgeFixture) email(user credbound.User) credbound.EmailAddress {
	verifiedAt := f.now
	return credbound.EmailAddress{ID: f.id(), UserID: user.ID, Address: user.Email, Primary: true, VerifiedAt: &verifiedAt, CreatedAt: f.now, UpdatedAt: f.now}
}

func TestTransactionHookSharesCommitAndRollsBack(t *testing.T) {
	f := newEdgeFixture(t)
	ctx := context.Background()
	if _, err := f.db.ExecContext(ctx, `CREATE TABLE host_outbox (id TEXT PRIMARY KEY, event_name TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	user := credbound.User{ID: f.id(), Email: "transaction@example.com", DisplayName: "Transaction", CreatedAt: f.now, UpdatedAt: f.now}
	email := f.email(user)
	membership := credbound.Membership{WorkspaceID: f.workspace.ID, UserID: user.ID, Role: credbound.RoleMember, CreatedAt: f.now, UpdatedAt: f.now}
	commit := f.event("user.transaction.reject")
	var leaked *Tx
	boom := errors.New("host outbox rejected")
	commit.Transactional = func(ctx context.Context, generic credbound.Tx) error {
		handle, ok := TxFrom(generic)
		if !ok || handle.Kind() != credbound.StoreSQLite || handle.Audit().ID != commit.Audit.ID {
			return errors.New("invalid SQLite transaction capability")
		}
		leaked = handle
		if _, err := handle.SQL().ExecContext(ctx, `INSERT INTO host_outbox (id, event_name) VALUES (?, ?)`, commit.Audit.ID, "user.created"); err != nil {
			return err
		}
		return boom
	}
	err := f.store.CreateUser(ctx, user, email, credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}, membership, commit)
	if !errors.Is(err, boom) {
		t.Fatalf("transaction error = %v", err)
	}
	if leaked == nil || leaked.SQL() != nil {
		t.Fatal("SQLite transaction lifetime was not bounded by the callback")
	}
	if handle, ok := TxFrom(leaked); ok || handle != nil {
		t.Fatal("expired SQLite transaction was accepted")
	}
	if _, err := f.store.UserByID(ctx, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("rejected Credbound mutation was not rolled back: %v", err)
	}
	var count int
	if err := f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM host_outbox`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected host outbox write count = %d, err = %v", count, err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM credbound_audit_events WHERE id = ?`, commit.Audit.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected audit count = %d, err = %v", count, err)
	}

	commit = f.event("user.transaction.commit")
	commit.Transactional = func(ctx context.Context, generic credbound.Tx) error {
		handle, ok := TxFrom(generic)
		if !ok {
			return errors.New("SQLite transaction unavailable")
		}
		_, err := handle.SQL().ExecContext(ctx, `INSERT INTO host_outbox (id, event_name) VALUES (?, ?)`, commit.Audit.ID, "user.created")
		return err
	}
	if err := f.store.CreateUser(ctx, user, email, credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}, membership, commit); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UserByID(ctx, user.ID); err != nil {
		t.Fatalf("committed user missing: %v", err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM host_outbox WHERE id = ?`, commit.Audit.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("committed host outbox write count = %d, err = %v", count, err)
	}
}

func TestNotFoundConflictAndCursorPaths(t *testing.T) {
	f := newEdgeFixture(t)
	ctx := context.Background()
	if _, err := f.store.UserByEmail(ctx, "missing@example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.store.UserByID(ctx, "missing"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.store.PasswordByUserID(ctx, "missing"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.store.RehashPassword(ctx, credbound.PasswordCredential{UserID: "missing"}, "old", f.event("password.missing")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatal(err)
	}
	if _, err := f.store.TOTPByUserID(ctx, "missing"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.store.ActivateTOTP(ctx, credbound.TOTPFactor{UserID: "missing"}, nil, f.event("totp.activate.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.store.DisableTOTP(ctx, "missing", f.event("totp.disable.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.store.TouchPasskey(ctx, f.user.ID, []byte("missing"), nil, f.now, f.event("passkey.touch.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.store.DeletePasskey(ctx, f.user.ID, "missing", f.event("passkey.delete.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.store.PATByPrefix(ctx, "missing"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.store.TouchPAT(ctx, "missing", f.now, f.event("pat.touch.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.store.RevokePAT(ctx, f.user.ID, "missing", f.now, f.event("pat.revoke.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.store.Membership(ctx, f.workspace.ID, "missing"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.store.InstanceAdministrator(ctx, "missing"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.store.RemoveInstanceRole(ctx, "missing", f.event("admin.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.store.SetInstanceRole(ctx, credbound.InstanceAdministrator{UserID: f.user.ID, Role: credbound.InstanceRoleDeveloper, CreatedAt: f.now, UpdatedAt: f.now}, f.event("admin.last.root.demote")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("last root demotion = %v", err)
	}
	if err := f.store.RemoveInstanceRole(ctx, f.user.ID, f.event("admin.last.root")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("last root removal = %v", err)
	}

	audit := f.event("audit.append")
	if err := f.store.AppendAudit(ctx, audit); err != nil {
		t.Fatal(err)
	}
	if err := f.store.AppendAudit(ctx, audit); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("duplicate audit = %v", err)
	}
	assertSQLiteSequenceError(t, f.store.PATs(ctx, f.user.ID, credbound.PageRequest{Cursor: "%%%", Limit: 50}), credbound.ErrInvalidInput)
	assertSQLiteSequenceError(t, f.store.Emails(ctx, f.user.ID, credbound.PageRequest{Cursor: "%%%", Limit: 50}), credbound.ErrInvalidInput)
	assertSQLiteSequenceError(t, f.store.SSOIdentities(ctx, f.user.ID, credbound.PageRequest{Cursor: "%%%", Limit: 50}), credbound.ErrInvalidInput)
	assertSQLiteSequenceError(t, f.store.AuditEvents(ctx, f.workspace.ID, credbound.PageRequest{Cursor: "e30", Limit: 50}), credbound.ErrInvalidInput)

	items := 0
	endWithCursor := false
	for event, err := range f.store.InstanceAuditEvents(ctx, credbound.PageRequest{Limit: 1}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			items++
		}
		if event.End != nil && event.End.HasMore && event.End.NextCursor != "" {
			endWithCursor = true
		}
	}
	if items != 1 || !endWithCursor {
		t.Fatalf("paginated audit = items %d, cursor %v", items, endWithCursor)
	}
}

func TestDisabledUserOptionalPATAndSecondRoot(t *testing.T) {
	f := newEdgeFixture(t)
	ctx := context.Background()
	user := credbound.User{ID: f.id(), Email: "second@example.com", DisplayName: "Second", Disabled: true, CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: f.workspace.ID, UserID: user.ID, Role: credbound.RoleMember, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateUser(ctx, user, f.email(user), credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}, membership, f.event("user.create")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.UserByID(ctx, user.ID); err != nil || !got.Disabled {
		t.Fatalf("disabled user = %#v, %v", got, err)
	}
	root := credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.SetInstanceRole(ctx, root, f.event("admin.root.set")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RemoveInstanceRole(ctx, user.ID, f.event("admin.root.remove")); err != nil {
		t.Fatal(err)
	}

	expires := f.now.Add(time.Hour)
	pat := credbound.PAT{
		ID: f.id(), UserID: f.user.ID, Name: "Optional", Prefix: "prefix000001", Digest: []byte("digest"),
		WorkspaceID: f.workspace.ID, Scopes: []string{"read"}, CreatedAt: f.now,
		ExpiresAt: &expires, LastUsedAt: &f.now, RevokedAt: &f.now,
	}
	if err := f.store.CreatePAT(ctx, pat, f.event("pat.optional")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.TouchPAT(ctx, pat.ID, f.now, f.event("pat.touch")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RevokePAT(ctx, f.user.ID, pat.ID, f.now, f.event("pat.revoke")); err != nil {
		t.Fatal(err)
	}
	got, err := f.store.PATByPrefix(ctx, pat.Prefix)
	if err != nil || got.ExpiresAt == nil || got.LastUsedAt == nil || got.RevokedAt == nil {
		t.Fatalf("optional PAT fields = %#v, %v", got, err)
	}
}

func TestInternalMappingAndScanErrors(t *testing.T) {
	boom := errors.New("boom")
	if err := affected(0, boom); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	// mapError classifies by the driver's typed result code, so a plain error
	// (not a *sqlite.Error) is passed through unchanged; real constraint
	// violations mapping to ErrConflict are covered by the store-level tests
	// (duplicate inserts, bad-id CHECK violations).
	if err := mapError(errors.New("UNIQUE constraint failed")); errors.Is(err, credbound.ErrConflict) {
		t.Fatal("plain error text must not be classified as a conflict")
	}
	if err := mapError(boom); !errors.Is(err, boom) || mapError(nil) != nil {
		t.Fatal(err)
	}
	if _, err := patFromRow(db.CredboundPersonalAccessToken{ScopesJson: "{"}); err == nil {
		t.Fatal("invalid stored scopes accepted")
	}
	if _, err := scanPAT(scannerFunc(func(...any) error { return boom })); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	invalidJSON := scannerFunc(func(dest ...any) error {
		*(dest[0].(*string)) = "id"
		*(dest[1].(*string)) = "user"
		*(dest[2].(*string)) = "name"
		*(dest[3].(*string)) = "prefix"
		*(dest[4].(*[]byte)) = []byte("digest")
		*(dest[6].(*string)) = "{"
		*(dest[7].(*time.Time)) = time.Now()
		return nil
	})
	if _, err := scanPAT(invalidJSON); err == nil {
		t.Fatal("invalid streamed scopes accepted")
	}
	if _, err := decodeCursor("%%% "); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatal(err)
	}
	if nullableString("").Valid || nullableTime(nil).Valid || timePointer(sql.NullTime{}) != nil {
		t.Fatal("nullable conversion is incorrect")
	}
}

func TestClosedDatabaseErrors(t *testing.T) {
	f := newEdgeFixture(t)
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.store.RehashPassword(ctx, credbound.PasswordCredential{UserID: f.user.ID}, "old", f.event("closed.mutation")); err == nil {
		t.Fatal("mutation on closed database succeeded")
	}
	configuration := credbound.SCIMConfiguration{ID: f.id(), WorkspaceID: f.workspace.ID}
	credential := credbound.SCIMCredential{ID: f.id(), ConfigurationID: configuration.ID}
	membership := credbound.Membership{WorkspaceID: f.workspace.ID, UserID: f.user.ID}
	user := credbound.SCIMUser{ID: f.id(), ConfigurationID: configuration.ID, UserID: f.user.ID}
	group := credbound.SCIMGroup{ID: f.id(), ConfigurationID: configuration.ID}
	for index, err := range []error{
		f.store.CreateSCIMConfiguration(ctx, configuration, credential, f.event("closed.scim.configuration")),
		f.store.SaveSCIMCredential(ctx, credential, f.event("closed.scim.credential")),
		f.store.TouchSCIMCredential(ctx, credential.ID, f.now, f.event("closed.scim.touch")),
		f.store.DisableSCIMConfiguration(ctx, configuration.ID, f.now, f.event("closed.scim.disable")),
		f.store.CreateSCIMUser(ctx, f.user, f.email(f.user), membership, user, f.event("closed.scim.user")),
		f.store.AdoptSCIMUser(ctx, membership, user, f.event("closed.scim.adopt")),
		f.store.UpdateSCIMUser(ctx, user, membership, true, f.event("closed.scim.update")),
		f.store.UpsertSCIMGroup(ctx, group, nil, f.event("closed.scim.group")),
		f.store.DeleteSCIMGroup(ctx, group, nil, f.event("closed.scim.group.delete")),
	} {
		if err == nil {
			t.Fatalf("closed SCIM mutation %d succeeded", index)
		}
	}
	for index, err := range []error{
		func() error { _, err := f.store.SCIMConfiguration(ctx, configuration.ID); return err }(),
		func() error { _, _, err := f.store.SCIMConfigurationByCredentialPrefix(ctx, "prefix"); return err }(),
		func() error { _, err := f.store.SCIMUser(ctx, configuration.ID, user.ID); return err }(),
		func() error { _, err := f.store.SCIMUserByExternalID(ctx, configuration.ID, "external"); return err }(),
		func() error { _, err := f.store.SCIMUserByUserName(ctx, configuration.ID, "user"); return err }(),
		func() error { _, err := f.store.SCIMGroup(ctx, configuration.ID, group.ID); return err }(),
		func() error { _, err := f.store.SCIMGroupByExternalID(ctx, configuration.ID, "external"); return err }(),
	} {
		if err == nil {
			t.Fatalf("closed SCIM lookup %d succeeded", index)
		}
	}
	issuer := credbound.OAuthIssuer{ID: f.id(), Issuer: "https://auth.example.com"}
	resource := credbound.OAuthProtectedResource{ID: f.id(), IssuerID: issuer.ID, WorkspaceID: f.workspace.ID, Resource: "https://mcp.example.com"}
	client := credbound.OAuthClient{ID: f.id(), IssuerID: issuer.ID, ClientID: "client"}
	initial := credbound.OAuthInitialAccessToken{ID: f.id(), IssuerID: issuer.ID, Prefix: "initial"}
	grant := credbound.OAuthGrant{ID: f.id(), ClientRecordID: client.ID, ResourceID: resource.ID}
	code := credbound.OAuthAuthorizationCode{ID: f.id(), GrantID: grant.ID, Prefix: "code"}
	access := credbound.OAuthAccessToken{ID: f.id(), GrantID: grant.ID, Prefix: "access"}
	refresh := credbound.OAuthRefreshToken{ID: f.id(), GrantID: grant.ID, FamilyID: f.id(), Prefix: "refresh"}
	for index, err := range []error{
		f.store.CreateOAuthIssuer(ctx, issuer, f.event("closed.oauth.issuer.create")),
		f.store.UpdateOAuthIssuer(ctx, issuer, f.event("closed.oauth.issuer.update")),
		f.store.SetOAuthIssuerDisabled(ctx, issuer.ID, true, f.now, f.event("closed.oauth.issuer.disable")),
		f.store.CreateOAuthProtectedResource(ctx, resource, f.event("closed.oauth.resource.create")),
		f.store.SetOAuthProtectedResourceDisabled(ctx, resource.ID, true, f.now, f.event("closed.oauth.resource.disable")),
		f.store.CreateOAuthClient(ctx, client, "", f.now, f.event("closed.oauth.client.create")),
		f.store.UpsertOAuthCIMDClient(ctx, client, f.event("closed.oauth.client.cimd")),
		f.store.SetOAuthClientDisabled(ctx, client.ID, true, f.now, f.event("closed.oauth.client.disable")),
		f.store.CreateOAuthInitialAccessToken(ctx, initial, f.event("closed.oauth.initial.create")),
		f.store.RevokeOAuthInitialAccessToken(ctx, initial.ID, f.now, f.event("closed.oauth.initial.revoke")),
		f.store.CreateOAuthGrantAndCode(ctx, grant, code, f.event("closed.oauth.grant.create")),
		f.store.RevokeOAuthGrant(ctx, grant.ID, f.now, f.event("closed.oauth.grant.revoke")),
		f.store.ConsumeOAuthAuthorizationCode(ctx, code.ID, f.now, access, &refresh, f.event("closed.oauth.code.consume")),
		f.store.RotateOAuthRefreshToken(ctx, refresh.ID, f.now, access, refresh, f.event("closed.oauth.refresh.rotate")),
		f.store.RevokeOAuthAccessToken(ctx, access.ID, f.now, f.event("closed.oauth.access.revoke")),
		f.store.RevokeOAuthRefreshFamily(ctx, refresh.FamilyID, f.now, f.event("closed.oauth.family.revoke")),
	} {
		if err == nil {
			t.Fatalf("closed OAuth mutation %d succeeded", index)
		}
	}
	for index, err := range []error{
		func() error { _, err := f.store.OAuthIssuerByID(ctx, issuer.ID); return err }(),
		func() error { _, err := f.store.OAuthIssuerByURL(ctx, issuer.Issuer); return err }(),
		func() error { _, err := f.store.OAuthProtectedResourceByID(ctx, resource.ID); return err }(),
		func() error { _, err := f.store.OAuthProtectedResourceByURI(ctx, resource.Resource); return err }(),
		func() error { _, err := f.store.OAuthClientByID(ctx, client.ID); return err }(),
		func() error { _, err := f.store.OAuthClientByClientID(ctx, issuer.ID, client.ClientID); return err }(),
		func() error { _, err := f.store.OAuthInitialAccessTokenByPrefix(ctx, initial.Prefix); return err }(),
		func() error { _, err := f.store.OAuthGrant(ctx, grant.ID); return err }(),
		func() error { _, err := f.store.OAuthAuthorizationCodeByPrefix(ctx, code.Prefix); return err }(),
		func() error { _, err := f.store.OAuthAccessTokenByPrefix(ctx, access.Prefix); return err }(),
		func() error { _, err := f.store.OAuthRefreshTokenByPrefix(ctx, refresh.Prefix); return err }(),
	} {
		if err == nil {
			t.Fatalf("closed OAuth lookup %d succeeded", index)
		}
	}
	assertSQLiteAnyError(t, f.store.Passkeys(ctx, f.user.ID))
	assertSQLiteAnyError(t, f.store.PATs(ctx, f.user.ID, credbound.PageRequest{Limit: 50}))
	assertSQLiteAnyError(t, f.store.InstanceAuditEvents(ctx, credbound.PageRequest{Limit: 50}))
	assertSQLiteAnyError(t, f.store.SCIMUsers(ctx, configuration.ID, credbound.SCIMFilter{}, credbound.PageRequest{Limit: 50}))
	assertSQLiteAnyError(t, f.store.SCIMGroups(ctx, configuration.ID, credbound.SCIMFilter{}, credbound.PageRequest{Limit: 50}))
	assertSQLiteAnyError(t, f.store.OAuthIssuers(ctx, credbound.PageRequest{Limit: 50}))
	assertSQLiteAnyError(t, f.store.OAuthProtectedResources(ctx, f.workspace.ID, credbound.PageRequest{Limit: 50}))
	assertSQLiteAnyError(t, f.store.OAuthClients(ctx, issuer.ID, credbound.PageRequest{Limit: 50}))
	assertSQLiteAnyError(t, f.store.OAuthGrants(ctx, f.user.ID, f.workspace.ID, credbound.PageRequest{Limit: 50}))
}

type scannerFunc func(...any) error

func (f scannerFunc) Scan(values ...any) error { return f(values...) }

func assertSQLiteSequenceError[T any](t *testing.T, sequence func(func(T, error) bool), target error) {
	t.Helper()
	seen := false
	for _, err := range sequence {
		seen = true
		if !errors.Is(err, target) {
			t.Fatalf("sequence error = %v, want %v", err, target)
		}
	}
	if !seen {
		t.Fatal("sequence did not yield an error")
	}
}

func assertSQLiteAnyError[T any](t *testing.T, sequence func(func(T, error) bool)) {
	t.Helper()
	seen := false
	for _, err := range sequence {
		seen = true
		if err == nil {
			t.Fatal("sequence yielded a nil error")
		}
	}
	if !seen {
		t.Fatal("sequence did not yield an error")
	}
}
