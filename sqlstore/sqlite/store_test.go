package sqlite_test

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
	"github.com/deepteams/credbound/migrations"
	sqlitestore "github.com/deepteams/credbound/sqlstore/sqlite"
	_ "modernc.org/sqlite"
)

type fixture struct {
	db    *sql.DB
	store *sqlitestore.Store
	next  int
	now   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared&_pragma=foreign_keys(1)&_texttotime=1"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
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
		up := strings.Split(string(migration), "-- +goose Down")[0]
		if _, err := database.Exec(up); err != nil {
			t.Fatalf("apply %s: %v", entry.Name(), err)
		}
	}
	store, err := sqlitestore.New(database, sqlitestore.WithStreamTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{db: database, store: store, next: 1, now: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)}
}

func (f *fixture) id() string {
	value := fmt.Sprintf("0198b463-0000-7000-8000-%012x", f.next)
	f.next++
	return value
}

func (f *fixture) event(actor, action, resource, workspace string) credbound.Commit {
	value := credbound.AuditEvent{
		ID: f.id(), OccurredAt: f.now, ActorID: actor, Action: action,
		ResourceType: "test", ResourceID: resource, WorkspaceID: workspace, Outcome: credbound.AuditSucceeded,
	}
	f.now = f.now.Add(time.Millisecond)
	return credbound.Commit{Audit: value}
}

func (f *fixture) email(user credbound.User) credbound.EmailAddress {
	verifiedAt := f.now
	return credbound.EmailAddress{ID: f.id(), UserID: user.ID, Address: user.Email, Primary: true, VerifiedAt: &verifiedAt, CreatedAt: f.now, UpdatedAt: f.now}
}

func TestStoreContractAndImmutableAudit(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	workspace := credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
	password := credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleAdmin, CreatedAt: f.now, UpdatedAt: f.now}
	admin := credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}
	bootstrapAudit := f.event(user.ID, "bootstrap", workspace.ID, workspace.ID)
	primaryEmail := f.email(user)
	if err := f.store.Bootstrap(ctx, user, primaryEmail, password, workspace, membership, admin, bootstrapAudit); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Bootstrap(ctx, user, primaryEmail, password, workspace, membership, admin, f.event(user.ID, "bootstrap", workspace.ID, workspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("second bootstrap = %v", err)
	}
	if got, err := f.store.UserByEmail(ctx, user.Email); err != nil || got.ID != user.ID {
		t.Fatalf("user by email = %#v, %v", got, err)
	}
	if got, err := f.store.UserByID(ctx, user.ID); err != nil || got.Disabled {
		t.Fatalf("user by id = %#v, %v", got, err)
	}
	if got, err := f.store.PasswordByUserID(ctx, user.ID); err != nil || got.Hash != "hash" {
		t.Fatalf("password = %#v, %v", got, err)
	}
	password.Hash = "new-hash"
	if err := f.store.ReplacePassword(ctx, password, f.event(user.ID, "password", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.store.PasswordByUserID(ctx, user.ID); got.Hash != "new-hash" {
		t.Fatalf("password was not replaced: %#v", got)
	}
	if got, err := f.store.Membership(ctx, workspace.ID, user.ID); err != nil || got.Role != credbound.RoleAdmin {
		t.Fatalf("membership = %#v, %v", got, err)
	}
	if got, err := f.store.InstanceAdministrator(ctx, user.ID); err != nil || got.Role != credbound.InstanceRoleRoot {
		t.Fatalf("admin = %#v, %v", got, err)
	}

	second := credbound.User{ID: f.id(), Email: "dev@example.com", DisplayName: "Dev", CreatedAt: f.now, UpdatedAt: f.now}
	secondMembership := credbound.Membership{WorkspaceID: workspace.ID, UserID: second.ID, Role: credbound.RoleMember, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateUser(ctx, second, f.email(second), credbound.PasswordCredential{UserID: second.ID, Hash: "hash2", UpdatedAt: f.now}, secondMembership, f.event(user.ID, "user.create", second.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	secondMembership.Role = credbound.RoleAdmin
	secondMembership.UpdatedAt = f.now
	if err := f.store.UpsertMembership(ctx, secondMembership, f.event(user.ID, "role", second.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	developer := credbound.InstanceAdministrator{UserID: second.ID, Role: credbound.InstanceRoleDeveloper, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.SetInstanceRole(ctx, developer, f.event(user.ID, "admin.set", second.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RemoveInstanceRole(ctx, second.ID, f.event(user.ID, "admin.remove", second.ID, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.InstanceAdministrator(ctx, second.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("removed admin = %v", err)
	}

	testTOTP(t, f, user)
	testPasskeys(t, f, user)
	testPATs(t, f, user, workspace)

	workspacePage := collectAudit(t, f.store.AuditEvents(ctx, workspace.ID, credbound.PageRequest{Limit: 50}))
	if len(workspacePage) < 2 {
		t.Fatalf("workspace audit events = %d", len(workspacePage))
	}
	instancePage := collectAudit(t, f.store.InstanceAuditEvents(ctx, credbound.PageRequest{Limit: 50}))
	if len(instancePage) < len(workspacePage) {
		t.Fatalf("instance audit events = %d, workspace = %d", len(instancePage), len(workspacePage))
	}
	if _, err := f.db.Exec(`UPDATE credbound_audit_events SET reason = 'tampered' WHERE id = ?`, bootstrapAudit.Audit.ID); err == nil {
		t.Fatal("audit update unexpectedly succeeded")
	}
	if _, err := f.db.Exec(`DELETE FROM credbound_audit_events WHERE id = ?`, bootstrapAudit.Audit.ID); err == nil {
		t.Fatal("audit delete unexpectedly succeeded")
	}
	for _, invalidID := range []string{
		"0198b463-0000-4000-8000-000000000001",
		"0198B463-0000-7000-8000-000000000001",
		"0198b463x0000-7000-8000-000000000001",
		"0198b463-0000-7000-7000-000000000001",
	} {
		_, err := f.db.Exec(`INSERT INTO credbound_users (id, display_name, disabled, created_at, updated_at) VALUES (?, 'Invalid', 0, ?, ?)`, invalidID, f.now, f.now)
		if err == nil {
			t.Fatalf("invalid UUIDv7 %q was accepted", invalidID)
		}
	}
}

func TestEmailSSOAndLastSeenContract(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	workspace := credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
	primary := f.email(user)
	password := credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleAdmin, CreatedAt: f.now, UpdatedAt: f.now}
	admin := credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.Bootstrap(ctx, user, primary, password, workspace, membership, admin, f.event(user.ID, "bootstrap", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}

	pending := credbound.EmailAddress{ID: f.id(), UserID: user.ID, Address: "alias@example.com", CreatedAt: f.now, UpdatedAt: f.now}
	verification := credbound.EmailVerificationCredential{EmailID: pending.ID, Digest: []byte("digest"), ExpiresAt: f.now.Add(time.Hour)}
	if err := f.store.SaveEmail(ctx, pending, verification, f.event(user.ID, "email.add", pending.ID, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UserByEmail(ctx, pending.Address); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("pending email login = %v", err)
	}
	if _, _, err := f.store.EmailVerificationByID(ctx, "0198b463-0000-7000-8000-0000000000ff"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing email verification = %v", err)
	}
	if err := f.store.SetPrimaryEmail(ctx, user.ID, pending.ID, f.event(user.ID, "email.primary.unverified", pending.ID, "")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unverified primary email = %v", err)
	}
	if err := f.store.SetPrimaryEmail(ctx, user.ID, "0198b463-0000-7000-8000-0000000000ff", f.event(user.ID, "email.primary.missing", pending.ID, "")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing primary email = %v", err)
	}
	gotEmail, gotVerification, err := f.store.EmailVerificationByID(ctx, pending.ID)
	if err != nil || gotEmail.Address != pending.Address || string(gotVerification.Digest) != "digest" {
		t.Fatalf("email verification lookup = %#v, %#v, %v", gotEmail, gotVerification, err)
	}
	verifiedAt := f.now.Add(time.Minute)
	if err := f.store.VerifyEmail(ctx, pending.ID, verifiedAt, f.event(user.ID, "email.verify", pending.ID, "")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.UserByEmail(ctx, pending.Address); err != nil || got.ID != user.ID || got.Email != primary.Address {
		t.Fatalf("verified alias lookup = %#v, %v", got, err)
	}
	if err := f.store.SetPrimaryEmail(ctx, user.ID, pending.ID, f.event(user.ID, "email.primary", pending.ID, "")); err != nil {
		t.Fatal(err)
	}
	emailCount := 0
	primaryCount := 0
	for event, err := range f.store.Emails(ctx, user.ID, credbound.PageRequest{Limit: 50}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			emailCount++
			if event.Data.Primary {
				primaryCount++
			}
		}
	}
	if emailCount != 2 || primaryCount != 1 {
		t.Fatalf("email stream = %d emails, %d primary", emailCount, primaryCount)
	}
	pagedItems := 0
	hasMore := false
	for event, err := range f.store.Emails(ctx, user.ID, credbound.PageRequest{Limit: 1}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			pagedItems++
		}
		if event.End != nil {
			hasMore = event.End.HasMore && event.End.NextCursor != ""
		}
	}
	if pagedItems != 1 || !hasMore {
		t.Fatalf("email pagination = %d, hasMore=%v", pagedItems, hasMore)
	}
	if err := f.store.RemoveEmail(ctx, user.ID, primary.ID, f.event(user.ID, "email.remove", primary.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RemoveEmail(ctx, user.ID, pending.ID, f.event(user.ID, "email.remove.primary", pending.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("primary removal = %v", err)
	}

	seenAt := f.now.Add(2 * time.Minute)
	if err := f.store.RecordAuthentication(ctx, user.ID, seenAt, f.event(user.ID, "auth.password", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.UserByID(ctx, user.ID); err != nil || got.LastSeenAt == nil || !got.LastSeenAt.Equal(seenAt) || got.Email != pending.Address {
		t.Fatalf("last seen or primary projection = %#v, %v", got, err)
	}

	identity := credbound.SSOIdentity{
		ID: f.id(), UserID: user.ID, ProviderConfigurationID: f.id(), ProviderKind: credbound.SSOProviderOIDC,
		Issuer: "https://idp.example.com", Subject: "subject", Email: pending.Address, CreatedAt: f.now, LastUsedAt: &seenAt,
	}
	if err := f.store.LinkSSO(ctx, identity, f.event(user.ID, "sso.link", identity.ID, "")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.SSOIdentity(ctx, identity.ProviderConfigurationID, identity.Issuer, identity.Subject); err != nil || got.ID != identity.ID {
		t.Fatalf("SSO lookup = %#v, %v", got, err)
	}
	usedAt := seenAt.Add(time.Minute)
	if err := f.store.TouchSSO(ctx, user.ID, identity.ID, usedAt, f.event(user.ID, "auth.sso", identity.ID, "")); err != nil {
		t.Fatal(err)
	}
	secondIdentity := identity
	secondIdentity.ID = f.id()
	secondIdentity.Subject = "subject-2"
	secondIdentity.LastUsedAt = &usedAt
	if err := f.store.LinkSSO(ctx, secondIdentity, f.event(user.ID, "sso.link", secondIdentity.ID, "")); err != nil {
		t.Fatal(err)
	}
	ssoCount := 0
	for event, err := range f.store.SSOIdentities(ctx, user.ID, credbound.PageRequest{Limit: 50}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			ssoCount++
			if event.Data.LastUsedAt == nil || !event.Data.LastUsedAt.Equal(usedAt) {
				t.Fatalf("SSO last used = %#v", event.Data.LastUsedAt)
			}
		}
	}
	if ssoCount != 2 {
		t.Fatalf("SSO stream count = %d", ssoCount)
	}
	pagedSSO := 0
	hasMoreSSO := false
	for event, err := range f.store.SSOIdentities(ctx, user.ID, credbound.PageRequest{Limit: 1}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			pagedSSO++
		}
		if event.End != nil {
			hasMoreSSO = event.End.HasMore && event.End.NextCursor != ""
		}
	}
	if pagedSSO != 1 || !hasMoreSSO {
		t.Fatalf("SSO pagination = %d, hasMore=%v", pagedSSO, hasMoreSSO)
	}
	if err := f.store.UnlinkSSO(ctx, user.ID, identity.ID, f.event(user.ID, "sso.unlink", identity.ID, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.SSOIdentity(ctx, identity.ProviderConfigurationID, identity.Issuer, identity.Subject); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unlinked SSO lookup = %v", err)
	}

	invalidEmail := pending
	invalidEmail.ID = "0198b463-0000-4000-8000-000000000001"
	invalidEmail.Address = "invalid@example.com"
	if err := f.store.SaveEmail(ctx, invalidEmail, verification, f.event(user.ID, "email.invalid_id", invalidEmail.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("invalid email UUIDv7 = %v", err)
	}
	invalidSSO := identity
	invalidSSO.ID = f.id()
	invalidSSO.ProviderConfigurationID = "0198b463-0000-4000-8000-000000000002"
	if err := f.store.LinkSSO(ctx, invalidSSO, f.event(user.ID, "sso.invalid_id", invalidSSO.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("invalid provider configuration UUIDv7 = %v", err)
	}
}

func TestBootstrapAndCreateUserRollbackBranches(t *testing.T) {
	bootstrapCases := []struct {
		name   string
		mutate func(*fixture, *credbound.User, *credbound.EmailAddress, *credbound.PasswordCredential, *credbound.Workspace, *credbound.Membership, *credbound.InstanceAdministrator)
	}{
		{name: "invalid user", mutate: func(_ *fixture, user *credbound.User, email *credbound.EmailAddress, password *credbound.PasswordCredential, _ *credbound.Workspace, membership *credbound.Membership, admin *credbound.InstanceAdministrator) {
			user.ID = "0198b463-0000-4000-8000-000000000001"
			email.UserID, password.UserID, membership.UserID, admin.UserID = user.ID, user.ID, user.ID, user.ID
		}},
		{name: "invalid email", mutate: func(_ *fixture, _ *credbound.User, email *credbound.EmailAddress, _ *credbound.PasswordCredential, _ *credbound.Workspace, _ *credbound.Membership, _ *credbound.InstanceAdministrator) {
			email.ID = "0198b463-0000-4000-8000-000000000002"
		}},
		{name: "missing password user", mutate: func(f *fixture, _ *credbound.User, _ *credbound.EmailAddress, password *credbound.PasswordCredential, _ *credbound.Workspace, _ *credbound.Membership, _ *credbound.InstanceAdministrator) {
			password.UserID = f.id()
		}},
		{name: "invalid workspace", mutate: func(_ *fixture, _ *credbound.User, _ *credbound.EmailAddress, _ *credbound.PasswordCredential, workspace *credbound.Workspace, membership *credbound.Membership, _ *credbound.InstanceAdministrator) {
			workspace.ID = "0198b463-0000-4000-8000-000000000003"
			membership.WorkspaceID = workspace.ID
		}},
		{name: "missing membership workspace", mutate: func(f *fixture, _ *credbound.User, _ *credbound.EmailAddress, _ *credbound.PasswordCredential, _ *credbound.Workspace, membership *credbound.Membership, _ *credbound.InstanceAdministrator) {
			membership.WorkspaceID = f.id()
		}},
		{name: "missing admin user", mutate: func(f *fixture, _ *credbound.User, _ *credbound.EmailAddress, _ *credbound.PasswordCredential, _ *credbound.Workspace, _ *credbound.Membership, admin *credbound.InstanceAdministrator) {
			admin.UserID = f.id()
		}},
	}
	for _, test := range bootstrapCases {
		t.Run("bootstrap "+test.name, func(t *testing.T) {
			f := newFixture(t)
			user := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
			email := f.email(user)
			password := credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}
			workspace := credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
			membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleAdmin, CreatedAt: f.now, UpdatedAt: f.now}
			admin := credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}
			test.mutate(f, &user, &email, &password, &workspace, &membership, &admin)
			if err := f.store.Bootstrap(context.Background(), user, email, password, workspace, membership, admin, f.event(user.ID, "bootstrap", workspace.ID, workspace.ID)); err == nil {
				t.Fatal("invalid bootstrap unexpectedly committed")
			}
			var instances int
			if err := f.db.QueryRow(`SELECT count(*) FROM credbound_instance`).Scan(&instances); err != nil || instances != 0 {
				t.Fatalf("bootstrap rollback left instance = %d, %v", instances, err)
			}
		})
	}

	createCases := []struct {
		name   string
		mutate func(*fixture, credbound.User, *credbound.User, *credbound.EmailAddress, *credbound.PasswordCredential, *credbound.Membership)
	}{
		{name: "invalid user", mutate: func(_ *fixture, _ credbound.User, user *credbound.User, email *credbound.EmailAddress, password *credbound.PasswordCredential, membership *credbound.Membership) {
			user.ID = "0198b463-0000-4000-8000-000000000010"
			email.UserID, password.UserID, membership.UserID = user.ID, user.ID, user.ID
		}},
		{name: "invalid email", mutate: func(_ *fixture, _ credbound.User, _ *credbound.User, email *credbound.EmailAddress, _ *credbound.PasswordCredential, _ *credbound.Membership) {
			email.ID = "0198b463-0000-4000-8000-000000000011"
		}},
		{name: "duplicate password owner", mutate: func(_ *fixture, root credbound.User, _ *credbound.User, _ *credbound.EmailAddress, password *credbound.PasswordCredential, _ *credbound.Membership) {
			password.UserID = root.ID
		}},
		{name: "missing workspace", mutate: func(f *fixture, _ credbound.User, _ *credbound.User, _ *credbound.EmailAddress, _ *credbound.PasswordCredential, membership *credbound.Membership) {
			membership.WorkspaceID = f.id()
		}},
	}
	for _, test := range createCases {
		t.Run("create "+test.name, func(t *testing.T) {
			f := newFixture(t)
			root, workspace := bootstrapSQLStore(t, f)
			user := credbound.User{ID: f.id(), Email: "new@example.com", DisplayName: "New", CreatedAt: f.now, UpdatedAt: f.now}
			email := f.email(user)
			password := credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}
			membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleMember, CreatedAt: f.now, UpdatedAt: f.now}
			test.mutate(f, root, &user, &email, &password, &membership)
			if err := f.store.CreateUser(context.Background(), user, email, password, membership, f.event(root.ID, "user.create", user.ID, workspace.ID)); err == nil {
				t.Fatal("invalid user creation unexpectedly committed")
			}
			var users int
			if err := f.db.QueryRow(`SELECT count(*) FROM credbound_users`).Scan(&users); err != nil || users != 1 {
				t.Fatalf("create rollback left users = %d, %v", users, err)
			}
		})
	}
}

func bootstrapSQLStore(t *testing.T, f *fixture) (credbound.User, credbound.Workspace) {
	t.Helper()
	user := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	workspace := credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
	password := credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleAdmin, CreatedAt: f.now, UpdatedAt: f.now}
	admin := credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.Bootstrap(context.Background(), user, f.email(user), password, workspace, membership, admin, f.event(user.ID, "bootstrap", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	return user, workspace
}

func testTOTP(t *testing.T, f *fixture, user credbound.User) {
	t.Helper()
	ctx := context.Background()
	factor := credbound.TOTPFactor{UserID: user.ID, EncryptedSecret: []byte("sealed"), CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.SaveTOTPEnrollment(ctx, factor, f.event(user.ID, "totp.begin", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.TOTPByUserID(ctx, user.ID); err != nil || got.Active {
		t.Fatalf("pending TOTP = %#v, %v", got, err)
	}
	factor.Active = true
	factor.UpdatedAt = f.now
	recovery := []credbound.RecoveryCode{{UserID: user.ID, Digest: []byte("recovery")}}
	if err := f.store.ActivateTOTP(ctx, factor, recovery, f.event(user.ID, "totp.activate", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	used, err := f.store.UseTOTP(ctx, user.ID, 42, f.event(user.ID, "totp.use", user.ID, ""))
	if err != nil || !used {
		t.Fatalf("TOTP use = %v, %v", used, err)
	}
	used, err = f.store.UseTOTP(ctx, user.ID, 42, f.event(user.ID, "totp.replay", user.ID, ""))
	if err != nil || used {
		t.Fatalf("TOTP replay = %v, %v", used, err)
	}
	used, err = f.store.ConsumeRecoveryCode(ctx, user.ID, []byte("recovery"), f.now, f.event(user.ID, "recovery.use", user.ID, ""))
	if err != nil || !used {
		t.Fatalf("recovery use = %v, %v", used, err)
	}
	if err := f.store.DisableTOTP(ctx, user.ID, f.event(user.ID, "totp.disable", user.ID, "")); err != nil {
		t.Fatal(err)
	}
}

func testPasskeys(t *testing.T, f *fixture, user credbound.User) {
	t.Helper()
	ctx := context.Background()
	passkey := credbound.Passkey{
		ID: f.id(), UserID: user.ID, Name: "Laptop", CredentialID: []byte("credential"),
		CredentialJSON: []byte("sealed-json"), CreatedAt: f.now,
	}
	if err := f.store.SavePasskey(ctx, passkey, f.event(user.ID, "passkey.create", passkey.ID, "")); err != nil {
		t.Fatal(err)
	}
	count := 0
	for got, err := range f.store.Passkeys(ctx, user.ID) {
		if err != nil || got.ID != passkey.ID {
			t.Fatalf("passkey = %#v, %v", got, err)
		}
		count++
	}
	if count != 1 {
		t.Fatalf("passkey count = %d", count)
	}
	if err := f.store.TouchPasskey(ctx, user.ID, passkey.CredentialID, []byte("updated"), f.now, f.event(user.ID, "passkey.use", passkey.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.DeletePasskey(ctx, user.ID, passkey.ID, f.event(user.ID, "passkey.delete", passkey.ID, "")); err != nil {
		t.Fatal(err)
	}
}

func testPATs(t *testing.T, f *fixture, user credbound.User, workspace credbound.Workspace) {
	t.Helper()
	ctx := context.Background()
	var pats []credbound.PAT
	for index := range 3 {
		pat := credbound.PAT{
			ID: f.id(), UserID: user.ID, Name: fmt.Sprintf("PAT %d", index), Prefix: fmt.Sprintf("prefix%06d", index),
			Digest: []byte{byte(index)}, WorkspaceID: workspace.ID, Scopes: []string{"read"}, CreatedAt: f.now,
		}
		f.now = f.now.Add(time.Second)
		if err := f.store.CreatePAT(ctx, pat, f.event(user.ID, "pat.create", pat.ID, workspace.ID)); err != nil {
			t.Fatal(err)
		}
		pats = append(pats, pat)
	}
	if got, err := f.store.PATByPrefix(ctx, pats[0].Prefix); err != nil || got.ID != pats[0].ID {
		t.Fatalf("PAT lookup = %#v, %v", got, err)
	}
	if err := f.store.TouchPAT(ctx, pats[0].ID, f.now, f.event(user.ID, "pat.use", pats[0].ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	first, cursor := collectPATs(t, f.store.PATs(ctx, user.ID, credbound.PageRequest{Limit: 2}))
	if len(first) != 2 || cursor == "" {
		t.Fatalf("first PAT page = %d, %q", len(first), cursor)
	}
	second, next := collectPATs(t, f.store.PATs(ctx, user.ID, credbound.PageRequest{Limit: 2, Cursor: cursor}))
	if len(second) != 1 || next != "" {
		t.Fatalf("second PAT page = %d, %q", len(second), next)
	}
	if err := f.store.RevokePAT(ctx, user.ID, pats[0].ID, f.now, f.event(user.ID, "pat.revoke", pats[0].ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
}

func collectPATs(t *testing.T, sequence func(func(credbound.PageEvent[credbound.PAT], error) bool)) ([]credbound.PAT, string) {
	t.Helper()
	var values []credbound.PAT
	var cursor string
	for event, err := range sequence {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			values = append(values, *event.Data)
		}
		if event.End != nil {
			cursor = event.End.NextCursor
		}
	}
	return values, cursor
}

func collectAudit(t *testing.T, sequence func(func(credbound.PageEvent[credbound.AuditEvent], error) bool)) []credbound.AuditEvent {
	t.Helper()
	var values []credbound.AuditEvent
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

func TestNewValidationAndContextCancellation(t *testing.T) {
	if _, err := sqlitestore.New(nil); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("nil DB error = %v", err)
	}
	database, err := sql.Open("sqlite", "file:validation?mode=memory")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := sqlitestore.New(database, sqlitestore.WithStreamTimeout(0)); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid timeout error = %v", err)
	}
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, err := range f.store.Passkeys(ctx, "missing") {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled stream error = %v", err)
		}
		return
	}
	t.Fatal("canceled stream did not yield an error")
}

func TestLifecycleStoreContract(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	root := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	original := credbound.Workspace{ID: f.id(), Name: "Original", CreatedAt: f.now, UpdatedAt: f.now}
	rootMembership := credbound.Membership{WorkspaceID: original.ID, UserID: root.ID, Role: credbound.RoleAdmin, Status: credbound.MembershipActive, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.Bootstrap(ctx, root, f.email(root), credbound.PasswordCredential{UserID: root.ID, Hash: "hash", UpdatedAt: f.now}, original, rootMembership, credbound.InstanceAdministrator{UserID: root.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}, f.event(root.ID, "bootstrap", original.ID, original.ID)); err != nil {
		t.Fatal(err)
	}
	user := credbound.User{ID: f.id(), Email: "other@example.com", DisplayName: "Other", CreatedAt: f.now, UpdatedAt: f.now}
	member := credbound.Membership{WorkspaceID: original.ID, UserID: user.ID, Role: credbound.RoleMember, Status: credbound.MembershipActive, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateUser(ctx, user, f.email(user), credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}, member, f.event(root.ID, "user.create", user.ID, original.ID)); err != nil {
		t.Fatal(err)
	}
	workspace := credbound.Workspace{ID: f.id(), Name: "Product", CreatedAt: f.now, UpdatedAt: f.now}
	owner := credbound.Membership{WorkspaceID: workspace.ID, UserID: root.ID, Role: credbound.RoleAdmin, Status: credbound.MembershipActive, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateWorkspace(ctx, workspace, owner, f.event(root.ID, "workspace.create", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.WorkspaceByID(ctx, workspace.ID); err != nil || got.Name != workspace.Name {
		t.Fatalf("workspace = %#v, %v", got, err)
	}
	workspace.Name, workspace.UpdatedAt = "Platform", f.now
	if err := f.store.UpdateWorkspace(ctx, workspace, f.event(root.ID, "workspace.update", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetWorkspaceDisabled(ctx, workspace.ID, true, f.now, f.event(root.ID, "workspace.disable", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.store.WorkspaceByID(ctx, workspace.ID); got.DisabledAt == nil {
		t.Fatal("workspace was not disabled")
	}
	if err := f.store.SetWorkspaceDisabled(ctx, workspace.ID, false, f.now, f.event(root.ID, "workspace.enable", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	member.WorkspaceID, member.UpdatedAt = workspace.ID, f.now
	if err := f.store.UpsertMembership(ctx, member, f.event(root.ID, "membership.add", user.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	workspaceOwner := owner
	workspaceOwner.Status = credbound.MembershipSuspended
	if err := f.store.UpsertMembership(ctx, workspaceOwner, f.event(root.ID, "membership.last_admin.suspend", root.ID, workspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("last active admin suspension = %v", err)
	}
	pat := credbound.PAT{
		ID: f.id(), UserID: user.ID, Name: "Workspace token", Prefix: "membership01", Digest: []byte("digest"),
		WorkspaceID: workspace.ID, Scopes: []string{"read"}, CreatedAt: f.now,
	}
	if err := f.store.CreatePAT(ctx, pat, f.event(root.ID, "pat.create", pat.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	member.Status = credbound.MembershipSuspended
	if err := f.store.UpsertMembership(ctx, member, f.event(root.ID, "membership.suspend", user.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if stored, err := f.store.PATByPrefix(ctx, pat.Prefix); err != nil || stored.RevokedAt == nil {
		t.Fatalf("suspended membership PAT = %#v, %v", stored, err)
	}
	member.Status = credbound.MembershipActive
	if err := f.store.UpsertMembership(ctx, member, f.event(root.ID, "membership.restore", user.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	page := credbound.PageRequest{Limit: 50}
	if values := collectOAuthPage(t, f.store.Users(ctx, page)); len(values) != 2 {
		t.Fatalf("users = %#v", values)
	}
	if values := collectOAuthPage(t, f.store.Workspaces(ctx, page)); len(values) != 2 {
		t.Fatalf("workspaces = %#v", values)
	}
	if values := collectOAuthPage(t, f.store.UserWorkspaces(ctx, user.ID, page)); len(values) != 2 {
		t.Fatalf("user workspaces = %#v", values)
	}
	if values := collectOAuthPage(t, f.store.Memberships(ctx, workspace.ID, page)); len(values) != 2 {
		t.Fatalf("memberships = %#v", values)
	}
	if err := f.store.RemoveMembership(ctx, workspace.ID, root.ID, f.now, f.event(root.ID, "membership.remove", root.ID, workspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("last admin removal = %v", err)
	}
	member.Role = credbound.RoleAdmin
	if err := f.store.UpsertMembership(ctx, member, f.event(root.ID, "membership.role", user.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.UpsertMembership(ctx, workspaceOwner, f.event(root.ID, "membership.admin.suspend", root.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	workspaceOwner.Status = credbound.MembershipActive
	if err := f.store.UpsertMembership(ctx, workspaceOwner, f.event(root.ID, "membership.admin.restore", root.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RemoveMembership(ctx, workspace.ID, root.ID, f.now, f.event(root.ID, "membership.remove", root.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetInstanceRole(ctx, credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}, f.event(root.ID, "admin.set", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.UpsertMembership(ctx, workspaceOwner, f.event(root.ID, "membership.admin.readd", root.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetUserDisabled(ctx, user.ID, true, f.now, f.event(root.ID, "user.disable", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetUserDisabled(ctx, root.ID, true, f.now, f.event(root.ID, "user.disable", root.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("last enabled root disable = %v", err)
	}
	if err := f.store.SetUserDisabled(ctx, user.ID, false, f.now, f.event(root.ID, "user.enable", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	renamed := user
	renamed.DisplayName = "Renamed"
	renamed.UpdatedAt = f.now
	if err := f.store.UpdateUser(ctx, renamed, f.event(root.ID, "user.profile.update", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	stored, err := f.store.UserByID(ctx, user.ID)
	if err != nil || stored.DisplayName != "Renamed" {
		t.Fatalf("renamed user = %#v, %v", stored, err)
	}
	unknown := user
	unknown.ID = f.id()
	if err := f.store.UpdateUser(ctx, unknown, f.event(root.ID, "user.profile.update.missing", unknown.ID, "")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("update of unknown user = %v", err)
	}
}

func TestLifecycleStoreStreamFailures(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	workspace := credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleAdmin, Status: credbound.MembershipActive, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.Bootstrap(ctx, user, f.email(user), credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}, workspace, membership, credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}, f.event(user.ID, "bootstrap", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	for name, sequence := range map[string]func() error{
		"users cursor": func() error {
			return firstOAuthPageError(f.store.Users(ctx, credbound.PageRequest{Cursor: "%%%", Limit: 50}))
		},
		"workspaces cursor": func() error {
			return firstOAuthPageError(f.store.Workspaces(ctx, credbound.PageRequest{Cursor: "%%%", Limit: 50}))
		},
		"memberships cursor": func() error {
			return firstOAuthPageError(f.store.Memberships(ctx, workspace.ID, credbound.PageRequest{Cursor: "%%%", Limit: 50}))
		},
	} {
		if err := sequence(); !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("%s = %v", name, err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	for name, sequence := range map[string]func() error{
		"users": func() error { return firstOAuthPageError(f.store.Users(canceled, credbound.PageRequest{Limit: 50})) },
		"workspaces": func() error {
			return firstOAuthPageError(f.store.Workspaces(canceled, credbound.PageRequest{Limit: 50}))
		},
		"memberships": func() error {
			return firstOAuthPageError(f.store.Memberships(canceled, workspace.ID, credbound.PageRequest{Limit: 50}))
		},
	} {
		if err := sequence(); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled %s = %v", name, err)
		}
	}
}
