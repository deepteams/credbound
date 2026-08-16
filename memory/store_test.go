package memory

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

type storeFixture struct {
	store     *Store
	user      credbound.User
	workspace credbound.Workspace
	now       time.Time
	next      int
}

func newStoreFixture(t *testing.T) *storeFixture {
	t.Helper()
	f := &storeFixture{
		store: New(), now: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC), next: 1,
	}
	f.user = credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	f.workspace = credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: f.workspace.ID, UserID: f.user.ID, Role: credbound.RoleAdmin, CreatedAt: f.now, UpdatedAt: f.now}
	admin := credbound.InstanceAdministrator{UserID: f.user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.Bootstrap(context.Background(), f.user, f.email(f.user), credbound.PasswordCredential{UserID: f.user.ID, Hash: "hash", UpdatedAt: f.now}, f.workspace, membership, admin, f.event("bootstrap")); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *storeFixture) id() string {
	id := fmt.Sprintf("0198b463-0000-7000-8000-%012x", f.next)
	f.next++
	return id
}

func (f *storeFixture) event(action string) credbound.Commit {
	event := credbound.AuditEvent{ID: f.id(), OccurredAt: f.now, ActorID: f.user.ID, Action: action, ResourceType: "test", ResourceID: action, Outcome: credbound.AuditSucceeded}
	f.now = f.now.Add(time.Millisecond)
	return credbound.Commit{Audit: event}
}

func (f *storeFixture) email(user credbound.User) credbound.EmailAddress {
	verifiedAt := f.now
	return credbound.EmailAddress{ID: f.id(), UserID: user.ID, Address: user.Email, Primary: true, VerifiedAt: &verifiedAt, CreatedAt: f.now, UpdatedAt: f.now}
}

func TestTransactionHookRollbackAndLifetime(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	user := credbound.User{ID: f.id(), Email: "transaction@example.com", DisplayName: "Transaction", CreatedAt: f.now, UpdatedAt: f.now}
	email := f.email(user)
	membership := credbound.Membership{WorkspaceID: f.workspace.ID, UserID: user.ID, Role: credbound.RoleMember, CreatedAt: f.now, UpdatedAt: f.now}
	commit := f.event("user.transaction.reject")
	var leaked *Tx
	boom := errors.New("host write rejected")
	commit.Transactional = func(_ context.Context, generic credbound.Tx) error {
		handle, ok := TxFrom(generic)
		if !ok || handle.Kind() != credbound.StoreMemory || handle.Audit().ID != commit.Audit.ID {
			t.Fatalf("invalid memory transaction: %#v", generic)
		}
		leaked = handle
		return boom
	}
	err := f.store.CreateUser(ctx, user, email, credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}, membership, commit)
	if !errors.Is(err, boom) {
		t.Fatalf("transaction error = %v", err)
	}
	if leaked == nil || leaked.Active() {
		t.Fatal("memory transaction lifetime was not bounded by the callback")
	}
	if handle, ok := TxFrom(leaked); ok || handle != nil {
		t.Fatal("expired memory transaction was accepted")
	}
	if _, err := f.store.UserByID(ctx, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("rejected user mutation was not rolled back: %v", err)
	}
	for event, err := range f.store.InstanceAuditEvents(ctx, credbound.PageRequest{Limit: 50}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil && event.Data.ID == commit.Audit.ID {
			t.Fatal("rejected mutation persisted its audit")
		}
	}

	commit = f.event("user.transaction.commit")
	commit.Transactional = func(_ context.Context, generic credbound.Tx) error {
		handle, ok := TxFrom(generic)
		if !ok || !handle.Active() {
			return errors.New("memory transaction unavailable")
		}
		return nil
	}
	if err := f.store.CreateUser(ctx, user, email, credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}, membership, commit); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UserByID(ctx, user.ID); err != nil {
		t.Fatalf("committed user missing: %v", err)
	}
}

func TestCanceledOperations(t *testing.T) {
	f := newStoreFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	password := credbound.PasswordCredential{UserID: f.user.ID}
	factor := credbound.TOTPFactor{UserID: f.user.ID}
	passkey := credbound.Passkey{ID: "passkey", UserID: f.user.ID}
	pat := credbound.PAT{ID: "pat", UserID: f.user.ID}
	membership := credbound.Membership{WorkspaceID: f.workspace.ID, UserID: f.user.ID}
	admin := credbound.InstanceAdministrator{UserID: f.user.ID}
	email := f.email(f.user)
	verification := credbound.EmailVerificationCredential{EmailID: email.ID}
	identity := credbound.SSOIdentity{ID: f.id(), UserID: f.user.ID}
	scimConfiguration := credbound.SCIMConfiguration{ID: f.id(), WorkspaceID: f.workspace.ID}
	scimCredential := credbound.SCIMCredential{ID: f.id(), ConfigurationID: scimConfiguration.ID}
	scimUser := credbound.SCIMUser{ID: f.id(), ConfigurationID: scimConfiguration.ID, UserID: f.user.ID}
	scimGroup := credbound.SCIMGroup{ID: f.id(), ConfigurationID: scimConfiguration.ID}
	event := f.event("canceled")

	checks := []error{
		f.store.Bootstrap(ctx, f.user, f.email(f.user), password, f.workspace, membership, admin, event),
		f.store.CreateUser(ctx, f.user, f.email(f.user), password, membership, event),
		f.store.SetUserDisabled(ctx, f.user.ID, true, f.now, event),
		f.store.ReplacePassword(ctx, password, event),
		f.store.RecordAuthentication(ctx, f.user.ID, f.now, event),
		f.store.SaveEmail(ctx, email, verification, event),
		f.store.VerifyEmail(ctx, email.ID, f.now, event),
		f.store.SetPrimaryEmail(ctx, f.user.ID, email.ID, event),
		f.store.RemoveEmail(ctx, f.user.ID, email.ID, event),
		f.store.SaveTOTPEnrollment(ctx, factor, event),
		f.store.ActivateTOTP(ctx, factor, nil, event),
		f.store.DisableTOTP(ctx, f.user.ID, event),
		f.store.SavePasskey(ctx, passkey, event),
		f.store.TouchPasskey(ctx, f.user.ID, nil, nil, f.now, event),
		f.store.DeletePasskey(ctx, f.user.ID, passkey.ID, event),
		f.store.CreatePAT(ctx, pat, event),
		f.store.TouchPAT(ctx, pat.ID, f.now, event),
		f.store.RevokePAT(ctx, f.user.ID, pat.ID, f.now, event),
		f.store.CreateWorkspace(ctx, f.workspace, membership, event),
		f.store.UpdateWorkspace(ctx, f.workspace, event),
		f.store.SetWorkspaceDisabled(ctx, f.workspace.ID, true, f.now, event),
		f.store.UpsertMembership(ctx, membership, event),
		f.store.RemoveMembership(ctx, f.workspace.ID, f.user.ID, f.now, event),
		f.store.SetInstanceRole(ctx, admin, event),
		f.store.RemoveInstanceRole(ctx, f.user.ID, event),
		f.store.LinkSSO(ctx, identity, event),
		f.store.TouchSSO(ctx, f.user.ID, identity.ID, f.now, event),
		f.store.UnlinkSSO(ctx, f.user.ID, identity.ID, event),
		f.store.CreateSCIMConfiguration(ctx, scimConfiguration, scimCredential, event),
		f.store.SaveSCIMCredential(ctx, scimCredential, event),
		f.store.TouchSCIMCredential(ctx, scimCredential.ID, f.now, event),
		f.store.DisableSCIMConfiguration(ctx, scimConfiguration.ID, f.now, event),
		f.store.CreateSCIMUser(ctx, f.user, email, membership, scimUser, event),
		f.store.AdoptSCIMUser(ctx, membership, scimUser, event),
		f.store.UpdateSCIMUser(ctx, scimUser, membership, true, event),
		f.store.UpsertSCIMGroup(ctx, scimGroup, nil, event),
		f.store.DeleteSCIMGroup(ctx, scimGroup, nil, event),
		f.store.AppendAudit(ctx, event),
	}
	for index, err := range checks {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled mutation %d = %v", index, err)
		}
	}
	if _, err := f.store.UserByEmail(ctx, f.user.Email); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := f.store.UserByID(ctx, f.user.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := f.store.WorkspaceByID(ctx, f.workspace.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := f.store.PasswordByUserID(ctx, f.user.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := f.store.TOTPByUserID(ctx, f.user.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if used, err := f.store.UseTOTP(ctx, f.user.ID, 1, event); used || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled TOTP = %v, %v", used, err)
	}
	if used, err := f.store.ConsumeRecoveryCode(ctx, f.user.ID, nil, f.now, event); used || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled recovery = %v, %v", used, err)
	}
	if _, err := f.store.PATByPrefix(ctx, "prefix"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := f.store.Membership(ctx, f.workspace.ID, f.user.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := f.store.InstanceAdministrator(ctx, f.user.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err := f.store.EmailVerificationByID(ctx, email.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := f.store.SSOIdentity(ctx, identity.ProviderConfigurationID, identity.Issuer, identity.Subject); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := f.store.SCIMConfiguration(ctx, scimConfiguration.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err := f.store.SCIMConfigurationByCredentialPrefix(ctx, "prefix"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := f.store.SCIMUser(ctx, scimConfiguration.ID, scimUser.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := f.store.SCIMUserByExternalID(ctx, scimConfiguration.ID, "external"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := f.store.SCIMUserByUserName(ctx, scimConfiguration.ID, "user"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := f.store.SCIMGroup(ctx, scimConfiguration.ID, scimGroup.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := f.store.SCIMGroupByExternalID(ctx, scimConfiguration.ID, "external"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	assertSequenceError(t, f.store.Passkeys(ctx, f.user.ID), context.Canceled)
	assertSequenceError(t, f.store.Users(ctx, credbound.PageRequest{Limit: 50}), context.Canceled)
	assertSequenceError(t, f.store.Workspaces(ctx, credbound.PageRequest{Limit: 50}), context.Canceled)
	assertSequenceError(t, f.store.UserWorkspaces(ctx, f.user.ID, credbound.PageRequest{Limit: 50}), context.Canceled)
	assertSequenceError(t, f.store.Memberships(ctx, f.workspace.ID, credbound.PageRequest{Limit: 50}), context.Canceled)
	assertSequenceError(t, f.store.Emails(ctx, f.user.ID, credbound.PageRequest{Limit: 50}), context.Canceled)
	assertSequenceError(t, f.store.PATs(ctx, f.user.ID, credbound.PageRequest{Limit: 50}), context.Canceled)
	assertSequenceError(t, f.store.SSOIdentities(ctx, f.user.ID, credbound.PageRequest{Limit: 50}), context.Canceled)
	assertSequenceError(t, f.store.SCIMUsers(ctx, scimConfiguration.ID, credbound.SCIMFilter{}, credbound.PageRequest{Limit: 50}), context.Canceled)
	assertSequenceError(t, f.store.SCIMGroups(ctx, scimConfiguration.ID, credbound.SCIMFilter{}, credbound.PageRequest{Limit: 50}), context.Canceled)
	assertSequenceError(t, f.store.InstanceAuditEvents(ctx, credbound.PageRequest{Limit: 50}), context.Canceled)
}

func TestConflictsNotFoundAndAuditFailures(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	user2 := credbound.User{ID: f.id(), Email: "dev@example.com", DisplayName: "Dev", CreatedAt: f.now, UpdatedAt: f.now}
	membership2 := credbound.Membership{WorkspaceID: f.workspace.ID, UserID: user2.ID, Role: credbound.RoleMember, CreatedAt: f.now, UpdatedAt: f.now}
	password2 := credbound.PasswordCredential{UserID: user2.ID, Hash: "hash", UpdatedAt: f.now}
	if err := f.store.CreateUser(ctx, user2, f.email(user2), password2, membership2, f.event("user.create")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateUser(ctx, user2, f.email(user2), password2, membership2, f.event("duplicate.id")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate user id = %v", err)
	}
	duplicateEmail := user2
	duplicateEmail.ID = f.id()
	if err := f.store.CreateUser(ctx, duplicateEmail, f.email(duplicateEmail), password2, membership2, f.event("duplicate.email")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate email = %v", err)
	}
	missingWorkspace := membership2
	missingWorkspace.WorkspaceID = "missing"
	missingWorkspace.UserID = duplicateEmail.ID
	missingUser := credbound.User{ID: duplicateEmail.ID, Email: "other@example.com"}
	if err := f.store.CreateUser(ctx, missingUser, f.email(missingUser), password2, missingWorkspace, f.event("missing.workspace")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing workspace = %v", err)
	}

	if _, err := f.store.UserByEmail(ctx, "missing@example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.store.UserByID(ctx, "missing"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.store.PasswordByUserID(ctx, "missing"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.store.ReplacePassword(ctx, credbound.PasswordCredential{UserID: "missing"}, f.event("password.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}

	factor := credbound.TOTPFactor{UserID: user2.ID, EncryptedSecret: []byte("sealed"), CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.SaveTOTPEnrollment(ctx, factor, f.event("totp.begin")); err != nil {
		t.Fatal(err)
	}
	active := factor
	active.Active = true
	if err := f.store.ActivateTOTP(ctx, active, nil, f.event("totp.activate")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SaveTOTPEnrollment(ctx, factor, f.event("totp.conflict")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("active enrollment = %v", err)
	}
	if err := f.store.ActivateTOTP(ctx, active, nil, f.event("totp.active")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("active activation = %v", err)
	}
	if used, err := f.store.UseTOTP(ctx, "missing", 1, f.event("totp.missing")); used || !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing TOTP = %v, %v", used, err)
	}
	if err := f.store.DisableTOTP(ctx, "missing", f.event("totp.disable.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}

	passkey := credbound.Passkey{ID: f.id(), UserID: user2.ID, CredentialID: []byte("credential"), CredentialJSON: []byte("json"), CreatedAt: f.now}
	if err := f.store.SavePasskey(ctx, passkey, f.event("passkey.create")); err != nil {
		t.Fatal(err)
	}
	duplicateCredential := passkey
	duplicateCredential.ID = f.id()
	duplicateCredential.UserID = f.user.ID
	if err := f.store.SavePasskey(ctx, duplicateCredential, f.event("passkey.duplicate")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate credential = %v", err)
	}
	if err := f.store.SavePasskey(ctx, credbound.Passkey{ID: f.id(), UserID: "missing", CredentialID: []byte("other")}, f.event("passkey.user.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.store.TouchPasskey(ctx, user2.ID, []byte("missing"), nil, f.now, f.event("passkey.touch.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.store.DeletePasskey(ctx, user2.ID, "missing", f.event("passkey.delete.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}

	pat := credbound.PAT{ID: f.id(), UserID: user2.ID, Prefix: "prefix000001", Digest: []byte("digest"), CreatedAt: f.now}
	if err := f.store.CreatePAT(ctx, pat, f.event("pat.create")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreatePAT(ctx, pat, f.event("pat.id.conflict")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatal(err)
	}
	duplicatePrefix := pat
	duplicatePrefix.ID = f.id()
	if err := f.store.CreatePAT(ctx, duplicatePrefix, f.event("pat.prefix.conflict")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatal(err)
	}
	if err := f.store.CreatePAT(ctx, credbound.PAT{ID: f.id(), UserID: "missing", Prefix: "prefix000002"}, f.event("pat.user.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.store.PATByPrefix(ctx, "missing"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.store.TouchPAT(ctx, "missing", f.now, f.event("pat.touch.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.store.RevokePAT(ctx, f.user.ID, pat.ID, f.now, f.event("pat.owner.mismatch")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}

	if err := f.store.UpsertMembership(ctx, credbound.Membership{WorkspaceID: "missing", UserID: user2.ID}, f.event("membership.workspace.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.store.UpsertMembership(ctx, credbound.Membership{WorkspaceID: f.workspace.ID, UserID: "missing"}, f.event("membership.user.missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.store.Membership(ctx, f.workspace.ID, "missing"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.store.SetInstanceRole(ctx, credbound.InstanceAdministrator{UserID: "missing"}, f.event("admin.user.missing")); !errors.Is(err, credbound.ErrNotFound) {
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

	invalidAudit := credbound.Commit{Audit: credbound.AuditEvent{}}
	if err := f.store.AppendAudit(ctx, invalidAudit); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("invalid audit = %v", err)
	}
	duplicateAudit := f.event("audit.duplicate")
	if err := f.store.AppendAudit(ctx, duplicateAudit); err != nil {
		t.Fatal(err)
	}
	if err := f.store.AppendAudit(ctx, duplicateAudit); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate audit = %v", err)
	}
	f.store.SetAuditFailure(errors.New("disk full"))
	if err := f.store.AppendAudit(ctx, f.event("audit.offline")); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("audit failure = %v", err)
	}

	assertSequenceError(t, f.store.PATs(ctx, user2.ID, credbound.PageRequest{Cursor: "%%%", Limit: 50}), credbound.ErrInvalidInput)
	assertSequenceError(t, f.store.AuditEvents(ctx, f.workspace.ID, credbound.PageRequest{Cursor: "e30", Limit: 50}), credbound.ErrInvalidInput)
}

func TestCursorOrderingAndCloneHelpers(t *testing.T) {
	now := time.Now().UTC()
	cursor, err := decodeCursor(encodeCursor(now, "b"))
	if err != nil || !afterCursor(now, "a", cursor) || afterCursor(now, "c", cursor) {
		t.Fatalf("cursor ordering = %#v, %v", cursor, err)
	}
	if !newer(now, "b", now, "a") || newer(now, "a", now, "b") {
		t.Fatal("stable id ordering is incorrect")
	}
	if _, err := decodeCursor("e30"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("incomplete cursor = %v", err)
	}
	usedAt := now
	recovery := cloneRecovery([]credbound.RecoveryCode{{Digest: []byte("digest"), UsedAt: &usedAt}})
	passkey := clonePasskey(credbound.Passkey{CredentialID: []byte("id"), CredentialJSON: []byte("json"), LastUsedAt: &usedAt})
	pat := clonePAT(credbound.PAT{Digest: []byte("digest"), Scopes: []string{"read"}, ExpiresAt: &usedAt, LastUsedAt: &usedAt, RevokedAt: &usedAt})
	if recovery[0].UsedAt == &usedAt || passkey.LastUsedAt == &usedAt || pat.ExpiresAt == &usedAt || cloneTime(nil) != nil {
		t.Fatal("mutable values were not cloned")
	}
}

func assertSequenceError[T any](t *testing.T, sequence func(func(T, error) bool), target error) {
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
