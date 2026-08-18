package sqlite_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

type sessionUsers struct {
	root      credbound.User
	workspace credbound.Workspace
}

func (f *fixture) bootstrapSessionUsers(t *testing.T) sessionUsers {
	t.Helper()
	ctx := context.Background()
	user := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	workspace := credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleAdmin, CreatedAt: f.now, UpdatedAt: f.now}
	admin := credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.Bootstrap(ctx, user, f.email(user), credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}, workspace, membership, admin, f.event(user.ID, "bootstrap", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	return sessionUsers{root: user, workspace: workspace}
}

func (f *fixture) newSessionMember(t *testing.T, users sessionUsers, email string) credbound.User {
	t.Helper()
	ctx := context.Background()
	user := credbound.User{ID: f.id(), Email: email, DisplayName: "Member", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: users.workspace.ID, UserID: user.ID, Role: credbound.RoleMember, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateUser(ctx, user, f.email(user), credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}, membership, f.event(users.root.ID, "user.create", user.ID, users.workspace.ID)); err != nil {
		t.Fatal(err)
	}
	return user
}

func (f *fixture) newSession(t *testing.T, userID string) credbound.Session {
	t.Helper()
	session := credbound.Session{
		ID: f.id(), UserID: userID, Method: credbound.MethodPassword, Level: credbound.AAL2,
		AuthenticatedAt: f.now, SecondFactorRequired: true,
		UserAgent: "agent", IPAddress: "203.0.113.7", Digest: []byte("digest"),
		CreatedAt: f.now, LastSeenAt: f.now, ExpiresAt: f.now.Add(30 * 24 * time.Hour),
	}
	f.now = f.now.Add(time.Millisecond)
	if err := f.store.CreateSession(context.Background(), session, nil, f.event(userID, "session.create", session.ID, "")); err != nil {
		t.Fatal(err)
	}
	return session
}

func TestSessionStoreLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	users := f.bootstrapSessionUsers(t)
	user := users.root
	session := f.newSession(t, user.ID)

	if err := f.store.CreateSession(ctx, session, nil, f.event(user.ID, "session.duplicate", session.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate session error = %v", err)
	}
	orphan := session
	orphan.ID = f.id()
	orphan.UserID = f.id()
	if err := f.store.CreateSession(ctx, orphan, nil, f.event(user.ID, "session.orphan", orphan.ID, "")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("orphan session error = %v", err)
	}

	stored, err := f.store.SessionByID(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.UserID != user.ID || stored.Method != credbound.MethodPassword || stored.Level != credbound.AAL2 ||
		!stored.SecondFactorRequired || stored.UserAgent != "agent" || stored.IPAddress != "203.0.113.7" ||
		string(stored.Digest) != "digest" || stored.RevokedAt != nil {
		t.Fatalf("stored session = %#v", stored)
	}
	if !stored.AuthenticatedAt.Equal(session.AuthenticatedAt) || !stored.ExpiresAt.Equal(session.ExpiresAt) {
		t.Fatalf("session timestamps drifted: %#v", stored)
	}

	seen := f.now.Add(time.Hour)
	if err := f.store.TouchSession(ctx, session.ID, seen, f.event(user.ID, "session.touch", session.ID, "")); err != nil {
		t.Fatal(err)
	}
	touched, err := f.store.SessionByID(ctx, session.ID)
	if err != nil || !touched.LastSeenAt.Equal(seen) {
		t.Fatalf("touched session = %#v, %v", touched, err)
	}
	refreshed, err := f.store.UserByID(ctx, user.ID)
	if err != nil || refreshed.LastSeenAt == nil || !refreshed.LastSeenAt.Equal(seen) {
		t.Fatalf("touch did not update user last seen: %#v, %v", refreshed, err)
	}
	if err := f.store.TouchSession(ctx, f.id(), seen, f.event(user.ID, "session.touch.unknown", "x", "")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown touch error = %v", err)
	}

	revokedAt := seen.Add(time.Minute)
	if err := f.store.RevokeSession(ctx, session.ID, revokedAt, f.event(user.ID, "session.revoke", session.ID, "")); err != nil {
		t.Fatal(err)
	}
	revoked, err := f.store.SessionByID(ctx, session.ID)
	if err != nil || revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(revokedAt) {
		t.Fatalf("revoked session = %#v, %v", revoked, err)
	}
	// A revoked session refuses the touch, so an authentication racing the
	// revocation cannot record activity on a dead session.
	if err := f.store.TouchSession(ctx, session.ID, revokedAt.Add(time.Minute), f.event(user.ID, "session.touch.revoked", session.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("revoked touch error = %v", err)
	}
	// Re-revoking is idempotent and keeps the first timestamp.
	if err := f.store.RevokeSession(ctx, session.ID, revokedAt.Add(time.Hour), f.event(user.ID, "session.revoke.repeat", session.ID, "")); err != nil {
		t.Fatal(err)
	}
	repeat, err := f.store.SessionByID(ctx, session.ID)
	if err != nil || !repeat.RevokedAt.Equal(revokedAt) {
		t.Fatalf("re-revoked session = %#v, %v", repeat, err)
	}
	if err := f.store.RevokeSession(ctx, f.id(), revokedAt, f.event(user.ID, "session.revoke.unknown", "x", "")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown revoke error = %v", err)
	}
	if err := f.store.RevokeUserSessions(ctx, f.id(), revokedAt, f.event(user.ID, "session.revoke_all.unknown", "x", "")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown user bulk revoke error = %v", err)
	}
	if _, err := f.store.SessionByID(ctx, f.id()); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown session lookup error = %v", err)
	}
}

func TestSessionStoreListingScrubsDigestsAndPaginates(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	users := f.bootstrapSessionUsers(t)
	user := users.root
	other := f.newSessionMember(t, users, "other@example.com")
	f.newSession(t, other.ID)
	var ids []string
	for range 3 {
		f.now = f.now.Add(time.Second)
		ids = append(ids, f.newSession(t, user.ID).ID)
	}
	var first []credbound.Session
	var end credbound.PageEnd
	for event, err := range f.store.Sessions(ctx, user.ID, credbound.PageRequest{Limit: 2}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			first = append(first, *event.Data)
		}
		if event.End != nil {
			end = *event.End
		}
	}
	if len(first) != 2 || !end.HasMore || end.NextCursor == "" {
		t.Fatalf("first page = %#v %#v", first, end)
	}
	for _, session := range first {
		if session.Digest != nil {
			t.Fatalf("listing leaked a digest: %#v", session)
		}
		if session.UserID != user.ID {
			t.Fatalf("listing crossed users: %#v", session)
		}
	}
	if first[0].ID != ids[2] || first[1].ID != ids[1] {
		t.Fatalf("ordering = %#v", first)
	}
	var second []credbound.Session
	for event, err := range f.store.Sessions(ctx, user.ID, credbound.PageRequest{Limit: 2, Cursor: end.NextCursor}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			second = append(second, *event.Data)
		}
		if event.End != nil {
			end = *event.End
		}
	}
	if len(second) != 1 || second[0].ID != ids[0] || end.HasMore {
		t.Fatalf("second page = %#v %#v", second, end)
	}
	for _, err := range f.store.Sessions(ctx, user.ID, credbound.PageRequest{Limit: 2, Cursor: "%%%"}) {
		if !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("invalid cursor error = %v", err)
		}
		break
	}
}

func TestSessionCascadesAreAtomic(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	users := f.bootstrapSessionUsers(t)
	user := users.root
	session := f.newSession(t, user.ID)
	reset := credbound.PasswordResetCredential{ID: f.id(), UserID: user.ID, Digest: []byte("reset"), CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	if err := f.store.CreatePasswordReset(ctx, reset, f.event(user.ID, "reset.create", reset.ID, "")); err != nil {
		t.Fatal(err)
	}

	// A rejected transaction hook rolls the whole reset back, session included.
	boom := errors.New("host write rejected")
	commit := f.event(user.ID, "reset.complete.rejected", reset.ID, "")
	commit.Transactional = func(context.Context, credbound.Tx) error { return boom }
	err := f.store.CompletePasswordReset(ctx, reset.ID, credbound.PasswordCredential{UserID: user.ID, Hash: "new", UpdatedAt: f.now}, f.now, commit)
	if !errors.Is(err, boom) {
		t.Fatalf("rejected reset error = %v", err)
	}
	active, err := f.store.SessionByID(ctx, session.ID)
	if err != nil || active.RevokedAt != nil {
		t.Fatalf("rolled-back reset revoked the session: %#v, %v", active, err)
	}

	at := f.now
	if err := f.store.CompletePasswordReset(ctx, reset.ID, credbound.PasswordCredential{UserID: user.ID, Hash: "new", UpdatedAt: f.now}, at, f.event(user.ID, "reset.complete", reset.ID, "")); err != nil {
		t.Fatal(err)
	}
	revoked, err := f.store.SessionByID(ctx, session.ID)
	if err != nil || revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(at) {
		t.Fatalf("reset did not revoke the session: %#v, %v", revoked, err)
	}
}

func TestSessionCascadeOnDisableAndCredentialRevocation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	users := f.bootstrapSessionUsers(t)
	root := users.root
	member := f.newSessionMember(t, users, "member@example.com")
	rootSession := f.newSession(t, root.ID)
	memberSession := f.newSession(t, member.ID)

	at := f.now
	if err := f.store.SetUserDisabled(ctx, member.ID, true, at, f.event(root.ID, "user.disable", member.ID, "")); err != nil {
		t.Fatal(err)
	}
	revoked, err := f.store.SessionByID(ctx, memberSession.ID)
	if err != nil || revoked.RevokedAt == nil {
		t.Fatalf("disable did not revoke the session: %#v, %v", revoked, err)
	}
	kept, err := f.store.SessionByID(ctx, rootSession.ID)
	if err != nil || kept.RevokedAt != nil {
		t.Fatalf("disable crossed users: %#v, %v", kept, err)
	}
	// Re-enabling never restores sessions.
	if err := f.store.SetUserDisabled(ctx, member.ID, false, f.now, f.event(root.ID, "user.enable", member.ID, "")); err != nil {
		t.Fatal(err)
	}
	restored, err := f.store.SessionByID(ctx, memberSession.ID)
	if err != nil || restored.RevokedAt == nil {
		t.Fatalf("enable restored the session: %#v, %v", restored, err)
	}

	replacement := f.newSession(t, member.ID)
	if err := f.store.RevokeUserCredentials(ctx, member.ID, f.now, f.event(root.ID, "credentials.revoke", member.ID, "")); err != nil {
		t.Fatal(err)
	}
	swept, err := f.store.SessionByID(ctx, replacement.ID)
	if err != nil || swept.RevokedAt == nil {
		t.Fatalf("credential revocation did not revoke the session: %#v, %v", swept, err)
	}

	// Bulk revocation targets a single user.
	rootReplacement := f.newSession(t, root.ID)
	if err := f.store.RevokeUserSessions(ctx, member.ID, f.now, f.event(root.ID, "session.revoke_all", member.ID, "")); err != nil {
		t.Fatal(err)
	}
	still, err := f.store.SessionByID(ctx, rootReplacement.ID)
	if err != nil || still.RevokedAt != nil {
		t.Fatalf("bulk revocation crossed users: %#v, %v", still, err)
	}
}

// TestAnonymizeUserConcurrentRootGuard exercises the TOCTOU that would erase
// the last root administrator: two concurrent anonymizations, each targeting a
// distinct root, must not both succeed. SQLite has no row-level locking, so the
// guard holds only because the store serializes write transactions (a single
// pooled connection); the second anonymization then reads the first's
// committed state and reports ErrConflict.
func TestAnonymizeUserConcurrentRootGuard(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	users := f.bootstrapSessionUsers(t)
	second := f.newSessionMember(t, users, "second-root@example.com")
	if err := f.store.SetInstanceRole(ctx, credbound.InstanceAdministrator{UserID: second.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}, f.event(users.root.ID, "admin.set", second.ID, "")); err != nil {
		t.Fatal(err)
	}

	// Build both commits before launching goroutines: the fixture's id/now
	// counters are not safe for concurrent use.
	firstCommit := f.event(users.root.ID, "user.anonymize", users.root.ID, "")
	secondCommit := f.event(second.ID, "user.anonymize", second.ID, "")
	targets := []struct {
		userID string
		commit credbound.Commit
	}{{users.root.ID, firstCommit}, {second.ID, secondCommit}}

	var wg sync.WaitGroup
	errs := make([]error, len(targets))
	wg.Add(len(targets))
	for i, target := range targets {
		go func(i int, userID string, commit credbound.Commit) {
			defer wg.Done()
			errs[i] = f.store.AnonymizeUser(ctx, userID, f.now, commit)
		}(i, target.userID, target.commit)
	}
	wg.Wait()

	succeeded, conflicted := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, credbound.ErrConflict):
			conflicted++
		default:
			t.Fatalf("unexpected anonymize error = %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("want exactly one success and one conflict, got %d success / %d conflict", succeeded, conflicted)
	}
	// A root administrator must remain enabled.
	rootStill, err := f.store.UserByID(ctx, users.root.ID)
	if err != nil {
		t.Fatal(err)
	}
	secondStill, err := f.store.UserByID(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rootStill.Disabled == secondStill.Disabled {
		t.Fatalf("exactly one root must remain enabled: root disabled=%v second disabled=%v", rootStill.Disabled, secondStill.Disabled)
	}
}

func TestAnonymizeUserStore(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	users := f.bootstrapSessionUsers(t)
	member := f.newSessionMember(t, users, "member@example.com")
	pat := credbound.PAT{
		ID: f.id(), UserID: member.ID, Name: "member token", Prefix: "aabbccddeeff",
		Digest: []byte("digest"), WorkspaceID: users.workspace.ID, Scopes: []string{"read"}, CreatedAt: f.now,
	}
	if err := f.store.CreatePAT(ctx, pat, f.event(member.ID, "pat.create", pat.ID, users.workspace.ID)); err != nil {
		t.Fatal(err)
	}
	session := f.newSession(t, member.ID)

	if err := f.store.AnonymizeUser(ctx, member.ID, f.now, f.event(users.root.ID, "user.anonymize", member.ID, "")); err != nil {
		t.Fatalf("anonymize = %v", err)
	}

	// Profile scrubbed and disabled.
	got, err := f.store.UserByID(ctx, member.ID)
	if err != nil || got.DisplayName != "" || !got.Disabled {
		t.Fatalf("user after anonymize = %#v, %v", got, err)
	}
	// Email replaced by a unique tombstone.
	var address string
	for event, err := range f.store.Emails(ctx, member.ID, credbound.PageRequest{Limit: 10}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			address = event.Data.Address
		}
	}
	if address == "member@example.com" || !strings.HasPrefix(address, "anonymized-") {
		t.Fatalf("email not tombstoned: %q", address)
	}
	// PAT name cleared and revoked.
	for event, err := range f.store.PATs(ctx, member.ID, credbound.PageRequest{Limit: 10}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil && (event.Data.Name != "" || event.Data.RevokedAt == nil) {
			t.Fatalf("PAT not scrubbed/revoked: %#v", event.Data)
		}
	}
	// Session IP/User-Agent scrubbed.
	stored, err := f.store.SessionByID(ctx, session.ID)
	if err != nil || stored.UserAgent != "" || stored.IPAddress != "" {
		t.Fatalf("session not scrubbed: %#v, %v", stored, err)
	}

	// A user who solely administers a workspace cannot be anonymized: the
	// disable would orphan the workspace, so the store refuses with
	// ErrConflict and leaves the account untouched.
	owner := f.newSessionMember(t, users, "owner@example.com")
	solo := credbound.Workspace{ID: f.id(), Name: "Solo", CreatedAt: f.now, UpdatedAt: f.now}
	soloMembership := credbound.Membership{WorkspaceID: solo.ID, UserID: owner.ID, Role: credbound.RoleAdmin, Status: credbound.MembershipActive, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateWorkspace(ctx, solo, soloMembership, f.event(owner.ID, "workspace.create", solo.ID, solo.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.AnonymizeUser(ctx, owner.ID, f.now, f.event(users.root.ID, "user.anonymize.orphan", owner.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("orphaning anonymize error = %v", err)
	}
	untouched, err := f.store.UserByID(ctx, owner.ID)
	if err != nil || untouched.Disabled || untouched.DisplayName == "" {
		t.Fatalf("refused anonymize mutated the user: %#v, %v", untouched, err)
	}
}
