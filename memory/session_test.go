package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

func (f *storeFixture) session(userID string) credbound.Session {
	session := credbound.Session{
		ID: f.id(), UserID: userID, Method: credbound.MethodPassword, Level: credbound.AAL1,
		AuthenticatedAt: f.now, UserAgent: "agent", IPAddress: "203.0.113.7", Digest: []byte("digest"),
		CreatedAt: f.now, LastSeenAt: f.now, ExpiresAt: f.now.Add(30 * 24 * time.Hour),
	}
	f.now = f.now.Add(time.Millisecond)
	return session
}

func TestSessionStoreLifecycle(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	session := f.session(f.user.ID)
	if err := f.store.CreateSession(ctx, session, nil, f.event("session.create")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateSession(ctx, session, nil, f.event("session.create.duplicate")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate session error = %v", err)
	}
	orphan := f.session(f.id())
	if err := f.store.CreateSession(ctx, orphan, nil, f.event("session.create.orphan")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("orphan session error = %v", err)
	}
	stored, err := f.store.SessionByID(ctx, session.ID)
	if err != nil || string(stored.Digest) != "digest" || stored.UserID != f.user.ID {
		t.Fatalf("stored session = %#v, %v", stored, err)
	}
	// The returned value is a clone: mutating it does not corrupt the store.
	stored.Digest[0] = 'X'
	again, err := f.store.SessionByID(ctx, session.ID)
	if err != nil || string(again.Digest) != "digest" {
		t.Fatalf("session digest aliased: %#v, %v", again, err)
	}
	seen := f.now.Add(time.Hour)
	if err := f.store.TouchSession(ctx, session.ID, seen, f.event("session.touch")); err != nil {
		t.Fatal(err)
	}
	touched, err := f.store.SessionByID(ctx, session.ID)
	if err != nil || !touched.LastSeenAt.Equal(seen) {
		t.Fatalf("touched session = %#v, %v", touched, err)
	}
	user, err := f.store.UserByID(ctx, f.user.ID)
	if err != nil || user.LastSeenAt == nil || !user.LastSeenAt.Equal(seen) {
		t.Fatalf("touch did not update user last seen: %#v, %v", user, err)
	}
	if err := f.store.TouchSession(ctx, f.id(), seen, f.event("session.touch.unknown")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown touch error = %v", err)
	}
	revokedAt := seen.Add(time.Minute)
	if err := f.store.RevokeSession(ctx, session.ID, revokedAt, f.event("session.revoke")); err != nil {
		t.Fatal(err)
	}
	revoked, err := f.store.SessionByID(ctx, session.ID)
	if err != nil || revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(revokedAt) {
		t.Fatalf("revoked session = %#v, %v", revoked, err)
	}
	// A revoked session refuses the touch, so an authentication racing the
	// revocation cannot record activity on a dead session.
	if err := f.store.TouchSession(ctx, session.ID, revokedAt.Add(time.Minute), f.event("session.touch.revoked")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("revoked touch error = %v", err)
	}
	// Re-revoking keeps the first timestamp.
	if err := f.store.RevokeSession(ctx, session.ID, revokedAt.Add(time.Hour), f.event("session.revoke.repeat")); err != nil {
		t.Fatal(err)
	}
	repeat, err := f.store.SessionByID(ctx, session.ID)
	if err != nil || !repeat.RevokedAt.Equal(revokedAt) {
		t.Fatalf("re-revoked session = %#v, %v", repeat, err)
	}
	if err := f.store.RevokeSession(ctx, f.id(), revokedAt, f.event("session.revoke.unknown")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown revoke error = %v", err)
	}
	if err := f.store.RevokeUserSessions(ctx, f.id(), revokedAt, f.event("session.revoke_all.unknown")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown user bulk revoke error = %v", err)
	}
}

func TestSessionStoreListingScrubsDigestsAndPaginates(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	var ids []string
	for range 3 {
		session := f.session(f.user.ID)
		session.CreatedAt = f.now
		if err := f.store.CreateSession(ctx, session, nil, f.event("session.create")); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, session.ID)
	}
	var first []credbound.Session
	var end credbound.PageEnd
	for event, err := range f.store.Sessions(ctx, f.user.ID, credbound.PageRequest{Limit: 2}) {
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
	}
	// Newest first.
	if first[0].ID != ids[2] || first[1].ID != ids[1] {
		t.Fatalf("ordering = %#v", first)
	}
	var second []credbound.Session
	for event, err := range f.store.Sessions(ctx, f.user.ID, credbound.PageRequest{Limit: 2, Cursor: end.NextCursor}) {
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
	if err := firstError(f.store.Sessions(ctx, f.user.ID, credbound.PageRequest{Limit: 2, Cursor: "%%%"})); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid cursor error = %v", err)
	}
}

func firstError(sequence func(func(credbound.PageEvent[credbound.Session], error) bool)) error {
	for _, err := range sequence {
		return err
	}
	return nil
}

func TestSessionCascadesAreAtomic(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	reset := credbound.PasswordResetCredential{ID: f.id(), UserID: f.user.ID, Digest: []byte("reset"), CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	if err := f.store.CreatePasswordReset(ctx, reset, f.event("reset.create")); err != nil {
		t.Fatal(err)
	}
	session := f.session(f.user.ID)
	if err := f.store.CreateSession(ctx, session, nil, f.event("session.create")); err != nil {
		t.Fatal(err)
	}

	// A rejected transaction hook rolls the session revocation back with the
	// rest of the reset.
	boom := errors.New("host write rejected")
	commit := f.event("reset.complete.rejected")
	commit.Transactional = func(context.Context, credbound.Tx) error { return boom }
	err := f.store.CompletePasswordReset(ctx, reset.ID, credbound.PasswordCredential{UserID: f.user.ID, Hash: "new", UpdatedAt: f.now}, f.now, commit)
	if !errors.Is(err, boom) {
		t.Fatalf("rejected reset error = %v", err)
	}
	active, err := f.store.SessionByID(ctx, session.ID)
	if err != nil || active.RevokedAt != nil {
		t.Fatalf("rolled-back reset revoked the session: %#v, %v", active, err)
	}

	// The committed reset revokes it atomically.
	at := f.now
	if err := f.store.CompletePasswordReset(ctx, reset.ID, credbound.PasswordCredential{UserID: f.user.ID, Hash: "new", UpdatedAt: f.now}, at, f.event("reset.complete")); err != nil {
		t.Fatal(err)
	}
	revoked, err := f.store.SessionByID(ctx, session.ID)
	if err != nil || revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(at) {
		t.Fatalf("reset did not revoke the session: %#v, %v", revoked, err)
	}
}

func TestSessionCascadeOnDisableAndCredentialRevocation(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	// A second user so the fixture root is not the last enabled root.
	other := credbound.User{ID: f.id(), Email: "other@example.com", DisplayName: "Other", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: f.workspace.ID, UserID: other.ID, Role: credbound.RoleMember, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateUser(ctx, other, f.email(other), credbound.PasswordCredential{UserID: other.ID, Hash: "hash", UpdatedAt: f.now}, membership, f.event("user.create")); err != nil {
		t.Fatal(err)
	}
	disableSession := f.session(other.ID)
	if err := f.store.CreateSession(ctx, disableSession, nil, f.event("session.create.disable")); err != nil {
		t.Fatal(err)
	}
	at := f.now
	if err := f.store.SetUserDisabled(ctx, other.ID, true, at, f.event("user.disable")); err != nil {
		t.Fatal(err)
	}
	revoked, err := f.store.SessionByID(ctx, disableSession.ID)
	if err != nil || revoked.RevokedAt == nil {
		t.Fatalf("disable did not revoke the session: %#v, %v", revoked, err)
	}
	// Re-enabling never restores sessions.
	if err := f.store.SetUserDisabled(ctx, other.ID, false, f.now, f.event("user.enable")); err != nil {
		t.Fatal(err)
	}
	restored, err := f.store.SessionByID(ctx, disableSession.ID)
	if err != nil || restored.RevokedAt == nil {
		t.Fatalf("enable restored the session: %#v, %v", restored, err)
	}

	credentialSession := f.session(other.ID)
	if err := f.store.CreateSession(ctx, credentialSession, nil, f.event("session.create.credentials")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RevokeUserCredentials(ctx, other.ID, f.now, f.event("credentials.revoke")); err != nil {
		t.Fatal(err)
	}
	swept, err := f.store.SessionByID(ctx, credentialSession.ID)
	if err != nil || swept.RevokedAt == nil {
		t.Fatalf("credential revocation did not revoke the session: %#v, %v", swept, err)
	}
}

func TestRevokeUserSessionsScopesToOneUser(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	other := credbound.User{ID: f.id(), Email: "other@example.com", DisplayName: "Other", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: f.workspace.ID, UserID: other.ID, Role: credbound.RoleMember, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateUser(ctx, other, f.email(other), credbound.PasswordCredential{UserID: other.ID, Hash: "hash", UpdatedAt: f.now}, membership, f.event("user.create")); err != nil {
		t.Fatal(err)
	}
	mine := f.session(f.user.ID)
	theirs := f.session(other.ID)
	if err := f.store.CreateSession(ctx, mine, nil, f.event("session.create.mine")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateSession(ctx, theirs, nil, f.event("session.create.theirs")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RevokeUserSessions(ctx, other.ID, f.now, f.event("session.revoke_all")); err != nil {
		t.Fatal(err)
	}
	kept, err := f.store.SessionByID(ctx, mine.ID)
	if err != nil || kept.RevokedAt != nil {
		t.Fatalf("bulk revocation crossed users: %#v, %v", kept, err)
	}
	gone, err := f.store.SessionByID(ctx, theirs.ID)
	if err != nil || gone.RevokedAt == nil {
		t.Fatalf("bulk revocation missed the target: %#v, %v", gone, err)
	}
}
