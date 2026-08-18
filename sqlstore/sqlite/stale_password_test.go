package sqlite_test

// These tests pin the store-side credential-currency guards on SQLite: the
// guarded sign-in finalization and the session-creation fingerprint check
// both refuse to act once the password credential moved.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

func TestPasswordCurrencyGuards(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	users := f.bootstrapSessionUsers(t)
	user := users.root

	// A finalization whose verified hash is no longer stored is refused and
	// leaves the throttle untouched.
	if _, err := f.store.RecordLoginFailure(ctx, user.ID, f.now, 5, f.now.Add(time.Hour), f.event(user.ID, "auth.failure", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RecordPasswordAuthentication(ctx, user.ID, "stale", f.now, f.event(user.ID, "auth.password.stale", user.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("stale finalization error = %v", err)
	}
	if _, err := f.store.LoginThrottleByUserID(ctx, user.ID); err != nil {
		t.Fatalf("throttle vanished on refused finalization: %v", err)
	}
	// The current hash finalizes and clears the throttle.
	if err := f.store.RecordPasswordAuthentication(ctx, user.ID, "hash", f.now, f.event(user.ID, "auth.password", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.LoginThrottleByUserID(ctx, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("throttle survived a completed sign-in: %v", err)
	}

	// Session creation refuses the fingerprint of a replaced credential and
	// accepts the fingerprint of the current one; an empty digest skips the
	// guard for non-password authentications.
	session := credbound.Session{
		ID: f.id(), UserID: user.ID, Method: credbound.MethodPassword, Level: credbound.AAL1,
		AuthenticatedAt: f.now, UserAgent: "agent", IPAddress: "203.0.113.7", Digest: []byte("digest"),
		CreatedAt: f.now, LastSeenAt: f.now, ExpiresAt: f.now.Add(30 * 24 * time.Hour),
	}
	if err := f.store.CreateSession(ctx, session, credbound.CredentialFingerprint("previous"), f.event(user.ID, "session.create.stale", session.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("stale session error = %v", err)
	}
	if err := f.store.CreateSession(ctx, session, credbound.CredentialFingerprint("hash"), f.event(user.ID, "session.create.current", session.ID, "")); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Millisecond)
	unguarded := session
	unguarded.ID = f.id()
	if err := f.store.CreateSession(ctx, unguarded, nil, f.event(user.ID, "session.create.unguarded", unguarded.ID, "")); err != nil {
		t.Fatal(err)
	}

	// A credential that vanished outright (say, the account went SSO-only)
	// conflicts exactly like a replaced one.
	if _, err := f.db.Exec(`DELETE FROM credbound_password_credentials WHERE user_id = ?`, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RecordPasswordAuthentication(ctx, user.ID, "hash", f.now, f.event(user.ID, "auth.password.vanished", user.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("vanished credential finalization error = %v", err)
	}
	vanished := session
	vanished.ID = f.id()
	if err := f.store.CreateSession(ctx, vanished, credbound.CredentialFingerprint("hash"), f.event(user.ID, "session.create.vanished", vanished.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("vanished credential session error = %v", err)
	}
}
