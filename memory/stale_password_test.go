package memory

// These tests pin the store-side credential-currency guards: the guarded
// sign-in finalization and the session-creation fingerprint check both refuse
// to act once the password credential moved.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

func TestPasswordCurrencyGuards(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()

	// A finalization whose verified hash is no longer stored is refused and
	// leaves the throttle untouched.
	if _, err := f.store.RecordLoginFailure(ctx, f.user.ID, f.now, 5, f.now.Add(time.Hour), f.event("auth.failure")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RecordPasswordAuthentication(ctx, f.user.ID, "stale", f.now, f.event("auth.password.stale")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("stale finalization error = %v", err)
	}
	if _, err := f.store.LoginThrottleByUserID(ctx, f.user.ID); err != nil {
		t.Fatalf("throttle vanished on refused finalization: %v", err)
	}
	// The current hash finalizes and clears the throttle.
	if err := f.store.RecordPasswordAuthentication(ctx, f.user.ID, "hash", f.now, f.event("auth.password")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.LoginThrottleByUserID(ctx, f.user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("throttle survived a completed sign-in: %v", err)
	}
	if err := f.store.RecordPasswordAuthentication(ctx, f.id(), "hash", f.now, f.event("auth.password.unknown")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown user finalization error = %v", err)
	}

	// Session creation refuses the fingerprint of a replaced credential and
	// accepts the fingerprint of the current one; an empty digest skips the
	// guard for non-password authentications.
	session := f.session(f.user.ID)
	if err := f.store.CreateSession(ctx, session, credbound.CredentialFingerprint("previous"), f.event("session.create.stale")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("stale session error = %v", err)
	}
	if err := f.store.CreateSession(ctx, session, credbound.CredentialFingerprint("hash"), f.event("session.create.current")); err != nil {
		t.Fatal(err)
	}
	unguarded := f.session(f.user.ID)
	if err := f.store.CreateSession(ctx, unguarded, nil, f.event("session.create.unguarded")); err != nil {
		t.Fatal(err)
	}
}
