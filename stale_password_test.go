package credbound_test

// These tests pin the credential-currency guarantee: a password sign-in that
// verified against a hash concurrently replaced by ChangePassword (or a
// reset) must neither finalize nor mint a session, while a concurrent
// transparent rehash of the same password must stay invisible.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
)

// stalePasswordStore steers the finalization guard from the outside: it can
// force RecordPasswordAuthentication outcomes and replace what re-reads of
// the password credential observe, so every conflict-resolution branch is
// reachable deterministically.
type stalePasswordStore struct {
	*memory.Store
	recordErr     error
	passwordReads int
	// laterCredential, when set, is returned by every PasswordByUserID call
	// after the first (the sign-in's initial load); laterErr takes precedence.
	laterCredential *credbound.PasswordCredential
	laterErr        error
}

func (s *stalePasswordStore) RecordPasswordAuthentication(ctx context.Context, userID, currentHash string, seenAt time.Time, commit credbound.Commit) error {
	if s.recordErr != nil {
		return s.recordErr
	}
	return s.Store.RecordPasswordAuthentication(ctx, userID, currentHash, seenAt, commit)
}

func (s *stalePasswordStore) PasswordByUserID(ctx context.Context, userID string) (credbound.PasswordCredential, error) {
	s.passwordReads++
	if s.passwordReads > 1 {
		if s.laterErr != nil {
			return credbound.PasswordCredential{}, s.laterErr
		}
		if s.laterCredential != nil {
			return *s.laterCredential, nil
		}
	}
	return s.Store.PasswordByUserID(ctx, userID)
}

// TestAuthenticatePasswordRefusesConcurrentlyReplacedPassword interleaves a
// password change inside a sign-in's verification window: the sign-in loaded
// and verified the old hash, but the guarded finalization must notice the
// credential moved and answer like a wrong password.
func TestAuthenticatePasswordRefusesConcurrentlyReplacedPassword(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()
	changed := false
	f.passwords.onVerify = func() {
		if changed {
			return
		}
		changed = true
		if err := f.manager.ChangePassword(ctx, authn, "correct horse battery", "brand new passphrase"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("stale sign-in error = %v", err)
	}
	f.passwords.onVerify = nil
	// The old password stays dead and the new one works.
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("replaced password error = %v", err)
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "brand new passphrase"); err != nil {
		t.Fatal(err)
	}
}

// TestCreateSessionRefusesStalePasswordAuthentication covers the second half
// of the race: an Authentication returned before the change must not mint a
// session afterwards, even though the change's revocation sweep already ran.
func TestCreateSessionRefusesStalePasswordAuthentication(t *testing.T) {
	f := newFixture(t)
	f.bootstrap(t)
	ctx := context.Background()
	authn, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.CreateSession(ctx, authn, credbound.CreateSessionInput{}); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.ChangePassword(ctx, authn, "correct horse battery", "brand new passphrase"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.CreateSession(ctx, authn, credbound.CreateSessionInput{}); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("stale session creation error = %v", err)
	}
	fresh, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "brand new passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.CreateSession(ctx, fresh, credbound.CreateSessionInput{}); err != nil {
		t.Fatal(err)
	}
}

// TestPasswordFinalizationConflictResolution drives every branch of the
// conflict resolution that follows a refused finalization: infrastructure
// failures pass through, a vanished or replaced credential answers like a
// wrong password, and an endlessly moving hash exhausts its retries instead
// of spinning.
func TestPasswordFinalizationConflictResolution(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*stalePasswordStore, *fakePasswords, *credbound.Manager) {
		t.Helper()
		store := &stalePasswordStore{Store: memory.New()}
		passwords := &fakePasswords{}
		manager := managerWith(t, store, passwords, fakeTOTP{}, &fakePasskeys{}, nil)
		if _, _, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
			Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
		}); err != nil {
			t.Fatal(err)
		}
		store.passwordReads = 0
		return store, passwords, manager
	}

	t.Run("finalization infrastructure failure", func(t *testing.T) {
		store, _, manager := setup(t)
		store.recordErr = errors.New("finalization offline")
		if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err == nil || errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("infrastructure failure = %v", err)
		}
	})
	t.Run("credential vanished", func(t *testing.T) {
		store, _, manager := setup(t)
		store.recordErr = credbound.ErrConflict
		store.laterErr = credbound.ErrNotFound
		if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("vanished credential error = %v", err)
		}
	})
	t.Run("re-read infrastructure failure", func(t *testing.T) {
		store, _, manager := setup(t)
		store.recordErr = credbound.ErrConflict
		store.laterErr = errors.New("credential storage offline")
		if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err == nil || errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("re-read failure = %v", err)
		}
	})
	t.Run("re-verification failure", func(t *testing.T) {
		store, passwords, manager := setup(t)
		store.recordErr = credbound.ErrConflict
		store.laterCredential = &credbound.PasswordCredential{UserID: "user", Hash: "hash:correct horse battery#7"}
		calls := 0
		passwords.onVerify = func() {
			calls++
			if calls == 2 {
				passwords.verifyErr = errors.New("hasher exploded")
			}
		}
		if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err == nil || !stringsContains(err.Error(), "verify password") {
			t.Fatalf("re-verification failure = %v", err)
		}
	})
	t.Run("retries exhausted", func(t *testing.T) {
		store, _, manager := setup(t)
		// The store keeps answering conflict while the credential still
		// verifies (an endlessly rehashing peer): the sign-in gives up after
		// its bounded retries rather than spinning.
		store.recordErr = credbound.ErrConflict
		store.laterCredential = &credbound.PasswordCredential{UserID: "user", Hash: "hash:correct horse battery#7"}
		if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("exhausted retries error = %v", err)
		}
	})
}

// TestAuthenticatePasswordToleratesConcurrentRehash pins the benign half of
// the guard: a concurrent transparent rehash moves the stored hash without
// changing the password, and the interrupted sign-in must still succeed by
// retrying against the refreshed hash.
func TestAuthenticatePasswordToleratesConcurrentRehash(t *testing.T) {
	f := newFixture(t)
	f.passwords.varyHashes = true
	f.passwords.rehash = true
	f.bootstrap(t)
	ctx := context.Background()
	raced := false
	f.passwords.onVerify = func() {
		if raced {
			return
		}
		raced = true
		// A parallel sign-in of the same user rehashes the same password to a
		// fresh encoding while ours is mid-verification.
		if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err != nil {
		t.Fatalf("rehash-raced sign-in error = %v", err)
	}
}
