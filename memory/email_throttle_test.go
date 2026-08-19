package memory

import (
	"context"
	"testing"
	"time"
)

// TestClaimEmailIssuancePrunesExpired pins the bookkeeping bound: entries
// older than the cooldown no longer throttle anything and every claim prunes
// them, so anonymous traffic cannot grow the map beyond the current window.
func TestClaimEmailIssuancePrunesExpired(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	base := f.now
	if ok, err := f.store.ClaimEmailIssuance(ctx, "key-a", "password.reset", base, base.Add(-time.Minute)); err != nil || !ok {
		t.Fatalf("first claim = %v, %v", ok, err)
	}
	if ok, err := f.store.ClaimEmailIssuance(ctx, "key-a", "password.reset", base.Add(10*time.Second), base.Add(10*time.Second).Add(-time.Minute)); err != nil || ok {
		t.Fatalf("throttled claim = %v, %v", ok, err)
	}
	later := base.Add(2 * time.Minute)
	if ok, err := f.store.ClaimEmailIssuance(ctx, "key-b", "password.reset", later, later.Add(-time.Minute)); err != nil || !ok {
		t.Fatalf("fresh claim = %v, %v", ok, err)
	}
	f.store.mu.RLock()
	entries := len(f.store.emailIssuance)
	f.store.mu.RUnlock()
	if entries != 1 {
		t.Fatalf("expired issuance entries survived pruning: %d", entries)
	}
}
