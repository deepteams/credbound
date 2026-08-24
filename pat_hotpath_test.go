package credbound_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/credboundtest"
	"github.com/deepteams/credbound/memory"
)

// hotPathFixture bootstraps a manager over an inspectable in-memory store and
// issues one PAT, the credential a machine authenticates with on every
// request.
func hotPathFixture(t *testing.T, mutate func(*credbound.Config)) (*credbound.Manager, *memory.Store, *credboundtest.Clock, credbound.IssuedPAT) {
	t.Helper()
	store := memory.New()
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager := credboundtest.NewManager(t, credboundtest.WithStore(store), credboundtest.WithClock(clock),
		credboundtest.WithConfig(mutate))
	authn, _ := credboundtest.Bootstrap(t, manager)
	issued, err := manager.CreatePAT(context.Background(), credboundtest.AAL2(authn.UserID, clock.Now()),
		credbound.CreatePATInput{Name: "machine", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	return manager, store, clock, issued
}

// chainLength reports how many audit events have been appended to the hash
// chain — that is, how many transactions took the instance-wide chain lock.
func chainLength(t *testing.T, store *memory.Store) int64 {
	t.Helper()
	sequence, _, err := store.AuditChainHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return sequence
}

// TestPATTouchIntervalCoalescesWrites pins the hot path: within the interval a
// successful authentication is read-only — no chain lock, no audit event — and
// every store-backed check still runs, so a revoked token is refused on the
// very next request.
func TestPATTouchIntervalCoalescesWrites(t *testing.T) {
	ctx := context.Background()
	manager, store, clock, issued := hotPathFixture(t, func(cfg *credbound.Config) { cfg.PATTouchInterval = time.Minute })

	// The first authentication writes: it is what sets last-used.
	if _, err := manager.AuthenticatePAT(ctx, issued.Token); err != nil {
		t.Fatal(err)
	}
	afterFirst := chainLength(t, store)

	clock.Advance(30 * time.Second)
	for range 50 {
		authn, err := manager.AuthenticatePAT(ctx, issued.Token)
		if err != nil || authn.UserID != issued.PAT.UserID || !authn.HasScope("read") {
			t.Fatalf("authentication inside the interval = %#v, %v", authn, err)
		}
	}
	if got := chainLength(t, store); got != afterFirst {
		t.Fatalf("50 authentications inside the interval appended %d chained events", got-afterFirst)
	}

	// Past the interval the write resumes, exactly once.
	clock.Advance(31 * time.Second)
	if _, err := manager.AuthenticatePAT(ctx, issued.Token); err != nil {
		t.Fatal(err)
	}
	if got := chainLength(t, store); got != afterFirst+1 {
		t.Fatalf("chained events after the interval = %d, want %d", got, afterFirst+1)
	}

	// Revocation is unaffected by the coalescing: the checks above run on
	// every call, so the very next request is refused.
	if err := manager.RevokePAT(ctx, credboundtest.AAL2(issued.PAT.UserID, clock.Now()), issued.PAT.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AuthenticatePAT(ctx, issued.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("revoked token inside the touch interval = %v", err)
	}
}

// TestPATTouchIntervalZeroKeepsPerRequestWrite pins that the coarsening is
// opt-in: the zero value writes on every authentication, as before.
func TestPATTouchIntervalZeroKeepsPerRequestWrite(t *testing.T) {
	ctx := context.Background()
	manager, store, _, issued := hotPathFixture(t, func(*credbound.Config) {})
	before := chainLength(t, store)
	for range 3 {
		if _, err := manager.AuthenticatePAT(ctx, issued.Token); err != nil {
			t.Fatal(err)
		}
	}
	if got := chainLength(t, store); got != before+3 {
		t.Fatalf("chained events = %d, want %d", got, before+3)
	}
}

// TestUnknownPATRejectionStaysOutOfTheChain pins the amplification guard: a
// token matching no record is still audited, but without taking the chain
// lock, while a rejection that names an account stays chained. The chain
// itself must still verify afterwards.
func TestUnknownPATRejectionStaysOutOfTheChain(t *testing.T) {
	ctx := context.Background()
	manager, store, clock, issued := hotPathFixture(t, func(*credbound.Config) {})
	root := credboundtest.AAL2(issued.PAT.UserID, clock.Now())
	before := chainLength(t, store)

	// A well-formed token whose prefix resolves to nothing: what an
	// unauthenticated scanner sends.
	unknown := "cbp_0123456789ab_" + issued.Token[len(issued.Token)-43:]
	for range 25 {
		if _, err := manager.AuthenticatePAT(ctx, unknown); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("unknown token = %v", err)
		}
	}
	if got := chainLength(t, store); got != before {
		t.Fatalf("25 unknown-token rejections appended %d chained events", got-before)
	}
	// Recorded all the same: the scan evidence is in the log, just not in the
	// chain.
	rejections := 0
	for event, err := range store.InstanceAuditEvents(ctx, credbound.PageRequest{Limit: 100}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil && event.Data.Action == "auth.pat" && event.Data.Outcome == credbound.AuditFailed {
			rejections++
			if event.Data.Sequence != 0 || event.Data.Hash != nil {
				t.Fatalf("unknown-token rejection was chained: %#v", *event.Data)
			}
		}
	}
	if rejections != 25 {
		t.Fatalf("recorded rejections = %d, want 25", rejections)
	}

	// A rejection that names an account is evidence about someone, so it
	// stays tamper-evident.
	if err := manager.RevokePAT(ctx, root, issued.PAT.ID); err != nil {
		t.Fatal(err)
	}
	chained := chainLength(t, store)
	if _, err := manager.AuthenticatePAT(ctx, issued.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("revoked token = %v", err)
	}
	if got := chainLength(t, store); got != chained+1 {
		t.Fatalf("revoked-token rejection appended %d chained events, want 1", got-chained)
	}

	if _, err := manager.VerifyAuditChain(ctx, root); err != nil {
		t.Fatalf("VerifyAuditChain = %v", err)
	}
}

// TestUnknownPATRejectionStillFailsClosed pins AUDIT-002 on the unchained
// path: an audit that cannot be written still refuses the authentication
// rather than answering silently.
func TestUnknownPATRejectionStillFailsClosed(t *testing.T) {
	ctx := context.Background()
	manager, store, _, issued := hotPathFixture(t, func(*credbound.Config) {})
	store.SetAuditFailure(errors.New("audit storage down"))
	unknown := "cbp_0123456789ab_" + issued.Token[len(issued.Token)-43:]
	if _, err := manager.AuthenticatePAT(ctx, unknown); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("unknown token with a failing audit store = %v", err)
	}
}

// TestNewRejectsNegativePATTouchInterval pins the configuration guard.
func TestNewRejectsNegativePATTouchInterval(t *testing.T) {
	_, err := credbound.New(credbound.Config{
		Store: memory.New(), Passwords: credboundtest.Passwords{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		PATTouchInterval: -time.Second,
	})
	if !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("negative PAT touch interval = %v", err)
	}
}
