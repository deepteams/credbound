// Package credboundtest provides deterministic test doubles and constructors
// for host services that integrate github.com/deepteams/credbound.
//
// NewManager builds a fully wired *credbound.Manager backed by the in-memory
// store, a fast fake password hasher, a deterministic clock and random source,
// and TOTP/passkey fakes whose enrollment and verification flows succeed with
// fixed inputs. Use it in host-service tests to exercise real Credbound flows
// — bootstrap, sign-in, second factors, step-up, PATs — without Argon2
// latency, real WebAuthn ceremonies, or wall-clock coupling.
//
// Nothing in this package is safe for production use. Passwords stores a
// recoverable marker instead of a real hash, TOTP accepts the fixed code
// ValidTOTPCode, AAL2 mints an assurance level that only a real second factor
// may produce in production, and the deterministic random source is
// predictable by design. Import it from _test files only.
package credboundtest

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
)

// DefaultStartTime is the initial instant of the deterministic clock used by
// NewManager when no WithClock option is given. Tests can rely on it when
// asserting timestamps or constructing an AAL2 step-up for a manager whose
// clock was never advanced.
var DefaultStartTime = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// Fixed identity used by Bootstrap. The password satisfies the default
// minimum length of twelve characters.
const (
	// BootstrapEmail is the primary address of the bootstrapped root user.
	BootstrapEmail = "root@example.com"
	// BootstrapPassword is the password of the bootstrapped root user.
	BootstrapPassword = "correct horse battery staple"
	// BootstrapDisplayName is the display name of the bootstrapped root user.
	BootstrapDisplayName = "Root"
	// BootstrapWorkspaceName is the name of the bootstrapped workspace.
	BootstrapWorkspaceName = "Main"
)

// Clock is a manually driven time source for deterministic tests. It only
// moves when Advance or Set is called, so freshness windows such as
// Config.StepUpMaxAge and TOTP steps are fully under test control. It is safe
// for concurrent use.
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

// NewClock returns a Clock frozen at start.
func NewClock(start time.Time) *Clock {
	return &Clock{now: start}
}

// Now returns the current instant of the clock. Pass the method value
// (clock.Now) as credbound.Config.Clock.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d. Use it to cross freshness boundaries,
// for example Advance(30*time.Second) between two TOTP verifications so the
// second code lands on a new step, or Advance past Config.StepUpMaxAge to
// expire a step-up.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Set moves the clock to the absolute instant at.
func (c *Clock) Set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = at
}

// settings collects the overridable parts of the manager built by NewManager.
type settings struct {
	clock        *Clock
	random       io.Reader
	store        credbound.Store
	policy       credbound.PasswordPolicy
	ssoProviders []credbound.SSOProvider
	hooks        []credbound.TransactionHook
	listeners    []credbound.EventListener
	mutators     []func(*credbound.Config)
}

// Option customizes the manager built by NewManager.
type Option func(*settings)

// WithClock replaces the manager's time source. Keep a reference to the clock
// to advance time from the test.
func WithClock(clock *Clock) Option {
	return func(s *settings) { s.clock = clock }
}

// WithRandom replaces the deterministic random source, for example with
// crypto/rand.Reader when a test needs unpredictable tokens.
func WithRandom(random io.Reader) Option {
	return func(s *settings) { s.random = random }
}

// WithStore replaces the default in-memory store, for example with a
// migration-applied SQLite store to test against real persistence.
func WithStore(store credbound.Store) Option {
	return func(s *settings) { s.store = store }
}

// WithPasswordPolicy installs an additional password vetting policy, mirroring
// credbound.Config.PasswordPolicy.
func WithPasswordPolicy(policy credbound.PasswordPolicy) Option {
	return func(s *settings) { s.policy = policy }
}

// WithSSOProviders registers SSO providers, mirroring
// credbound.Config.SSOProviders.
func WithSSOProviders(providers ...credbound.SSOProvider) Option {
	return func(s *settings) { s.ssoProviders = providers }
}

// WithTransactionHooks registers transaction hooks, mirroring
// credbound.Config.TransactionHooks.
func WithTransactionHooks(hooks ...credbound.TransactionHook) Option {
	return func(s *settings) { s.hooks = hooks }
}

// WithEventListeners registers post-commit event listeners, mirroring
// credbound.Config.EventListeners.
func WithEventListeners(listeners ...credbound.EventListener) Option {
	return func(s *settings) { s.listeners = listeners }
}

// WithConfig applies an arbitrary mutation to the assembled credbound.Config
// just before New runs, covering everything without a dedicated option —
// Config.SignUp, Config.OAuth, Config.SessionTTL, TTLs, and so on:
//
//	manager := credboundtest.NewManager(t, credboundtest.WithConfig(func(cfg *credbound.Config) {
//		cfg.SignUp = &credbound.SignUpConfig{}
//	}))
//
// Mutators run in registration order, after the other options are applied.
func WithConfig(mutate func(*credbound.Config)) Option {
	return func(s *settings) { s.mutators = append(s.mutators, mutate) }
}

// NewManager builds a *credbound.Manager wired for tests: memory.New() store,
// the fast Passwords hasher, the TOTP and Passkeys fakes, fixed secret key and
// peppers, a Clock frozen at DefaultStartTime, and a deterministic random
// source. Options override individual parts. Construction failures fail the
// test immediately.
//
// The resulting manager must never back a production service: every secret it
// derives is fixed and every credential it accepts is predictable.
func NewManager(t testing.TB, opts ...Option) *credbound.Manager {
	t.Helper()
	s := settings{
		clock:  NewClock(DefaultStartTime),
		random: NewDeterministicRandom(),
		store:  memory.New(),
	}
	for _, opt := range opts {
		opt(&s)
	}
	cfg := credbound.Config{
		Store:            s.store,
		Passwords:        Passwords{},
		TOTP:             TOTP{},
		Passkeys:         Passkeys{},
		SecretKey:        bytes.Repeat([]byte{0x11}, 32),
		PATPepper:        bytes.Repeat([]byte{0x22}, 32),
		RecoveryPepper:   bytes.Repeat([]byte{0x33}, 32),
		Clock:            s.clock.Now,
		Random:           s.random,
		PasswordPolicy:   s.policy,
		SSOProviders:     s.ssoProviders,
		TransactionHooks: s.hooks,
		EventListeners:   s.listeners,
	}
	for _, mutate := range s.mutators {
		mutate(&cfg)
	}
	manager, err := credbound.New(cfg)
	if err != nil {
		t.Fatalf("credboundtest: build manager: %v", err)
	}
	return manager
}

// Bootstrap creates the first user and workspace of the instance with the
// fixed Bootstrap* identity and returns the resulting authentication and
// workspace. It fails the test on error, including the credbound.ErrConflict
// returned by a second call on the same manager.
func Bootstrap(t testing.TB, manager *credbound.Manager) (credbound.Authentication, credbound.Workspace) {
	t.Helper()
	authn, workspace, err := manager.Bootstrap(context.Background(), credbound.BootstrapInput{
		Email:         BootstrapEmail,
		DisplayName:   BootstrapDisplayName,
		Password:      BootstrapPassword,
		WorkspaceName: BootstrapWorkspaceName,
	})
	if err != nil {
		t.Fatalf("credboundtest: bootstrap: %v", err)
	}
	return authn, workspace
}

// AAL2 fabricates an interactive AAL2 authentication for userID as of at, as
// if the user had just verified a TOTP code. Use it to satisfy step-up checks
// (for example before CreatePAT) without running a second-factor ceremony in
// every test.
//
// This helper is test-only by definition: production code must never
// construct an AAL2 authentication itself — only VerifyTOTP, a passkey, or
// SSO reauthentication may produce one.
func AAL2(userID string, at time.Time) credbound.Authentication {
	return credbound.Authentication{
		UserID:          userID,
		Method:          credbound.MethodTOTP,
		Level:           credbound.AAL2,
		AuthenticatedAt: at,
	}
}
