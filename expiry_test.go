package credbound_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/credboundtest"
)

// Every credential Credbound issues expires, and the suite proved that with
// coarse jumps — "advance an hour, expect a refusal" — which passes just as
// well when the comparison is off by one in either direction. The tests below
// pin the boundary itself: valid at one nanosecond before the deadline,
// refused at the deadline exactly, refused after. That exclusive convention is
// what the code implements at every site (`!now.Before(expiresAt)`), and a
// flip to inclusive would silently keep a token alive for a whole clock tick
// past its stated life.

// expiring describes one credential's lifetime.
type expiring struct {
	name string
	// ttl is the configured lifetime.
	ttl time.Duration
	// configure applies the lifetime to the manager configuration.
	configure func(*credbound.Config, time.Duration)
	// issue mints the credential and returns the value redeem consumes.
	issue func(t *testing.T, h *expiryHarness) string
	// redeem attempts the redemption; a nil error means accepted.
	redeem func(t *testing.T, h *expiryHarness, credential string) error
}

type expiryHarness struct {
	manager *credbound.Manager
	clock   *credboundtest.Clock
	ctx     context.Context
	root    credbound.Authentication
	space   credbound.Workspace
}

func (h *expiryHarness) stepUp() credbound.Authentication {
	return credboundtest.AAL2(h.root.UserID, h.clock.Now())
}

// TestExpiryBoundaries walks every time-limited credential to the nanosecond
// around its deadline.
func TestExpiryBoundaries(t *testing.T) {
	const ttl = 30 * time.Minute
	cases := []expiring{
		{
			name: "email verification",
			ttl:  ttl,
			configure: func(cfg *credbound.Config, ttl time.Duration) {
				cfg.EmailVerificationTTL = ttl
			},
			issue: func(t *testing.T, h *expiryHarness) string {
				issued, err := h.manager.BeginEmailAddition(h.ctx, h.stepUp(), "second@example.com")
				if err != nil {
					t.Fatalf("begin email addition: %v", err)
				}
				return issued.Token
			},
			redeem: func(t *testing.T, h *expiryHarness, credential string) error {
				_, err := h.manager.ConfirmEmail(h.ctx, credential)
				return err
			},
		},
		{
			name: "password reset",
			ttl:  ttl,
			configure: func(cfg *credbound.Config, ttl time.Duration) {
				cfg.PasswordResetTTL = ttl
			},
			issue: func(t *testing.T, h *expiryHarness) string {
				issued, err := h.manager.BeginPasswordReset(h.ctx, credboundtest.BootstrapEmail)
				if err != nil {
					t.Fatalf("begin reset: %v", err)
				}
				return issued.Token
			},
			redeem: func(t *testing.T, h *expiryHarness, credential string) error {
				_, err := h.manager.CompletePasswordReset(h.ctx, credential, "another correct horse battery")
				return err
			},
		},
		{
			name: "magic link",
			ttl:  ttl,
			configure: func(cfg *credbound.Config, ttl time.Duration) {
				cfg.EmailAuthenticationTTL = ttl
			},
			issue: func(t *testing.T, h *expiryHarness) string {
				issued, err := h.manager.BeginEmailAuthentication(h.ctx, credboundtest.BootstrapEmail)
				if err != nil {
					t.Fatalf("begin magic link: %v", err)
				}
				return issued.Token
			},
			redeem: func(t *testing.T, h *expiryHarness, credential string) error {
				_, err := h.manager.CompleteEmailAuthentication(h.ctx, credential)
				return err
			},
		},
		{
			name: "workspace invitation",
			ttl:  ttl,
			configure: func(cfg *credbound.Config, ttl time.Duration) {
				cfg.InvitationTTL = ttl
			},
			issue: func(t *testing.T, h *expiryHarness) string {
				issued, err := h.manager.InviteToWorkspace(h.ctx, h.stepUp(), h.space.ID, credbound.InviteToWorkspaceInput{
					Email: "invitee@example.com", Role: credbound.RoleMember,
				})
				if err != nil {
					t.Fatalf("invite: %v", err)
				}
				return issued.Token
			},
			redeem: func(t *testing.T, h *expiryHarness, credential string) error {
				_, _, err := h.manager.RegisterFromInvitation(h.ctx, credential, credbound.RegisterFromInvitationInput{
					DisplayName: "Invitee", Password: "member correct horse battery",
				})
				return err
			},
		},
		{
			name: "session",
			ttl:  ttl,
			configure: func(cfg *credbound.Config, ttl time.Duration) {
				cfg.SessionTTL = ttl
			},
			issue: func(t *testing.T, h *expiryHarness) string {
				issued, err := h.manager.CreateSession(h.ctx, h.stepUp(), credbound.CreateSessionInput{})
				if err != nil {
					t.Fatalf("create session: %v", err)
				}
				return issued.Token
			},
			redeem: func(t *testing.T, h *expiryHarness, credential string) error {
				_, _, err := h.manager.AuthenticateSession(h.ctx, credential)
				return err
			},
		},
		{
			name: "passkey ceremony continuation",
			ttl:  ttl,
			configure: func(cfg *credbound.Config, ttl time.Duration) {
				cfg.CeremonyTTL = ttl
			},
			issue: func(t *testing.T, h *expiryHarness) string {
				challenge, err := h.manager.BeginPasskeyRegistration(h.ctx, h.stepUp(), "laptop")
				if err != nil {
					t.Fatalf("begin passkey registration: %v", err)
				}
				return challenge.Continuation
			},
			redeem: func(t *testing.T, h *expiryHarness, credential string) error {
				_, err := h.manager.FinishPasskeyRegistration(h.ctx, h.stepUp(), credential, []byte(credboundtest.ValidPasskeyResponse))
				return err
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// Just before the deadline the credential still works.
			accepted := newExpiryHarness(t, testCase)
			credential := testCase.issue(t, accepted)
			accepted.clock.Advance(testCase.ttl - time.Nanosecond)
			if err := testCase.redeem(t, accepted, credential); err != nil {
				t.Fatalf("refused one nanosecond before expiry: %v", err)
			}

			// At the deadline exactly it does not: expiry is exclusive.
			atDeadline := newExpiryHarness(t, testCase)
			credential = testCase.issue(t, atDeadline)
			atDeadline.clock.Advance(testCase.ttl)
			if err := testCase.redeem(t, atDeadline, credential); err == nil {
				t.Fatal("accepted at the expiry instant, where the convention is exclusive")
			}

			// And well past it, it stays refused.
			afterwards := newExpiryHarness(t, testCase)
			credential = testCase.issue(t, afterwards)
			afterwards.clock.Advance(testCase.ttl + time.Hour)
			if err := testCase.redeem(t, afterwards, credential); err == nil {
				t.Fatal("accepted after expiry")
			}
		})
	}
}

func newExpiryHarness(t *testing.T, testCase expiring) *expiryHarness {
	t.Helper()
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager := credboundtest.NewManager(t,
		credboundtest.WithClock(clock),
		credboundtest.WithConfig(func(cfg *credbound.Config) {
			testCase.configure(cfg, testCase.ttl)
			// The step-up window must outlive the credential under test, or
			// it would be the one expiring.
			cfg.StepUpMaxAge = 10 * 365 * 24 * time.Hour
		}))
	root, space := credboundtest.Bootstrap(t, manager)
	return &expiryHarness{manager: manager, clock: clock, ctx: context.Background(), root: root, space: space}
}

// TestStepUpFreshnessBoundary pins the step-up window, which is not a stored
// expiry but a comparison against the authentication timestamp the host
// replays on every call. Its boundary is inclusive — an age of exactly
// StepUpMaxAge still passes — where every stored expiry is exclusive; the
// difference is one nanosecond wide and deliberate, and pinning it keeps a
// refactor from quietly aligning one convention onto the other.
func TestStepUpFreshnessBoundary(t *testing.T) {
	const window = 10 * time.Minute
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager := credboundtest.NewManager(t,
		credboundtest.WithClock(clock),
		credboundtest.WithConfig(func(cfg *credbound.Config) { cfg.StepUpMaxAge = window }))
	root, _ := credboundtest.Bootstrap(t, manager)
	authenticated := clock.Now()
	actor := credboundtest.AAL2(root.UserID, authenticated)

	clock.Set(authenticated.Add(window))
	if err := manager.RequireStepUp(actor); err != nil {
		t.Fatalf("refused at an age of exactly StepUpMaxAge: %v", err)
	}
	clock.Set(authenticated.Add(window + time.Nanosecond))
	if err := manager.RequireStepUp(actor); err == nil {
		t.Fatal("accepted one nanosecond past the window")
	}

	// A context timestamped after the current instant — a host clock that
	// stepped backwards, or a fabricated timestamp — is refused rather than
	// treated as maximally fresh, which is the fail-closed reading of a
	// negative age.
	clock.Set(authenticated.Add(-time.Nanosecond))
	if err := manager.RequireStepUp(actor); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("a context authenticated in the future = %v, want ErrStepUpRequired", err)
	}

	// The other refusals of the same guard, pinned together: a non-interactive
	// method, an assurance below AAL2, and a pending second factor.
	clock.Set(authenticated)
	for name, context := range map[string]credbound.Authentication{
		"PAT":            {UserID: root.UserID, Method: credbound.MethodPAT, Level: credbound.AAL2, AuthenticatedAt: authenticated},
		"AAL1":           {UserID: root.UserID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: authenticated},
		"pending factor": {UserID: root.UserID, Method: credbound.MethodTOTP, Level: credbound.AAL2, AuthenticatedAt: authenticated, SecondFactorRequired: true},
		"anonymous":      {Method: credbound.MethodTOTP, Level: credbound.AAL2, AuthenticatedAt: authenticated},
	} {
		if err := manager.RequireStepUp(context); err == nil {
			t.Fatalf("a %s context satisfied a step-up", name)
		}
	}
}

// TestPATExpiryBoundary pins the caller-chosen PAT expiry, which is the one
// deadline a host sets itself.
func TestPATExpiryBoundary(t *testing.T) {
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager := credboundtest.NewManager(t, credboundtest.WithClock(clock))
	root, workspace := credboundtest.Bootstrap(t, manager)
	ctx := context.Background()

	// An expiry that has already passed is refused at creation.
	past := clock.Now().Add(-time.Second)
	if _, err := manager.CreatePAT(ctx, credboundtest.AAL2(root.UserID, clock.Now()), credbound.CreatePATInput{
		Name: "stale", WorkspaceID: workspace.ID, Scopes: []string{"read"}, ExpiresAt: &past,
	}); err == nil {
		t.Fatal("a PAT expiring in the past was minted")
	}
	// So is one expiring exactly now.
	now := clock.Now()
	if _, err := manager.CreatePAT(ctx, credboundtest.AAL2(root.UserID, clock.Now()), credbound.CreatePATInput{
		Name: "instant", WorkspaceID: workspace.ID, Scopes: []string{"read"}, ExpiresAt: &now,
	}); err == nil {
		t.Fatal("a PAT expiring at the creation instant was minted")
	}

	expiry := clock.Now().Add(time.Hour)
	issued, err := manager.CreatePAT(ctx, credboundtest.AAL2(root.UserID, clock.Now()), credbound.CreatePATInput{
		Name: "ci", WorkspaceID: workspace.ID, Scopes: []string{"read"}, ExpiresAt: &expiry,
	})
	if err != nil {
		t.Fatalf("create pat: %v", err)
	}
	clock.Set(expiry.Add(-time.Nanosecond))
	if _, err := manager.AuthenticatePAT(ctx, issued.Token); err != nil {
		t.Fatalf("refused one nanosecond before expiry: %v", err)
	}
	clock.Set(expiry)
	if _, err := manager.AuthenticatePAT(ctx, issued.Token); err == nil {
		t.Fatal("accepted at the expiry instant, where the convention is exclusive")
	}
}

// TestSessionIdleAndAbsoluteBoundaries pins the two independent session
// deadlines: activity keeps the idle window open, and nothing keeps the
// absolute one open.
func TestSessionIdleAndAbsoluteBoundaries(t *testing.T) {
	const (
		absolute = 2 * time.Hour
		idle     = 30 * time.Minute
	)
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager := credboundtest.NewManager(t,
		credboundtest.WithClock(clock),
		credboundtest.WithConfig(func(cfg *credbound.Config) {
			cfg.SessionTTL = absolute
			cfg.SessionIdleTimeout = idle
		}))
	root, _ := credboundtest.Bootstrap(t, manager)
	ctx := context.Background()

	issued, err := manager.CreateSession(ctx, credboundtest.AAL2(root.UserID, clock.Now()), credbound.CreateSessionInput{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	// Activity just inside the idle window keeps the session alive, twice
	// over — the second check proves the window slides with each use.
	for range 2 {
		clock.Advance(idle - time.Nanosecond)
		if _, _, err := manager.AuthenticateSession(ctx, issued.Token); err != nil {
			t.Fatalf("refused one nanosecond before the idle window closes: %v", err)
		}
	}
	// Idling exactly one window closes it.
	clock.Advance(idle)
	if _, _, err := manager.AuthenticateSession(ctx, issued.Token); err == nil {
		t.Fatal("accepted at the idle boundary, where the convention is exclusive")
	}

	// The absolute deadline is never extended by activity: a session used
	// continuously still dies at CreatedAt plus SessionTTL.
	clock.Set(credboundtest.DefaultStartTime)
	fresh, err := manager.CreateSession(ctx, credboundtest.AAL2(root.UserID, clock.Now()), credbound.CreateSessionInput{})
	if err != nil {
		t.Fatalf("create second session: %v", err)
	}
	deadline := fresh.Session.ExpiresAt
	for clock.Now().Add(idle - time.Nanosecond).Before(deadline) {
		clock.Advance(idle - time.Nanosecond)
		if _, _, err := manager.AuthenticateSession(ctx, fresh.Token); err != nil {
			t.Fatalf("active session refused at %v: %v", clock.Now(), err)
		}
	}
	clock.Set(deadline)
	if _, _, err := manager.AuthenticateSession(ctx, fresh.Token); err == nil {
		t.Fatal("a continuously used session outlived its absolute deadline")
	}
}
