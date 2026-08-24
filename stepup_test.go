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

// patStepUpFixture builds a manager whose PAT mutations follow policy, with a
// bootstrapped root account. The returned authentication is the AAL1,
// interactive password context Bootstrap mints — exactly what a user holds
// before any second factor.
func patStepUpFixture(t *testing.T, policy credbound.StepUpPolicy) (*credbound.Manager, *credboundtest.Clock, credbound.Authentication, credbound.Workspace) {
	t.Helper()
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager := credboundtest.NewManager(t, credboundtest.WithClock(clock),
		credboundtest.WithConfig(func(cfg *credbound.Config) { cfg.PATStepUp = policy }))
	authn, workspace := credboundtest.Bootstrap(t, manager)
	return manager, clock, authn, workspace
}

// TestPATStepUpPolicyRequiredIsTheDefault pins that a zero Config keeps the
// historical gate: only a fresh interactive AAL2 context mints or revokes a
// token, whatever the user has enrolled.
func TestPATStepUpPolicyRequiredIsTheDefault(t *testing.T) {
	ctx := context.Background()
	for _, policy := range []credbound.StepUpPolicy{"", credbound.StepUpPolicyRequired} {
		manager, clock, authn, _ := patStepUpFixture(t, policy)
		if _, err := manager.CreatePAT(ctx, authn, credbound.CreatePATInput{Name: "ci", Scopes: []string{"read"}}); !errors.Is(err, credbound.ErrStepUpRequired) {
			t.Fatalf("policy %q: AAL1 creation = %v", policy, err)
		}
		issued, err := manager.CreatePAT(ctx, credboundtest.AAL2(authn.UserID, clock.Now()), credbound.CreatePATInput{Name: "ci", Scopes: []string{"read"}})
		if err != nil {
			t.Fatalf("policy %q: step-up creation = %v", policy, err)
		}
		if err := manager.RevokePAT(ctx, authn, issued.PAT.ID); !errors.Is(err, credbound.ErrStepUpRequired) {
			t.Fatalf("policy %q: AAL1 revocation = %v", policy, err)
		}
		// A stale AAL2 context is refused just like an AAL1 one.
		clock.Advance(time.Hour)
		if err := manager.RevokePAT(ctx, credboundtest.AAL2(authn.UserID, credboundtest.DefaultStartTime), issued.PAT.ID); !errors.Is(err, credbound.ErrStepUpRequired) {
			t.Fatalf("policy %q: stale AAL2 revocation = %v", policy, err)
		}
	}
}

// TestPATStepUpPolicyNone pins the relaxed mode: any interactive context of an
// active user mints and revokes tokens, at any assurance level and any age,
// while the non-interactive floor holds — a PAT can never mint or revoke a
// PAT, and a pending second factor never counts as an authentication.
func TestPATStepUpPolicyNone(t *testing.T) {
	ctx := context.Background()
	manager, clock, authn, _ := patStepUpFixture(t, credbound.StepUpPolicyNone)
	// Far past Config.StepUpMaxAge: the relaxed mode checks no freshness.
	clock.Advance(24 * time.Hour)
	issued, err := manager.CreatePAT(ctx, authn, credbound.CreatePATInput{Name: "ci", Scopes: []string{"read"}})
	if err != nil {
		t.Fatalf("AAL1 creation under the none policy = %v", err)
	}

	patAuth, err := manager.AuthenticatePAT(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CreatePAT(ctx, patAuth, credbound.CreatePATInput{Name: "spawn", Scopes: []string{"read"}}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("a PAT minted another PAT: %v", err)
	}
	if err := manager.RevokePAT(ctx, patAuth, issued.PAT.ID); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("a PAT revoked a PAT: %v", err)
	}

	pending := authn
	pending.SecondFactorRequired = true
	if _, err := manager.CreatePAT(ctx, pending, credbound.CreatePATInput{Name: "pending", Scopes: []string{"read"}}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("a half-finished sign-in minted a PAT: %v", err)
	}
	if _, err := manager.CreatePAT(ctx, credbound.Authentication{}, credbound.CreatePATInput{Name: "anonymous", Scopes: []string{"read"}}); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous creation = %v", err)
	}
	if err := manager.RevokePAT(ctx, authn, issued.PAT.ID); err != nil {
		t.Fatalf("AAL1 revocation under the none policy = %v", err)
	}
}

// TestPATStepUpPolicyUserCapable pins the middle mode: a user with no second
// factor keeps issuing tokens interactively, and enrolling one tightens the
// gate to a full step-up for that user alone, with no configuration change.
func TestPATStepUpPolicyUserCapable(t *testing.T) {
	ctx := context.Background()
	manager, clock, authn, _ := patStepUpFixture(t, credbound.StepUpPolicyUserCapable)
	issued, err := manager.CreatePAT(ctx, authn, credbound.CreatePATInput{Name: "ci", Scopes: []string{"read"}})
	if err != nil {
		t.Fatalf("creation without an enrolled factor = %v", err)
	}

	if _, err := manager.BeginTOTPEnrollment(ctx, authn); err != nil {
		t.Fatal(err)
	}
	// An enrollment that was never confirmed is not a capability: the factor
	// stays inactive and cannot answer a step-up.
	if _, err := manager.CreatePAT(ctx, authn, credbound.CreatePATInput{Name: "enrolling", Scopes: []string{"read"}}); err != nil {
		t.Fatalf("creation during an unconfirmed enrollment = %v", err)
	}
	if _, err := manager.ConfirmTOTPEnrollment(ctx, authn, credboundtest.ValidTOTPCode); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CreatePAT(ctx, authn, credbound.CreatePATInput{Name: "after", Scopes: []string{"read"}}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 creation with an active TOTP factor = %v", err)
	}
	if err := manager.RevokePAT(ctx, authn, issued.PAT.ID); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 revocation with an active TOTP factor = %v", err)
	}
	if err := manager.RevokePAT(ctx, credboundtest.AAL2(authn.UserID, clock.Now()), issued.PAT.ID); err != nil {
		t.Fatalf("step-up revocation = %v", err)
	}
}

// TestPATStepUpPolicyUserCapableCountsPasskeys pins that a registered passkey
// is a step-up capability too: its owner is held to the full step-up even
// without a TOTP factor.
func TestPATStepUpPolicyUserCapableCountsPasskeys(t *testing.T) {
	ctx := context.Background()
	manager, clock, authn, _ := patStepUpFixture(t, credbound.StepUpPolicyUserCapable)
	challenge, err := manager.BeginPasskeyRegistration(ctx, authn, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.FinishPasskeyRegistration(ctx, authn, challenge.Continuation, []byte(credboundtest.ValidPasskeyResponse)); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CreatePAT(ctx, authn, credbound.CreatePATInput{Name: "ci", Scopes: []string{"read"}}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 creation with a registered passkey = %v", err)
	}
	if _, err := manager.CreatePAT(ctx, credboundtest.AAL2(authn.UserID, clock.Now()), credbound.CreatePATInput{Name: "ci", Scopes: []string{"read"}}); err != nil {
		t.Fatalf("step-up creation = %v", err)
	}
}

// TestPATStepUpPolicyKeepsAuditAndAccountChecks pins what no policy relaxes:
// a refusal still emits the step-up event a host prompts on, a disabled
// account is still refused, and a workspace requiring MFA still keeps a
// workspace-bound token behind AAL2.
func TestPATStepUpPolicyKeepsAuditAndAccountChecks(t *testing.T) {
	ctx := context.Background()
	manager, clock, root, workspace := patStepUpFixture(t, credbound.StepUpPolicyNone)
	recorder := &stepUpRecorder{}
	manager.AddEventListener(recorder)

	issued, err := manager.CreatePAT(ctx, root, credbound.CreatePATInput{Name: "ci", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	patAuth, err := manager.AuthenticatePAT(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CreatePAT(ctx, patAuth, credbound.CreatePATInput{Name: "spawn", Scopes: []string{"read"}}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("PAT creation from a PAT = %v", err)
	}
	if len(recorder.events) != 1 || recorder.events[0].Operation != "auth.pat.create" || recorder.events[0].UserID != root.UserID {
		t.Fatalf("step-up denial events = %#v", recorder.events)
	}

	// TENANT-006 is untouched: a workspace requiring MFA still refuses an
	// AAL1 context, so a relaxed policy cannot mint a token there.
	mfaWorkspace, err := manager.CreateWorkspace(ctx, credboundtest.AAL2(root.UserID, clock.Now()), credbound.CreateWorkspaceInput{Name: "Regulated", RequireMFA: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CreatePAT(ctx, root, credbound.CreatePATInput{Name: "bound", WorkspaceID: mfaWorkspace.ID, Scopes: []string{"read"}}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 creation in an MFA workspace = %v", err)
	}

	member, err := manager.CreateUser(ctx, credboundtest.AAL2(root.UserID, clock.Now()), workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	memberAuth := credbound.Authentication{UserID: member.ID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: clock.Now()}
	if _, err := manager.CreatePAT(ctx, memberAuth, credbound.CreatePATInput{Name: "member", Scopes: []string{"read"}}); err != nil {
		t.Fatalf("member creation under the none policy = %v", err)
	}
	if err := manager.DisableUser(ctx, credboundtest.AAL2(root.UserID, clock.Now()), credbound.TrustedRequest{}, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CreatePAT(ctx, memberAuth, credbound.CreatePATInput{Name: "disabled", Scopes: []string{"read"}}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("disabled account creation = %v", err)
	}
}

// TestNewRejectsUnknownPATStepUpPolicy pins that a typo fails construction
// rather than silently selecting a mode.
func TestNewRejectsUnknownPATStepUpPolicy(t *testing.T) {
	_, err := credbound.New(credbound.Config{
		Store: memory.New(), Passwords: credboundtest.Passwords{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		PATStepUp: credbound.StepUpPolicy("optional"),
	})
	if !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("unknown PAT step-up policy = %v", err)
	}
}
