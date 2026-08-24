package credbound_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/credboundtest"
	"github.com/deepteams/credbound/memory"
)

// stepUpFixture builds a manager under the given policies with a bootstrapped
// root account. The returned authentication is the AAL1, interactive password
// context Bootstrap mints — exactly what a user holds before any second
// factor.
func stepUpFixture(t *testing.T, policies credbound.StepUpPolicies) (*credbound.Manager, *credboundtest.Clock, credbound.Authentication, credbound.Workspace) {
	t.Helper()
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager := credboundtest.NewManager(t, credboundtest.WithClock(clock),
		credboundtest.WithConfig(func(cfg *credbound.Config) { cfg.StepUp = policies }))
	authn, workspace := credboundtest.Bootstrap(t, manager)
	return manager, clock, authn, workspace
}

// patStepUpFixture is stepUpFixture with policy applied to the PAT scope
// alone, leaving every other family strict.
func patStepUpFixture(t *testing.T, policy credbound.StepUpPolicy) (*credbound.Manager, *credboundtest.Clock, credbound.Authentication, credbound.Workspace) {
	t.Helper()
	return stepUpFixture(t, credbound.StepUpPolicies{PAT: policy})
}

// enrollTOTP activates a TOTP factor for the actor, making them capable of a
// step-up under StepUpPolicyUserCapable.
func enrollTOTP(t *testing.T, manager *credbound.Manager, actor credbound.Authentication) {
	t.Helper()
	if _, err := manager.BeginTOTPEnrollment(context.Background(), actor); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ConfirmTOTPEnrollment(context.Background(), actor, credboundtest.ValidTOTPCode); err != nil {
		t.Fatal(err)
	}
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
	if err := manager.RequireStepUpFor(ctx, authn, credbound.StepUpScopePAT); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("RequireStepUpFor after enrollment = %v", err)
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

// TestNewRejectsUnknownStepUpPolicy pins that a typo fails construction
// rather than silently selecting a mode, and names the offending field.
func TestNewRejectsUnknownStepUpPolicy(t *testing.T) {
	for field, policies := range map[string]credbound.StepUpPolicies{
		"StepUp.Default":   {Default: credbound.StepUpPolicy("optional")},
		"StepUp.PAT":       {PAT: credbound.StepUpPolicy("optional")},
		"StepUp.Workspace": {Workspace: credbound.StepUpPolicy("optional")},
		"StepUp.Account":   {Account: credbound.StepUpPolicy("optional")},
		"StepUp.Admin":     {Admin: credbound.StepUpPolicy("optional")},
	} {
		_, err := credbound.New(credbound.Config{
			Store: memory.New(), Passwords: credboundtest.Passwords{},
			SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
			StepUp: policies,
		})
		if !errors.Is(err, credbound.ErrInvalidInput) || !strings.Contains(err.Error(), field) {
			t.Fatalf("unknown %s policy = %v", field, err)
		}
	}
}

// TestStepUpPolicyWorkspaceScope pins the tenant family: an administrator with
// no enrolled factor runs the day-to-day workspace mutations from a plain
// password context, the scopes stay independent of one another, and enrolling
// a factor puts that same administrator back behind the full step-up.
func TestStepUpPolicyWorkspaceScope(t *testing.T) {
	ctx := context.Background()
	manager, clock, root, workspace := stepUpFixture(t, credbound.StepUpPolicies{Workspace: credbound.StepUpPolicyUserCapable})

	created, err := manager.CreateWorkspace(ctx, root, credbound.CreateWorkspaceInput{Name: "Routing"})
	if err != nil {
		t.Fatalf("CreateWorkspace = %v", err)
	}
	if _, err := manager.UpdateWorkspace(ctx, root, created.ID, credbound.UpdateWorkspaceInput{Name: "Routing v2"}); err != nil {
		t.Fatalf("UpdateWorkspace = %v", err)
	}
	if _, err := manager.InviteToWorkspace(ctx, root, created.ID, credbound.InviteToWorkspaceInput{Email: "invitee@example.com", Role: credbound.RoleMember}); err != nil {
		t.Fatalf("InviteToWorkspace = %v", err)
	}
	member, err := manager.CreateUser(ctx, root, created.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatalf("CreateUser = %v", err)
	}
	if err := manager.GrantRole(ctx, root, created.ID, member.ID, credbound.RoleAdmin); err != nil {
		t.Fatalf("GrantRole = %v", err)
	}
	if err := manager.RemoveMembership(ctx, root, created.ID, member.ID); err != nil {
		t.Fatalf("RemoveMembership = %v", err)
	}
	for _, err := range manager.AuditEvents(ctx, root, created.ID, credbound.PageRequest{Limit: 50}) {
		if err != nil {
			t.Fatalf("AuditEvents = %v", err)
		}
	}
	if err := manager.DisableWorkspace(ctx, root, created.ID); err != nil {
		t.Fatalf("DisableWorkspace = %v", err)
	}

	// The other families keep their own policy: PAT and account inherit the
	// strict default, so relaxing the tenant mutations relaxes nothing else.
	if _, err := manager.CreatePAT(ctx, root, credbound.CreatePATInput{Name: "ci", Scopes: []string{"read"}}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("PAT creation under a workspace-only relaxation = %v", err)
	}

	enrollTOTP(t, manager, root)
	if _, err := manager.CreateWorkspace(ctx, root, credbound.CreateWorkspaceInput{Name: "After"}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 CreateWorkspace with an active TOTP factor = %v", err)
	}
	if _, err := manager.InviteToWorkspace(ctx, root, workspace.ID, credbound.InviteToWorkspaceInput{Email: "late@example.com", Role: credbound.RoleMember}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 invitation with an active TOTP factor = %v", err)
	}
	if _, err := manager.CreateWorkspace(ctx, credboundtest.AAL2(root.UserID, clock.Now()), credbound.CreateWorkspaceInput{Name: "Stepped up"}); err != nil {
		t.Fatalf("step-up CreateWorkspace = %v", err)
	}
}

// TestStepUpPolicyAccountScope pins the credential family, where the
// user_capable mode earns its keep: the very users who could lose a factor to
// a password-only attacker are the ones it keeps behind the full step-up,
// while the none mode is the deployment's explicit choice to drop that.
func TestStepUpPolicyAccountScope(t *testing.T) {
	ctx := context.Background()
	register := func(t *testing.T, manager *credbound.Manager, actor credbound.Authentication) credbound.Passkey {
		t.Helper()
		challenge, err := manager.BeginPasskeyRegistration(ctx, actor, "laptop")
		if err != nil {
			t.Fatal(err)
		}
		passkey, err := manager.FinishPasskeyRegistration(ctx, actor, challenge.Continuation, []byte(credboundtest.ValidPasskeyResponse))
		if err != nil {
			t.Fatal(err)
		}
		return passkey
	}

	manager, clock, root, _ := stepUpFixture(t, credbound.StepUpPolicies{Default: credbound.StepUpPolicyUserCapable})
	passkey := register(t, manager, root)
	if err := manager.DeletePasskey(ctx, root, passkey.ID); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("a password-only context deleted the passkey it is protected by: %v", err)
	}
	if err := manager.DeletePasskey(ctx, credboundtest.AAL2(root.UserID, clock.Now()), passkey.ID); err != nil {
		t.Fatalf("step-up passkey deletion = %v", err)
	}

	relaxed, _, rootB, _ := stepUpFixture(t, credbound.StepUpPolicies{Account: credbound.StepUpPolicyNone})
	passkeyB := register(t, relaxed, rootB)
	if err := relaxed.DeletePasskey(ctx, rootB, passkeyB.ID); err != nil {
		t.Fatalf("passkey deletion under the none policy = %v", err)
	}
}

// TestStepUpPolicyAdminScope pins that instance administration follows
// Default like every other family, and that naming Admin explicitly keeps it
// strict while the rest is relaxed.
func TestStepUpPolicyAdminScope(t *testing.T) {
	ctx := context.Background()
	newMember := func(t *testing.T, manager *credbound.Manager, actor credbound.Authentication, workspaceID credbound.UUID) credbound.User {
		t.Helper()
		user, err := manager.CreateUser(ctx, actor, workspaceID, credbound.CreateUserInput{
			Email: "member@example.com", DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
		})
		if err != nil {
			t.Fatal(err)
		}
		return user
	}

	manager, _, root, workspace := stepUpFixture(t, credbound.StepUpPolicies{Default: credbound.StepUpPolicyUserCapable})
	member := newMember(t, manager, root, workspace.ID)
	if err := manager.DisableUser(ctx, root, credbound.TrustedRequest{}, member.ID); err != nil {
		t.Fatalf("DisableUser without an enrolled factor = %v", err)
	}
	enrollTOTP(t, manager, root)
	if err := manager.EnableUser(ctx, root, credbound.TrustedRequest{}, member.ID); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 EnableUser with an active TOTP factor = %v", err)
	}

	strict, _, rootB, workspaceB := stepUpFixture(t, credbound.StepUpPolicies{Default: credbound.StepUpPolicyNone, Admin: credbound.StepUpPolicyRequired})
	memberB := newMember(t, strict, rootB, workspaceB.ID)
	if err := strict.DisableUser(ctx, rootB, credbound.TrustedRequest{}, memberB.ID); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("DisableUser under an explicitly strict admin scope = %v", err)
	}
	// The loopback waiver is a property of the admin gate, not of the policy.
	if err := strict.DisableUser(ctx, rootB, credbound.TrustedRequest{Local: true}, memberB.ID); err != nil {
		t.Fatalf("trusted local DisableUser = %v", err)
	}
}

// TestRequireStepUpForReportsPerScope pins the answer a host prompts on: the
// exported check reports each scope's own verdict for the same actor, and
// keeps refusing a non-interactive credential everywhere.
func TestRequireStepUpForReportsPerScope(t *testing.T) {
	ctx := context.Background()
	manager, _, root, _ := stepUpFixture(t, credbound.StepUpPolicies{Default: credbound.StepUpPolicyNone, PAT: credbound.StepUpPolicyRequired})
	if err := manager.RequireStepUpFor(ctx, root, credbound.StepUpScopeWorkspace); err != nil {
		t.Fatalf("workspace scope = %v", err)
	}
	if err := manager.RequireStepUpFor(ctx, root, credbound.StepUpScopePAT); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("PAT scope = %v", err)
	}
	if err := manager.RequireStepUpFor(ctx, credbound.Authentication{}, credbound.StepUpScopeAccount); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous account scope = %v", err)
	}
	issued, err := manager.CreatePAT(ctx, credboundtest.AAL2(root.UserID, credboundtest.DefaultStartTime), credbound.CreatePATInput{Name: "ci", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	patAuth, err := manager.AuthenticatePAT(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []credbound.StepUpScope{credbound.StepUpScopePAT, credbound.StepUpScopeWorkspace, credbound.StepUpScopeAccount, credbound.StepUpScopeAdmin} {
		if err := manager.RequireStepUpFor(ctx, patAuth, scope); !errors.Is(err, credbound.ErrStepUpRequired) {
			t.Fatalf("PAT context in scope %q = %v", scope, err)
		}
	}
}
