package credbound_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

func TestPasswordChangeAndInputValidation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	invalidBootstraps := []credbound.BootstrapInput{
		{Email: "bad", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main"},
		{Email: "root@example.com", Password: "correct horse battery", WorkspaceName: "Main"},
		{Email: "root@example.com", DisplayName: "Root", Password: "short", WorkspaceName: "Main"},
	}
	for _, input := range invalidBootstraps {
		if _, _, err := f.manager.Bootstrap(ctx, input); !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("invalid bootstrap %#v = %v", input, err)
		}
	}
	authn, _ := f.bootstrap(t)
	if err := f.manager.ChangePassword(ctx, credbound.Authentication{}, "old", "another secure password"); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("unauthorized password change = %v", err)
	}
	if err := f.manager.ChangePassword(ctx, authn, "wrong", "another secure password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("wrong current password = %v", err)
	}
	if err := f.manager.ChangePassword(ctx, authn, "correct horse battery", strings.Repeat("x", 1025)); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("oversized password = %v", err)
	}
	if err := f.manager.ChangePassword(ctx, authn, "correct horse battery", "another secure password"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("old password login = %v", err)
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "another secure password"); err != nil {
		t.Fatalf("new password login = %v", err)
	}
}

// TestChangePasswordRevokesSessionsKeepsPATs verifies the cascade choice for a
// voluntary password change: interactive sessions die (a leaked session token
// must not outlive the password) while PATs, being integration credentials,
// keep working.
func TestChangePasswordRevokesSessionsKeepsPATs(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()
	actor := aal2(authn.UserID, f.now)

	session, err := f.manager.CreateSession(ctx, actor, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	pat, err := f.manager.CreatePAT(ctx, actor, credbound.CreatePATInput{Name: "ci", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.manager.AuthenticateSession(ctx, session.Token); err != nil {
		t.Fatalf("session before change = %v", err)
	}
	if _, err := f.manager.AuthenticatePAT(ctx, pat.Token); err != nil {
		t.Fatalf("pat before change = %v", err)
	}

	if err := f.manager.ChangePassword(ctx, actor, "correct horse battery", "another secure password"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := f.manager.AuthenticateSession(ctx, session.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("session after change = %v, want revoked", err)
	}
	if _, err := f.manager.AuthenticatePAT(ctx, pat.Token); err != nil {
		t.Fatalf("pat after change = %v, want still valid", err)
	}
}

// TestEmailIssuanceCooldown verifies the per-address anti-bombing cooldown:
// within the window a repeated request returns the enumeration-safe decoy (no
// token, no error), a different purpose is independent, and the window slides
// shut and reopens with the clock.
func TestEmailIssuanceCooldown(t *testing.T) {
	f := newFixture(t)
	f.bootstrap(t)
	ctx := context.Background()
	manager, err := credbound.New(credbound.Config{
		Store: f.store, Passwords: f.passwords, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return f.now }, Random: &counterReader{next: 0x77},
		EmailIssuanceCooldown: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.BeginPasswordReset(ctx, "root@example.com")
	if err != nil || first.Token == "" {
		t.Fatalf("first reset = %#v, %v", first, err)
	}
	// A second reset inside the cooldown answers with the decoy, no token.
	second, err := manager.BeginPasswordReset(ctx, "root@example.com")
	if err != nil || second.Token != "" {
		t.Fatalf("throttled reset = %#v, %v", second, err)
	}
	// A different purpose (magic link) has its own window.
	link, err := manager.BeginEmailAuthentication(ctx, "root@example.com")
	if err != nil || link.Token == "" {
		t.Fatalf("independent purpose = %#v, %v", link, err)
	}
	// Once the cooldown elapses, reset issues again.
	f.now = f.now.Add(2 * time.Minute)
	third, err := manager.BeginPasswordReset(ctx, "root@example.com")
	if err != nil || third.Token == "" {
		t.Fatalf("post-cooldown reset = %#v, %v", third, err)
	}
}

func TestStepUpAuthorizationAndRBACFailures(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	cases := []credbound.Authentication{
		{},
		{UserID: authn.UserID, Method: credbound.MethodPAT, Level: credbound.AAL2, AuthenticatedAt: f.now},
		{UserID: authn.UserID, Method: credbound.MethodTOTP, Level: credbound.AAL2, AuthenticatedAt: f.now.Add(time.Second)},
		{UserID: authn.UserID, Method: credbound.MethodTOTP, Level: credbound.AAL2, AuthenticatedAt: f.now.Add(-time.Hour)},
	}
	for _, candidate := range cases {
		if err := f.manager.RequireStepUp(candidate); err == nil {
			t.Fatalf("accepted invalid step-up %#v", candidate)
		}
	}
	if err := f.manager.Authorize(ctx, credbound.Authentication{}, workspace.ID, credbound.RoleMember); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous role authorization = %v", err)
	}
	if err := f.manager.AuthorizePermission(ctx, credbound.Authentication{}, workspace.ID, credbound.PermissionWorkspaceAccess); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous permission authorization = %v", err)
	}
	if err := f.manager.AuthorizePermission(ctx, authn, "", credbound.PermissionWorkspaceAccess); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("empty permission workspace = %v", err)
	}
	if err := f.manager.Authorize(ctx, authn, "", credbound.RoleMember); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("empty workspace = %v", err)
	}
	if err := f.manager.Authorize(ctx, authn, workspace.ID, credbound.Role("owner")); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("unknown role = %v", err)
	}
	pending := authn
	pending.SecondFactorRequired = true
	if err := f.manager.Authorize(ctx, pending, workspace.ID, credbound.RoleMember); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("TOTP-pending role authorization = %v", err)
	}
	if err := f.manager.AuthorizePermission(ctx, pending, workspace.ID, credbound.PermissionWorkspaceAccess); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("TOTP-pending permission authorization = %v", err)
	}
	bound := authn
	bound.WorkspaceID = "0198b463-0000-7000-8000-ffffffffffff"
	if err := f.manager.Authorize(ctx, bound, workspace.ID, credbound.RoleMember); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("workspace-bound auth = %v", err)
	}
	missing := authn
	missing.UserID = "0198b463-0000-7000-8000-eeeeeeeeeeee"
	if err := f.manager.Authorize(ctx, missing, workspace.ID, credbound.RoleMember); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("missing membership = %v", err)
	}
	missingWorkspace := "0198b463-0000-7000-8000-fffffffffff0"
	if err := f.manager.Authorize(ctx, authn, missingWorkspace, credbound.RoleMember); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("missing workspace role authorization = %v", err)
	}
	if err := f.manager.AuthorizePermission(ctx, authn, missingWorkspace, credbound.PermissionWorkspaceAccess); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("missing workspace permission authorization = %v", err)
	}
	stepUp := aal2(authn.UserID, f.now)
	if err := f.manager.DisableWorkspace(ctx, stepUp, workspace.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Authorize(ctx, authn, workspace.ID, credbound.RoleMember); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("disabled workspace role authorization = %v", err)
	}
	if err := f.manager.AuthorizePermission(ctx, authn, workspace.ID, credbound.PermissionWorkspaceAccess); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("disabled workspace permission authorization = %v", err)
	}
	if err := f.manager.EnableWorkspace(ctx, stepUp, workspace.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.GrantRole(ctx, aal2(authn.UserID, f.now), workspace.ID, "missing", credbound.RoleMember); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("grant missing user = %v", err)
	}
}

func TestTOTPAndPATFailureBoundaries(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	if _, err := f.manager.BeginTOTPEnrollment(ctx, credbound.Authentication{}); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("unauthorized enrollment = %v", err)
	}
	if _, err := f.manager.VerifyTOTP(ctx, authn, "123456"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("verify without factor = %v", err)
	}
	if _, err := f.manager.BeginTOTPEnrollment(ctx, authn); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.ConfirmTOTPEnrollment(ctx, authn, "123456"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.BeginTOTPEnrollment(ctx, authn); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("second enrollment = %v", err)
	}
	if _, err := f.manager.ConfirmTOTPEnrollment(ctx, authn, "123456"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("confirm active factor = %v", err)
	}
	stepUp := aal2(authn.UserID, f.now)
	expired := f.now.Add(-time.Second)
	invalidPATs := []credbound.CreatePATInput{
		{},
		{Name: "x", Scopes: []string{}},
		{Name: "x", Scopes: []string{"read"}, ExpiresAt: &expired},
		{Name: "x", Scopes: []string{""}},
		{Name: strings.Repeat("x", 101), Scopes: []string{"read"}},
	}
	for _, input := range invalidPATs {
		if _, err := f.manager.CreatePAT(ctx, stepUp, input); !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("invalid PAT %#v = %v", input, err)
		}
	}
	otherWorkspace := "0198b463-0000-7000-8000-dddddddddddd"
	if _, err := f.manager.CreatePAT(ctx, stepUp, credbound.CreatePATInput{Name: "x", WorkspaceID: otherWorkspace, Scopes: []string{"read"}}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("foreign workspace PAT = %v", err)
	}
	for _, raw := range []string{"", "cbp_bad", "cbp_zzzzzzzzzzzz_" + strings.Repeat("a", 43), "cbp_000000000000_short"} {
		if _, err := f.manager.AuthenticatePAT(ctx, raw); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("malformed PAT %q = %v", raw, err)
		}
	}
	if err := f.manager.RevokePAT(ctx, stepUp, ""); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("empty PAT revocation = %v", err)
	}
	if err := f.manager.Authorize(ctx, stepUp, workspace.ID, credbound.RoleMember); err != nil {
		t.Fatal(err)
	}
}

func TestPasskeyAndAdminFailureBoundaries(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()
	if _, err := f.manager.BeginPasskeyRegistration(ctx, authn, ""); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("empty passkey name = %v", err)
	}
	challenge, err := f.manager.BeginPasskeyRegistration(ctx, authn, "Phone")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.FinishPasskeyRegistration(ctx, authn, challenge.Continuation, []byte("bad")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("bad registration response = %v", err)
	}
	f.now = f.now.Add(6 * time.Minute)
	if _, err := f.manager.FinishPasskeyRegistration(ctx, authn, challenge.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrExpired) {
		t.Fatalf("expired registration = %v", err)
	}
	// An unknown address returns a decoy challenge rather than an error, so it
	// never reveals whether the account exists; finishing it fails closed.
	decoy, err := f.manager.BeginPasskeyAuthentication(ctx, "missing@example.com")
	if err != nil || len(decoy.Options) == 0 || decoy.Continuation == "" {
		t.Fatalf("unknown passkey user decoy = %#v, %v", decoy, err)
	}
	if _, err := f.manager.FinishPasskeyAuthentication(ctx, decoy.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("decoy finish = %v", err)
	}
	if err := f.manager.DeletePasskey(ctx, aal2(authn.UserID, f.now), ""); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("empty passkey deletion = %v", err)
	}
	root := aal2(authn.UserID, f.now)
	if err := f.manager.SetInstanceRole(ctx, root, credbound.TrustedRequest{}, authn.UserID, credbound.InstanceRoleSales); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("self downgrade = %v", err)
	}
	if err := f.manager.SetInstanceRole(ctx, root, credbound.TrustedRequest{}, "", credbound.InstanceRoleSales); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("empty target role = %v", err)
	}
	if err := f.manager.SetInstanceRole(ctx, root, credbound.TrustedRequest{}, "missing", credbound.InstanceRole("unknown")); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("unknown instance role = %v", err)
	}
	if err := f.manager.RemoveInstanceRole(ctx, root, credbound.TrustedRequest{}, authn.UserID); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("self role removal = %v", err)
	}
	if err := f.manager.RequireAdminMutation(credbound.Authentication{UserID: authn.UserID, Method: credbound.MethodPAT}, credbound.TrustedRequest{Local: true}); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("local PAT admin mutation = %v", err)
	}
}

func TestWorkspaceAuditAndErrorSequences(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	admin := aal2(authn.UserID, f.now)
	page := collectAuditPage(t, f.manager.AuditEvents(context.Background(), admin, workspace.ID, credbound.PageRequest{}))
	if len(page.items) == 0 || page.end == nil {
		t.Fatalf("workspace audit = %#v", page)
	}
	for _, sequence := range []func(func(credbound.PageEvent[credbound.PAT], error) bool){
		f.manager.PATs(context.Background(), credbound.Authentication{}, "", credbound.PageRequest{}),
		f.manager.PATs(context.Background(), authn, "", credbound.PageRequest{Limit: 101}),
	} {
		seen := false
		for _, err := range sequence {
			seen = true
			if err == nil {
				t.Fatal("error sequence yielded nil")
			}
		}
		if !seen {
			t.Fatal("error sequence yielded nothing")
		}
	}
}

func TestEarlyAuthorizationAndIdentityBoundaries(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	if _, err := f.manager.BeginPasskeyRegistration(ctx, credbound.Authentication{}, "Phone"); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("unauthorized registration begin = %v", err)
	}
	challenge, err := f.manager.BeginPasskeyRegistration(ctx, authn, "Phone")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.FinishPasskeyRegistration(ctx, credbound.Authentication{}, challenge.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("unauthorized registration finish = %v", err)
	}
	other := authn
	other.UserID = "0198b463-0000-7000-8000-ffffffffffff"
	if _, err := f.manager.FinishPasskeyRegistration(ctx, other, challenge.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("cross-user continuation = %v", err)
	}
	if err := f.manager.DeletePasskey(ctx, credbound.Authentication{}, "passkey"); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("unauthorized passkey deletion = %v", err)
	}
	if err := f.manager.GrantRole(ctx, authn, workspace.ID, authn.UserID, credbound.RoleMember); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("role grant without step-up = %v", err)
	}
	if err := f.manager.GrantRole(ctx, aal2(authn.UserID, f.now), workspace.ID, authn.UserID, credbound.Role("owner")); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid granted role = %v", err)
	}
	for _, err := range f.manager.InstanceAuditEvents(ctx, aal2(authn.UserID, f.now), credbound.PageRequest{Limit: 101}) {
		if !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("invalid instance audit page = %v", err)
		}
	}
}

func TestCorruptStoredPasskeyFailsClosed(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	event := credbound.AuditEvent{
		ID: "0198b463-0000-7000-8000-fffffffffff0", OccurredAt: f.now,
		ActorID: authn.UserID, Action: "test.passkey.corrupt", ResourceType: "passkey",
		ResourceID: "0198b463-0000-7000-8000-fffffffffff1", Outcome: credbound.AuditSucceeded,
	}
	err := f.store.SavePasskey(context.Background(), credbound.Passkey{
		ID: event.ResourceID, UserID: authn.UserID, Name: "Corrupt",
		CredentialID: []byte("corrupt"), CredentialJSON: []byte("not-encrypted"), CreatedAt: f.now,
	}, credbound.Commit{Audit: event})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.BeginPasskeyAuthentication(context.Background(), "root@example.com"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("corrupt stored credential = %v", err)
	}
}
