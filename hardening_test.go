package credbound_test

import (
	"context"
	"errors"
	"iter"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
)

func collectPasskeys(t *testing.T, sequence func(func(credbound.Passkey, error) bool)) ([]credbound.Passkey, error) {
	t.Helper()
	var items []credbound.Passkey
	for value, err := range sequence {
		if err != nil {
			return items, err
		}
		items = append(items, value)
	}
	return items, nil
}

func TestPasskeyListing(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	challenge, err := f.manager.BeginPasskeyRegistration(context.Background(), authn, "MacBook")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.FinishPasskeyRegistration(context.Background(), authn, challenge.Continuation, []byte("valid")); err != nil {
		t.Fatal(err)
	}

	passkeys, err := collectPasskeys(t, f.manager.Passkeys(context.Background(), authn, ""))
	if err != nil || len(passkeys) != 1 {
		t.Fatalf("passkeys = %#v, %v", passkeys, err)
	}
	if passkeys[0].Name != "MacBook" || passkeys[0].CredentialJSON != nil || len(passkeys[0].CredentialID) == 0 {
		t.Fatalf("unsafe passkey listing: %#v", passkeys[0])
	}

	if _, err := collectPasskeys(t, f.manager.Passkeys(context.Background(), credbound.Authentication{}, "")); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous listing error = %v", err)
	}
	stale := authn
	stale.AuthenticatedAt = f.now.Add(-time.Hour)
	if _, err := collectPasskeys(t, f.manager.Passkeys(context.Background(), stale, "")); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("stale listing error = %v", err)
	}

	// The bootstrap root holds admin.users.read, so it may inspect another user.
	other, err := f.manager.CreateUser(context.Background(), aal2(authn.UserID, f.now), workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	if items, err := collectPasskeys(t, f.manager.Passkeys(context.Background(), authn, other.ID)); err != nil || len(items) != 0 {
		t.Fatalf("admin listing = %#v, %v", items, err)
	}
	memberAuthn := credbound.Authentication{UserID: other.ID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: f.now}
	if _, err := collectPasskeys(t, f.manager.Passkeys(context.Background(), memberAuthn, authn.UserID)); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("cross-user listing error = %v", err)
	}
}

func TestTOTPStatusLifecycle(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)

	status, err := f.manager.TOTPStatus(context.Background(), authn, "")
	if err != nil || status.Enrolled || status.Active {
		t.Fatalf("initial status = %#v, %v", status, err)
	}
	if _, err := f.manager.BeginTOTPEnrollment(context.Background(), authn); err != nil {
		t.Fatal(err)
	}
	status, err = f.manager.TOTPStatus(context.Background(), authn, "")
	if err != nil || !status.Enrolled || status.Active || status.UnusedRecoveryCodes != 0 {
		t.Fatalf("enrolled status = %#v, %v", status, err)
	}
	codes, err := f.manager.ConfirmTOTPEnrollment(context.Background(), authn, "123456")
	if err != nil {
		t.Fatal(err)
	}
	status, err = f.manager.TOTPStatus(context.Background(), authn, "")
	if err != nil || !status.Active || status.UnusedRecoveryCodes != 10 {
		t.Fatalf("active status = %#v, %v", status, err)
	}
	if _, err := f.manager.VerifyTOTP(context.Background(), authn, codes[0]); err != nil {
		t.Fatal(err)
	}
	status, err = f.manager.TOTPStatus(context.Background(), authn, "")
	if err != nil || status.UnusedRecoveryCodes != 9 {
		t.Fatalf("status after recovery use = %#v, %v", status, err)
	}
	if _, err := f.manager.TOTPStatus(context.Background(), credbound.Authentication{}, ""); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous status error = %v", err)
	}
}

func TestAuditRequestMetadata(t *testing.T) {
	f := newFixture(t)
	ctx := credbound.WithRequestMetadata(context.Background(), credbound.RequestMetadata{
		IPAddress: "  203.0.113.7  ",
		UserAgent: "Mozilla/5.0\x00\x1f (X11; Linux) " + strings.Repeat("x", 300),
	})
	authn, _, err := f.manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Without metadata in the context, audit fields stay empty.
	if _, err := f.manager.AuthenticatePassword(context.Background(), "root@example.com", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	events := collectAuditPage(t, f.manager.InstanceAuditEvents(context.Background(), authn, credbound.PageRequest{Limit: 10}))
	byAction := map[string]credbound.AuditEvent{}
	for _, event := range events.items {
		byAction[event.Action] = event
	}
	recorded, found := byAction["instance.bootstrap"]
	if !found || recorded.IPAddress != "203.0.113.7" {
		t.Fatalf("audited IP = %#v", recorded)
	}
	if strings.ContainsAny(recorded.UserAgent, "\x00\x1f") || len([]rune(recorded.UserAgent)) != 256 {
		t.Fatalf("audited user agent not sanitized: %q (%d)", recorded.UserAgent, len([]rune(recorded.UserAgent)))
	}
	if recorded.Sequence != 1 || len(recorded.Hash) == 0 {
		t.Fatalf("audit event not chained: %#v", recorded)
	}
	login, found := byAction["auth.password"]
	if !found || login.IPAddress != "" || login.UserAgent != "" {
		t.Fatalf("unexpected metadata: %#v", login)
	}
}

func TestVerifyAuditChain(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	if _, err := f.manager.AuthenticatePassword(context.Background(), "root@example.com", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.CreateWorkspace(context.Background(), aal2(authn.UserID, f.now), credbound.CreateWorkspaceInput{Name: "Second"}); err != nil {
		t.Fatal(err)
	}
	// AuthorizeAdmin audits the verification itself, so the chain holds the
	// bootstrap, the login, the workspace creation and this admin check.
	report, err := f.manager.VerifyAuditChain(context.Background(), authn)
	if err != nil || report.Events != 4 || report.HeadSequence != 4 || len(report.HeadHash) != 32 {
		t.Fatalf("chain report = %#v, %v", report, err)
	}
	member, err := f.manager.CreateUser(context.Background(), aal2(authn.UserID, f.now), workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	memberAuthn := credbound.Authentication{UserID: member.ID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: f.now}
	if _, err := f.manager.VerifyAuditChain(context.Background(), memberAuthn); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("member verification error = %v", err)
	}
}

type lockoutFixture struct {
	manager *credbound.Manager
	now     time.Time
}

func newLockoutFixture(t *testing.T, maxFailedLogins int, lockoutDuration time.Duration) *lockoutFixture {
	t.Helper()
	f := &lockoutFixture{now: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)}
	manager, err := credbound.New(credbound.Config{
		Store: memory.New(), Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return f.now }, Random: &counterReader{next: 0x21},
		MaxFailedLogins: maxFailedLogins, LockoutDuration: lockoutDuration,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.manager = manager
	return f
}

func (f *lockoutFixture) bootstrap(t *testing.T) credbound.Authentication {
	t.Helper()
	authn, _, err := f.manager.Bootstrap(context.Background(), credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	return authn
}

func TestPasswordLockout(t *testing.T) {
	f := newLockoutFixture(t, 3, 15*time.Minute)
	f.bootstrap(t)
	ctx := context.Background()
	for range 3 {
		if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "wrong password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("failure error = %v", err)
		}
	}
	// The account is locked: even the correct password is rejected, and the
	// public answer stays ErrInvalidCredentials so the lockout never
	// confirms that the address exists.
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); !errors.Is(err, credbound.ErrInvalidCredentials) || errors.Is(err, credbound.ErrLocked) {
		t.Fatalf("locked login error = %v", err)
	}
	// Unknown accounts keep answering ErrInvalidCredentials, never ErrLocked.
	if _, err := f.manager.AuthenticatePassword(ctx, "ghost@example.com", "whatever password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("unknown account error = %v", err)
	}
	// After the lockout expires, one failure does not immediately re-lock.
	f.now = f.now.Add(16 * time.Minute)
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "wrong password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("post-lockout failure error = %v", err)
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err != nil {
		t.Fatalf("post-lockout login = %v", err)
	}
	// Success reset the counter: three fresh failures are needed to re-lock.
	for range 2 {
		if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "wrong password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("failure error = %v", err)
		}
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err != nil {
		t.Fatalf("login after reset = %v", err)
	}
}

func TestTOTPLockout(t *testing.T) {
	f := newLockoutFixture(t, 3, 15*time.Minute)
	authn := f.bootstrap(t)
	ctx := context.Background()
	if _, err := f.manager.BeginTOTPEnrollment(ctx, authn); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.ConfirmTOTPEnrollment(ctx, authn, "123456"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := f.manager.VerifyTOTP(ctx, authn, "000000"); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("TOTP failure error = %v", err)
		}
	}
	if _, err := f.manager.VerifyTOTP(ctx, authn, "123456"); !errors.Is(err, credbound.ErrLocked) {
		t.Fatalf("locked TOTP error = %v", err)
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("locked password error = %v", err)
	}
	f.now = f.now.Add(16 * time.Minute)
	if _, err := f.manager.VerifyTOTP(ctx, authn, "123456"); err != nil {
		t.Fatalf("post-lockout TOTP = %v", err)
	}
}

func TestLockoutDisabled(t *testing.T) {
	f := newLockoutFixture(t, -1, 0)
	f.bootstrap(t)
	ctx := context.Background()
	for range 12 {
		if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "wrong password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("failure error = %v", err)
		}
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err != nil {
		t.Fatalf("login with lockout disabled = %v", err)
	}
}

func TestWorkspaceRequireMFA(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	stepUp := aal2(authn.UserID, f.now)
	secure, err := f.manager.CreateWorkspace(ctx, stepUp, credbound.CreateWorkspaceInput{Name: "Secure", RequireMFA: true})
	if err != nil || !secure.RequireMFA {
		t.Fatalf("secure workspace = %#v, %v", secure, err)
	}
	// An interactive AAL1 session is rejected with the step-up sentinel.
	if err := f.manager.Authorize(ctx, authn, secure.ID, credbound.RoleMember); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 authorization error = %v", err)
	}
	if err := f.manager.AuthorizePermission(ctx, authn, secure.ID, credbound.PermissionWorkspaceAccess); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 permission error = %v", err)
	}
	if err := f.manager.Authorize(ctx, stepUp, secure.ID, credbound.RoleAdmin); err != nil {
		t.Fatalf("AAL2 authorization = %v", err)
	}
	// A workspace-bound PAT is non-interactive and stays usable, within the
	// permissions its scopes name.
	issued, err := f.manager.CreatePAT(ctx, stepUp, credbound.CreatePATInput{Name: "ci", WorkspaceID: secure.ID, Scopes: []string{string(credbound.PermissionWorkspaceAccess)}})
	if err != nil {
		t.Fatal(err)
	}
	patAuthn, err := f.manager.AuthenticatePAT(ctx, issued.Token)
	if err != nil {
		t.Fatalf("PAT in MFA workspace = %v", err)
	}
	if err := f.manager.AuthorizePermission(ctx, patAuthn, secure.ID, credbound.PermissionWorkspaceAccess); err != nil {
		t.Fatalf("PAT authorization = %v", err)
	}
	// The default workspace stays unaffected, and the policy can be lifted.
	if err := f.manager.Authorize(ctx, authn, workspace.ID, credbound.RoleMember); err != nil {
		t.Fatalf("default workspace = %v", err)
	}
	disabled := false
	if _, err := f.manager.UpdateWorkspace(ctx, stepUp, secure.ID, credbound.UpdateWorkspaceInput{Name: "Secure", RequireMFA: &disabled}); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Authorize(ctx, authn, secure.ID, credbound.RoleMember); err != nil {
		t.Fatalf("post-toggle authorization = %v", err)
	}
}

func TestPasswordResetFlow(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	issued, err := f.manager.CreatePAT(ctx, aal2(authn.UserID, f.now), credbound.CreatePATInput{
		Name: "laptop", WorkspaceID: workspace.ID, Scopes: []string{"read"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if issued, err := f.manager.BeginPasswordReset(ctx, "ghost@example.com"); err != nil || issued.Token != "" {
		t.Fatalf("unknown email reset = %#v, %v", issued, err)
	}
	reset, err := f.manager.BeginPasswordReset(ctx, "ROOT@example.com")
	if err != nil || reset.UserID != authn.UserID || !strings.HasPrefix(reset.Token, "cbr_") {
		t.Fatalf("reset = %#v, %v", reset, err)
	}
	if !reset.ExpiresAt.Equal(f.now.Add(time.Hour)) {
		t.Fatalf("reset TTL = %v", reset.ExpiresAt)
	}

	if _, err := f.manager.CompletePasswordReset(ctx, "not-a-token", "brand new password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("malformed token error = %v", err)
	}
	if _, err := f.manager.CompletePasswordReset(ctx, reset.Token, "short"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("weak password error = %v", err)
	}
	user, err := f.manager.CompletePasswordReset(ctx, reset.Token, "brand new password")
	if err != nil || user.ID != authn.UserID {
		t.Fatalf("complete reset = %#v, %v", user, err)
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("old password error = %v", err)
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "brand new password"); err != nil {
		t.Fatalf("new password login = %v", err)
	}
	// The recovery policy revoked the PAT and the token is single use.
	if _, err := f.manager.AuthenticatePAT(ctx, issued.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("PAT after reset error = %v", err)
	}
	if _, err := f.manager.CompletePasswordReset(ctx, reset.Token, "brand new password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("reused token error = %v", err)
	}

	expired, err := f.manager.BeginPasswordReset(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(2 * time.Hour)
	if _, err := f.manager.CompletePasswordReset(ctx, expired.Token, "yet another password"); !errors.Is(err, credbound.ErrExpired) {
		t.Fatalf("expired token error = %v", err)
	}
}

func TestPasswordResetUnlocksAccount(t *testing.T) {
	f := newLockoutFixture(t, 3, 15*time.Minute)
	f.bootstrap(t)
	ctx := context.Background()
	for range 3 {
		if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "wrong password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("failure error = %v", err)
		}
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("locked error = %v", err)
	}
	reset, err := f.manager.BeginPasswordReset(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.CompletePasswordReset(ctx, reset.Token, "fresh account password"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "fresh account password"); err != nil {
		t.Fatalf("post-reset login = %v", err)
	}
}

func TestMagicLinkAuthentication(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()

	if issued, err := f.manager.BeginEmailAuthentication(ctx, "ghost@example.com"); err != nil || issued.Token != "" {
		t.Fatalf("unknown email link = %#v, %v", issued, err)
	}
	link, err := f.manager.BeginEmailAuthentication(ctx, "Root@example.com")
	if err != nil || link.UserID != authn.UserID || !strings.HasPrefix(link.Token, "cbl_") || link.EmailID == "" {
		t.Fatalf("magic link = %#v, %v", link, err)
	}
	login, err := f.manager.CompleteEmailAuthentication(ctx, link.Token)
	if err != nil || login.Method != credbound.MethodEmail || login.Level != credbound.AAL1 || !login.Interactive() || login.SecondFactorRequired {
		t.Fatalf("magic-link login = %#v, %v", login, err)
	}
	// The fresh interactive authentication can start TOTP enrollment.
	if _, err := f.manager.BeginTOTPEnrollment(ctx, login); err != nil {
		t.Fatalf("interactive use = %v", err)
	}
	if _, err := f.manager.CompleteEmailAuthentication(ctx, link.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("reused link error = %v", err)
	}

	// With an active TOTP factor, the link reports the pending second factor.
	if _, err := f.manager.ConfirmTOTPEnrollment(ctx, authn, "123456"); err != nil {
		t.Fatal(err)
	}
	second, err := f.manager.BeginEmailAuthentication(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	mfaLogin, err := f.manager.CompleteEmailAuthentication(ctx, second.Token)
	if err != nil || !mfaLogin.SecondFactorRequired {
		t.Fatalf("second factor flag = %#v, %v", mfaLogin, err)
	}
	otpIssued, err := f.manager.BeginEmailOTP(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	otpLogin, err := f.manager.CompleteEmailOTP(ctx, otpIssued.Continuation, otpIssued.Code)
	if err != nil || !otpLogin.SecondFactorRequired {
		t.Fatalf("OTP second factor flag = %#v, %v", otpLogin, err)
	}

	expired, err := f.manager.BeginEmailAuthentication(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(16 * time.Minute)
	if _, err := f.manager.CompleteEmailAuthentication(ctx, expired.Token); !errors.Is(err, credbound.ErrExpired) {
		t.Fatalf("expired link error = %v", err)
	}
}

func TestRevokeUserCredentials(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	stepUp := aal2(authn.UserID, f.now)
	issued, err := f.manager.CreatePAT(context.Background(), stepUp, credbound.CreatePATInput{
		Name: "laptop", WorkspaceID: workspace.ID, Scopes: []string{"read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.AuthenticatePAT(context.Background(), issued.Token); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.RevokeUserCredentials(context.Background(), stepUp, credbound.TrustedRequest{}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.AuthenticatePAT(context.Background(), issued.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("revoked PAT error = %v", err)
	}

	member, err := f.manager.CreateUser(context.Background(), stepUp, workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	memberStepUp := aal2(member.ID, f.now)
	if err := f.manager.RevokeUserCredentials(context.Background(), memberStepUp, credbound.TrustedRequest{}, authn.UserID); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("member revoking root error = %v", err)
	}
	if err := f.manager.RevokeUserCredentials(context.Background(), stepUp, credbound.TrustedRequest{}, member.ID); err != nil {
		t.Fatalf("admin revocation = %v", err)
	}
	if err := f.manager.RevokeUserCredentials(context.Background(), stepUp, credbound.TrustedRequest{}, "not-a-uuid"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid user id error = %v", err)
	}
	if err := f.manager.RevokeUserCredentials(context.Background(), credbound.Authentication{}, credbound.TrustedRequest{}, ""); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("anonymous revocation error = %v", err)
	}
}

func TestInvitationRegistration(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	stepUp := aal2(authn.UserID, f.now)

	issued, err := f.manager.InviteToWorkspace(ctx, stepUp, workspace.ID, credbound.InviteToWorkspaceInput{
		Email: "Invitee@example.com", Role: credbound.RoleMember,
	})
	if err != nil || !strings.HasPrefix(issued.Token, "cbi_") || issued.Invitation.Digest != nil {
		t.Fatalf("invitation = %#v, %v", issued, err)
	}
	if issued.Invitation.Email != "invitee@example.com" || issued.Invitation.Role != credbound.RoleMember {
		t.Fatalf("invitation content = %#v", issued.Invitation)
	}
	// Only one pending invitation per address and workspace.
	if _, err := f.manager.InviteToWorkspace(ctx, stepUp, workspace.ID, credbound.InviteToWorkspaceInput{
		Email: "invitee@example.com", Role: credbound.RoleMember,
	}); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate invitation error = %v", err)
	}
	// Existing members cannot be invited again.
	if _, err := f.manager.InviteToWorkspace(ctx, stepUp, workspace.ID, credbound.InviteToWorkspaceInput{
		Email: "root@example.com", Role: credbound.RoleMember,
	}); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("member invitation error = %v", err)
	}

	if _, _, err := f.manager.RegisterFromInvitation(ctx, issued.Token, credbound.RegisterFromInvitationInput{
		DisplayName: "", Password: "chosen by invitee",
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("missing display name error = %v", err)
	}
	invited, user, err := f.manager.RegisterFromInvitation(ctx, issued.Token, credbound.RegisterFromInvitationInput{
		DisplayName: "Invitee", Password: "chosen by invitee",
	})
	if err != nil || invited.Level != credbound.AAL1 || user.Email != "invitee@example.com" {
		t.Fatalf("registration = %#v, %#v, %v", invited, user, err)
	}
	if err := f.manager.Authorize(ctx, invited, workspace.ID, credbound.RoleMember); err != nil {
		t.Fatalf("invited member authorization = %v", err)
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "invitee@example.com", "chosen by invitee"); err != nil {
		t.Fatalf("invitee login = %v", err)
	}
	// The token is single use.
	if _, _, err := f.manager.RegisterFromInvitation(ctx, issued.Token, credbound.RegisterFromInvitationInput{
		DisplayName: "Again", Password: "another password!!",
	}); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("reused invitation error = %v", err)
	}
}

func TestInvitationAcceptRevokeAndExpiry(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	stepUp := aal2(authn.UserID, f.now)
	member, err := f.manager.CreateUser(ctx, stepUp, workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.manager.CreateWorkspace(ctx, stepUp, credbound.CreateWorkspaceInput{Name: "Second"})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := f.manager.InviteToWorkspace(ctx, stepUp, second.ID, credbound.InviteToWorkspaceInput{
		Email: "member@example.com", Role: credbound.RoleAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The wrong account cannot accept someone else's invitation.
	if _, err := f.manager.AcceptInvitation(ctx, stepUp, issued.Token); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("email mismatch error = %v", err)
	}
	memberAuthn := credbound.Authentication{UserID: member.ID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: f.now}
	membership, err := f.manager.AcceptInvitation(ctx, memberAuthn, issued.Token)
	if err != nil || membership.WorkspaceID != second.ID || membership.Role != credbound.RoleAdmin {
		t.Fatalf("accepted membership = %#v, %v", membership, err)
	}
	if _, err := f.manager.AcceptInvitation(ctx, memberAuthn, issued.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("reused acceptance error = %v", err)
	}

	// Revocation kills a pending token.
	revocable, err := f.manager.InviteToWorkspace(ctx, stepUp, second.ID, credbound.InviteToWorkspaceInput{
		Email: "revoked@example.com", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.RevokeInvitation(ctx, stepUp, second.ID, revocable.Invitation.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.manager.RegisterFromInvitation(ctx, revocable.Token, credbound.RegisterFromInvitationInput{
		DisplayName: "Revoked", Password: "some password here",
	}); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("revoked invitation error = %v", err)
	}

	// Listing shows both invitations without digests.
	listed := 0
	for event, err := range f.manager.WorkspaceInvitations(ctx, stepUp, second.ID, credbound.PageRequest{Limit: 10}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			listed++
			if event.Data.Digest != nil {
				t.Fatalf("digest leaked: %#v", event.Data)
			}
		}
	}
	if listed != 2 {
		t.Fatalf("listed invitations = %d", listed)
	}

	// Expired invitations are rejected.
	expiring, err := f.manager.InviteToWorkspace(ctx, stepUp, second.ID, credbound.InviteToWorkspaceInput{
		Email: "late@example.com", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(8 * 24 * time.Hour)
	if _, _, err := f.manager.RegisterFromInvitation(ctx, expiring.Token, credbound.RegisterFromInvitationInput{
		DisplayName: "Late", Password: "some password here",
	}); !errors.Is(err, credbound.ErrExpired) {
		t.Fatalf("expired invitation error = %v", err)
	}
}

// forgeSecret keeps a token's identifier but replaces its secret with a
// well-formed but wrong value.
func forgeSecret(token string) string {
	parts := strings.SplitN(token, "_", 3)
	return parts[0] + "_" + parts[1] + "_" + strings.Repeat("A", 43)
}

func TestTokenForgeryAndDisabledUserPaths(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	stepUp := aal2(authn.UserID, f.now)
	member, err := f.manager.CreateUser(ctx, stepUp, workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}

	reset, err := f.manager.BeginPasswordReset(ctx, "member@example.com")
	if err != nil {
		t.Fatal(err)
	}
	link, err := f.manager.BeginEmailAuthentication(ctx, "member@example.com")
	if err != nil {
		t.Fatal(err)
	}
	otp, err := f.manager.BeginEmailOTP(ctx, "member@example.com")
	if err != nil || otp.Code == "" {
		t.Fatalf("member OTP = %#v, %v", otp, err)
	}
	// A forged secret with a valid identifier is rejected.
	if _, err := f.manager.CompletePasswordReset(ctx, forgeSecret(reset.Token), "some new password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("forged reset error = %v", err)
	}
	if _, err := f.manager.CompleteEmailAuthentication(ctx, forgeSecret(link.Token)); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("forged link error = %v", err)
	}
	// A well-formed token with an unknown identifier is rejected too.
	ghostReset := "cbr_" + reset.UserID + "_" + strings.Repeat("A", 43)
	if _, err := f.manager.CompletePasswordReset(ctx, ghostReset, "some new password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("unknown reset error = %v", err)
	}
	if _, err := f.manager.CompleteEmailAuthentication(ctx, "cbl_"+link.UserID+"_"+strings.Repeat("A", 43)); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("unknown link error = %v", err)
	}

	// Disabling the account voids its pending tokens and further requests.
	if err := f.manager.DisableUser(ctx, stepUp, credbound.TrustedRequest{Local: true}, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.CompletePasswordReset(ctx, reset.Token, "some new password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("reset for disabled user error = %v", err)
	}
	if _, err := f.manager.CompleteEmailAuthentication(ctx, link.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("link for disabled user error = %v", err)
	}
	if issued, err := f.manager.BeginPasswordReset(ctx, "member@example.com"); err != nil || issued.Token != "" {
		t.Fatalf("reset request for disabled user = %#v, %v", issued, err)
	}
	if issued, err := f.manager.BeginEmailAuthentication(ctx, "member@example.com"); err != nil || issued.Token != "" {
		t.Fatalf("link request for disabled user = %#v, %v", issued, err)
	}
	if _, err := f.manager.CompleteEmailOTP(ctx, otp.Continuation, otp.Code); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("OTP for disabled user error = %v", err)
	}
	if issued, err := f.manager.BeginEmailOTP(ctx, "member@example.com"); err != nil || issued.Code != "" || issued.Continuation == "" {
		t.Fatalf("OTP request for disabled user = %#v, %v", issued, err)
	}
}

func TestInvitationForgedAndDisabledWorkspace(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()
	stepUp := aal2(authn.UserID, f.now)
	second, err := f.manager.CreateWorkspace(ctx, stepUp, credbound.CreateWorkspaceInput{Name: "Second"})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := f.manager.InviteToWorkspace(ctx, stepUp, second.ID, credbound.InviteToWorkspaceInput{
		Email: "invitee@example.com", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.manager.RegisterFromInvitation(ctx, forgeSecret(issued.Token), credbound.RegisterFromInvitationInput{
		DisplayName: "Invitee", Password: "chosen by invitee",
	}); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("forged invitation error = %v", err)
	}
	if _, _, err := f.manager.RegisterFromInvitation(ctx, "cbi_"+second.ID+"_"+strings.Repeat("A", 43), credbound.RegisterFromInvitationInput{
		DisplayName: "Invitee", Password: "chosen by invitee",
	}); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("unknown invitation error = %v", err)
	}
	if err := f.manager.DisableWorkspace(ctx, stepUp, second.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.manager.RegisterFromInvitation(ctx, issued.Token, credbound.RegisterFromInvitationInput{
		DisplayName: "Invitee", Password: "chosen by invitee",
	}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("invitation to disabled workspace error = %v", err)
	}
	// Inviting into the disabled workspace is denied as well.
	if _, err := f.manager.InviteToWorkspace(ctx, stepUp, second.ID, credbound.InviteToWorkspaceInput{
		Email: "late@example.com", Role: credbound.RoleMember,
	}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("invitation in disabled workspace error = %v", err)
	}
	// Listing and revocation validation paths.
	if _, err := collectPasskeys(t, f.manager.Passkeys(context.Background(), stepUp, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.RevokeInvitation(ctx, stepUp, second.ID, "not-a-uuid"); !errors.Is(err, credbound.ErrForbidden) {
		// The disabled workspace is rejected before the id validation.
		t.Fatalf("revoke in disabled workspace error = %v", err)
	}
}

func TestMagicLinkOnSecondaryVerifiedAddress(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()
	issued, err := f.manager.BeginEmailAddition(ctx, authn, "secondary@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.ConfirmEmail(ctx, issued.Token); err != nil {
		t.Fatal(err)
	}
	link, err := f.manager.BeginEmailAuthentication(ctx, "secondary@example.com")
	if err != nil || link.EmailID != issued.Email.ID {
		t.Fatalf("secondary magic link = %#v, %v", link, err)
	}
	if _, err := f.manager.CompleteEmailAuthentication(ctx, link.Token); err != nil {
		t.Fatalf("secondary magic-link login = %v", err)
	}
}

func TestHardeningAuditUnavailable(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	stepUp := aal2(authn.UserID, f.now)
	reset, err := f.manager.BeginPasswordReset(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	link, err := f.manager.BeginEmailAuthentication(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	otp, err := f.manager.BeginEmailOTP(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := f.manager.InviteToWorkspace(ctx, stepUp, workspace.ID, credbound.InviteToWorkspaceInput{
		Email: "invitee@example.com", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}

	f.store.SetAuditFailure(errors.New("disk full"))
	defer f.store.SetAuditFailure(nil)
	if _, err := f.manager.BeginPasswordReset(ctx, "unknown@example.com"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("reset request audit failure = %v", err)
	}
	if _, err := f.manager.BeginPasswordReset(ctx, "root@example.com"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("reset begin audit failure = %v", err)
	}
	if _, err := f.manager.CompletePasswordReset(ctx, reset.Token, "brand new password"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("reset complete audit failure = %v", err)
	}
	if _, err := f.manager.CompletePasswordReset(ctx, forgeSecret(reset.Token), "brand new password"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("reset forged audit failure = %v", err)
	}
	if _, err := f.manager.BeginEmailAuthentication(ctx, "root@example.com"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("link begin audit failure = %v", err)
	}
	if _, err := f.manager.CompleteEmailAuthentication(ctx, link.Token); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("link complete audit failure = %v", err)
	}
	if _, err := f.manager.CompleteEmailAuthentication(ctx, forgeSecret(link.Token)); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("link forged audit failure = %v", err)
	}
	if _, err := f.manager.BeginEmailOTP(ctx, "unknown@example.com"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("OTP request audit failure = %v", err)
	}
	if _, err := f.manager.BeginEmailOTP(ctx, "root@example.com"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("OTP begin audit failure = %v", err)
	}
	if _, err := f.manager.CompleteEmailOTP(ctx, otp.Continuation, otp.Code); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("OTP complete audit failure = %v", err)
	}
	if _, err := f.manager.CompleteEmailOTP(ctx, otp.Continuation, "00000000"); !errors.Is(err, credbound.ErrAuditUnavailable) && !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("OTP wrong-code audit failure = %v", err)
	}
	f.store.SetAuditFailure(nil)
	decoy, err := f.manager.BeginEmailOTP(ctx, "ghost@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.CompleteEmailOTP(ctx, otp.Continuation, otp.Code); err != nil {
		t.Fatalf("OTP baseline completion = %v", err)
	}
	expiredOTP, err := f.manager.BeginEmailOTP(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	f.store.SetAuditFailure(errors.New("disk full"))
	if _, err := f.manager.CompleteEmailOTP(ctx, decoy.Continuation, "00000000"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("OTP decoy audit failure = %v", err)
	}
	if _, err := f.manager.CompleteEmailOTP(ctx, otp.Continuation, otp.Code); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("OTP reuse audit failure = %v", err)
	}
	f.now = f.now.Add(15*time.Minute + 30*time.Second)
	if _, err := f.manager.CompleteEmailOTP(ctx, expiredOTP.Continuation, expiredOTP.Code); !errors.Is(err, credbound.ErrAuditUnavailable) && !errors.Is(err, credbound.ErrExpired) {
		t.Fatalf("OTP expired audit failure = %v", err)
	}
	f.now = f.now.Add(-(15*time.Minute + 30*time.Second))
	if err := f.manager.RevokeUserCredentials(ctx, stepUp, credbound.TrustedRequest{}, ""); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("revocation audit failure = %v", err)
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "wrong password"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("counted failure audit failure = %v", err)
	}
	if _, _, err := f.manager.RegisterFromInvitation(ctx, invitation.Token, credbound.RegisterFromInvitationInput{
		DisplayName: "Invitee", Password: "chosen by invitee",
	}); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("registration audit failure = %v", err)
	}
	if _, _, err := f.manager.RegisterFromInvitation(ctx, forgeSecret(invitation.Token), credbound.RegisterFromInvitationInput{
		DisplayName: "Invitee", Password: "chosen by invitee",
	}); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("forged registration audit failure = %v", err)
	}
	if err := f.manager.RevokeInvitation(ctx, stepUp, workspace.ID, invitation.Invitation.ID); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("invitation revocation audit failure = %v", err)
	}
}

// hardeningFaultStore injects infrastructure failures into the new store
// lookups so Manager error propagation is observable.
type hardeningFaultStore struct {
	credbound.Store
	throttleErr      error
	recordFailErr    error
	resetErr         error
	linkErr          error
	invitationErr    error
	userByEmailErr   error
	emailsErr        error
	recoveryCountErr error
	totpErr          error
	workspaceErr     error
	consumeLinkErr   error
	completeResetErr error
}

func (s *hardeningFaultStore) TOTPByUserID(ctx context.Context, userID string) (credbound.TOTPFactor, error) {
	if s.totpErr != nil {
		return credbound.TOTPFactor{}, s.totpErr
	}
	return s.Store.TOTPByUserID(ctx, userID)
}

func (s *hardeningFaultStore) WorkspaceByID(ctx context.Context, workspaceID string) (credbound.Workspace, error) {
	if s.workspaceErr != nil {
		return credbound.Workspace{}, s.workspaceErr
	}
	return s.Store.WorkspaceByID(ctx, workspaceID)
}

func (s *hardeningFaultStore) ConsumeEmailAuthentication(ctx context.Context, tokenID, userID string, at time.Time, commit credbound.Commit) error {
	if s.consumeLinkErr != nil {
		return s.consumeLinkErr
	}
	return s.Store.ConsumeEmailAuthentication(ctx, tokenID, userID, at, commit)
}

func (s *hardeningFaultStore) CompletePasswordReset(ctx context.Context, resetID string, password credbound.PasswordCredential, at time.Time, commit credbound.Commit) error {
	if s.completeResetErr != nil {
		return s.completeResetErr
	}
	return s.Store.CompletePasswordReset(ctx, resetID, password, at, commit)
}

func (s *hardeningFaultStore) LoginThrottleByUserID(ctx context.Context, userID string) (credbound.LoginThrottle, error) {
	if s.throttleErr != nil {
		return credbound.LoginThrottle{}, s.throttleErr
	}
	return s.Store.LoginThrottleByUserID(ctx, userID)
}

func (s *hardeningFaultStore) RecordLoginFailure(ctx context.Context, userID string, at time.Time, threshold int64, lockedUntil time.Time, commit credbound.Commit) (credbound.LoginThrottle, error) {
	if s.recordFailErr != nil {
		return credbound.LoginThrottle{}, s.recordFailErr
	}
	return s.Store.RecordLoginFailure(ctx, userID, at, threshold, lockedUntil, commit)
}

func (s *hardeningFaultStore) PasswordResetByID(ctx context.Context, resetID string) (credbound.PasswordResetCredential, error) {
	if s.resetErr != nil {
		return credbound.PasswordResetCredential{}, s.resetErr
	}
	return s.Store.PasswordResetByID(ctx, resetID)
}

func (s *hardeningFaultStore) EmailAuthenticationByID(ctx context.Context, tokenID string) (credbound.EmailAuthenticationCredential, error) {
	if s.linkErr != nil {
		return credbound.EmailAuthenticationCredential{}, s.linkErr
	}
	return s.Store.EmailAuthenticationByID(ctx, tokenID)
}

func (s *hardeningFaultStore) WorkspaceInvitationByID(ctx context.Context, invitationID string) (credbound.WorkspaceInvitation, error) {
	if s.invitationErr != nil {
		return credbound.WorkspaceInvitation{}, s.invitationErr
	}
	return s.Store.WorkspaceInvitationByID(ctx, invitationID)
}

func (s *hardeningFaultStore) UserByEmail(ctx context.Context, email string) (credbound.User, error) {
	if s.userByEmailErr != nil {
		return credbound.User{}, s.userByEmailErr
	}
	return s.Store.UserByEmail(ctx, email)
}

func (s *hardeningFaultStore) Emails(ctx context.Context, userID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.EmailAddress], error] {
	if s.emailsErr != nil {
		return func(yield func(credbound.PageEvent[credbound.EmailAddress], error) bool) {
			yield(credbound.PageEvent[credbound.EmailAddress]{}, s.emailsErr)
		}
	}
	return s.Store.Emails(ctx, userID, page)
}

func (s *hardeningFaultStore) CountUnusedRecoveryCodes(ctx context.Context, userID string) (int64, error) {
	if s.recoveryCountErr != nil {
		return 0, s.recoveryCountErr
	}
	return s.Store.CountUnusedRecoveryCodes(ctx, userID)
}

func TestHardeningInfrastructureFailures(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	stepUp := aal2(authn.UserID, f.now)
	reset, err := f.manager.BeginPasswordReset(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	link, err := f.manager.BeginEmailAuthentication(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := f.manager.InviteToWorkspace(ctx, stepUp, workspace.ID, credbound.InviteToWorkspaceInput{
		Email: "invitee@example.com", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.BeginTOTPEnrollment(ctx, authn); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.ConfirmTOTPEnrollment(ctx, authn, "123456"); err != nil {
		t.Fatal(err)
	}

	fault := &hardeningFaultStore{Store: f.store}
	manager := managerWith(t, fault, f.passwords, fakeTOTP{}, f.passkeys, &counterReader{next: 0x70})

	boom := errors.New("storage offline")
	fault.throttleErr = boom
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err != nil {
		t.Fatalf("baseline login = %v", err)
	}
	if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); !errors.Is(err, boom) {
		t.Fatalf("throttle lookup failure = %v", err)
	}
	if _, err := manager.VerifyTOTP(ctx, authn, "123456"); !errors.Is(err, boom) {
		t.Fatalf("TOTP throttle failure = %v", err)
	}
	fault.throttleErr = nil
	fault.recordFailErr = boom
	if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "wrong password"); !errors.Is(err, boom) {
		t.Fatalf("failure counting failure = %v", err)
	}
	fault.recordFailErr = nil
	fault.resetErr = boom
	if _, err := manager.CompletePasswordReset(ctx, reset.Token, "brand new password"); !errors.Is(err, boom) {
		t.Fatalf("reset lookup failure = %v", err)
	}
	fault.resetErr = nil
	fault.linkErr = boom
	if _, err := manager.CompleteEmailAuthentication(ctx, link.Token); !errors.Is(err, boom) {
		t.Fatalf("link lookup failure = %v", err)
	}
	fault.linkErr = nil
	fault.invitationErr = boom
	if _, _, err := manager.RegisterFromInvitation(ctx, invitation.Token, credbound.RegisterFromInvitationInput{
		DisplayName: "Invitee", Password: "chosen by invitee",
	}); !errors.Is(err, boom) {
		t.Fatalf("invitation lookup failure = %v", err)
	}
	fault.invitationErr = nil
	fault.userByEmailErr = boom
	if _, err := manager.BeginPasswordReset(ctx, "root@example.com"); !errors.Is(err, boom) {
		t.Fatalf("reset user lookup failure = %v", err)
	}
	if _, err := manager.BeginEmailAuthentication(ctx, "root@example.com"); !errors.Is(err, boom) {
		t.Fatalf("link user lookup failure = %v", err)
	}
	fault.userByEmailErr = nil
	fault.emailsErr = boom
	if _, err := manager.BeginEmailAuthentication(ctx, "root@example.com"); !errors.Is(err, boom) {
		t.Fatalf("email enumeration failure = %v", err)
	}
	if _, err := manager.AcceptInvitation(ctx, stepUp, invitation.Token); !errors.Is(err, boom) {
		t.Fatalf("verified email check failure = %v", err)
	}
	fault.emailsErr = nil
	fault.recoveryCountErr = boom
	if _, err := manager.TOTPStatus(ctx, authn, ""); !errors.Is(err, boom) {
		t.Fatalf("recovery count failure = %v", err)
	}
	fault.recoveryCountErr = nil
	freshLink, err := f.manager.BeginEmailAuthentication(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	fault.totpErr = boom
	if _, err := manager.CompleteEmailAuthentication(ctx, freshLink.Token); !errors.Is(err, boom) {
		t.Fatalf("magic-link factor lookup failure = %v", err)
	}
	fault.totpErr = nil
	fault.consumeLinkErr = credbound.ErrConflict
	if _, err := manager.CompleteEmailAuthentication(ctx, freshLink.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("magic-link consume race = %v", err)
	}
	fault.consumeLinkErr = nil
	freshReset, err := f.manager.BeginPasswordReset(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	fault.completeResetErr = credbound.ErrConflict
	if _, err := manager.CompletePasswordReset(ctx, freshReset.Token, "brand new password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("reset consume race = %v", err)
	}
	fault.completeResetErr = nil
	fault.workspaceErr = boom
	if _, _, err := manager.RegisterFromInvitation(ctx, invitation.Token, credbound.RegisterFromInvitationInput{
		DisplayName: "Invitee", Password: "chosen by invitee",
	}); !errors.Is(err, boom) {
		t.Fatalf("invitation workspace lookup failure = %v", err)
	}
	fault.workspaceErr = nil

	fault.userByEmailErr = boom
	if _, err := manager.BeginEmailOTP(ctx, "root@example.com"); !errors.Is(err, boom) {
		t.Fatalf("OTP user lookup failure = %v", err)
	}
	fault.userByEmailErr = nil
	fault.emailsErr = boom
	if _, err := manager.BeginEmailOTP(ctx, "root@example.com"); !errors.Is(err, boom) {
		t.Fatalf("OTP email enumeration failure = %v", err)
	}
	fault.emailsErr = nil
	freshOTP, err := f.manager.BeginEmailOTP(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	fault.linkErr = boom
	if _, err := manager.CompleteEmailOTP(ctx, freshOTP.Continuation, freshOTP.Code); !errors.Is(err, boom) {
		t.Fatalf("OTP lookup failure = %v", err)
	}
	fault.linkErr = nil
	fault.totpErr = boom
	if _, err := manager.CompleteEmailOTP(ctx, freshOTP.Continuation, freshOTP.Code); !errors.Is(err, boom) {
		t.Fatalf("OTP factor lookup failure = %v", err)
	}
	fault.totpErr = nil
	fault.consumeLinkErr = credbound.ErrConflict
	if _, err := manager.CompleteEmailOTP(ctx, freshOTP.Continuation, freshOTP.Code); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("OTP consume race = %v", err)
	}
	fault.consumeLinkErr = nil
}

func TestHardeningReadAuthorization(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	stepUp := aal2(authn.UserID, f.now)
	member, err := f.manager.CreateUser(ctx, stepUp, workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The root administrator may inspect another user's TOTP state.
	if status, err := f.manager.TOTPStatus(ctx, authn, member.ID); err != nil || status.Enrolled {
		t.Fatalf("admin TOTP status = %#v, %v", status, err)
	}
	memberAuthn := credbound.Authentication{UserID: member.ID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: f.now}
	if _, err := f.manager.TOTPStatus(ctx, memberAuthn, authn.UserID); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("member TOTP status error = %v", err)
	}
	// Invitation listing requires the users read permission and a valid page.
	for _, err := range f.manager.WorkspaceInvitations(ctx, memberAuthn, workspace.ID, credbound.PageRequest{Limit: 10}) {
		if !errors.Is(err, credbound.ErrForbidden) {
			t.Fatalf("member invitation listing error = %v", err)
		}
	}
	for _, err := range f.manager.WorkspaceInvitations(ctx, stepUp, workspace.ID, credbound.PageRequest{Limit: -1}) {
		if !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("invalid page error = %v", err)
		}
	}
}

func TestInvitationEdgeCases(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	stepUp := aal2(authn.UserID, f.now)
	member, err := f.manager.CreateUser(ctx, stepUp, workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.manager.CreateWorkspace(ctx, stepUp, credbound.CreateWorkspaceInput{Name: "Second"})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := f.manager.InviteToWorkspace(ctx, stepUp, second.ID, credbound.InviteToWorkspaceInput{
		Email: "member@example.com", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A stale session cannot accept.
	memberAuthn := credbound.Authentication{UserID: member.ID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: f.now.Add(-time.Hour)}
	if _, err := f.manager.AcceptInvitation(ctx, memberAuthn, issued.Token); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("stale acceptance error = %v", err)
	}
	// A user who became a member between invite and accept conflicts.
	if _, err := f.manager.AddMembership(ctx, stepUp, second.ID, member.ID, credbound.RoleMember); err != nil {
		t.Fatal(err)
	}
	memberAuthn.AuthenticatedAt = f.now
	if _, err := f.manager.AcceptInvitation(ctx, memberAuthn, issued.Token); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("already-member acceptance error = %v", err)
	}

	// Input validation on invitation creation.
	if _, err := f.manager.InviteToWorkspace(ctx, stepUp, second.ID, credbound.InviteToWorkspaceInput{
		Email: "not-an-email", Role: credbound.RoleMember,
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid email error = %v", err)
	}
	if _, err := f.manager.InviteToWorkspace(ctx, stepUp, second.ID, credbound.InviteToWorkspaceInput{
		Email: "valid@example.com", Role: credbound.Role("ghost-role"),
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid role error = %v", err)
	}
	if _, err := f.manager.InviteToWorkspace(ctx, authn, second.ID, credbound.InviteToWorkspaceInput{
		Email: "valid@example.com", Role: credbound.RoleMember,
	}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 invitation error = %v", err)
	}
	// Admin revocation of another user's credentials still needs a step-up.
	weakAdmin := credbound.Authentication{UserID: authn.UserID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: f.now}
	if err := f.manager.RevokeUserCredentials(ctx, weakAdmin, credbound.TrustedRequest{}, member.ID); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 admin revocation error = %v", err)
	}
	// Revocation validation.
	if err := f.manager.RevokeInvitation(ctx, stepUp, second.ID, "not-a-uuid"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid invitation id error = %v", err)
	}
	if err := f.manager.RevokeInvitation(ctx, stepUp, workspace.ID, issued.Invitation.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("cross-workspace revocation error = %v", err)
	}
	if err := f.manager.RevokeInvitation(ctx, stepUp, second.ID, issued.Invitation.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.RevokeInvitation(ctx, stepUp, second.ID, issued.Invitation.ID); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("double revocation error = %v", err)
	}
	// Early consumer break in the scrubbed listing.
	for event, err := range f.manager.WorkspaceInvitations(ctx, stepUp, second.ID, credbound.PageRequest{Limit: 10}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			break
		}
	}
}

// tamperedChainStore corrupts what the store returns so the Manager-level
// verification must notice.
type tamperedChainStore struct {
	credbound.Store
	corruptReason bool
	dropFirst     bool
	corruptedHead bool
}

func (s *tamperedChainStore) ChainedAuditEvents(ctx context.Context) iter.Seq2[credbound.AuditEvent, error] {
	return func(yield func(credbound.AuditEvent, error) bool) {
		first := true
		for event, err := range s.Store.ChainedAuditEvents(ctx) {
			if err != nil {
				yield(credbound.AuditEvent{}, err)
				return
			}
			if first && s.dropFirst {
				first = false
				continue
			}
			first = false
			if s.corruptReason && event.Sequence == 1 {
				event.Reason = "rewritten"
			}
			if !yield(event, nil) {
				return
			}
		}
	}
}

func (s *tamperedChainStore) AuditChainHead(ctx context.Context) (int64, []byte, error) {
	sequence, hash, err := s.Store.AuditChainHead(ctx)
	if s.corruptedHead && err == nil {
		hash = make([]byte, len(hash))
	}
	return sequence, hash, err
}

func TestVerifyAuditChainDetectsTampering(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	if _, err := f.manager.AuthenticatePassword(context.Background(), "root@example.com", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	for index, tampered := range []*tamperedChainStore{
		{Store: f.store, corruptReason: true},
		{Store: f.store, dropFirst: true},
		{Store: f.store, corruptedHead: true},
	} {
		manager := managerWith(t, tampered, f.passwords, fakeTOTP{}, f.passkeys, &counterReader{next: byte(0x60 + index)})
		if _, err := manager.VerifyAuditChain(context.Background(), authn); !errors.Is(err, credbound.ErrAuditCompromised) {
			t.Fatalf("tampered chain (%+v) error = %v", tampered, err)
		}
	}
}

func TestAdminResetSecondFactor(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	root := aal2(authn.UserID, f.now)

	member, err := f.manager.CreateUser(ctx, root, workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	memberAuthn := aal2(member.ID, f.now)
	if _, err := f.manager.BeginTOTPEnrollment(ctx, memberAuthn); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.ConfirmTOTPEnrollment(ctx, memberAuthn, "123456"); err != nil {
		t.Fatal(err)
	}
	challenge, err := f.manager.BeginPasskeyRegistration(ctx, memberAuthn, "MacBook")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.FinishPasskeyRegistration(ctx, memberAuthn, challenge.Continuation, []byte("valid")); err != nil {
		t.Fatal(err)
	}
	session, err := f.manager.CreateSession(ctx, memberAuthn, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}

	// Guards: self-reset, non-admin actor, invalid and unknown targets.
	if err := f.manager.AdminResetSecondFactor(ctx, root, credbound.TrustedRequest{Local: true}, authn.UserID); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("self reset error = %v", err)
	}
	if err := f.manager.AdminResetSecondFactor(ctx, memberAuthn, credbound.TrustedRequest{}, authn.UserID); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("member reset error = %v", err)
	}
	if err := f.manager.AdminResetSecondFactor(ctx, root, credbound.TrustedRequest{Local: true}, "not-a-uuid"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid target error = %v", err)
	}
	if err := f.manager.AdminResetSecondFactor(ctx, root, credbound.TrustedRequest{Local: true}, "01890000-0000-7000-8000-000000000000"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown target error = %v", err)
	}

	if err := f.manager.AdminResetSecondFactor(ctx, root, credbound.TrustedRequest{Local: true}, member.ID); err != nil {
		t.Fatalf("admin reset = %v", err)
	}

	// TOTP, recovery codes, passkeys and sessions are all gone atomically.
	status, err := f.manager.TOTPStatus(ctx, root, member.ID)
	if err != nil || status.Enrolled || status.Active || status.UnusedRecoveryCodes != 0 {
		t.Fatalf("status after reset = %#v, %v", status, err)
	}
	passkeys, err := collectPasskeys(t, f.manager.Passkeys(ctx, root, member.ID))
	if err != nil || len(passkeys) != 0 {
		t.Fatalf("passkeys after reset = %#v, %v", passkeys, err)
	}
	if _, _, err := f.manager.AuthenticateSession(ctx, session.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("session after reset error = %v", err)
	}
	// The account falls back to its first factor without a pending 2FA step.
	signin, err := f.manager.AuthenticatePassword(ctx, "member@example.com", "another strong password")
	if err != nil || signin.SecondFactorRequired {
		t.Fatalf("post-reset sign-in = %#v, %v", signin, err)
	}
	// Resetting an account that has no second factor left stays a success.
	if err := f.manager.AdminResetSecondFactor(ctx, root, credbound.TrustedRequest{Local: true}, member.ID); err != nil {
		t.Fatalf("idempotent reset = %v", err)
	}
}

func TestRegenerateRecoveryCodes(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()
	stepUp := aal2(authn.UserID, f.now)

	// Without an active factor the regeneration reports ErrNotFound.
	if _, err := f.manager.RegenerateRecoveryCodes(ctx, stepUp); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("no factor error = %v", err)
	}
	if _, err := f.manager.BeginTOTPEnrollment(ctx, stepUp); err != nil {
		t.Fatal(err)
	}
	original, err := f.manager.ConfirmTOTPEnrollment(ctx, stepUp, "123456")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.RegenerateRecoveryCodes(ctx, authn); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 regeneration error = %v", err)
	}
	replacement, err := f.manager.RegenerateRecoveryCodes(ctx, stepUp)
	if err != nil || len(replacement) != 10 {
		t.Fatalf("regenerated codes = %d, %v", len(replacement), err)
	}
	// The previous set stopped working in the same transaction.
	if _, err := f.manager.VerifyTOTP(ctx, authn, original[0]); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("old recovery code error = %v", err)
	}
	if _, err := f.manager.VerifyTOTP(ctx, authn, replacement[0]); err != nil {
		t.Fatalf("new recovery code = %v", err)
	}
	status, err := f.manager.TOTPStatus(ctx, stepUp, "")
	if err != nil || status.UnusedRecoveryCodes != 9 {
		t.Fatalf("status after regeneration = %#v, %v", status, err)
	}
}

func TestPATScopeEnforcement(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	stepUp := aal2(authn.UserID, f.now)

	// Scopes outside the permission grammar are rejected at creation.
	if _, err := f.manager.CreatePAT(ctx, stepUp, credbound.CreatePATInput{
		Name: "bad", WorkspaceID: workspace.ID, Scopes: []string{"Read Only"},
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid scope error = %v", err)
	}

	narrow, err := f.manager.CreatePAT(ctx, stepUp, credbound.CreatePATInput{
		Name: "narrow", WorkspaceID: workspace.ID, Scopes: []string{string(credbound.PermissionWorkspaceAccess)},
	})
	if err != nil {
		t.Fatal(err)
	}
	narrowAuthn, err := f.manager.AuthenticatePAT(ctx, narrow.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.AuthorizePermission(ctx, narrowAuthn, workspace.ID, credbound.PermissionWorkspaceAccess); err != nil {
		t.Fatalf("in-scope permission = %v", err)
	}
	// The owner is a workspace admin, but the token's scopes stay the
	// ceiling: the role never widens a narrow PAT.
	if err := f.manager.AuthorizePermission(ctx, narrowAuthn, workspace.ID, credbound.PermissionWorkspaceUsersRead); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("out-of-scope permission error = %v", err)
	}
	// The coarse role check requires the wildcard from scoped credentials.
	if err := f.manager.Authorize(ctx, narrowAuthn, workspace.ID, credbound.RoleMember); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("scoped role authorization error = %v", err)
	}

	wildcard, err := f.manager.CreatePAT(ctx, stepUp, credbound.CreatePATInput{
		Name: "wildcard", WorkspaceID: workspace.ID, Scopes: []string{"*"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wildcardAuthn, err := f.manager.AuthenticatePAT(ctx, wildcard.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.AuthorizePermission(ctx, wildcardAuthn, workspace.ID, credbound.PermissionWorkspaceUsersRead); err != nil {
		t.Fatalf("wildcard permission = %v", err)
	}
	if err := f.manager.Authorize(ctx, wildcardAuthn, workspace.ID, credbound.RoleAdmin); err != nil {
		t.Fatalf("wildcard role authorization = %v", err)
	}
}
