package credbound_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
)

// TestAuthenticationInfrastructureAndRehashPaths pins the manager half of
// AUTH-002 — a hash flagged by the hasher is renewed after a successful
// authentication, without breaking the sign-in when the rehash loses a
// concurrent race — plus the infrastructure-failure branches of the password
// flow.
func TestAuthenticationInfrastructureAndRehashPaths(t *testing.T) {
	ctx := context.Background()
	base := memory.New()
	passwords := &fakePasswords{}
	manager := managerWith(t, base, passwords, fakeTOTP{}, &fakePasskeys{}, nil)
	authn, _, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	passwords.rehash = true
	if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err != nil {
		t.Fatalf("rehash login = %v", err)
	}
	// A rehash that loses its compare-and-swap to a concurrent password
	// change is skipped: the sign-in still succeeds and never overwrites
	// the newer credential.
	conflicted := &faultStore{Store: base, replacePasswordErr: credbound.ErrConflict}
	conflictedManager := managerWith(t, conflicted, passwords, fakeTOTP{}, &fakePasskeys{}, nil)
	if _, err := conflictedManager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err != nil {
		t.Fatalf("conflicted rehash login = %v", err)
	}
	passwords.rehash = false
	passwords.verifyErr = errors.New("hasher failed")
	if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err == nil || !stringsContains(err.Error(), "verify password") {
		t.Fatalf("hasher failure = %v", err)
	}
	passwords.verifyErr = nil

	fault := &faultStore{Store: base, userByEmailErr: errors.New("database offline")}
	manager = managerWith(t, fault, passwords, fakeTOTP{}, &fakePasskeys{}, nil)
	if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err == nil || err.Error() != "database offline" {
		t.Fatalf("lookup infrastructure failure = %v", err)
	}
	fault.userByEmailErr = nil
	fault.passwordErr = errors.New("credential storage offline")
	if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err == nil || err.Error() != "credential storage offline" {
		t.Fatalf("credential infrastructure failure = %v", err)
	}
	// A user without a password credential (SSO- or passkey-only) must fail
	// exactly like a wrong password, never leak a distinguishable error.
	fault.passwordErr = credbound.ErrNotFound
	if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("passwordless account error = %v", err)
	}
	fault.passwordErr = nil
	fault.totpErr = errors.New("factor storage offline")
	if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err == nil || err.Error() != "factor storage offline" {
		t.Fatalf("factor infrastructure failure = %v", err)
	}
	fault.totpErr = nil
	fault.appendAuditErr = credbound.ErrAuditUnavailable
	if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("login audit failure = %v", err)
	}
	_ = authn
}

func TestProviderAndEntropyFailures(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	manager := managerWith(t, store, &fakePasswords{}, errorTOTP{}, &fakePasskeys{}, nil)
	authn, _, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.BeginTOTPEnrollment(ctx, authn); err == nil || !stringsContains(err.Error(), "generate totp") {
		t.Fatalf("TOTP provider failure = %v", err)
	}

	passkeys := &failingPasskeys{beginErr: errors.New("passkey offline")}
	manager = managerWith(t, store, &fakePasswords{}, fakeTOTP{}, passkeys, nil)
	if _, err := manager.BeginPasskeyRegistration(ctx, authn, "Phone"); err == nil {
		t.Fatal("passkey begin failure ignored")
	}
	passkeys.beginErr = nil
	challenge, err := manager.BeginPasskeyRegistration(ctx, authn, "Phone")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.FinishPasskeyRegistration(ctx, authn, challenge.Continuation, []byte("response")); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("empty provider credential = %v", err)
	}

	entropyManager := managerWith(t, memory.New(), &fakePasswords{}, fakeTOTP{}, &fakePasskeys{}, errorReader{})
	if _, _, err := entropyManager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	}); err == nil {
		t.Fatal("entropy failure ignored")
	}
}

func TestCreateUserAndAuditAuthorizationFailures(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	stepUp := aal2(authn.UserID, f.now)
	invalid := []credbound.CreateUserInput{
		{Email: "00000000-0000-4000-8000-000000000000", DisplayName: "Name", Password: "another secure password", Role: credbound.RoleMember},
		{Email: "new@example.com", Password: "another secure password", Role: credbound.RoleMember},
		{Email: "new@example.com", DisplayName: "Name", Password: "short", Role: credbound.RoleMember},
		{Email: "new@example.com", DisplayName: "Name", Password: "another secure password", Role: credbound.Role("owner")},
	}
	for _, input := range invalid {
		if _, err := f.manager.CreateUser(ctx, stepUp, workspace.ID, input); !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("invalid user %#v = %v", input, err)
		}
	}
	if _, err := f.manager.CreateUser(ctx, authn, workspace.ID, invalid[0]); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("user create without step-up = %v", err)
	}
	for _, sequence := range []func(func(credbound.PageEvent[credbound.AuditEvent], error) bool){
		f.manager.AuditEvents(ctx, authn, workspace.ID, credbound.PageRequest{}),
		f.manager.AuditEvents(ctx, stepUp, workspace.ID, credbound.PageRequest{Limit: 101}),
		f.manager.InstanceAuditEvents(ctx, credbound.Authentication{}, credbound.PageRequest{}),
	} {
		seen := false
		for _, err := range sequence {
			seen = true
			if err == nil {
				t.Fatal("expected audit sequence error")
			}
		}
		if !seen {
			t.Fatal("audit error sequence was empty")
		}
	}
}

func TestMutationAndAuthorizationInfrastructureFailures(t *testing.T) {
	ctx := context.Background()
	base := memory.New()
	passwords := &fakePasswords{}
	fault := &faultStore{Store: base}
	manager := managerWith(t, fault, passwords, fakeTOTP{}, &fakePasskeys{}, nil)
	authn, workspace, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	stepUp := aal2(authn.UserID, time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC))

	passwords.hashErr = errors.New("hash offline")
	if _, err := manager.CreateUser(ctx, stepUp, workspace.ID, credbound.CreateUserInput{
		Email: "new@example.com", DisplayName: "New", Password: "another secure password", Role: credbound.RoleMember,
	}); err == nil || !stringsContains(err.Error(), "hash password") {
		t.Fatalf("create user hash failure = %v", err)
	}
	passwords.hashErr = nil
	fault.createUserErr = errors.New("write offline")
	if _, err := manager.CreateUser(ctx, stepUp, workspace.ID, credbound.CreateUserInput{
		Email: "new@example.com", DisplayName: "New", Password: "another secure password", Role: credbound.RoleMember,
	}); err == nil || err.Error() != "write offline" {
		t.Fatalf("create user storage failure = %v", err)
	}
	fault.createUserErr = nil

	fault.membershipErr = errors.New("membership offline")
	if err := manager.Authorize(ctx, authn, workspace.ID, credbound.RoleMember); err == nil || err.Error() != "membership offline" {
		t.Fatalf("membership infrastructure failure = %v", err)
	}
	fault.membershipErr = nil
	fault.adminErr = errors.New("admin storage offline")
	if err := manager.AuthorizeAdmin(ctx, authn, credbound.PermissionAdminAccess); err == nil || err.Error() != "admin storage offline" {
		t.Fatalf("admin lookup infrastructure failure = %v", err)
	}
	fault.adminErr = nil

	fault.loginThrottleErr = errors.New("throttle offline")
	if err := manager.ChangePassword(ctx, authn, "correct horse battery", "another secure password"); err == nil || err.Error() != "throttle offline" {
		t.Fatalf("change password throttle failure = %v", err)
	}
	fault.loginThrottleErr = nil
	passwords.verifyErr = errors.New("verify offline")
	if err := manager.ChangePassword(ctx, authn, "correct horse battery", "another secure password"); err == nil || !stringsContains(err.Error(), "verify password") {
		t.Fatalf("change password verify failure = %v", err)
	}
	passwords.verifyErr = nil
	passwords.hashErr = errors.New("hash offline")
	if err := manager.ChangePassword(ctx, authn, "correct horse battery", "another secure password"); err == nil || !stringsContains(err.Error(), "hash password") {
		t.Fatalf("change password hash failure = %v", err)
	}
	passwords.hashErr = nil
	fault.replacePasswordErr = credbound.ErrAuditUnavailable
	if err := manager.ChangePassword(ctx, authn, "correct horse battery", "another secure password"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("change password audit failure = %v", err)
	}
	fault.replacePasswordErr = nil

	fault.userByIDErr = errors.New("user lookup offline")
	if err := manager.SetInstanceRole(ctx, stepUp, credbound.TrustedRequest{}, credbound.MustParseUUID("0198b463-0000-7000-8000-34a04005bcaf"), credbound.InstanceRoleDeveloper); err == nil || err.Error() != "user lookup offline" {
		t.Fatalf("set instance role lookup failure = %v", err)
	}
	fault.userByIDErr = nil
	fault.removeRoleErr = credbound.ErrAuditUnavailable
	if err := manager.RemoveInstanceRole(ctx, stepUp, credbound.TrustedRequest{}, credbound.MustParseUUID("0198b463-0000-7000-8000-34a04005bcaf")); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("remove role audit failure = %v", err)
	}
}

func TestPATPasskeyAndTOTPFailurePaths(t *testing.T) {
	ctx := context.Background()
	base := memory.New()
	fault := &faultStore{Store: base}
	passkeys := &failingPasskeys{}
	// A mutable clock: ConfirmTOTPEnrollment now consumes its step, so later
	// TOTP operations must fall in a fresh step.
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	manager, err := credbound.New(credbound.Config{
		Store: fault, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: passkeys,
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return now }, Random: &counterReader{next: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	authn, workspace, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	stepUp := aal2(authn.UserID, time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC))

	fault.saveTOTPErr = credbound.ErrAuditUnavailable
	if _, err := manager.BeginTOTPEnrollment(ctx, authn); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("TOTP enrollment audit failure = %v", err)
	}
	fault.saveTOTPErr = nil
	if _, err := manager.BeginTOTPEnrollment(ctx, authn); err != nil {
		t.Fatal(err)
	}
	fault.activateTOTPErr = credbound.ErrAuditUnavailable
	if _, err := manager.ConfirmTOTPEnrollment(ctx, authn, "123456"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("TOTP activation audit failure = %v", err)
	}
	fault.activateTOTPErr = nil
	if _, err := manager.ConfirmTOTPEnrollment(ctx, authn, "123456"); err != nil {
		t.Fatal(err)
	}
	fault.useTOTPErr = credbound.ErrAuditUnavailable
	if _, err := manager.VerifyTOTP(ctx, authn, "123456"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("TOTP use audit failure = %v", err)
	}
	fault.useTOTPErr = nil
	fault.consumeRecoveryErr = credbound.ErrAuditUnavailable
	if _, err := manager.VerifyTOTP(ctx, authn, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("recovery audit failure = %v", err)
	}
	fault.consumeRecoveryErr = nil
	// Move to a fresh step so the disable code is not rejected as a replay of
	// the step the enrollment/verification already consumed.
	now = now.Add(30 * time.Second)
	fault.disableTOTPErr = credbound.ErrAuditUnavailable
	if err := manager.DisableTOTP(ctx, authn, "123456"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("disable TOTP audit failure = %v", err)
	}
	fault.disableTOTPErr = nil

	passkeys.beginAuthenticationErr = errors.New("passkey offline")
	if _, err := manager.BeginPasskeyAuthentication(ctx, "root@example.com"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("passkey begin authentication failure = %v", err)
	}
	passkeys.beginAuthenticationErr = nil
	login, err := manager.BeginPasskeyAuthentication(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	passkeys.finishAuthenticationErr = errors.New("invalid assertion")
	if _, err := manager.FinishPasskeyAuthentication(ctx, login.Continuation, []byte("00000000-0000-4000-8000-000000000000")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("passkey finish authentication failure = %v", err)
	}
	passkeys.finishAuthenticationErr = nil

	fault.createPATErr = credbound.ErrAuditUnavailable
	if _, err := manager.CreatePAT(ctx, stepUp, credbound.CreatePATInput{Name: "automation", WorkspaceID: workspace.ID, Scopes: []string{"read"}}); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("PAT creation audit failure = %v", err)
	}
	fault.createPATErr = nil
	issued, err := manager.CreatePAT(ctx, stepUp, credbound.CreatePATInput{Name: "automation", WorkspaceID: workspace.ID, Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(issued.Token, "_", 3)
	if len(parts) != 3 {
		t.Fatalf("issued malformed PAT %q", issued.Token)
	}
	if stored, lookupErr := base.PATByPrefix(ctx, parts[1]); lookupErr != nil || stored.ID != issued.PAT.ID {
		t.Fatalf("stored PAT = %#v, %v", stored, lookupErr)
	}
	fault.touchPATErr = credbound.ErrAuditUnavailable
	if _, err := manager.AuthenticatePAT(ctx, issued.Token); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("PAT touch audit failure = %v", err)
	}
	fault.touchPATErr = nil
	fault.revokePATErr = credbound.ErrAuditUnavailable
	if err := manager.RevokePAT(ctx, stepUp, issued.PAT.ID); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("PAT revoke audit failure = %v", err)
	}
}

func TestSCIMInfrastructureFailures(t *testing.T) {
	ctx := context.Background()
	fault := &faultStore{Store: memory.New(), scimErr: errors.New("scim storage offline")}
	manager := managerWith(t, fault, &fakePasswords{}, fakeTOTP{}, &fakePasskeys{}, nil)
	root, workspace, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	admin := aal2(root.UserID, time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC))
	fault.scimOperation = "configuration.create"
	if _, err := manager.CreateSCIMConfiguration(ctx, admin, workspace.ID, credbound.CreateSCIMConfigurationInput{}); err == nil {
		t.Fatal("SCIM configuration storage failure ignored")
	}
	fault.scimOperation = ""
	issued, err := manager.CreateSCIMConfiguration(ctx, admin, workspace.ID, credbound.CreateSCIMConfigurationInput{})
	if err != nil {
		t.Fatal(err)
	}
	fault.scimOperation = "configuration.credential"
	if _, err := manager.AuthenticateSCIM(ctx, issued.Token); err == nil {
		t.Fatal("SCIM credential lookup failure ignored")
	}
	fault.scimOperation = ""
	principal, err := manager.AuthenticateSCIM(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	fault.scimOperation = "credential.touch"
	if _, err := manager.AuthenticateSCIM(ctx, issued.Token); err == nil {
		t.Fatal("SCIM credential touch failure ignored")
	}
	fault.scimOperation = "credential.save"
	if _, err := manager.RotateSCIMCredential(ctx, admin, issued.Configuration.ID, nil); err == nil {
		t.Fatal("SCIM credential rotation failure ignored")
	}
	fault.scimOperation = "user.create"
	input := credbound.SCIMUserInput{UserName: "user@example.com", Emails: []credbound.SCIMEmail{{Value: "user@example.com"}}, Active: true}
	if _, err := manager.ProvisionSCIMUser(ctx, principal, input); err == nil {
		t.Fatal("SCIM user storage failure ignored")
	}
	fault.scimOperation = ""
	link, err := manager.ProvisionSCIMUser(ctx, principal, input)
	if err != nil {
		t.Fatal(err)
	}
	fault.scimOperation = "user.update"
	if _, err := manager.ReplaceSCIMUser(ctx, principal, link.ID, input); err == nil {
		t.Fatal("SCIM user update failure ignored")
	}
	fault.scimOperation = "group.upsert"
	groupInput := credbound.SCIMGroupInput{ExternalID: "group", DisplayName: "Group", MemberIDs: []credbound.UUID{link.ID}}
	if _, err := manager.UpsertSCIMGroup(ctx, principal, credbound.UUID{}, groupInput); err == nil {
		t.Fatal("SCIM group storage failure ignored")
	}
	fault.scimOperation = ""
	group, err := manager.UpsertSCIMGroup(ctx, principal, credbound.UUID{}, groupInput)
	if err != nil {
		t.Fatal(err)
	}
	fault.scimOperation = "group.delete"
	if err := manager.DeleteSCIMGroup(ctx, principal, group.ID); err == nil {
		t.Fatal("SCIM group delete failure ignored")
	}
	fault.scimOperation = "configuration.get"
	if _, err := manager.SCIMUser(ctx, principal, link.ID); err == nil {
		t.Fatal("SCIM configuration lookup failure ignored")
	}
	fault.scimOperation = "configuration.disable"
	if err := manager.DisableSCIMConfiguration(ctx, admin, issued.Configuration.ID); err == nil {
		t.Fatal("SCIM configuration disable failure ignored")
	}
}

type faultStore struct {
	*memory.Store
	userByEmailErr     error
	userByIDErr        error
	passwordErr        error
	loginThrottleErr   error
	totpErr            error
	membershipErr      error
	adminErr           error
	appendAuditErr     error
	createUserErr      error
	replacePasswordErr error
	saveTOTPErr        error
	activateTOTPErr    error
	useTOTPErr         error
	consumeRecoveryErr error
	disableTOTPErr     error
	createPATErr       error
	touchPATErr        error
	revokePATErr       error
	removeRoleErr      error
	emailByAddressErr  error
	reissueEmailErr    error
	scimOperation      string
	scimErr            error
}

func (s *faultStore) EmailByAddress(ctx context.Context, address string) (credbound.EmailAddress, error) {
	if s.emailByAddressErr != nil {
		return credbound.EmailAddress{}, s.emailByAddressErr
	}
	return s.Store.EmailByAddress(ctx, address)
}

func (s *faultStore) ReissueEmailVerification(ctx context.Context, emailID credbound.UUID, verification credbound.EmailVerificationCredential, commit credbound.Commit) error {
	if s.reissueEmailErr != nil {
		return s.reissueEmailErr
	}
	return s.Store.ReissueEmailVerification(ctx, emailID, verification, commit)
}

func (s *faultStore) UserByEmail(ctx context.Context, email string) (credbound.User, error) {
	if s.userByEmailErr != nil {
		return credbound.User{}, s.userByEmailErr
	}
	return s.Store.UserByEmail(ctx, email)
}
func (s *faultStore) UserByID(ctx context.Context, userID credbound.UUID) (credbound.User, error) {
	if s.userByIDErr != nil {
		return credbound.User{}, s.userByIDErr
	}
	return s.Store.UserByID(ctx, userID)
}
func (s *faultStore) PasswordByUserID(ctx context.Context, userID credbound.UUID) (credbound.PasswordCredential, error) {
	if s.passwordErr != nil {
		return credbound.PasswordCredential{}, s.passwordErr
	}
	return s.Store.PasswordByUserID(ctx, userID)
}
func (s *faultStore) TOTPByUserID(ctx context.Context, userID credbound.UUID) (credbound.TOTPFactor, error) {
	if s.totpErr != nil {
		return credbound.TOTPFactor{}, s.totpErr
	}
	return s.Store.TOTPByUserID(ctx, userID)
}
func (s *faultStore) AppendAudit(ctx context.Context, commit credbound.Commit) error {
	if s.appendAuditErr != nil {
		return s.appendAuditErr
	}
	return s.Store.AppendAudit(ctx, commit)
}

func (s *faultStore) RecordAuthentication(ctx context.Context, userID credbound.UUID, seenAt time.Time, commit credbound.Commit) error {
	if s.appendAuditErr != nil {
		return s.appendAuditErr
	}
	return s.Store.RecordAuthentication(ctx, userID, seenAt, commit)
}

func (s *faultStore) RecordPasswordAuthentication(ctx context.Context, userID credbound.UUID, currentHash string, seenAt time.Time, commit credbound.Commit) error {
	if s.appendAuditErr != nil {
		return s.appendAuditErr
	}
	return s.Store.RecordPasswordAuthentication(ctx, userID, currentHash, seenAt, commit)
}

func (s *faultStore) Membership(ctx context.Context, workspaceID, userID credbound.UUID) (credbound.Membership, error) {
	if s.membershipErr != nil {
		return credbound.Membership{}, s.membershipErr
	}
	return s.Store.Membership(ctx, workspaceID, userID)
}

func (s *faultStore) InstanceAdministrator(ctx context.Context, userID credbound.UUID) (credbound.InstanceAdministrator, error) {
	if s.adminErr != nil {
		return credbound.InstanceAdministrator{}, s.adminErr
	}
	return s.Store.InstanceAdministrator(ctx, userID)
}

func (s *faultStore) CreateUser(ctx context.Context, user credbound.User, email credbound.EmailAddress, password credbound.PasswordCredential, membership credbound.Membership, commit credbound.Commit) error {
	if s.createUserErr != nil {
		return s.createUserErr
	}
	return s.Store.CreateUser(ctx, user, email, password, membership, commit)
}

func (s *faultStore) RehashPassword(ctx context.Context, password credbound.PasswordCredential, previousHash string, commit credbound.Commit) error {
	if s.replacePasswordErr != nil {
		return s.replacePasswordErr
	}
	return s.Store.RehashPassword(ctx, password, previousHash, commit)
}

func (s *faultStore) LoginThrottleByUserID(ctx context.Context, userID credbound.UUID) (credbound.LoginThrottle, error) {
	if s.loginThrottleErr != nil {
		return credbound.LoginThrottle{}, s.loginThrottleErr
	}
	return s.Store.LoginThrottleByUserID(ctx, userID)
}

func (s *faultStore) ChangePassword(ctx context.Context, password credbound.PasswordCredential, at time.Time, commit credbound.Commit) error {
	if s.replacePasswordErr != nil {
		return s.replacePasswordErr
	}
	return s.Store.ChangePassword(ctx, password, at, commit)
}

func (s *faultStore) SaveTOTPEnrollment(ctx context.Context, factor credbound.TOTPFactor, commit credbound.Commit) error {
	if s.saveTOTPErr != nil {
		return s.saveTOTPErr
	}
	return s.Store.SaveTOTPEnrollment(ctx, factor, commit)
}

func (s *faultStore) ActivateTOTP(ctx context.Context, factor credbound.TOTPFactor, recovery []credbound.RecoveryCode, commit credbound.Commit) error {
	if s.activateTOTPErr != nil {
		return s.activateTOTPErr
	}
	return s.Store.ActivateTOTP(ctx, factor, recovery, commit)
}

func (s *faultStore) UseTOTP(ctx context.Context, userID credbound.UUID, step int64, commit credbound.Commit) (bool, error) {
	if s.useTOTPErr != nil {
		return false, s.useTOTPErr
	}
	return s.Store.UseTOTP(ctx, userID, step, commit)
}

func (s *faultStore) ConsumeRecoveryCode(ctx context.Context, userID credbound.UUID, digest []byte, usedAt time.Time, commit credbound.Commit) (bool, error) {
	if s.consumeRecoveryErr != nil {
		return false, s.consumeRecoveryErr
	}
	return s.Store.ConsumeRecoveryCode(ctx, userID, digest, usedAt, commit)
}

func (s *faultStore) DisableTOTP(ctx context.Context, userID credbound.UUID, commit credbound.Commit) error {
	if s.disableTOTPErr != nil {
		return s.disableTOTPErr
	}
	return s.Store.DisableTOTP(ctx, userID, commit)
}

func (s *faultStore) CreatePAT(ctx context.Context, pat credbound.PAT, commit credbound.Commit) error {
	if s.createPATErr != nil {
		return s.createPATErr
	}
	return s.Store.CreatePAT(ctx, pat, commit)
}

func (s *faultStore) TouchPAT(ctx context.Context, id credbound.UUID, usedAt time.Time, commit credbound.Commit) error {
	if s.touchPATErr != nil {
		return s.touchPATErr
	}
	return s.Store.TouchPAT(ctx, id, usedAt, commit)
}

func (s *faultStore) RevokePAT(ctx context.Context, userID, id credbound.UUID, revokedAt time.Time, commit credbound.Commit) error {
	if s.revokePATErr != nil {
		return s.revokePATErr
	}
	return s.Store.RevokePAT(ctx, userID, id, revokedAt, commit)
}

func (s *faultStore) RemoveInstanceRole(ctx context.Context, userID credbound.UUID, commit credbound.Commit) error {
	if s.removeRoleErr != nil {
		return s.removeRoleErr
	}
	return s.Store.RemoveInstanceRole(ctx, userID, commit)
}

func (s *faultStore) CreateSCIMConfiguration(ctx context.Context, configuration credbound.SCIMConfiguration, credential credbound.SCIMCredential, commit credbound.Commit) error {
	if s.scimOperation == "configuration.create" {
		return s.scimErr
	}
	return s.Store.CreateSCIMConfiguration(ctx, configuration, credential, commit)
}

func (s *faultStore) SCIMConfiguration(ctx context.Context, id credbound.UUID) (credbound.SCIMConfiguration, error) {
	if s.scimOperation == "configuration.get" {
		return credbound.SCIMConfiguration{}, s.scimErr
	}
	return s.Store.SCIMConfiguration(ctx, id)
}

func (s *faultStore) SCIMConfigurationByCredentialPrefix(ctx context.Context, prefix string) (credbound.SCIMConfiguration, credbound.SCIMCredential, error) {
	if s.scimOperation == "configuration.credential" {
		return credbound.SCIMConfiguration{}, credbound.SCIMCredential{}, s.scimErr
	}
	return s.Store.SCIMConfigurationByCredentialPrefix(ctx, prefix)
}

func (s *faultStore) SaveSCIMCredential(ctx context.Context, credential credbound.SCIMCredential, commit credbound.Commit) error {
	if s.scimOperation == "credential.save" {
		return s.scimErr
	}
	return s.Store.SaveSCIMCredential(ctx, credential, commit)
}

func (s *faultStore) TouchSCIMCredential(ctx context.Context, id credbound.UUID, usedAt time.Time, commit credbound.Commit) error {
	if s.scimOperation == "credential.touch" {
		return s.scimErr
	}
	return s.Store.TouchSCIMCredential(ctx, id, usedAt, commit)
}

func (s *faultStore) DisableSCIMConfiguration(ctx context.Context, id credbound.UUID, disabledAt time.Time, commit credbound.Commit) error {
	if s.scimOperation == "configuration.disable" {
		return s.scimErr
	}
	return s.Store.DisableSCIMConfiguration(ctx, id, disabledAt, commit)
}

func (s *faultStore) CreateSCIMUser(ctx context.Context, user credbound.User, email credbound.EmailAddress, membership credbound.Membership, link credbound.SCIMUser, commit credbound.Commit) error {
	if s.scimOperation == "user.create" {
		return s.scimErr
	}
	return s.Store.CreateSCIMUser(ctx, user, email, membership, link, commit)
}

func (s *faultStore) UpdateSCIMUser(ctx context.Context, link credbound.SCIMUser, membership credbound.Membership, revoke bool, commit credbound.Commit) error {
	if s.scimOperation == "user.update" {
		return s.scimErr
	}
	return s.Store.UpdateSCIMUser(ctx, link, membership, revoke, commit)
}

func (s *faultStore) UpsertSCIMGroup(ctx context.Context, group credbound.SCIMGroup, memberships []credbound.Membership, commit credbound.Commit) error {
	if s.scimOperation == "group.upsert" {
		return s.scimErr
	}
	return s.Store.UpsertSCIMGroup(ctx, group, memberships, commit)
}

func (s *faultStore) DeleteSCIMGroup(ctx context.Context, group credbound.SCIMGroup, memberships []credbound.Membership, commit credbound.Commit) error {
	if s.scimOperation == "group.delete" {
		return s.scimErr
	}
	return s.Store.DeleteSCIMGroup(ctx, group, memberships, commit)
}

type errorTOTP struct{}

func (errorTOTP) Generate(string) (string, string, error)          { return "", "", errors.New("offline") }
func (errorTOTP) Validate(string, string, time.Time) (int64, bool) { return 0, false }

type failingPasskeys struct {
	beginErr                error
	beginAuthenticationErr  error
	finishAuthenticationErr error
}

func (f *failingPasskeys) BeginRegistration(context.Context, credbound.PasskeyUser) (json.RawMessage, []byte, error) {
	if f.beginErr != nil {
		return nil, nil, f.beginErr
	}
	return json.RawMessage(`{}`), []byte("session"), nil
}
func (*failingPasskeys) FinishRegistration(context.Context, credbound.PasskeyUser, []byte, []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (f *failingPasskeys) BeginAuthentication(context.Context, credbound.PasskeyUser) (json.RawMessage, []byte, error) {
	if f.beginAuthenticationErr != nil {
		return nil, nil, f.beginAuthenticationErr
	}
	return json.RawMessage(`{}`), []byte("session"), nil
}
func (f *failingPasskeys) BeginDecoyAuthentication(context.Context, []byte) (json.RawMessage, []byte, error) {
	if f.beginAuthenticationErr != nil {
		return nil, nil, f.beginAuthenticationErr
	}
	return json.RawMessage(`{}`), []byte("decoy-session"), nil
}
func (f *failingPasskeys) FinishAuthentication(context.Context, credbound.PasskeyUser, []byte, []byte) ([]byte, []byte, error) {
	if f.finishAuthenticationErr != nil {
		return nil, nil, f.finishAuthenticationErr
	}
	return []byte("credential"), []byte(`{}`), nil
}

func managerWith(t *testing.T, store credbound.Store, passwords credbound.PasswordHasher, totp credbound.TOTPProvider, passkeys credbound.PasskeyProvider, random io.Reader) *credbound.Manager {
	t.Helper()
	if random == nil {
		random = &counterReader{next: 1}
	}
	manager, err := credbound.New(credbound.Config{
		Store: store, Passwords: passwords, TOTP: totp, Passkeys: passkeys,
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC) }, Random: random,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func stringsContains(value, part string) bool {
	for index := 0; index+len(part) <= len(value); index++ {
		if value[index:index+len(part)] == part {
			return true
		}
	}
	return false
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func TestResendEmailVerificationLookupFault(t *testing.T) {
	ctx := context.Background()
	fault := &faultStore{Store: memory.New()}
	manager := managerWith(t, fault, &fakePasswords{}, fakeTOTP{}, &fakePasskeys{}, nil)
	if _, _, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	}); err != nil {
		t.Fatal(err)
	}
	// A non-NotFound lookup error from the store propagates rather than being
	// swallowed by the enumeration-safe decoy.
	fault.emailByAddressErr = credbound.ErrAuditUnavailable
	if _, err := manager.ResendEmailVerification(ctx, "root@example.com"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("lookup fault = %v", err)
	}
}
