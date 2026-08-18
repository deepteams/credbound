package credbound_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
)

type signupRecorder struct {
	credbound.UnimplementedEventListener
	names     []credbound.EventName
	completed []credbound.SignUpCompletedEvent
}

func (r *signupRecorder) OnUserCreated(_ context.Context, event credbound.UserCreatedEvent) error {
	r.names = append(r.names, event.Name)
	return nil
}

func (r *signupRecorder) OnWorkspaceCreated(_ context.Context, event credbound.WorkspaceCreatedEvent) error {
	r.names = append(r.names, event.Name)
	return nil
}

func (r *signupRecorder) OnSignUpCompleted(_ context.Context, event credbound.SignUpCompletedEvent) error {
	r.names = append(r.names, event.Name)
	r.completed = append(r.completed, event)
	return nil
}

type signupFixture struct {
	manager   *credbound.Manager
	store     *memory.Store
	passwords *fakePasswords
	recorder  *signupRecorder
	now       time.Time
}

func newSignupFixture(t *testing.T, autoVerify bool, store credbound.Store) *signupFixture {
	t.Helper()
	f := &signupFixture{
		store: nil, now: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
		passwords: &fakePasswords{}, recorder: &signupRecorder{},
	}
	if store == nil {
		f.store = memory.New()
		store = f.store
	} else if memoryStore, ok := store.(*memory.Store); ok {
		f.store = memoryStore
	}
	manager, err := credbound.New(credbound.Config{
		Store: store, Passwords: f.passwords, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return f.now }, Random: &counterReader{next: 0x42},
		SignUp:         &credbound.SignUpConfig{AutoVerifyEmail: autoVerify},
		PasswordPolicy: rejectingPolicy{rejected: "compromised passphrase"},
		EventListeners: []credbound.EventListener{f.recorder},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.manager = manager
	return f
}

func signUpInput(email string) credbound.SignUpInput {
	return credbound.SignUpInput{
		Email: email, DisplayName: "Visitor", Password: "correct horse battery", WorkspaceName: "Startup",
	}
}

// coreStore hides every optional capability of the wrapped store behind the
// plain Store interface.
type coreStore struct{ credbound.Store }

func TestSignUpNotSupported(t *testing.T) {
	ctx := context.Background()
	// Config.SignUp nil: the standard fixture never enables signup.
	f := newFixture(t)
	if _, err := f.manager.SignUp(ctx, signUpInput("visitor@example.com")); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("disabled signup error = %v", err)
	}
	// Config.SignUp set but the store lacks the SignupStore capability is a
	// construction error, not a silently disabled capability.
	_, err := credbound.New(credbound.Config{
		Store: coreStore{Store: memory.New()}, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		SignUp: &credbound.SignUpConfig{},
	})
	if !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("incapable store with Config.SignUp = %v, want ErrInvalidInput", err)
	}
}

func TestSignUpValidation(t *testing.T) {
	f := newSignupFixture(t, false, nil)
	ctx := context.Background()
	cases := []struct {
		name  string
		input credbound.SignUpInput
		field string
	}{
		{"invalid email", credbound.SignUpInput{Email: "not-an-address", DisplayName: "V", Password: "correct horse battery", WorkspaceName: "W"}, "email"},
		{"missing display name", credbound.SignUpInput{Email: "v@example.com", DisplayName: "  ", Password: "correct horse battery", WorkspaceName: "W"}, "display_name"},
		{"missing workspace name", credbound.SignUpInput{Email: "v@example.com", DisplayName: "V", Password: "correct horse battery", WorkspaceName: " "}, "workspace_name"},
		{"short password", credbound.SignUpInput{Email: "v@example.com", DisplayName: "V", Password: "short", WorkspaceName: "W"}, "password"},
	}
	for _, testCase := range cases {
		_, err := f.manager.SignUp(ctx, testCase.input)
		var validation *credbound.ValidationError
		if !errors.As(err, &validation) || validation.Field != testCase.field || !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("%s error = %v", testCase.name, err)
		}
	}
	input := signUpInput("v@example.com")
	input.Password = "compromised passphrase"
	if _, err := f.manager.SignUp(ctx, input); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("policy-rejected password error = %v", err)
	}
	if _, err := f.store.UserByEmail(ctx, "v@example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatal("rejected signup persisted an account")
	}
}

// TestSignUpVerificationFlow pins AUTH-015: self-service signup atomically
// creates the user, their workspace, and their admin membership without any
// instance role, and the unverified primary address must be proven by the
// returned verification token before the first sign-in.
func TestSignUpVerificationFlow(t *testing.T) {
	f := newSignupFixture(t, false, nil)
	ctx := context.Background()
	result, err := f.manager.SignUp(ctx, signUpInput(" Visitor@Example.com "))
	if err != nil {
		t.Fatal(err)
	}
	if result.ExistingAccount {
		t.Fatal("fresh signup reported an existing account")
	}
	if !uuidV7.MatchString(result.User.ID) || !uuidV7.MatchString(result.Workspace.ID) {
		t.Fatalf("non UUIDv7 ids: %q %q", result.User.ID, result.Workspace.ID)
	}
	if result.User.Email != "visitor@example.com" || result.User.DisplayName != "Visitor" || result.User.LastSeenAt != nil {
		t.Fatalf("user = %#v", result.User)
	}
	if result.Workspace.Name != "Startup" {
		t.Fatalf("workspace = %#v", result.Workspace)
	}
	if result.Authentication.UserID != "" {
		t.Fatalf("verification-pending signup returned an authentication: %#v", result.Authentication)
	}
	verification := result.EmailVerification
	if verification.Token == "" || verification.Email.Address != "visitor@example.com" || verification.Email.VerifiedAt != nil || !verification.Email.Primary {
		t.Fatalf("issued verification = %#v", verification)
	}
	if !verification.Deliverable {
		t.Fatal("real signup issuance must be Deliverable so the host sends the verification email")
	}
	membership, err := f.store.Membership(ctx, result.Workspace.ID, result.User.ID)
	if err != nil || membership.Role != credbound.RoleAdmin || membership.Status != credbound.MembershipActive || membership.ProvisioningSource != credbound.ProvisioningSourceLocal {
		t.Fatalf("membership = %#v, %v", membership, err)
	}
	if _, err := f.store.InstanceAdministrator(ctx, result.User.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("signup granted an instance role: %v", err)
	}
	wantEvents := []credbound.EventName{credbound.EventUserCreated, credbound.EventWorkspaceCreated, credbound.EventSignUpCompleted}
	if len(f.recorder.names) != len(wantEvents) {
		t.Fatalf("events = %v", f.recorder.names)
	}
	for index, name := range wantEvents {
		if f.recorder.names[index] != name {
			t.Fatalf("events = %v", f.recorder.names)
		}
	}
	if len(f.recorder.completed) != 1 || f.recorder.completed[0].User.ID != result.User.ID || f.recorder.completed[0].Workspace.ID != result.Workspace.ID {
		t.Fatalf("signup.completed payload = %#v", f.recorder.completed)
	}

	// The unverified primary address cannot authenticate.
	if _, err := f.manager.AuthenticatePassword(ctx, "visitor@example.com", "correct horse battery"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("unverified login error = %v", err)
	}
	confirmed, err := f.manager.ConfirmEmail(ctx, verification.Token)
	if err != nil || confirmed.VerifiedAt == nil || confirmed.ID != verification.Email.ID {
		t.Fatalf("confirmation = %#v, %v", confirmed, err)
	}
	authn, err := f.manager.AuthenticatePassword(ctx, "visitor@example.com", "correct horse battery")
	if err != nil || authn.UserID != result.User.ID || authn.Level != credbound.AAL1 || authn.Method != credbound.MethodPassword {
		t.Fatalf("post-confirmation login = %#v, %v", authn, err)
	}
}

func TestResendEmailVerification(t *testing.T) {
	f := newSignupFixture(t, false, nil)
	ctx := context.Background()
	result, err := f.manager.SignUp(ctx, signUpInput("visitor@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	original := result.EmailVerification.Token

	// The original token expires before the user acts: the account would be
	// permanently unreachable without a resend path.
	f.now = f.now.Add(48 * time.Hour)
	if _, err := f.manager.ConfirmEmail(ctx, original); !errors.Is(err, credbound.ErrExpired) {
		t.Fatalf("expired original token = %v", err)
	}

	// Unknown and already-verified addresses answer with an empty-token decoy,
	// never an error, so the call is not an enumeration oracle.
	if reissued, err := f.manager.ResendEmailVerification(ctx, "ghost@example.com"); err != nil || reissued.Token != "" {
		t.Fatalf("unknown-address resend = %#v, %v", reissued, err)
	}

	// The pending address gets a fresh, working token.
	reissued, err := f.manager.ResendEmailVerification(ctx, "Visitor@Example.com ")
	if err != nil || reissued.Token == "" || reissued.Email.ID != result.EmailVerification.Email.ID {
		t.Fatalf("resend = %#v, %v", reissued, err)
	}
	if reissued.Token == original {
		t.Fatal("resend returned the same token")
	}
	// The superseded token no longer works; the new one does.
	if _, err := f.manager.ConfirmEmail(ctx, original); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("superseded token = %v", err)
	}
	confirmed, err := f.manager.ConfirmEmail(ctx, reissued.Token)
	if err != nil || confirmed.VerifiedAt == nil {
		t.Fatalf("confirm reissued = %#v, %v", confirmed, err)
	}
	// Once verified, a resend is a no-op decoy.
	if again, err := f.manager.ResendEmailVerification(ctx, "visitor@example.com"); err != nil || again.Token != "" {
		t.Fatalf("verified-address resend = %#v, %v", again, err)
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "visitor@example.com", "correct horse battery"); err != nil {
		t.Fatalf("post-resend login = %v", err)
	}
}

func TestSignUpAutoVerifyEmail(t *testing.T) {
	f := newSignupFixture(t, true, nil)
	ctx := context.Background()
	result, err := f.manager.SignUp(ctx, signUpInput("visitor@example.com"))
	if err != nil || result.ExistingAccount {
		t.Fatalf("signup = %#v, %v", result, err)
	}
	if result.EmailVerification.Token != "" {
		t.Fatal("auto-verified signup issued a verification token")
	}
	authn := result.Authentication
	if authn.UserID != result.User.ID || authn.Method != credbound.MethodPassword || authn.Level != credbound.AAL1 || !authn.AuthenticatedAt.Equal(f.now) {
		t.Fatalf("authentication = %#v", authn)
	}
	loggedIn, err := f.manager.AuthenticatePassword(ctx, "visitor@example.com", "correct horse battery")
	if err != nil || loggedIn.UserID != result.User.ID {
		t.Fatalf("immediate login = %#v, %v", loggedIn, err)
	}
}

// TestSignUpExistingAccountIsIndistinguishable proves the collision clause of
// AUTH-015: an address that already has an account produces an outwardly
// identical response and reports the collision only to the host.
func TestSignUpExistingAccountIsIndistinguishable(t *testing.T) {
	f := newSignupFixture(t, false, nil)
	ctx := context.Background()
	first, err := f.manager.SignUp(ctx, signUpInput("visitor@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	// Before confirmation the address is invisible to UserByEmail, so the
	// collision is only caught by the store's uniqueness constraint.
	race, err := f.manager.SignUp(ctx, signUpInput("visitor@example.com"))
	if err != nil || !race.ExistingAccount {
		t.Fatalf("race collision = %#v, %v", race, err)
	}
	if race.User.ID != "" || race.Workspace.ID != "" || race.EmailVerification.Token != "" || race.Authentication.UserID != "" {
		t.Fatalf("race collision leaked data: %#v", race)
	}
	if _, err := f.manager.ConfirmEmail(ctx, first.EmailVerification.Token); err != nil {
		t.Fatal(err)
	}
	// After confirmation the collision is caught by the enumeration-safe
	// lookup; the response shape is identical.
	repeat, err := f.manager.SignUp(ctx, signUpInput("visitor@example.com"))
	if err != nil || !repeat.ExistingAccount {
		t.Fatalf("repeat collision = %#v, %v", repeat, err)
	}
	if !reflect.DeepEqual(repeat, race) {
		t.Fatalf("collision results differ: %#v vs %#v", repeat, race)
	}
	// Both collisions were audited to the host without emitting events.
	if len(f.recorder.completed) != 1 {
		t.Fatalf("collision emitted signup.completed: %d", len(f.recorder.completed))
	}
	failures := 0
	for event, err := range f.store.InstanceAuditEvents(ctx, credbound.PageRequest{Limit: 100}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil && event.Data.Action == "signup" && event.Data.Outcome == credbound.AuditFailed && event.Data.Reason == "email_taken" {
			failures++
		}
	}
	if failures != 2 {
		t.Fatalf("audited collisions = %d", failures)
	}
}

func TestSignUpTransactionHookRollback(t *testing.T) {
	f := newSignupFixture(t, false, nil)
	ctx := context.Background()
	hook := &bootstrapHook{reject: errors.New("host write rejected")}
	subscription := f.manager.AddTransactionHook(hook)
	if _, err := f.manager.SignUp(ctx, signUpInput("visitor@example.com")); !errors.Is(err, credbound.ErrTransactionRejected) {
		t.Fatalf("rejected hook error = %v", err)
	}
	if len(f.recorder.completed) != 0 {
		t.Fatal("rejected signup emitted signup.completed")
	}
	subscription.Remove()
	// The rejected registration left nothing behind: the address is free again.
	result, err := f.manager.SignUp(ctx, signUpInput("visitor@example.com"))
	if err != nil || result.ExistingAccount {
		t.Fatalf("signup after rollback = %#v, %v", result, err)
	}
}

func TestSignUpAuditUnavailableAndFaults(t *testing.T) {
	f := newSignupFixture(t, false, nil)
	ctx := context.Background()
	f.store.SetAuditFailure(errors.New("disk full"))
	if _, err := f.manager.SignUp(ctx, signUpInput("visitor@example.com")); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("audit-unavailable signup = %v", err)
	}
	f.store.SetAuditFailure(nil)
	result, err := f.manager.SignUp(ctx, signUpInput("visitor@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.ConfirmEmail(ctx, result.EmailVerification.Token); err != nil {
		t.Fatal(err)
	}
	// The collision audit fails closed too.
	f.store.SetAuditFailure(errors.New("disk full"))
	if _, err := f.manager.SignUp(ctx, signUpInput("visitor@example.com")); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("audit-unavailable collision = %v", err)
	}
	f.store.SetAuditFailure(nil)

	// Hasher failures surface as infrastructure errors.
	f.passwords.hashErr = errors.New("hasher offline")
	if _, err := f.manager.SignUp(ctx, signUpInput("other@example.com")); err == nil || errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("hash failure = %v", err)
	}
	f.passwords.hashErr = nil

	// Store lookup failures propagate instead of masquerading as collisions.
	infrastructure := errors.New("database offline")
	fault := &faultStore{Store: memory.New(), userByEmailErr: infrastructure}
	faulty := newSignupFixture(t, false, fault)
	if _, err := faulty.manager.SignUp(ctx, signUpInput("visitor@example.com")); !errors.Is(err, infrastructure) {
		t.Fatalf("lookup fault = %v", err)
	}

	// Entropy failures abort before any store write.
	entropy, err := credbound.New(credbound.Config{
		Store: memory.New(), Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Random: errorReader{}, SignUp: &credbound.SignUpConfig{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entropy.SignUp(ctx, signUpInput("visitor@example.com")); err == nil {
		t.Fatal("entropy failure ignored")
	}
}
