package credbound_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
)

var otpCode = regexp.MustCompile(`^[0-9]{8}$`)

func TestEmailOTPAuthentication(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()

	decoy, err := f.manager.BeginEmailOTP(ctx, "ghost@example.com")
	if err != nil || decoy.Code != "" || decoy.Continuation == "" || decoy.UserID != "" {
		t.Fatalf("unknown email OTP = %#v, %v", decoy, err)
	}
	if _, err := f.manager.CompleteEmailOTP(ctx, decoy.Continuation, "12345678"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("decoy completion = %v", err)
	}

	issued, err := f.manager.BeginEmailOTP(ctx, " ROOT@Example.com ")
	if err != nil || issued.UserID != authn.UserID || !otpCode.MatchString(issued.Code) || issued.Continuation == "" || issued.EmailID == "" {
		t.Fatalf("issued OTP = %#v, %v", issued, err)
	}
	if !issued.ExpiresAt.Equal(f.now.Add(15 * time.Minute)) {
		t.Fatalf("OTP TTL = %v", issued.ExpiresAt)
	}

	if _, err := f.manager.CompleteEmailOTP(ctx, "not-a-continuation", issued.Code); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("malformed continuation = %v", err)
	}
	wrong := "00000000"
	if wrong == issued.Code {
		wrong = "00000001"
	}
	if _, err := f.manager.CompleteEmailOTP(ctx, issued.Continuation, wrong); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("wrong code = %v", err)
	}

	session, err := f.manager.CompleteEmailOTP(ctx, issued.Continuation, issued.Code)
	if err != nil || session.UserID != authn.UserID || session.Method != credbound.MethodEmail || session.Level != credbound.AAL1 || session.SecondFactorRequired {
		t.Fatalf("OTP authentication = %#v, %v", session, err)
	}
	if _, err := f.manager.CompleteEmailOTP(ctx, issued.Continuation, issued.Code); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("reused OTP = %v", err)
	}

	expired, err := f.manager.BeginEmailOTP(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(15*time.Minute + 30*time.Second)
	if _, err := f.manager.CompleteEmailOTP(ctx, expired.Continuation, expired.Code); !errors.Is(err, credbound.ErrExpired) {
		t.Fatalf("expired OTP = %v", err)
	}
}

func TestEmailOTPWrongCodesLockAccount(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()

	issued, err := f.manager.BeginEmailOTP(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	wrong := "00000000"
	if wrong == issued.Code {
		wrong = "00000001"
	}
	for attempt := 0; attempt < 10; attempt++ {
		if _, err := f.manager.CompleteEmailOTP(ctx, issued.Continuation, wrong); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("attempt %d = %v", attempt, err)
		}
	}
	if _, err := f.manager.CompleteEmailOTP(ctx, issued.Continuation, issued.Code); !errors.Is(err, credbound.ErrLocked) {
		t.Fatalf("locked OTP completion = %v", err)
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("locked password login = %v", err)
	}
	_ = authn
}

type rejectingPolicy struct{ rejected string }

func (p rejectingPolicy) ValidatePassword(_ context.Context, password string) error {
	if password == p.rejected {
		return fmt.Errorf("%w: password found in breach corpus", credbound.ErrInvalidInput)
	}
	return nil
}

func TestPasswordPolicyPort(t *testing.T) {
	store := memory.New()
	manager, err := credbound.New(credbound.Config{
		Store: store, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Random:         &counterReader{next: 0x42},
		PasswordPolicy: rejectingPolicy{rejected: "compromised passphrase"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "compromised passphrase", WorkspaceName: "Main",
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("rejected bootstrap password = %v", err)
	}
	authn, _, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ChangePassword(ctx, authn, "correct horse battery", "compromised passphrase"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("rejected change password = %v", err)
	}
}

type authEventRecorder struct {
	credbound.UnimplementedEventListener
	succeeded []credbound.AuthenticationEvent
	failed    []credbound.AuthenticationFailureEvent
	locked    []credbound.UserLockedEvent
}

func (r *authEventRecorder) OnAuthenticationSucceeded(_ context.Context, event credbound.AuthenticationEvent) error {
	r.succeeded = append(r.succeeded, event)
	return nil
}

func (r *authEventRecorder) OnAuthenticationFailed(_ context.Context, event credbound.AuthenticationFailureEvent) error {
	r.failed = append(r.failed, event)
	return nil
}

func (r *authEventRecorder) OnUserLocked(_ context.Context, event credbound.UserLockedEvent) error {
	r.locked = append(r.locked, event)
	return nil
}

func TestAuthenticationEventsCarryRequestMetadata(t *testing.T) {
	recorder := &authEventRecorder{}
	store := memory.New()
	manager, err := credbound.New(credbound.Config{
		Store: store, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Random:         &counterReader{next: 0x42},
		EventListeners: []credbound.EventListener{recorder},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := credbound.WithRequestMetadata(context.Background(), credbound.RequestMetadata{
		IPAddress: "203.0.113.9", UserAgent: "integration-test/1.0",
	})
	if _, _, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "wrong password entirely"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("failed login = %v", err)
	}
	if len(recorder.failed) != 1 || recorder.failed[0].Request.IPAddress != "203.0.113.9" || recorder.failed[0].Request.UserAgent != "integration-test/1.0" {
		t.Fatalf("failure event metadata = %#v", recorder.failed)
	}
	if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if len(recorder.succeeded) != 1 || recorder.succeeded[0].Request.IPAddress != "203.0.113.9" {
		t.Fatalf("success event metadata = %#v", recorder.succeeded)
	}
	for attempt := 0; attempt < 10; attempt++ {
		if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "wrong password entirely"); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("attempt %d = %v", attempt, err)
		}
	}
	if len(recorder.locked) != 1 || recorder.locked[0].Request.IPAddress != "203.0.113.9" {
		t.Fatalf("locked event metadata = %#v", recorder.locked)
	}
}

// budgetReader serves at most remaining bytes, then fails, to exercise
// entropy-failure branches at precise points of a flow.
type budgetReader struct{ remaining int }

func (r *budgetReader) Read(p []byte) (int, error) {
	if r.remaining < len(p) {
		return 0, errors.New("entropy exhausted")
	}
	for index := range p {
		p[index] = 0x24
	}
	r.remaining -= len(p)
	return len(p), nil
}

// phantomEmailStore resolves every address to a fixed user so flows can be
// driven into their "known user, unverified address" branch.
type phantomEmailStore struct {
	credbound.Store
	user credbound.User
}

func (s phantomEmailStore) UserByEmail(context.Context, string) (credbound.User, error) {
	return s.user, nil
}

func TestEmailOTPEntropyAndUnverifiedBranches(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()

	for _, budget := range []int{0, 16, 20, 32, 48} {
		manager := managerWith(t, f.store, f.passwords, fakeTOTP{}, f.passkeys, &budgetReader{remaining: budget})
		if _, err := manager.BeginEmailOTP(ctx, "root@example.com"); err == nil {
			t.Fatalf("budget %d accepted", budget)
		}
	}

	root, err := f.store.UserByID(ctx, authn.UserID)
	if err != nil {
		t.Fatal(err)
	}
	phantom := phantomEmailStore{Store: f.store, user: root}
	manager := managerWith(t, phantom, f.passwords, fakeTOTP{}, f.passkeys, nil)
	if issued, err := manager.BeginEmailOTP(ctx, "phantom@example.com"); err != nil || issued.Code != "" || issued.Continuation == "" {
		t.Fatalf("unverified OTP = %#v, %v", issued, err)
	}
	if issued, err := manager.BeginEmailAuthentication(ctx, "phantom@example.com"); err != nil || issued.Token != "" {
		t.Fatalf("unverified link = %#v, %v", issued, err)
	}
}

func TestEmailOTPCodeResampling(t *testing.T) {
	f := newFixture(t)
	f.bootstrap(t)
	ctx := context.Background()
	// 16 bytes of identifier, one rejected 0xff draw, one accepted draw, and
	// enough left over for the sealed continuation.
	sequence := append(append(make([]byte, 0, 64), bytes.Repeat([]byte{0x11}, 16)...), 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02, 0x03)
	sequence = append(sequence, bytes.Repeat([]byte{0x22}, 80)...)
	manager := managerWith(t, f.store, f.passwords, fakeTOTP{}, f.passkeys, bytes.NewReader(sequence))
	issued, err := manager.BeginEmailOTP(ctx, "root@example.com")
	if err != nil || !otpCode.MatchString(issued.Code) {
		t.Fatalf("resampled OTP = %#v, %v", issued, err)
	}
}
