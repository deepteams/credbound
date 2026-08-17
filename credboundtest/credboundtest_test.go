package credboundtest_test

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

func TestCredboundtestBootstrapAndPasswordAuthentication(t *testing.T) {
	manager := credboundtest.NewManager(t)
	authn, workspace := credboundtest.Bootstrap(t, manager)
	if authn.UserID == "" || workspace.ID == "" || workspace.Name != credboundtest.BootstrapWorkspaceName {
		t.Fatalf("bootstrap = %#v, %#v", authn, workspace)
	}
	loggedIn, err := manager.AuthenticatePassword(context.Background(), credboundtest.BootstrapEmail, credboundtest.BootstrapPassword)
	if err != nil || loggedIn.UserID != authn.UserID || loggedIn.Level != credbound.AAL1 || loggedIn.Method != credbound.MethodPassword {
		t.Fatalf("password authentication = %#v, %v", loggedIn, err)
	}
	if _, err := manager.AuthenticatePassword(context.Background(), credboundtest.BootstrapEmail, "wrong password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("wrong password error = %v", err)
	}
}

func TestCredboundtestTOTPEnrollmentAndVerification(t *testing.T) {
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager := credboundtest.NewManager(t, credboundtest.WithClock(clock))
	authn, _ := credboundtest.Bootstrap(t, manager)
	enrollment, err := manager.BeginTOTPEnrollment(context.Background(), authn)
	if err != nil || !strings.HasPrefix(enrollment.URI, "otpauth://") {
		t.Fatalf("enrollment = %#v, %v", enrollment, err)
	}
	if _, err := manager.ConfirmTOTPEnrollment(context.Background(), authn, "000000"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("invalid confirmation error = %v", err)
	}
	codes, err := manager.ConfirmTOTPEnrollment(context.Background(), authn, credboundtest.ValidTOTPCode)
	if err != nil || len(codes) == 0 {
		t.Fatalf("recovery codes = %d, %v", len(codes), err)
	}
	promoted, err := manager.VerifyTOTP(context.Background(), authn, credboundtest.ValidTOTPCode)
	if err != nil || promoted.Level != credbound.AAL2 || promoted.Method != credbound.MethodTOTP {
		t.Fatalf("promoted = %#v, %v", promoted, err)
	}
	// The fake reports real 30-second steps, so replaying the code inside the
	// same step is rejected and advancing the clock opens the next step.
	if _, err := manager.VerifyTOTP(context.Background(), authn, credboundtest.ValidTOTPCode); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("replayed TOTP error = %v", err)
	}
	clock.Advance(30 * time.Second)
	if _, err := manager.VerifyTOTP(context.Background(), authn, credboundtest.ValidTOTPCode); err != nil {
		t.Fatalf("next-step TOTP = %v", err)
	}
}

func TestCredboundtestPATCreateAndAuthenticate(t *testing.T) {
	manager := credboundtest.NewManager(t)
	authn, workspace := credboundtest.Bootstrap(t, manager)
	stepUp := credboundtest.AAL2(authn.UserID, credboundtest.DefaultStartTime)
	issued, err := manager.CreatePAT(context.Background(), stepUp, credbound.CreatePATInput{
		Name: "ci", WorkspaceID: workspace.ID, Scopes: []string{"read"},
	})
	if err != nil || issued.Token == "" {
		t.Fatalf("issued PAT = %#v, %v", issued, err)
	}
	patAuth, err := manager.AuthenticatePAT(context.Background(), issued.Token)
	if err != nil || patAuth.Method != credbound.MethodPAT || !patAuth.HasScope("read") || patAuth.HasScope("admin") {
		t.Fatalf("PAT authentication = %#v, %v", patAuth, err)
	}
	// AAL1 fails the step-up that CreatePAT requires; the AAL2 helper is the
	// intended way to satisfy it in tests.
	if _, err := manager.CreatePAT(context.Background(), authn, credbound.CreatePATInput{
		Name: "denied", WorkspaceID: workspace.ID, Scopes: []string{"read"},
	}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 CreatePAT error = %v", err)
	}
}

func TestCredboundtestPasskeyCeremonies(t *testing.T) {
	manager := credboundtest.NewManager(t)
	authn, _ := credboundtest.Bootstrap(t, manager)
	challenge, err := manager.BeginPasskeyRegistration(context.Background(), authn, "laptop")
	if err != nil || challenge.Continuation == "" {
		t.Fatalf("registration challenge = %#v, %v", challenge, err)
	}
	if _, err := manager.FinishPasskeyRegistration(context.Background(), authn, challenge.Continuation, []byte(credboundtest.ValidPasskeyResponse)); err != nil {
		t.Fatalf("finish registration = %v", err)
	}
	login, err := manager.BeginPasskeyAuthentication(context.Background(), credboundtest.BootstrapEmail)
	if err != nil {
		t.Fatal(err)
	}
	passkeyAuth, err := manager.FinishPasskeyAuthentication(context.Background(), login.Continuation, []byte(credboundtest.ValidPasskeyResponse))
	if err != nil || passkeyAuth.Level != credbound.AAL2 || passkeyAuth.Method != credbound.MethodPasskey {
		t.Fatalf("passkey authentication = %#v, %v", passkeyAuth, err)
	}
	if _, err := manager.FinishPasskeyAuthentication(context.Background(), login.Continuation, []byte("forged")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("forged response error = %v", err)
	}
}

func TestCredboundtestClockOptionDrivesStepUpFreshness(t *testing.T) {
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager := credboundtest.NewManager(t, credboundtest.WithClock(clock))
	authn, _ := credboundtest.Bootstrap(t, manager)
	stepUp := credboundtest.AAL2(authn.UserID, clock.Now())
	if err := manager.RequireStepUp(stepUp); err != nil {
		t.Fatalf("fresh step-up = %v", err)
	}
	clock.Advance(11 * time.Minute)
	if err := manager.RequireStepUp(stepUp); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("stale step-up error = %v", err)
	}
}

type recordingListener struct {
	credbound.UnimplementedEventListener
	bootstraps int
}

func (l *recordingListener) OnBootstrapCompleted(context.Context, credbound.BootstrapCompletedEvent) error {
	l.bootstraps++
	return nil
}

func TestCredboundtestStoreAndListenerOptions(t *testing.T) {
	store := memory.New()
	listener := &recordingListener{}
	manager := credboundtest.NewManager(t,
		credboundtest.WithStore(store),
		credboundtest.WithEventListeners(listener),
		credboundtest.WithTransactionHooks(credbound.UnimplementedTransactionHook{}),
	)
	authn, _ := credboundtest.Bootstrap(t, manager)
	if listener.bootstraps != 1 {
		t.Fatalf("bootstrap events = %d", listener.bootstraps)
	}
	if _, err := store.UserByID(context.Background(), authn.UserID); err != nil {
		t.Fatalf("user missing from injected store: %v", err)
	}
}

func TestCredboundtestWithConfig(t *testing.T) {
	manager := credboundtest.NewManager(t, credboundtest.WithConfig(func(cfg *credbound.Config) {
		cfg.SignUp = &credbound.SignUpConfig{AutoVerifyEmail: true}
	}))
	result, err := manager.SignUp(context.Background(), credbound.SignUpInput{
		Email: "founder@example.com", DisplayName: "Founder",
		Password: "another strong password", WorkspaceName: "Startup",
	})
	if err != nil || result.Authentication.UserID == "" || result.ExistingAccount {
		t.Fatalf("signup through WithConfig = %#v, %v", result, err)
	}
}
