package credboundtest_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
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
	// Enrollment consumes its step, so verifying needs the next one.
	clock.Advance(30 * time.Second)
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

// blockingPolicy refuses one known-breached password, mirroring a HIBP
// integration.
type blockingPolicy struct{ breached string }

func (p blockingPolicy) ValidatePassword(_ context.Context, password string) error {
	if password == p.breached {
		return fmt.Errorf("%w: password found in a breach corpus", credbound.ErrInvalidInput)
	}
	return nil
}

// stubSSOProvider is the smallest provider the manager accepts; the ceremony
// itself is covered by the adapter packages.
type stubSSOProvider struct{ id string }

func (p stubSSOProvider) ConfigurationID() string       { return p.id }
func (stubSSOProvider) Kind() credbound.SSOProviderKind { return credbound.SSOProviderOIDC }
func (stubSSOProvider) Begin(context.Context, credbound.SSORequest) (credbound.SSOProviderChallenge, error) {
	return credbound.SSOProviderChallenge{RedirectURL: "https://idp.example.com/authorize", Session: []byte("session")}, nil
}

func (stubSSOProvider) Finish(context.Context, []byte, []byte) (credbound.SSOClaims, error) {
	return credbound.SSOClaims{Issuer: "https://idp.example.com", Subject: "subject", Email: "user@example.com", EmailVerified: true}, nil
}

// TestCredboundtestRemainingOptions covers the options a host reaches for once
// its tests go past the happy path: an unpredictable random source, a password
// policy, registered SSO providers, and an absolute clock move. They shipped
// without a single test, which is a poor promise for the package hosts are
// told to build their own suites on.
func TestCredboundtestRemainingOptions(t *testing.T) {
	ctx := context.Background()

	// WithRandom: crypto/rand makes two managers mint different identifiers,
	// where the deterministic default repeats them.
	first := credboundtest.NewManager(t, credboundtest.WithRandom(rand.Reader))
	second := credboundtest.NewManager(t, credboundtest.WithRandom(rand.Reader))
	firstRoot, _ := credboundtest.Bootstrap(t, first)
	secondRoot, _ := credboundtest.Bootstrap(t, second)
	if firstRoot.UserID == secondRoot.UserID {
		t.Fatal("WithRandom(crypto/rand) produced the same identifier twice")
	}
	deterministicFirst := credboundtest.NewManager(t)
	deterministicSecond := credboundtest.NewManager(t)
	deterministicRoot, _ := credboundtest.Bootstrap(t, deterministicFirst)
	repeatedRoot, _ := credboundtest.Bootstrap(t, deterministicSecond)
	if deterministicRoot.UserID != repeatedRoot.UserID {
		t.Fatalf("the default random source is not deterministic: %q then %q", deterministicRoot.UserID, repeatedRoot.UserID)
	}

	// WithPasswordPolicy: the vetting port rejects the password before any
	// account is created.
	policy := blockingPolicy{breached: "correct horse battery staple"}
	vetted := credboundtest.NewManager(t, credboundtest.WithPasswordPolicy(policy))
	if _, _, err := vetted.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: policy.breached, WorkspaceName: "Main",
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("breached password = %v", err)
	}
	if _, _, err := vetted.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "another correct horse battery", WorkspaceName: "Main",
	}); err != nil {
		t.Fatalf("vetted password: %v", err)
	}

	// WithSSOProviders: a registered provider is reachable by its
	// configuration identifier, an unknown one is not.
	provider := stubSSOProvider{id: "0198b463-0000-7000-8000-0000000000aa"}
	sso := credboundtest.NewManager(t, credboundtest.WithSSOProviders(provider))
	credboundtest.Bootstrap(t, sso)
	if _, err := sso.BeginSSO(ctx, provider.id); err != nil {
		t.Fatalf("begin sso: %v", err)
	}
	if _, err := sso.BeginSSO(ctx, "0198b463-0000-7000-8000-0000000000bb"); err == nil {
		t.Fatal("an unregistered provider started a ceremony")
	}

	// Clock.Set moves to an absolute instant, expiring a step-up that
	// Advance would have to walk to.
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	timed := credboundtest.NewManager(t, credboundtest.WithClock(clock))
	root, workspace := credboundtest.Bootstrap(t, timed)
	stale := credboundtest.AAL2(root.UserID, clock.Now())
	clock.Set(credboundtest.DefaultStartTime.Add(48 * time.Hour))
	if !clock.Now().Equal(credboundtest.DefaultStartTime.Add(48 * time.Hour)) {
		t.Fatalf("Set moved the clock to %v", clock.Now())
	}
	if _, err := timed.CreatePAT(ctx, stale, credbound.CreatePATInput{
		Name: "ci", WorkspaceID: workspace.ID, Scopes: []string{"read"},
	}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("stale step-up after Set = %v", err)
	}
}

// TestCredboundtestDiscoverablePasskeys covers the usernameless fake: the
// plain Passkeys double leaves the flow unsupported, and the discoverable one
// completes a ceremony through the manager's credential lookup.
func TestCredboundtestDiscoverablePasskeys(t *testing.T) {
	ctx := context.Background()
	plain := credboundtest.NewManager(t)
	credboundtest.Bootstrap(t, plain)
	if _, err := plain.BeginDiscoverablePasskeyAuthentication(ctx); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("plain fake discoverable = %v", err)
	}

	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager := credboundtest.NewManager(t, credboundtest.WithClock(clock), credboundtest.WithConfig(func(cfg *credbound.Config) {
		cfg.Passkeys = credboundtest.DiscoverablePasskeys{}
	}))
	root, _ := credboundtest.Bootstrap(t, manager)
	actor := credboundtest.AAL2(root.UserID, clock.Now())

	// A discoverable ceremony that resolves no credential fails: the fake
	// surfaces the manager's lookup rather than answering on its own.
	orphan, err := manager.BeginDiscoverablePasskeyAuthentication(ctx)
	if err != nil {
		t.Fatalf("begin discoverable without a passkey: %v", err)
	}
	if _, err := manager.FinishDiscoverablePasskeyAuthentication(ctx, orphan.Continuation, []byte(credboundtest.ValidPasskeyResponse)); err == nil {
		t.Fatal("a discoverable ceremony resolved an account with no passkey")
	}

	challenge, err := manager.BeginPasskeyRegistration(ctx, actor, "laptop")
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	if _, err := manager.FinishPasskeyRegistration(ctx, actor, challenge.Continuation, []byte(credboundtest.ValidPasskeyResponse)); err != nil {
		t.Fatalf("finish registration: %v", err)
	}
	discoverable, err := manager.BeginDiscoverablePasskeyAuthentication(ctx)
	if err != nil {
		t.Fatalf("begin discoverable: %v", err)
	}
	authn, err := manager.FinishDiscoverablePasskeyAuthentication(ctx, discoverable.Continuation, []byte(credboundtest.ValidPasskeyResponse))
	if err != nil || authn.UserID != root.UserID || authn.Level != credbound.AAL2 {
		t.Fatalf("finish discoverable = %#v, %v", authn, err)
	}
	if _, err := manager.FinishDiscoverablePasskeyAuthentication(ctx, discoverable.Continuation, []byte("wrong")); err == nil {
		t.Fatal("a wrong client response completed the ceremony")
	}
}
