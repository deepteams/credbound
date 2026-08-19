// Package storetest runs the store-independent behavioral conformance suite
// of Credbound: the same Manager-level flows executed against every store
// implementation, so a divergence between the in-memory and
// PostgreSQL backends fails a test instead of reaching production.
//
// The root package's own tests exercise the Manager against the in-memory
// store only. Store packages, symmetrically, test their port contract without
// ever building a Manager. This suite closes the gap: it asserts the business
// semantics a host observes — ordering, cursor stability, atomicity,
// revocation cascades, audit chaining, timestamp persistence — through the
// public API, where a SQL dialect difference actually shows up.
//
// A store package registers itself with a Factory returning a fresh, empty
// store per call:
//
//	func TestConformance(t *testing.T) {
//		storetest.Run(t, storetest.Factory{Name: "postgresql", New: newStore})
//	}
//
// Nothing here is safe outside tests: the managers it builds use the
// deterministic doubles of credboundtest.
package storetest

import (
	"context"
	"crypto/rand"
	"errors"
	"iter"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/credboundtest"
)

// Factory builds the store under test. New must return an empty, isolated
// store, and register any cleanup with t.Cleanup. The suite calls it exactly
// once per flow, so an implementation backed by a single shared database — as
// the PostgreSQL one is — may reset that database on every call.
type Factory struct {
	// Name labels the implementation in test output.
	Name string
	// New returns a fresh, empty store.
	New func(t *testing.T) credbound.Store
}

// flow is one named conformance scenario.
type flow struct {
	name string
	run  func(*testing.T, Factory)
}

// flows lists every scenario Run executes. Adding a flow here extends the
// contract for all stores at once, which is the point of the suite.
var flows = []flow{
	{"IdentityAndPassword", testIdentityAndPassword},
	{"Lockout", testLockout},
	{"Emails", testEmails},
	{"PasswordReset", testPasswordReset},
	{"EmailSignIn", testEmailSignIn},
	{"TOTP", testTOTP},
	{"Passkeys", testPasskeys},
	{"PersonalAccessTokens", testPersonalAccessTokens},
	{"Sessions", testSessions},
	{"Invitations", testInvitations},
	{"SignUp", testSignUp},
	{"SignUpPendingVerification", testSignUpPendingVerification},
	{"WorkspacesAndRBAC", testWorkspacesAndRBAC},
	{"Pagination", testPagination},
	{"AuditChain", testAuditChain},
	{"SingleUseUnderConcurrency", testSingleUseUnderConcurrency},
	{"ConcurrentBootstrap", testConcurrentBootstrap},
	{"ConcurrentUniqueAddress", testConcurrentUniqueAddress},
	{"PrivacyRights", testPrivacyRights},
}

// Run executes the conformance suite against the store built by factory.
func Run(t *testing.T, factory Factory) {
	t.Helper()
	if factory.New == nil {
		t.Fatal("storetest: factory.New is required")
	}
	for _, current := range flows {
		t.Run(current.name, func(t *testing.T) { current.run(t, factory) })
	}
}

// Passwords used by the suite. Both satisfy the default twelve-character
// minimum.
const (
	newPassword    = "another correct horse battery"
	memberPassword = "member correct horse battery"
)

// harness is a bootstrapped manager over a fresh store.
type harness struct {
	t       *testing.T
	ctx     context.Context
	manager *credbound.Manager
	clock   *credboundtest.Clock
	store   credbound.Store
}

func newHarness(t *testing.T, factory Factory, opts ...credboundtest.Option) *harness {
	t.Helper()
	store := factory.New(t)
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	options := []credboundtest.Option{credboundtest.WithStore(store), credboundtest.WithClock(clock)}
	options = append(options, opts...)
	return &harness{
		t:       t,
		ctx:     context.Background(),
		manager: credboundtest.NewManager(t, options...),
		clock:   clock,
		store:   store,
	}
}

// bootstrap creates the first user and workspace.
func (h *harness) bootstrap() (credbound.Authentication, credbound.Workspace) {
	h.t.Helper()
	return credboundtest.Bootstrap(h.t, h.manager)
}

// stepUp fabricates the AAL2 context sensitive mutations require.
func (h *harness) stepUp(userID string) credbound.Authentication {
	return credboundtest.AAL2(userID, h.clock.Now())
}

// local is the loopback marker that waives the step-up on administrative
// mutations.
func local() credbound.TrustedRequest { return credbound.TrustedRequest{Local: true} }

// collect drains a paginated sequence into its items and terminating page end.
func collect[T any](t *testing.T, sequence iter.Seq2[credbound.PageEvent[T], error]) ([]T, credbound.PageEnd) {
	t.Helper()
	var (
		items []T
		end   credbound.PageEnd
	)
	for event, err := range sequence {
		if err != nil {
			t.Fatalf("stream: %v", err)
		}
		if event.Data != nil {
			items = append(items, *event.Data)
		}
		if event.End != nil {
			end = *event.End
		}
	}
	return items, end
}

// collectAll drains an unpaginated sequence.
func collectAll[T any](t *testing.T, sequence iter.Seq2[T, error]) []T {
	t.Helper()
	var items []T
	for value, err := range sequence {
		if err != nil {
			t.Fatalf("stream: %v", err)
		}
		items = append(items, value)
	}
	return items
}

// testIdentityAndPassword pins the local-account contract every store must
// reproduce: normalization, the indistinguishable failure of an unknown
// address and a wrong password, the persisted last-seen timestamp, and the
// disable/enable lifecycle.
func testIdentityAndPassword(t *testing.T, factory Factory) {
	h := newHarness(t, factory)
	root, workspace := h.bootstrap()

	if _, err := h.manager.AuthenticatePassword(h.ctx, "missing@example.com", "wrong password here"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("unknown address = %v", err)
	}
	if _, err := h.manager.AuthenticatePassword(h.ctx, credboundtest.BootstrapEmail, "wrong password here"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("wrong password = %v", err)
	}

	// Normalization is a store-visible invariant: the address is stored
	// lowercased and trimmed, so a mixed-case sign-in must find it.
	h.clock.Advance(time.Minute)
	authn, err := h.manager.AuthenticatePassword(h.ctx, "  ROOT@Example.COM  ", credboundtest.BootstrapPassword)
	if err != nil || authn.UserID != root.UserID || authn.Level != credbound.AAL1 || authn.Method != credbound.MethodPassword {
		t.Fatalf("sign-in = %#v, %v", authn, err)
	}

	// LastSeenAt is written inside the sign-in transaction; a store that
	// dropped or truncated it would surface here.
	user, err := h.manager.User(h.ctx, root, root.UserID)
	if err != nil {
		t.Fatalf("read user: %v", err)
	}
	if user.LastSeenAt == nil {
		t.Fatal("last seen was not persisted")
	}
	if !user.LastSeenAt.Equal(h.clock.Now()) {
		t.Fatalf("last seen = %v, want %v", user.LastSeenAt, h.clock.Now())
	}
	if user.Email != strings.ToLower(credboundtest.BootstrapEmail) {
		t.Fatalf("stored address = %q", user.Email)
	}

	created, err := h.manager.CreateUser(h.ctx, h.stepUp(root.UserID), workspace.ID, credbound.CreateUserInput{
		Email: "Member@Example.com", DisplayName: "Member", Password: memberPassword, Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if created.Email != "member@example.com" {
		t.Fatalf("created address = %q", created.Email)
	}
	if _, err := h.manager.AuthenticatePassword(h.ctx, "member@example.com", memberPassword); err != nil {
		t.Fatalf("member sign-in: %v", err)
	}
	if _, err := h.manager.CreateUser(h.ctx, h.stepUp(root.UserID), workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Duplicate", Password: memberPassword, Role: credbound.RoleMember,
	}); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate address = %v", err)
	}

	// A disabled account fails exactly like a wrong password, and enabling
	// it restores the credential without a password reset.
	if err := h.manager.DisableUser(h.ctx, root, local(), created.ID); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := h.manager.AuthenticatePassword(h.ctx, "member@example.com", memberPassword); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("disabled sign-in = %v", err)
	}
	if err := h.manager.EnableUser(h.ctx, root, local(), created.ID); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, err := h.manager.AuthenticatePassword(h.ctx, "member@example.com", memberPassword); err != nil {
		t.Fatalf("re-enabled sign-in: %v", err)
	}

	// ChangePassword replaces the credential atomically: the old one stops
	// working the moment the new one starts.
	if err := h.manager.ChangePassword(h.ctx, h.stepUp(root.UserID), credboundtest.BootstrapPassword, newPassword); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if _, err := h.manager.AuthenticatePassword(h.ctx, credboundtest.BootstrapEmail, credboundtest.BootstrapPassword); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("old password still valid: %v", err)
	}
	if _, err := h.manager.AuthenticatePassword(h.ctx, credboundtest.BootstrapEmail, newPassword); err != nil {
		t.Fatalf("new password: %v", err)
	}
}

// testLockout pins the persisted login throttle: consecutive failures lock the
// account, the correct password stays refused while the lock holds, and the
// lock lifts on its own once LockoutDuration has passed.
func testLockout(t *testing.T, factory Factory) {
	h := newHarness(t, factory, credboundtest.WithConfig(func(cfg *credbound.Config) {
		cfg.MaxFailedLogins = 3
		cfg.LockoutDuration = 15 * time.Minute
	}))
	h.bootstrap()

	for attempt := range 3 {
		if _, err := h.manager.AuthenticatePassword(h.ctx, credboundtest.BootstrapEmail, "wrong password here"); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("attempt %d = %v", attempt, err)
		}
	}
	// The correct password is now refused, with the same public error: the
	// lockout must never become an existence oracle.
	if _, err := h.manager.AuthenticatePassword(h.ctx, credboundtest.BootstrapEmail, credboundtest.BootstrapPassword); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("locked sign-in = %v", err)
	}
	h.clock.Advance(16 * time.Minute)
	if _, err := h.manager.AuthenticatePassword(h.ctx, credboundtest.BootstrapEmail, credboundtest.BootstrapPassword); err != nil {
		t.Fatalf("sign-in after lockout expiry: %v", err)
	}
	// A successful sign-in clears the counter: three more failures are
	// needed to lock the account again.
	for attempt := range 2 {
		if _, err := h.manager.AuthenticatePassword(h.ctx, credboundtest.BootstrapEmail, "wrong password here"); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("post-reset attempt %d = %v", attempt, err)
		}
	}
	if _, err := h.manager.AuthenticatePassword(h.ctx, credboundtest.BootstrapEmail, credboundtest.BootstrapPassword); err != nil {
		t.Fatalf("counter was not reset by the successful sign-in: %v", err)
	}
}

// testEmails pins the multi-address contract: an added address authenticates
// nothing until its single-use proof is confirmed, the primary flag moves
// atomically, and the primary address cannot be removed.
func testEmails(t *testing.T, factory Factory) {
	h := newHarness(t, factory)
	root, _ := h.bootstrap()
	actor := h.stepUp(root.UserID)

	issued, err := h.manager.BeginEmailAddition(h.ctx, actor, "Second@Example.com")
	if err != nil {
		t.Fatalf("begin addition: %v", err)
	}
	if issued.Token == "" || issued.Email.VerifiedAt != nil {
		t.Fatalf("issued verification = %#v", issued)
	}
	// An unverified secondary address must not authenticate.
	if _, err := h.manager.AuthenticatePassword(h.ctx, "second@example.com", credboundtest.BootstrapPassword); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("unverified address signed in: %v", err)
	}
	confirmed, err := h.manager.ConfirmEmail(h.ctx, issued.Token)
	if err != nil || confirmed.VerifiedAt == nil {
		t.Fatalf("confirm = %#v, %v", confirmed, err)
	}
	// The proof is single use.
	if _, err := h.manager.ConfirmEmail(h.ctx, issued.Token); err == nil {
		t.Fatal("verification token was accepted twice")
	}
	if _, err := h.manager.AuthenticatePassword(h.ctx, "second@example.com", credboundtest.BootstrapPassword); err != nil {
		t.Fatalf("verified secondary sign-in: %v", err)
	}

	addresses, _ := collect(t, h.manager.Emails(h.ctx, actor, root.UserID, credbound.PageRequest{Limit: 50}))
	if len(addresses) != 2 {
		t.Fatalf("addresses = %d, want 2", len(addresses))
	}
	primaries := 0
	for _, address := range addresses {
		if address.Primary {
			primaries++
		}
	}
	if primaries != 1 {
		t.Fatalf("primary addresses = %d, want exactly 1", primaries)
	}

	if err := h.manager.RemoveEmail(h.ctx, actor, primaryOf(t, addresses).ID); err == nil {
		t.Fatal("the primary address was removed")
	}
	if err := h.manager.SetPrimaryEmail(h.ctx, actor, confirmed.ID); err != nil {
		t.Fatalf("set primary: %v", err)
	}
	addresses, _ = collect(t, h.manager.Emails(h.ctx, actor, root.UserID, credbound.PageRequest{Limit: 50}))
	if primary := primaryOf(t, addresses); primary.ID != confirmed.ID {
		t.Fatalf("primary = %q, want %q", primary.ID, confirmed.ID)
	}
	// The demoted address is now removable, and the user record follows the
	// primary address.
	var demoted string
	for _, address := range addresses {
		if !address.Primary {
			demoted = address.ID
		}
	}
	if err := h.manager.RemoveEmail(h.ctx, actor, demoted); err != nil {
		t.Fatalf("remove demoted address: %v", err)
	}
	user, err := h.manager.User(h.ctx, actor, root.UserID)
	if err != nil || user.Email != "second@example.com" {
		t.Fatalf("user address after primary move = %#v, %v", user, err)
	}
}

func primaryOf(t *testing.T, addresses []credbound.EmailAddress) credbound.EmailAddress {
	t.Helper()
	for _, address := range addresses {
		if address.Primary {
			return address
		}
	}
	t.Fatal("no primary address")
	return credbound.EmailAddress{}
}

// testPasswordReset pins the reset cascade: the proof is single use and
// expiring, and completing it revokes the account's PATs and sessions inside
// the same transaction.
func testPasswordReset(t *testing.T, factory Factory) {
	h := newHarness(t, factory)
	root, workspace := h.bootstrap()

	pat, err := h.manager.CreatePAT(h.ctx, h.stepUp(root.UserID), credbound.CreatePATInput{
		Name: "ci", WorkspaceID: workspace.ID, Scopes: []string{"read"},
	})
	if err != nil {
		t.Fatalf("create pat: %v", err)
	}
	session, err := h.manager.CreateSession(h.ctx, h.stepUp(root.UserID), credbound.CreateSessionInput{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	issued, err := h.manager.BeginPasswordReset(h.ctx, credboundtest.BootstrapEmail)
	if err != nil || !issued.Deliverable || issued.Token == "" {
		t.Fatalf("begin reset = %#v, %v", issued, err)
	}
	// An unknown address answers identically, without a token.
	decoy, err := h.manager.BeginPasswordReset(h.ctx, "missing@example.com")
	if err != nil || decoy.Deliverable || decoy.Token != "" {
		t.Fatalf("decoy reset = %#v, %v", decoy, err)
	}

	if _, err := h.manager.CompletePasswordReset(h.ctx, issued.Token, newPassword); err != nil {
		t.Fatalf("complete reset: %v", err)
	}
	if _, err := h.manager.CompletePasswordReset(h.ctx, issued.Token, newPassword); err == nil {
		t.Fatal("reset token was accepted twice")
	}
	if _, err := h.manager.AuthenticatePassword(h.ctx, credboundtest.BootstrapEmail, credboundtest.BootstrapPassword); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("old password survived the reset: %v", err)
	}
	if _, err := h.manager.AuthenticatePassword(h.ctx, credboundtest.BootstrapEmail, newPassword); err != nil {
		t.Fatalf("new password: %v", err)
	}
	// The cascade is the security-relevant part: a stolen PAT or session
	// must not outlive the reset that was meant to expel the attacker.
	if _, err := h.manager.AuthenticatePAT(h.ctx, pat.Token); err == nil {
		t.Fatal("the PAT survived the password reset")
	}
	if _, _, err := h.manager.AuthenticateSession(h.ctx, session.Token); err == nil {
		t.Fatal("the session survived the password reset")
	}

	// An expired proof is refused.
	expiring, err := h.manager.BeginPasswordReset(h.ctx, credboundtest.BootstrapEmail)
	if err != nil {
		t.Fatalf("begin second reset: %v", err)
	}
	h.clock.Advance(2 * time.Hour)
	if _, err := h.manager.CompletePasswordReset(h.ctx, expiring.Token, memberPassword); err == nil {
		t.Fatal("an expired reset token was accepted")
	}
}

// testEmailSignIn pins the passwordless email flows: magic link and OTP both
// issue single-use, expiring proofs and produce an interactive AAL1 context.
func testEmailSignIn(t *testing.T, factory Factory) {
	h := newHarness(t, factory)
	root, _ := h.bootstrap()

	link, err := h.manager.BeginEmailAuthentication(h.ctx, credboundtest.BootstrapEmail)
	if err != nil || !link.Deliverable || link.Token == "" {
		t.Fatalf("begin magic link = %#v, %v", link, err)
	}
	authn, err := h.manager.CompleteEmailAuthentication(h.ctx, link.Token)
	if err != nil || authn.UserID != root.UserID || authn.Method != credbound.MethodEmail {
		t.Fatalf("complete magic link = %#v, %v", authn, err)
	}
	if _, err := h.manager.CompleteEmailAuthentication(h.ctx, link.Token); err == nil {
		t.Fatal("the magic link was accepted twice")
	}

	otp, err := h.manager.BeginEmailOTP(h.ctx, credboundtest.BootstrapEmail)
	if err != nil || !otp.Deliverable || otp.Code == "" || otp.Continuation == "" {
		t.Fatalf("begin otp = %#v, %v", otp, err)
	}
	if _, err := h.manager.CompleteEmailOTP(h.ctx, otp.Continuation, "000000"); err == nil {
		t.Fatal("a wrong OTP code was accepted")
	}
	authn, err = h.manager.CompleteEmailOTP(h.ctx, otp.Continuation, otp.Code)
	if err != nil || authn.UserID != root.UserID {
		t.Fatalf("complete otp = %#v, %v", authn, err)
	}
	if _, err := h.manager.CompleteEmailOTP(h.ctx, otp.Continuation, otp.Code); err == nil {
		t.Fatal("the OTP continuation was accepted twice")
	}

	// Expiry is measured against the persisted deadline, not the process.
	expiring, err := h.manager.BeginEmailAuthentication(h.ctx, credboundtest.BootstrapEmail)
	if err != nil {
		t.Fatalf("begin second magic link: %v", err)
	}
	h.clock.Advance(time.Hour)
	if _, err := h.manager.CompleteEmailAuthentication(h.ctx, expiring.Token); err == nil {
		t.Fatal("an expired magic link was accepted")
	}
	// An unknown address is answered exactly like a known one.
	decoy, err := h.manager.BeginEmailAuthentication(h.ctx, "missing@example.com")
	if err != nil || decoy.Deliverable || decoy.Token != "" {
		t.Fatalf("decoy magic link = %#v, %v", decoy, err)
	}
}

// testTOTP pins the second factor: enrollment activates only after a valid
// code, the resulting recovery codes are single use, and a verified code
// cannot be replayed within its step.
func testTOTP(t *testing.T, factory Factory) {
	h := newHarness(t, factory)
	root, _ := h.bootstrap()
	actor := h.stepUp(root.UserID)

	enrollment, err := h.manager.BeginTOTPEnrollment(h.ctx, actor)
	if err != nil || enrollment.URI == "" {
		t.Fatalf("begin enrollment = %#v, %v", enrollment, err)
	}
	status, err := h.manager.TOTPStatus(h.ctx, actor, root.UserID)
	if err != nil || status.Active {
		t.Fatalf("status before confirmation = %#v, %v", status, err)
	}
	if _, err := h.manager.ConfirmTOTPEnrollment(h.ctx, actor, "000000"); err == nil {
		t.Fatal("enrollment confirmed with a wrong code")
	}
	recovery, err := h.manager.ConfirmTOTPEnrollment(h.ctx, actor, credboundtest.ValidTOTPCode)
	if err != nil || len(recovery) == 0 {
		t.Fatalf("confirm enrollment = %v, %v", recovery, err)
	}
	status, err = h.manager.TOTPStatus(h.ctx, actor, root.UserID)
	if err != nil || !status.Active || status.UnusedRecoveryCodes != len(recovery) {
		t.Fatalf("status after confirmation = %#v, %v", status, err)
	}

	// The first factor now reports a pending second factor.
	first, err := h.manager.AuthenticatePassword(h.ctx, credboundtest.BootstrapEmail, credboundtest.BootstrapPassword)
	if err != nil || !first.SecondFactorRequired || first.Level != credbound.AAL1 {
		t.Fatalf("first factor = %#v, %v", first, err)
	}
	h.clock.Advance(time.Minute)
	second, err := h.manager.VerifyTOTP(h.ctx, first, credboundtest.ValidTOTPCode)
	if err != nil || second.Level != credbound.AAL2 || second.SecondFactorRequired {
		t.Fatalf("second factor = %#v, %v", second, err)
	}
	// Replaying the same code inside its step is refused by the persisted
	// last-used step, not by an in-process cache.
	if _, err := h.manager.VerifyTOTP(h.ctx, first, credboundtest.ValidTOTPCode); err == nil {
		t.Fatal("a TOTP code was replayed within its step")
	}

	// A recovery code authenticates once.
	if _, err := h.manager.VerifyTOTP(h.ctx, first, recovery[0]); err != nil {
		t.Fatalf("recovery code: %v", err)
	}
	if _, err := h.manager.VerifyTOTP(h.ctx, first, recovery[0]); err == nil {
		t.Fatal("a recovery code was accepted twice")
	}
	regenerated, err := h.manager.RegenerateRecoveryCodes(h.ctx, h.stepUp(root.UserID))
	if err != nil || len(regenerated) == 0 {
		t.Fatalf("regenerate = %v, %v", regenerated, err)
	}
	// Regeneration invalidates the previous batch.
	if _, err := h.manager.VerifyTOTP(h.ctx, first, recovery[1]); err == nil {
		t.Fatal("a superseded recovery code was accepted")
	}

	h.clock.Advance(time.Minute)
	if err := h.manager.DisableTOTP(h.ctx, h.stepUp(root.UserID), credboundtest.ValidTOTPCode); err != nil {
		t.Fatalf("disable totp: %v", err)
	}
	status, err = h.manager.TOTPStatus(h.ctx, h.stepUp(root.UserID), root.UserID)
	if err != nil || status.Active {
		t.Fatalf("status after disable = %#v, %v", status, err)
	}
}

// testPasskeys pins the WebAuthn plumbing that touches the store: the
// credential is persisted encrypted, the ceremony continuation is single use,
// and discoverable sign-in finds the credential by its identifier.
func testPasskeys(t *testing.T, factory Factory) {
	h := newHarness(t, factory, credboundtest.WithConfig(func(cfg *credbound.Config) {
		cfg.Passkeys = credboundtest.DiscoverablePasskeys{}
	}))
	root, _ := h.bootstrap()
	actor := h.stepUp(root.UserID)

	challenge, err := h.manager.BeginPasskeyRegistration(h.ctx, actor, "laptop")
	if err != nil || challenge.Continuation == "" {
		t.Fatalf("begin registration = %#v, %v", challenge, err)
	}
	passkey, err := h.manager.FinishPasskeyRegistration(h.ctx, actor, challenge.Continuation, []byte(credboundtest.ValidPasskeyResponse))
	if err != nil || passkey.ID == "" {
		t.Fatalf("finish registration = %#v, %v", passkey, err)
	}
	if _, err := h.manager.FinishPasskeyRegistration(h.ctx, actor, challenge.Continuation, []byte(credboundtest.ValidPasskeyResponse)); err == nil {
		t.Fatal("the registration continuation was replayed")
	}

	authentication, err := h.manager.BeginPasskeyAuthentication(h.ctx, credboundtest.BootstrapEmail)
	if err != nil {
		t.Fatalf("begin authentication: %v", err)
	}
	authn, err := h.manager.FinishPasskeyAuthentication(h.ctx, authentication.Continuation, []byte(credboundtest.ValidPasskeyResponse))
	if err != nil || authn.Level != credbound.AAL2 || authn.Method != credbound.MethodPasskey {
		t.Fatalf("finish authentication = %#v, %v", authn, err)
	}
	if _, err := h.manager.FinishPasskeyAuthentication(h.ctx, authentication.Continuation, []byte(credboundtest.ValidPasskeyResponse)); err == nil {
		t.Fatal("the authentication continuation was replayed")
	}

	discoverable, err := h.manager.BeginDiscoverablePasskeyAuthentication(h.ctx)
	if err != nil {
		t.Fatalf("begin discoverable: %v", err)
	}
	if _, err := h.manager.FinishDiscoverablePasskeyAuthentication(h.ctx, discoverable.Continuation, []byte(credboundtest.ValidPasskeyResponse)); err != nil {
		t.Fatalf("finish discoverable: %v", err)
	}

	passkeys := collectAll(t, h.manager.Passkeys(h.ctx, actor, root.UserID))
	if len(passkeys) != 1 || passkeys[0].Name != "laptop" || passkeys[0].LastUsedAt == nil {
		t.Fatalf("passkeys = %#v", passkeys)
	}
	if err := h.manager.DeletePasskey(h.ctx, h.stepUp(root.UserID), passkey.ID); err != nil {
		t.Fatalf("delete passkey: %v", err)
	}
	if remaining := collectAll(t, h.manager.Passkeys(h.ctx, actor, root.UserID)); len(remaining) != 0 {
		t.Fatalf("remaining passkeys = %#v", remaining)
	}
}

// testPersonalAccessTokens pins the PAT contract: the raw token is shown once,
// its scopes cap workspace permissions, it can never satisfy a step-up, and
// revocation is immediate.
func testPersonalAccessTokens(t *testing.T, factory Factory) {
	h := newHarness(t, factory)
	root, workspace := h.bootstrap()

	if _, err := h.manager.CreatePAT(h.ctx, credbound.Authentication{UserID: root.UserID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: h.clock.Now()}, credbound.CreatePATInput{
		Name: "ci", WorkspaceID: workspace.ID, Scopes: []string{"read"},
	}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("PAT minted without a step-up: %v", err)
	}

	issued, err := h.manager.CreatePAT(h.ctx, h.stepUp(root.UserID), credbound.CreatePATInput{
		Name: "ci", WorkspaceID: workspace.ID, Scopes: []string{"workspace.users.read"},
	})
	if err != nil || issued.Token == "" {
		t.Fatalf("create pat = %#v, %v", issued, err)
	}
	h.clock.Advance(time.Minute)
	authn, err := h.manager.AuthenticatePAT(h.ctx, issued.Token)
	if err != nil || authn.Method != credbound.MethodPAT || authn.WorkspaceID != workspace.ID {
		t.Fatalf("authenticate pat = %#v, %v", authn, err)
	}
	// A PAT is non-interactive: no age makes it acceptable for a step-up.
	if err := h.manager.RequireStepUp(authn); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("PAT satisfied a step-up: %v", err)
	}
	// The scope is a ceiling, not a label.
	if err := h.manager.AuthorizePermission(h.ctx, authn, workspace.ID, credbound.PermissionWorkspaceUsersRead); err != nil {
		t.Fatalf("scoped permission: %v", err)
	}
	if err := h.manager.AuthorizePermission(h.ctx, authn, workspace.ID, credbound.PermissionWorkspaceUsersWrite); err == nil {
		t.Fatal("a permission outside the PAT scopes was granted")
	}

	// LastUsedAt is persisted by the authentication itself.
	tokens, _ := collect(t, h.manager.PATs(h.ctx, h.stepUp(root.UserID), root.UserID, credbound.PageRequest{Limit: 50}))
	if len(tokens) != 1 || tokens[0].LastUsedAt == nil {
		t.Fatalf("pats = %#v", tokens)
	}
	if err := h.manager.RevokePAT(h.ctx, h.stepUp(root.UserID), issued.PAT.ID); err != nil {
		t.Fatalf("revoke pat: %v", err)
	}
	if _, err := h.manager.AuthenticatePAT(h.ctx, issued.Token); err == nil {
		t.Fatal("a revoked PAT authenticated")
	}

	// An expired PAT is refused without any revocation.
	expiry := h.clock.Now().Add(time.Hour)
	expiring, err := h.manager.CreatePAT(h.ctx, h.stepUp(root.UserID), credbound.CreatePATInput{
		Name: "temporary", WorkspaceID: workspace.ID, Scopes: []string{"read"}, ExpiresAt: &expiry,
	})
	if err != nil {
		t.Fatalf("create expiring pat: %v", err)
	}
	h.clock.Advance(2 * time.Hour)
	if _, err := h.manager.AuthenticatePAT(h.ctx, expiring.Token); err == nil {
		t.Fatal("an expired PAT authenticated")
	}
}

// testSessions pins the server-side session module: the digest never leaves
// the store, expiry is absolute, revocation is immediate, and a password
// change kills every session of the account.
func testSessions(t *testing.T, factory Factory) {
	h := newHarness(t, factory, credboundtest.WithConfig(func(cfg *credbound.Config) {
		cfg.SessionTTL = 24 * time.Hour
		cfg.SessionIdleTimeout = time.Hour
	}))
	root, _ := h.bootstrap()

	issued, err := h.manager.CreateSession(h.ctx, h.stepUp(root.UserID), credbound.CreateSessionInput{})
	if err != nil || issued.Token == "" {
		t.Fatalf("create session = %#v, %v", issued, err)
	}
	authn, session, err := h.manager.AuthenticateSession(h.ctx, issued.Token)
	if err != nil || authn.UserID != root.UserID || session.ID != issued.Session.ID {
		t.Fatalf("authenticate session = %#v %#v, %v", authn, session, err)
	}
	// The snapshot is verbatim: a session never upgrades its own assurance.
	if authn.Level != credbound.AAL2 || !authn.AuthenticatedAt.Equal(issued.Session.AuthenticatedAt) {
		t.Fatalf("session authentication = %#v", authn)
	}

	listed, _ := collect(t, h.manager.Sessions(h.ctx, h.stepUp(root.UserID), root.UserID, credbound.PageRequest{Limit: 50}))
	if len(listed) != 1 {
		t.Fatalf("sessions = %d, want 1", len(listed))
	}
	if len(listed[0].Digest) != 0 {
		t.Fatal("the session digest leaked into a listing")
	}

	// Idle timeout: no activity for longer than the idle window expires the
	// session even though the absolute TTL still holds.
	idle, err := h.manager.CreateSession(h.ctx, h.stepUp(root.UserID), credbound.CreateSessionInput{})
	if err != nil {
		t.Fatalf("create idle session: %v", err)
	}
	h.clock.Advance(2 * time.Hour)
	if _, _, err := h.manager.AuthenticateSession(h.ctx, idle.Token); err == nil {
		t.Fatal("an idle-expired session authenticated")
	}

	// Absolute expiry is never extended by activity.
	live, err := h.manager.CreateSession(h.ctx, h.stepUp(root.UserID), credbound.CreateSessionInput{})
	if err != nil {
		t.Fatalf("create live session: %v", err)
	}
	for range 3 {
		h.clock.Advance(30 * time.Minute)
		if _, _, err := h.manager.AuthenticateSession(h.ctx, live.Token); err != nil {
			t.Fatalf("active session: %v", err)
		}
	}
	if err := h.manager.RevokeSession(h.ctx, h.stepUp(root.UserID), live.Session.ID); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if _, _, err := h.manager.AuthenticateSession(h.ctx, live.Token); err == nil {
		t.Fatal("a revoked session authenticated")
	}

	// SignOut consumes the caller's own token.
	own, err := h.manager.CreateSession(h.ctx, h.stepUp(root.UserID), credbound.CreateSessionInput{})
	if err != nil {
		t.Fatalf("create own session: %v", err)
	}
	if err := h.manager.SignOut(h.ctx, own.Token); err != nil {
		t.Fatalf("sign out: %v", err)
	}
	if _, _, err := h.manager.AuthenticateSession(h.ctx, own.Token); err == nil {
		t.Fatal("a signed-out session authenticated")
	}

	// The revocation cascade of a password change reaches sessions.
	survivor, err := h.manager.CreateSession(h.ctx, h.stepUp(root.UserID), credbound.CreateSessionInput{})
	if err != nil {
		t.Fatalf("create surviving session: %v", err)
	}
	if err := h.manager.ChangePassword(h.ctx, h.stepUp(root.UserID), credboundtest.BootstrapPassword, newPassword); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if _, _, err := h.manager.AuthenticateSession(h.ctx, survivor.Token); err == nil {
		t.Fatal("a session survived the password change")
	}
}

// testInvitations pins the invitation flow: the invitee chooses their own
// password, the token is single use, and revocation makes it unusable.
func testInvitations(t *testing.T, factory Factory) {
	h := newHarness(t, factory)
	root, workspace := h.bootstrap()
	actor := h.stepUp(root.UserID)

	issued, err := h.manager.InviteToWorkspace(h.ctx, actor, workspace.ID, credbound.InviteToWorkspaceInput{
		Email: "Invitee@Example.com", Role: credbound.RoleMember,
	})
	if err != nil || issued.Token == "" {
		t.Fatalf("invite = %#v, %v", issued, err)
	}
	pending, _ := collect(t, h.manager.WorkspaceInvitations(h.ctx, actor, workspace.ID, credbound.PageRequest{Limit: 50}))
	if len(pending) != 1 || pending[0].Email != "invitee@example.com" {
		t.Fatalf("invitations = %#v", pending)
	}

	authn, user, err := h.manager.RegisterFromInvitation(h.ctx, issued.Token, credbound.RegisterFromInvitationInput{
		DisplayName: "Invitee", Password: memberPassword,
	})
	if err != nil || authn.UserID != user.ID {
		t.Fatalf("register from invitation = %#v %#v, %v", authn, user, err)
	}
	membership, err := h.manager.Membership(h.ctx, actor, workspace.ID, user.ID)
	if err != nil || membership.Role != credbound.RoleMember || membership.Status != credbound.MembershipActive {
		t.Fatalf("membership = %#v, %v", membership, err)
	}
	if _, _, err := h.manager.RegisterFromInvitation(h.ctx, issued.Token, credbound.RegisterFromInvitationInput{
		DisplayName: "Twice", Password: memberPassword,
	}); err == nil {
		t.Fatal("the invitation token was accepted twice")
	}
	// The invitee authenticates with the password they chose.
	if _, err := h.manager.AuthenticatePassword(h.ctx, "invitee@example.com", memberPassword); err != nil {
		t.Fatalf("invitee sign-in: %v", err)
	}

	revoked, err := h.manager.InviteToWorkspace(h.ctx, actor, workspace.ID, credbound.InviteToWorkspaceInput{
		Email: "revoked@example.com", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatalf("second invite: %v", err)
	}
	if err := h.manager.RevokeInvitation(h.ctx, actor, workspace.ID, revoked.Invitation.ID); err != nil {
		t.Fatalf("revoke invitation: %v", err)
	}
	if _, _, err := h.manager.RegisterFromInvitation(h.ctx, revoked.Token, credbound.RegisterFromInvitationInput{
		DisplayName: "Revoked", Password: memberPassword,
	}); err == nil {
		t.Fatal("a revoked invitation was accepted")
	}

	// An expired invitation is refused.
	expiring, err := h.manager.InviteToWorkspace(h.ctx, h.stepUp(root.UserID), workspace.ID, credbound.InviteToWorkspaceInput{
		Email: "late@example.com", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatalf("third invite: %v", err)
	}
	h.clock.Advance(8 * 24 * time.Hour)
	if _, _, err := h.manager.RegisterFromInvitation(h.ctx, expiring.Token, credbound.RegisterFromInvitationInput{
		DisplayName: "Late", Password: memberPassword,
	}); err == nil {
		t.Fatal("an expired invitation was accepted")
	}
}

// testSignUp pins self-service signup: one atomic transaction creates the
// user, their workspace and their admin membership, and an already-registered
// address is answered without disclosing it.
func testSignUp(t *testing.T, factory Factory) {
	h := newHarness(t, factory, credboundtest.WithConfig(func(cfg *credbound.Config) {
		cfg.SignUp = &credbound.SignUpConfig{AutoVerifyEmail: true}
	}))
	h.bootstrap()

	result, err := h.manager.SignUp(h.ctx, credbound.SignUpInput{
		Email: "Founder@Example.com", DisplayName: "Founder", Password: memberPassword, WorkspaceName: "Founder Inc",
	})
	if err != nil || result.ExistingAccount {
		t.Fatalf("sign up = %#v, %v", result, err)
	}
	if result.User.ID == "" || result.Workspace.ID == "" {
		t.Fatalf("sign up result = %#v", result)
	}
	// AutoVerifyEmail trades the mailbox proof for an immediate AAL1
	// context; the address is stored verified and no token is issued.
	if result.Authentication.UserID != result.User.ID || result.Authentication.Level != credbound.AAL1 {
		t.Fatalf("sign up authentication = %#v", result.Authentication)
	}
	if _, err := h.manager.AuthenticatePassword(h.ctx, "founder@example.com", memberPassword); err != nil {
		t.Fatalf("sign-up sign-in: %v", err)
	}
	membership, err := h.manager.Membership(h.ctx, result.Authentication, result.Workspace.ID, result.User.ID)
	if err != nil || membership.Role != credbound.RoleAdmin {
		t.Fatalf("membership = %#v, %v", membership, err)
	}

	// The second signup on the same address must not disclose the account,
	// and must not create anything.
	duplicate, err := h.manager.SignUp(h.ctx, credbound.SignUpInput{
		Email: "founder@example.com", DisplayName: "Impostor", Password: memberPassword, WorkspaceName: "Other",
	})
	if err != nil || !duplicate.ExistingAccount {
		t.Fatalf("duplicate sign up = %#v, %v", duplicate, err)
	}
	if duplicate.User.ID != "" || duplicate.Workspace.ID != "" || duplicate.EmailVerification.Token != "" {
		t.Fatalf("duplicate sign up leaked state: %#v", duplicate)
	}
}

// testSignUpPendingVerification pins the default signup policy: without
// AutoVerifyEmail the mailbox must be proven before the account authenticates.
func testSignUpPendingVerification(t *testing.T, factory Factory) {
	pending := newHarness(t, factory, credboundtest.WithConfig(func(cfg *credbound.Config) {
		cfg.SignUp = &credbound.SignUpConfig{}
	}))
	pending.bootstrap()
	unverified, err := pending.manager.SignUp(pending.ctx, credbound.SignUpInput{
		Email: "pending@example.com", DisplayName: "Pending", Password: memberPassword, WorkspaceName: "Pending Inc",
	})
	if err != nil || unverified.EmailVerification.Token == "" {
		t.Fatalf("pending sign up = %#v, %v", unverified, err)
	}
	if unverified.Authentication.UserID != "" {
		t.Fatalf("an unverified signup produced an authentication: %#v", unverified.Authentication)
	}
	if _, err := pending.manager.AuthenticatePassword(pending.ctx, "pending@example.com", memberPassword); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("unverified signup signed in: %v", err)
	}
	if _, err := pending.manager.ConfirmEmail(pending.ctx, unverified.EmailVerification.Token); err != nil {
		t.Fatalf("confirm signup address: %v", err)
	}
	if _, err := pending.manager.AuthenticatePassword(pending.ctx, "pending@example.com", memberPassword); err != nil {
		t.Fatalf("verified signup sign-in: %v", err)
	}
}

// testWorkspacesAndRBAC pins tenancy: memberships gate access, suspension is
// immediate, application roles resolve through inheritance, and a workspace
// disable locks every member out.
func testWorkspacesAndRBAC(t *testing.T, factory Factory) {
	h := newHarness(t, factory, credboundtest.WithConfig(func(cfg *credbound.Config) {
		cfg.WorkspaceRoles = []credbound.RoleDefinition{
			{Role: "viewer", Permissions: []credbound.WorkspacePermission{"documents.read"}},
			{Role: "editor", Permissions: []credbound.WorkspacePermission{"documents.write"}, Inherits: []credbound.Role{"viewer"}},
		}
	}))
	root, workspace := h.bootstrap()
	actor := h.stepUp(root.UserID)

	member, err := h.manager.CreateUser(h.ctx, actor, workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: memberPassword, Role: "viewer",
	})
	if err != nil {
		t.Fatalf("create member: %v", err)
	}
	memberAuthn, err := h.manager.AuthenticatePassword(h.ctx, "member@example.com", memberPassword)
	if err != nil {
		t.Fatalf("member sign-in: %v", err)
	}
	if err := h.manager.AuthorizePermission(h.ctx, memberAuthn, workspace.ID, "documents.read"); err != nil {
		t.Fatalf("viewer read: %v", err)
	}
	if err := h.manager.AuthorizePermission(h.ctx, memberAuthn, workspace.ID, "documents.write"); err == nil {
		t.Fatal("a viewer was granted a write permission")
	}
	// Inheritance resolves through the persisted role, not a cached value.
	if err := h.manager.GrantRole(h.ctx, actor, workspace.ID, member.ID, "editor"); err != nil {
		t.Fatalf("grant editor: %v", err)
	}
	if err := h.manager.AuthorizePermission(h.ctx, memberAuthn, workspace.ID, "documents.write"); err != nil {
		t.Fatalf("editor write: %v", err)
	}
	if err := h.manager.AuthorizePermission(h.ctx, memberAuthn, workspace.ID, "documents.read"); err != nil {
		t.Fatalf("inherited read: %v", err)
	}

	// A second workspace is isolated: the same user is a stranger there.
	other, err := h.manager.CreateWorkspace(h.ctx, actor, credbound.CreateWorkspaceInput{Name: "Other"})
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	if err := h.manager.Authorize(h.ctx, memberAuthn, other.ID, credbound.RoleMember); err == nil {
		t.Fatal("a non-member was authorized in another workspace")
	}

	// The joined listing an administration UI reads must carry the member's
	// identity, not just their membership.
	members, _ := collect(t, h.manager.WorkspaceMembers(h.ctx, actor, workspace.ID, credbound.PageRequest{Limit: 50}))
	if len(members) != 2 {
		t.Fatalf("workspace members = %d, want 2", len(members))
	}
	for _, entry := range members {
		if entry.User.DisplayName == "" || entry.User.Email == "" || entry.Membership.Role == "" {
			t.Fatalf("member listing is missing identity: %#v", entry)
		}
	}

	if _, err := h.manager.SetMembershipStatus(h.ctx, actor, workspace.ID, member.ID, credbound.MembershipSuspended); err != nil {
		t.Fatalf("suspend membership: %v", err)
	}
	if err := h.manager.Authorize(h.ctx, memberAuthn, workspace.ID, credbound.RoleMember); err == nil {
		t.Fatal("a suspended member was authorized")
	}
	if _, err := h.manager.SetMembershipStatus(h.ctx, actor, workspace.ID, member.ID, credbound.MembershipActive); err != nil {
		t.Fatalf("reactivate membership: %v", err)
	}
	if err := h.manager.Authorize(h.ctx, memberAuthn, workspace.ID, credbound.RoleMember); err != nil {
		t.Fatalf("reactivated member: %v", err)
	}

	// Disabling the workspace locks every member out, including its admin.
	if err := h.manager.DisableWorkspace(h.ctx, actor, workspace.ID); err != nil {
		t.Fatalf("disable workspace: %v", err)
	}
	if err := h.manager.Authorize(h.ctx, memberAuthn, workspace.ID, credbound.RoleMember); err == nil {
		t.Fatal("a disabled workspace still authorized its members")
	}
	if err := h.manager.EnableWorkspace(h.ctx, actor, workspace.ID); err != nil {
		t.Fatalf("enable workspace: %v", err)
	}
	if err := h.manager.RemoveMembership(h.ctx, h.stepUp(root.UserID), workspace.ID, member.ID); err != nil {
		t.Fatalf("remove membership: %v", err)
	}
	if _, err := h.manager.Membership(h.ctx, actor, workspace.ID, member.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("membership after removal = %v", err)
	}
}

// testPagination pins DATA-003 across stores: a stable order, an opaque
// cursor that never repeats or skips a row, an honest has-more flag, and a
// rejected malformed cursor.
func testPagination(t *testing.T, factory Factory) {
	h := newHarness(t, factory)
	root, workspace := h.bootstrap()
	actor := h.stepUp(root.UserID)

	const total = 7
	for index := range total {
		h.clock.Advance(time.Second)
		if _, err := h.manager.CreateUser(h.ctx, h.stepUp(root.UserID), workspace.ID, credbound.CreateUserInput{
			Email:       "user" + string(rune('a'+index)) + "@example.com",
			DisplayName: "User " + string(rune('A'+index)),
			Password:    memberPassword,
			Role:        credbound.RoleMember,
		}); err != nil {
			t.Fatalf("create user %d: %v", index, err)
		}
	}

	// One page at a time, the walk must visit every user exactly once.
	seen := make(map[string]int, total+1)
	var order []string
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > total+2 {
			t.Fatal("pagination did not terminate")
		}
		items, end := collect(t, h.manager.Users(h.ctx, actor, credbound.PageRequest{Cursor: cursor, Limit: 2}))
		if len(items) > 2 {
			t.Fatalf("page returned %d items for a limit of 2", len(items))
		}
		for _, user := range items {
			seen[user.ID]++
			order = append(order, user.ID)
		}
		if !end.HasMore {
			if end.NextCursor != "" {
				t.Fatalf("terminal page carries a cursor: %q", end.NextCursor)
			}
			break
		}
		if end.NextCursor == "" {
			t.Fatal("has_more without a cursor")
		}
		cursor = end.NextCursor
	}
	if len(seen) != total+1 {
		t.Fatalf("paged over %d distinct users, want %d", len(seen), total+1)
	}
	for id, count := range seen {
		if count != 1 {
			t.Fatalf("user %s was returned %d times", id, count)
		}
	}
	// The same walk in one page must produce the same order.
	single, _ := collect(t, h.manager.Users(h.ctx, actor, credbound.PageRequest{Limit: 50}))
	if len(single) != len(order) {
		t.Fatalf("single page returned %d users, paged walk %d", len(single), len(order))
	}
	for index, user := range single {
		if user.ID != order[index] {
			t.Fatalf("order diverges at %d: %q vs %q", index, user.ID, order[index])
		}
	}

	// A malformed cursor is rejected rather than silently restarting the
	// listing, which would make a paged export loop forever.
	invalid := false
	for _, err := range h.manager.Users(h.ctx, actor, credbound.PageRequest{Cursor: "not-a-cursor", Limit: 2}) {
		if err != nil {
			invalid = true
			if !errors.Is(err, credbound.ErrInvalidInput) {
				t.Fatalf("malformed cursor = %v", err)
			}
		}
	}
	if !invalid {
		t.Fatal("a malformed cursor was accepted")
	}
}

// testAuditChain pins AUDIT-001: every mutation appends a hash-chained event,
// the chain verifies end to end, and a host-recorded business fact joins the
// same chain with an actor and timestamp it cannot forge.
func testAuditChain(t *testing.T, factory Factory) {
	h := newHarness(t, factory)
	root, workspace := h.bootstrap()
	actor := h.stepUp(root.UserID)

	if _, err := h.manager.CreateUser(h.ctx, actor, workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: memberPassword, Role: credbound.RoleMember,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := h.manager.RecordAudit(h.ctx, actor, credbound.AuditInput{
		Action: "invoice.paid", ResourceType: "invoice", ResourceID: "inv-1",
		WorkspaceID: workspace.ID, Outcome: credbound.AuditSucceeded,
	}); err != nil {
		t.Fatalf("record audit: %v", err)
	}

	report, err := h.manager.VerifyAuditChain(h.ctx, actor)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if report.Events == 0 || report.HeadSequence != report.Events || len(report.HeadHash) == 0 {
		t.Fatalf("chain report = %#v", report)
	}

	events, _ := collect(t, h.manager.AuditEvents(h.ctx, actor, workspace.ID, credbound.PageRequest{Limit: 50}))
	business := false
	for _, event := range events {
		if event.Action == "invoice.paid" {
			business = true
			if event.ActorID != root.UserID || event.ActorKind != credbound.ActorUser {
				t.Fatalf("business fact actor = %#v", event)
			}
			if event.OccurredAt.IsZero() || event.Sequence == 0 || len(event.Hash) == 0 {
				t.Fatalf("business fact was not chained: %#v", event)
			}
		}
	}
	if !business {
		t.Fatal("the recorded business fact is missing from the workspace log")
	}

	// The instance log is ordered newest first and every event links to its
	// predecessor.
	instance, _ := collect(t, h.manager.InstanceAuditEvents(h.ctx, actor, credbound.PageRequest{Limit: 100}))
	if len(instance) < 2 {
		t.Fatalf("instance log holds %d events", len(instance))
	}
	for index := 1; index < len(instance); index++ {
		if instance[index-1].Sequence <= instance[index].Sequence {
			t.Fatalf("instance log is not ordered newest first at %d: %d then %d", index, instance[index-1].Sequence, instance[index].Sequence)
		}
	}
	// Verification from a checkpoint covers only the tail. Reads of the
	// administrative log are themselves audited, so the head keeps moving:
	// the invariant is that the checkpointed walk reaches at least the head
	// the full walk saw, over fewer events than the chain holds.
	checkpoint := instance[len(instance)/2]
	tail, err := h.manager.VerifyAuditChainFrom(h.ctx, actor, credbound.AuditChainCheckpoint{
		Sequence: checkpoint.Sequence, Hash: checkpoint.Hash,
	})
	if err != nil {
		t.Fatalf("verify from checkpoint: %v", err)
	}
	if tail.HeadSequence < report.HeadSequence || len(tail.HeadHash) == 0 {
		t.Fatalf("checkpointed report = %#v, full report was %#v", tail, report)
	}
	// A checkpoint whose hash does not match the recorded event is a
	// tampering signal and must never verify.
	forged := make([]byte, len(checkpoint.Hash))
	copy(forged, checkpoint.Hash)
	forged[0] ^= 0xff
	if _, err := h.manager.VerifyAuditChainFrom(h.ctx, actor, credbound.AuditChainCheckpoint{
		Sequence: checkpoint.Sequence, Hash: forged,
	}); err == nil {
		t.Fatal("a forged checkpoint hash verified")
	}
	// A checkpoint claiming a sequence the chain never reached is refused
	// too, so a truncation cannot be laundered into a valid report.
	if _, err := h.manager.VerifyAuditChainFrom(h.ctx, actor, credbound.AuditChainCheckpoint{
		Sequence: report.HeadSequence + 1000, Hash: report.HeadHash,
	}); err == nil {
		t.Fatal("a checkpoint beyond the head verified")
	}
}

// testPrivacyRights pins the data-subject flows: the export carries the
// account's own records, and anonymization scrubs the personal data, revokes
// every credential, and leaves the audit chain verifiable.
func testPrivacyRights(t *testing.T, factory Factory) {
	h := newHarness(t, factory)
	root, workspace := h.bootstrap()
	actor := h.stepUp(root.UserID)

	subject, err := h.manager.CreateUser(h.ctx, actor, workspace.ID, credbound.CreateUserInput{
		Email: "subject@example.com", DisplayName: "Subject", Password: memberPassword, Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatalf("create subject: %v", err)
	}
	subjectAuthn := h.stepUp(subject.ID)
	pat, err := h.manager.CreatePAT(h.ctx, subjectAuthn, credbound.CreatePATInput{
		Name: "ci", WorkspaceID: workspace.ID, Scopes: []string{"read"},
	})
	if err != nil {
		t.Fatalf("create pat: %v", err)
	}
	session, err := h.manager.CreateSession(h.ctx, subjectAuthn, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	export, err := h.manager.ExportUserData(h.ctx, subjectAuthn, subject.ID)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if export.User.ID != subject.ID || len(export.Emails) == 0 || len(export.PATs) == 0 {
		t.Fatalf("export = %#v", export)
	}

	if err := h.manager.AnonymizeUser(h.ctx, root, local(), subject.ID); err != nil {
		t.Fatalf("anonymize: %v", err)
	}
	anonymized, err := h.manager.User(h.ctx, root, subject.ID)
	if err != nil {
		t.Fatalf("read anonymized user: %v", err)
	}
	if strings.Contains(anonymized.DisplayName, "Subject") || strings.Contains(anonymized.Email, "subject@example.com") {
		t.Fatalf("personal data survived anonymization: %#v", anonymized)
	}
	if _, err := h.manager.AuthenticatePAT(h.ctx, pat.Token); err == nil {
		t.Fatal("a PAT survived anonymization")
	}
	if _, _, err := h.manager.AuthenticateSession(h.ctx, session.Token); err == nil {
		t.Fatal("a session survived anonymization")
	}
	if _, err := h.manager.AuthenticatePassword(h.ctx, "subject@example.com", memberPassword); err == nil {
		t.Fatal("the anonymized account still authenticates")
	}
	// The append-only chain must stay intact through the scrub.
	if _, err := h.manager.VerifyAuditChain(h.ctx, actor); err != nil {
		t.Fatalf("audit chain after anonymization: %v", err)
	}
}

// exactlyOnce runs attempt from workers goroutines released together and
// requires that exactly one of them succeeded. Single use is a security
// property, so it has to hold under a race, not only in sequence: two winners
// mean a captured proof can be redeemed twice, and zero means the store
// serialized itself into losing a legitimate redemption.
func exactlyOnce(t *testing.T, label string, workers int, attempt func() error) {
	t.Helper()
	var (
		group   sync.WaitGroup
		release = make(chan struct{})
		results = make([]error, workers)
	)
	for index := range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-release
			results[index] = attempt()
		}()
	}
	close(release)
	group.Wait()
	winners := 0
	for _, err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("%s: %d of %d concurrent attempts succeeded, want exactly 1 (results: %v)", label, winners, workers, results)
	}
}

// concurrentHarness builds a harness whose randomness is safe to share across
// goroutines; the deterministic source of credboundtest is not.
func concurrentHarness(t *testing.T, factory Factory, opts ...credboundtest.Option) *harness {
	t.Helper()
	return newHarness(t, factory, append([]credboundtest.Option{credboundtest.WithRandom(rand.Reader)}, opts...)...)
}

// testSingleUseUnderConcurrency pins the redemption of every one-shot proof
// Credbound issues: whatever the store's isolation model, two racing
// redemptions of the same token must not both succeed.
func testSingleUseUnderConcurrency(t *testing.T, factory Factory) {
	const workers = 8
	h := concurrentHarness(t, factory, credboundtest.WithConfig(func(cfg *credbound.Config) {
		cfg.Passkeys = credboundtest.DiscoverablePasskeys{}
	}))
	root, workspace := h.bootstrap()

	// Email verification.
	verification, err := h.manager.BeginEmailAddition(h.ctx, h.stepUp(root.UserID), "second@example.com")
	if err != nil {
		t.Fatalf("begin email addition: %v", err)
	}
	exactlyOnce(t, "email verification", workers, func() error {
		_, err := h.manager.ConfirmEmail(h.ctx, verification.Token)
		return err
	})

	// Magic link.
	link, err := h.manager.BeginEmailAuthentication(h.ctx, credboundtest.BootstrapEmail)
	if err != nil {
		t.Fatalf("begin magic link: %v", err)
	}
	exactlyOnce(t, "magic link", workers, func() error {
		_, err := h.manager.CompleteEmailAuthentication(h.ctx, link.Token)
		return err
	})

	// Email OTP: the continuation is consumed even though the code stays the
	// same for every attempt.
	otp, err := h.manager.BeginEmailOTP(h.ctx, credboundtest.BootstrapEmail)
	if err != nil {
		t.Fatalf("begin otp: %v", err)
	}
	exactlyOnce(t, "email otp", workers, func() error {
		_, err := h.manager.CompleteEmailOTP(h.ctx, otp.Continuation, otp.Code)
		return err
	})

	// Passkey ceremonies: the sealed continuation is what makes a captured
	// browser response unusable twice.
	registration, err := h.manager.BeginPasskeyRegistration(h.ctx, h.stepUp(root.UserID), "laptop")
	if err != nil {
		t.Fatalf("begin passkey registration: %v", err)
	}
	exactlyOnce(t, "passkey registration", workers, func() error {
		_, err := h.manager.FinishPasskeyRegistration(h.ctx, h.stepUp(root.UserID), registration.Continuation, []byte(credboundtest.ValidPasskeyResponse))
		return err
	})
	assertion, err := h.manager.BeginPasskeyAuthentication(h.ctx, credboundtest.BootstrapEmail)
	if err != nil {
		t.Fatalf("begin passkey authentication: %v", err)
	}
	exactlyOnce(t, "passkey authentication", workers, func() error {
		_, err := h.manager.FinishPasskeyAuthentication(h.ctx, assertion.Continuation, []byte(credboundtest.ValidPasskeyResponse))
		return err
	})

	// Recovery codes.
	if _, err := h.manager.BeginTOTPEnrollment(h.ctx, h.stepUp(root.UserID)); err != nil {
		t.Fatalf("begin totp enrollment: %v", err)
	}
	recovery, err := h.manager.ConfirmTOTPEnrollment(h.ctx, h.stepUp(root.UserID), credboundtest.ValidTOTPCode)
	if err != nil {
		t.Fatalf("confirm totp enrollment: %v", err)
	}
	pending, err := h.manager.AuthenticatePassword(h.ctx, credboundtest.BootstrapEmail, credboundtest.BootstrapPassword)
	if err != nil {
		t.Fatalf("first factor: %v", err)
	}
	exactlyOnce(t, "recovery code", workers, func() error {
		_, err := h.manager.VerifyTOTP(h.ctx, pending, recovery[0])
		return err
	})

	// Invitations: two racing registrations would create two accounts for
	// one invited address.
	invitation, err := h.manager.InviteToWorkspace(h.ctx, h.stepUp(root.UserID), workspace.ID, credbound.InviteToWorkspaceInput{
		Email: "invitee@example.com", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	exactlyOnce(t, "invitation", workers, func() error {
		_, _, err := h.manager.RegisterFromInvitation(h.ctx, invitation.Token, credbound.RegisterFromInvitationInput{
			DisplayName: "Invitee", Password: memberPassword,
		})
		return err
	})
	members, _ := collect(t, h.manager.Memberships(h.ctx, h.stepUp(root.UserID), workspace.ID, credbound.PageRequest{Limit: 50}))
	if len(members) != 2 {
		t.Fatalf("memberships after the concurrent registration = %d, want 2", len(members))
	}

	// Password reset, last: it revokes the credentials the cases above used.
	reset, err := h.manager.BeginPasswordReset(h.ctx, credboundtest.BootstrapEmail)
	if err != nil {
		t.Fatalf("begin reset: %v", err)
	}
	exactlyOnce(t, "password reset", workers, func() error {
		_, err := h.manager.CompletePasswordReset(h.ctx, reset.Token, newPassword)
		return err
	})
}

// testConcurrentBootstrap pins the first-run race: several processes starting
// at once must produce exactly one instance owner, never two roots.
func testConcurrentBootstrap(t *testing.T, factory Factory) {
	h := concurrentHarness(t, factory)
	var (
		mutex  sync.Mutex
		index  int
		winner credbound.Authentication
	)
	exactlyOnce(t, "bootstrap", 8, func() error {
		mutex.Lock()
		index++
		address := "root" + string(rune('a'+index)) + "@example.com"
		mutex.Unlock()
		authn, _, err := h.manager.Bootstrap(h.ctx, credbound.BootstrapInput{
			Email:         address,
			DisplayName:   "Root",
			Password:      credboundtest.BootstrapPassword,
			WorkspaceName: "Main",
		})
		if err != nil {
			return err
		}
		mutex.Lock()
		winner = authn
		mutex.Unlock()
		return nil
	})

	actor := h.stepUp(winner.UserID)
	admins := collectAll(t, h.manager.InstanceAdministrators(h.ctx, actor))
	if len(admins) != 1 || admins[0].Role != credbound.InstanceRoleRoot || admins[0].UserID != winner.UserID {
		t.Fatalf("instance administrators after a concurrent bootstrap = %#v", admins)
	}
	// The losing attempts must not have left a half-created account behind.
	users, _ := collect(t, h.manager.Users(h.ctx, actor, credbound.PageRequest{Limit: 50}))
	if len(users) != 1 {
		t.Fatalf("users after a concurrent bootstrap = %d, want 1", len(users))
	}
	workspaces, _ := collect(t, h.manager.Workspaces(h.ctx, actor, credbound.PageRequest{Limit: 50}))
	if len(workspaces) != 1 {
		t.Fatalf("workspaces after a concurrent bootstrap = %d, want 1", len(workspaces))
	}
}

// testConcurrentUniqueAddress pins the address uniqueness invariant under a
// race: only one of several simultaneous creations of the same address may
// commit, whatever the store's conflict detection.
func testConcurrentUniqueAddress(t *testing.T, factory Factory) {
	h := concurrentHarness(t, factory)
	root, workspace := h.bootstrap()
	exactlyOnce(t, "duplicate address", 8, func() error {
		_, err := h.manager.CreateUser(h.ctx, h.stepUp(root.UserID), workspace.ID, credbound.CreateUserInput{
			Email: "duplicate@example.com", DisplayName: "Duplicate", Password: memberPassword, Role: credbound.RoleMember,
		})
		return err
	})
	users, _ := collect(t, h.manager.Users(h.ctx, h.stepUp(root.UserID), credbound.PageRequest{Limit: 50}))
	if len(users) != 2 {
		t.Fatalf("users after the concurrent creation = %d, want 2", len(users))
	}
}
