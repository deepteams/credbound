package credbound_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
)

var uuidV7 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type fixture struct {
	manager   *credbound.Manager
	store     *memory.Store
	now       time.Time
	passwords *fakePasswords
	passkeys  *fakePasskeys
}

func newFixture(t *testing.T, ssoProviders ...credbound.SSOProvider) *fixture {
	t.Helper()
	f := &fixture{
		store: memory.New(), now: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
		passwords: &fakePasswords{}, passkeys: &fakePasskeys{},
	}
	// SSO grants AAL2 only for providers the host trusts through an assurance
	// policy; the fixture trusts every provider it registers so link/JIT/
	// step-up paths keep exercising AAL2. TestSSOAAL1WithoutAssurance covers
	// the fail-safe default separately.
	assurance := make(map[credbound.UUID]credbound.SSOAssurancePolicy, len(ssoProviders))
	for _, provider := range ssoProviders {
		assurance[provider.ConfigurationID()] = credbound.SSOAssurancePolicy{TrustUnverified: true}
	}
	manager, err := credbound.New(credbound.Config{
		Store: f.store, Passwords: f.passwords, TOTP: fakeTOTP{}, Passkeys: f.passkeys,
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return f.now }, Random: &counterReader{next: 0x42},
		StepUpMaxAge: 10 * time.Minute, CeremonyTTL: 5 * time.Minute,
		SSOProviders: ssoProviders,
		SSOAssurance: assurance,
		// Domain confirmations in tests assert verification out of band;
		// TestConfirmWorkspaceDomainVerifier covers the DNS-verifier path.
		TrustActorDomainVerification: true,
		TransactionHooks:             []credbound.TransactionHook{credbound.UnimplementedTransactionHook{}},
		EventListeners:               []credbound.EventListener{credbound.UnimplementedEventListener{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.manager = manager
	return f
}

func (f *fixture) bootstrap(t *testing.T) (credbound.Authentication, credbound.Workspace) {
	t.Helper()
	authn, workspace, err := f.manager.Bootstrap(context.Background(), credbound.BootstrapInput{
		Email: " ROOT@Example.com ", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	return authn, workspace
}

// TestBootstrapPasswordAndUUIDv7 pins the local-account contract — a
// normalized address and password authenticate the active user, while an
// unknown address and a wrong password answer with the same public error
// (AUTH-001) — and that the identifiers Credbound mints are canonical UUIDv7
// values that stay monotonic within the process (ID-001).
func TestBootstrapPasswordAndUUIDv7(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	if !uuidV7.MatchString(authn.UserID.String()) || !uuidV7.MatchString(workspace.ID.String()) {
		t.Fatalf("non UUIDv7 ids: %q %q", authn.UserID, workspace.ID)
	}
	if authn.UserID.Compare(workspace.ID) >= 0 {
		t.Fatalf("UUIDv7 ids are not monotonic: %q >= %q", authn.UserID, workspace.ID)
	}
	// ADMIN-002: the first account created by Bootstrap receives the
	// instance-level root role.
	admin, err := f.store.InstanceAdministrator(context.Background(), authn.UserID)
	if err != nil || admin.Role != credbound.InstanceRoleRoot {
		t.Fatalf("bootstrap admin = %#v, %v", admin, err)
	}
	if _, _, err := f.manager.Bootstrap(context.Background(), credbound.BootstrapInput{
		Email: "other@example.com", DisplayName: "Other", Password: "correct horse battery", WorkspaceName: "Other",
	}); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("second bootstrap error = %v", err)
	}

	// AUTH-006: the unknown identifier and the invalid password produce the
	// same public error, and the dummy derivation (asserted via verifyCalls
	// below) keeps the cryptographic work identical.
	if _, err := f.manager.AuthenticatePassword(context.Background(), "missing@example.com", "wrong"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("unknown login error = %v", err)
	}
	if _, err := f.manager.AuthenticatePassword(context.Background(), "root@example.com", "wrong"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("bad password error = %v", err)
	}
	loggedIn, err := f.manager.AuthenticatePassword(context.Background(), "ROOT@example.com", "correct horse battery")
	if err != nil || loggedIn.UserID != authn.UserID || loggedIn.Level != credbound.AAL1 {
		t.Fatalf("login = %#v, %v", loggedIn, err)
	}
	if f.passwords.verifyCalls < 3 {
		t.Fatalf("expected dummy and real password verification, got %d", f.passwords.verifyCalls)
	}
}

// TestTOTPRecoveryAndReplayProtection pins AUTH-004: TOTP activates only
// after a valid code is confirmed, the user receives single-use recovery
// codes, and neither codes nor recovery codes can be replayed.
func TestTOTPRecoveryAndReplayProtection(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	enrollment, err := f.manager.BeginTOTPEnrollment(context.Background(), authn)
	if err != nil || !strings.HasPrefix(enrollment.URI, "otpauth://") {
		t.Fatalf("enrollment = %#v, %v", enrollment, err)
	}
	if _, err := f.manager.ConfirmTOTPEnrollment(context.Background(), authn, "000000"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("invalid confirmation error = %v", err)
	}
	codes, err := f.manager.ConfirmTOTPEnrollment(context.Background(), authn, "123456")
	if err != nil || len(codes) != 10 {
		t.Fatalf("recovery codes = %d, %v", len(codes), err)
	}
	// The enrollment code's step is now consumed: replaying it as a full second
	// factor within the same window is rejected.
	if _, err := f.manager.VerifyTOTP(context.Background(), authn, "123456"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("enrollment code replay error = %v", err)
	}
	f.now = f.now.Add(30 * time.Second)
	promoted, err := f.manager.VerifyTOTP(context.Background(), authn, "123456")
	if err != nil || promoted.Level != credbound.AAL2 || promoted.Method != credbound.MethodTOTP {
		t.Fatalf("promoted = %#v, %v", promoted, err)
	}
	if _, err := f.manager.VerifyTOTP(context.Background(), authn, "123456"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("replayed TOTP error = %v", err)
	}
	recovered, err := f.manager.VerifyTOTP(context.Background(), authn, strings.ToLower(codes[0]))
	if err != nil || recovered.Level != credbound.AAL2 {
		t.Fatalf("recovery authentication = %#v, %v", recovered, err)
	}
	if _, err := f.manager.VerifyTOTP(context.Background(), authn, codes[0]); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("replayed recovery error = %v", err)
	}
	f.now = f.now.Add(30 * time.Second)
	if err := f.manager.DisableTOTP(context.Background(), authn, "123456"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.TOTPByUserID(context.Background(), authn.UserID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("disabled factor error = %v", err)
	}
}

// TestPATLifecycleAndPagination pins the PAT lifecycle: the plaintext token
// is returned exactly once at creation and the record handed back never
// carries the digest (PAT-001, PAT-003); a user owns several named tokens
// that are revoked independently (PAT-002); and the metadata list pages
// through an opaque cursor with a stable order (DATA-003).
func TestPATLifecycleAndPagination(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	stepUp := aal2(authn.UserID, f.now)
	var tokens []credbound.IssuedPAT
	for index := range 3 {
		issued, err := f.manager.CreatePAT(context.Background(), stepUp, credbound.CreatePATInput{
			Name: fmt.Sprintf("token-%d", index), WorkspaceID: workspace.ID, Scopes: []string{"write", "read", "read"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if issued.Token == "" || issued.PAT.Digest != nil || len(issued.PAT.Scopes) != 2 {
			t.Fatalf("unsafe issued PAT: %#v", issued)
		}
		tokens = append(tokens, issued)
		f.now = f.now.Add(time.Second)
		stepUp.AuthenticatedAt = f.now
	}
	patAuth, err := f.manager.AuthenticatePAT(context.Background(), tokens[0].Token)
	if err != nil || patAuth.Method != credbound.MethodPAT || !patAuth.HasScope("read") || patAuth.HasScope("admin") {
		t.Fatalf("PAT auth = %#v, %v", patAuth, err)
	}
	if !errors.Is(f.manager.RequireStepUp(patAuth), credbound.ErrStepUpRequired) {
		t.Fatal("PAT unexpectedly satisfied step-up")
	}

	first := collectPage(t, f.manager.PATs(context.Background(), stepUp, credbound.UUID{}, credbound.PageRequest{Limit: 2}))
	if len(first.items) != 2 || first.end == nil || !first.end.HasMore || first.end.NextCursor == "" {
		t.Fatalf("first page = %#v", first)
	}
	second := collectPage(t, f.manager.PATs(context.Background(), stepUp, credbound.UUID{}, credbound.PageRequest{Limit: 2, Cursor: first.end.NextCursor}))
	if len(second.items) != 1 || second.end == nil || second.end.HasMore {
		t.Fatalf("second page = %#v", second)
	}
	if err := f.manager.RevokePAT(context.Background(), stepUp, tokens[0].PAT.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.AuthenticatePAT(context.Background(), tokens[0].Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("revoked PAT error = %v", err)
	}
}

// TestPATPrefixIsConfigurable pins Config.PATPrefix: a deployment issues PATs
// under its own marker and authenticates them, while a token carrying anyone
// else's marker — the "cbp" default included — is refused before it can reach
// a store lookup. That is what lets several deployments be told apart from a
// token's text alone.
func TestPATPrefixIsConfigurable(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	manager, err := credbound.New(credbound.Config{
		Store: store, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return now }, Random: &counterReader{next: 0x42},
		PATPrefix: "acmepat",
	})
	if err != nil {
		t.Fatal(err)
	}
	authn, _, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := manager.CreatePAT(ctx, aal2(authn.UserID, now), credbound.CreatePATInput{Name: "deploy", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(issued.Token, "acmepat_") {
		t.Fatalf("issued PAT = %q, want the configured marker", issued.Token)
	}
	if _, err := manager.AuthenticatePAT(ctx, issued.Token); err != nil {
		t.Fatalf("configured-marker PAT = %v", err)
	}
	// Only the marker differs from a token this deployment would accept, and
	// the digest covers it, so swapping it back to the default cannot pass.
	foreign := "cbp" + strings.TrimPrefix(issued.Token, "acmepat")
	if _, err := manager.AuthenticatePAT(ctx, foreign); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("default-marker PAT against a configured deployment = %v", err)
	}
}

// TestPasskeyCeremoniesEncryptStoredCredential drives the full WebAuthn
// registration and authentication ceremonies (AUTH-003) and proves the
// stored credential never rests in plaintext.
func TestPasskeyCeremoniesEncryptStoredCredential(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	challenge, err := f.manager.BeginPasskeyRegistration(context.Background(), authn, "MacBook")
	if err != nil || len(challenge.Options) == 0 || challenge.Continuation == "" {
		t.Fatalf("challenge = %#v, %v", challenge, err)
	}
	passkey, err := f.manager.FinishPasskeyRegistration(context.Background(), authn, challenge.Continuation, []byte("valid"))
	if err != nil || passkey.CredentialJSON != nil || !uuidV7.MatchString(passkey.ID.String()) {
		t.Fatalf("passkey = %#v, %v", passkey, err)
	}
	// The registration ceremony is single use: replaying the continuation
	// and captured response can never register a second credential.
	if _, err := f.manager.FinishPasskeyRegistration(context.Background(), authn, challenge.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("replayed passkey registration = %v", err)
	}
	stored := firstPasskey(t, f.store.Passkeys(context.Background(), authn.UserID))
	if string(stored.CredentialJSON) == string(f.passkeys.credentialJSON) {
		t.Fatal("WebAuthn credential was stored in plaintext")
	}
	login, err := f.manager.BeginPasskeyAuthentication(context.Background(), "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	passkeyAuth, err := f.manager.FinishPasskeyAuthentication(context.Background(), login.Continuation, []byte("valid"))
	if err != nil || passkeyAuth.Level != credbound.AAL2 || !f.passkeys.sawDecryptedCredential {
		t.Fatalf("passkey auth = %#v, %v, decrypted=%v", passkeyAuth, err, f.passkeys.sawDecryptedCredential)
	}
	// The authentication ceremony is single use: replaying the continuation
	// and captured response can never mint a second authentication, even
	// though the fake authenticator (like many real ones) would verify the
	// same response again.
	if _, err := f.manager.FinishPasskeyAuthentication(context.Background(), login.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("replayed passkey ceremony = %v", err)
	}
	if err := f.manager.DeletePasskey(context.Background(), passkeyAuth, passkey.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.FinishPasskeyAuthentication(context.Background(), login.Continuation+"x", []byte("valid")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("tampered continuation error = %v", err)
	}
}

// TestDiscoverablePasskeyAuthentication pins AUTH-018: the usernameless
// ceremony starts without any address, names no credentials in its challenge,
// resolves the account from the asserted credential, and fails closed when
// the credential resolves to no account or the provider lacks the extension.
func TestDiscoverablePasskeyAuthentication(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()
	registration, err := f.manager.BeginPasskeyRegistration(ctx, authn, "MacBook")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.FinishPasskeyRegistration(ctx, authn, registration.Continuation, []byte("valid")); err != nil {
		t.Fatal(err)
	}

	// The usernameless ceremony asks for no address, so there is no
	// per-address challenge left to probe for passkey presence or count.
	challenge, err := f.manager.BeginDiscoverablePasskeyAuthentication(ctx)
	if err != nil || len(challenge.Options) == 0 || challenge.Continuation == "" {
		t.Fatalf("discoverable challenge = %#v, %v", challenge, err)
	}
	login, err := f.manager.FinishDiscoverablePasskeyAuthentication(ctx, challenge.Continuation, []byte("valid"))
	if err != nil || login.UserID != authn.UserID || login.Level != credbound.AAL2 || login.Method != credbound.MethodPasskey {
		t.Fatalf("discoverable auth = %#v, %v", login, err)
	}
	// The ceremony is single use, exactly like the email-first flow.
	if _, err := f.manager.FinishDiscoverablePasskeyAuthentication(ctx, challenge.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("replayed discoverable ceremony = %v", err)
	}
	// An assertion whose credential resolves to no account fails closed.
	unresolved, err := f.manager.BeginDiscoverablePasskeyAuthentication(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.FinishDiscoverablePasskeyAuthentication(ctx, unresolved.Continuation, []byte("unknown")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("unresolved discoverable ceremony = %v", err)
	}
	// A continuation from the email-first flow cannot finish the
	// discoverable one and vice versa.
	emailFirst, err := f.manager.BeginPasskeyAuthentication(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.FinishDiscoverablePasskeyAuthentication(ctx, emailFirst.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("cross-flow continuation = %v", err)
	}

	// A provider without the discoverable extension reports ErrNotSupported.
	legacy, err := credbound.New(credbound.Config{
		Store: memory.New(), Passwords: &fakePasswords{}, Passkeys: legacyPasskeys{inner: &fakePasskeys{}},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.BeginDiscoverablePasskeyAuthentication(ctx); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("legacy provider begin = %v", err)
	}
	if _, err := legacy.FinishDiscoverablePasskeyAuthentication(ctx, challenge.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("legacy provider finish = %v", err)
	}
}

// TestAdministrationRolesAndAudit pins the instance-administration surface:
// instance roles are separate from workspace RBAC and out of reach of
// workspace-bound or scope-narrowed credentials (ADMIN-001), each role maps to
// explicit permissions checked through AuthorizeAdmin (ADMIN-003), and only a
// root may grant, modify, or remove an instance role (ADMIN-004).
func TestAdministrationRolesAndAudit(t *testing.T) {
	f := newFixture(t)
	root, workspace := f.bootstrap(t)
	if err := f.manager.AuthorizeAdmin(context.Background(), root, credbound.PermissionAdminAccess); err != nil {
		t.Fatal(err)
	}
	// ADMIN-005: an administrative mutation demands fresh AAL2, except for a
	// trusted local request.
	if !errors.Is(f.manager.RequireAdminMutation(root, credbound.TrustedRequest{}), credbound.ErrStepUpRequired) {
		t.Fatal("AAL1 remote admin mutation was accepted")
	}
	if err := f.manager.RequireAdminMutation(root, credbound.TrustedRequest{Local: true}); err != nil {
		t.Fatalf("trusted local mutation = %v", err)
	}
	rootAAL2 := aal2(root.UserID, f.now)
	user, err := f.manager.CreateUser(context.Background(), rootAAL2, workspace.ID, credbound.CreateUserInput{
		Email: "dev@example.com", DisplayName: "Dev", Password: "another secure password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.SetInstanceRole(context.Background(), rootAAL2, credbound.TrustedRequest{}, user.ID, credbound.InstanceRoleDeveloper); err != nil {
		t.Fatal(err)
	}
	developer := aal2(user.ID, f.now)
	if err := f.manager.AuthorizeAdmin(context.Background(), developer, credbound.PermissionSettingsWrite); err != nil {
		t.Fatalf("developer settings permission = %v", err)
	}
	if err := f.manager.AuthorizeAdmin(context.Background(), developer, credbound.PermissionInstanceRolesWrite); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("developer role-write error = %v", err)
	}
	// A scope-narrowed or workspace-bound credential can never exercise
	// instance administration, even when its owner is the root user; a
	// "*"-scoped credential is unrestricted and still passes.
	scoped := credbound.Authentication{UserID: root.UserID, Method: credbound.MethodPAT, Scopes: []string{"settings.write"}, AuthenticatedAt: f.now}
	if err := f.manager.AuthorizeAdmin(context.Background(), scoped, credbound.PermissionAdminAccess); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("scoped PAT admin access = %v", err)
	}
	bound := credbound.Authentication{UserID: root.UserID, Method: credbound.MethodPAT, WorkspaceID: workspace.ID, AuthenticatedAt: f.now}
	if err := f.manager.AuthorizeAdmin(context.Background(), bound, credbound.PermissionAdminAccess); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("workspace-bound PAT admin access = %v", err)
	}
	wildcard := credbound.Authentication{UserID: root.UserID, Method: credbound.MethodPAT, Scopes: []string{"*"}, AuthenticatedAt: f.now}
	if err := f.manager.AuthorizeAdmin(context.Background(), wildcard, credbound.PermissionAdminAccess); err != nil {
		t.Fatalf("wildcard PAT admin access = %v", err)
	}
	// ADMIN-004: a non-root instance administrator may not grant or modify an
	// instance-administration role.
	if err := f.manager.SetInstanceRole(context.Background(), developer, credbound.TrustedRequest{}, root.UserID, credbound.InstanceRoleSales); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("developer elevated role error = %v", err)
	}
	if err := f.manager.GrantRole(context.Background(), rootAAL2, workspace.ID, user.ID, credbound.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Authorize(context.Background(), developer, workspace.ID, credbound.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	events := collectAuditPage(t, f.manager.InstanceAuditEvents(context.Background(), rootAAL2, credbound.PageRequest{}))
	if len(events.items) == 0 || events.end == nil {
		t.Fatalf("instance audit page = %#v", events)
	}
	if err := f.manager.RemoveInstanceRole(context.Background(), rootAAL2, credbound.TrustedRequest{}, user.ID); err != nil {
		t.Fatal(err)
	}
}

// TestAuditFailureFailsMutationClosed pins that a sensitive mutation fails —
// and leaves nothing committed — when its audit event cannot be persisted
// atomically (AUDIT-002).
func TestAuditFailureFailsMutationClosed(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	f.store.SetAuditFailure(errors.New("disk full"))
	_, err := f.manager.CreatePAT(context.Background(), aal2(authn.UserID, f.now), credbound.CreatePATInput{
		Name: "blocked", WorkspaceID: workspace.ID, Scopes: []string{"read"},
	})
	if !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("audit failure error = %v", err)
	}
	f.store.SetAuditFailure(nil)
	page := collectPage(t, f.manager.PATs(context.Background(), authn, credbound.UUID{}, credbound.PageRequest{}))
	if len(page.items) != 0 {
		t.Fatalf("mutation committed despite audit failure: %#v", page.items)
	}
}

func TestConfigurationValidation(t *testing.T) {
	valid := credbound.Config{
		Store: memory.New(), Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
	}
	bad := valid
	bad.Store = nil
	if _, err := credbound.New(bad); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("missing dependency error = %v", err)
	}
	bad = valid
	bad.SecretKey = []byte("short")
	if _, err := credbound.New(bad); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("short key error = %v", err)
	}
	bad = valid
	bad.MinPasswordLen = 9
	if _, err := credbound.New(bad); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("weak minimum error = %v", err)
	}
	bad = valid
	bad.PATPepper = []byte("short")
	if _, err := credbound.New(bad); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("short pepper error = %v", err)
	}
	// A PAT marker is compared verbatim against the token's first segment, so
	// the underscore the parser splits on and any spelling variant are refused
	// rather than silently yielding a marker no token can ever carry.
	for _, marker := range []string{"acme_pat", "CBP", "cbp!", strings.Repeat("a", 17), " cbp"} {
		bad = valid
		bad.PATPrefix = marker
		if _, err := credbound.New(bad); !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("PAT prefix %q error = %v", marker, err)
		}
	}
	bad = valid
	bad.AdminPermissions = map[credbound.InstanceRole][]credbound.Permission{
		credbound.InstanceRoleSales: {credbound.PermissionSettingsWrite},
	}
	if _, err := credbound.New(bad); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("permission widening error = %v", err)
	}
	bad = valid
	bad.AdminPermissions = map[credbound.InstanceRole][]credbound.Permission{
		credbound.InstanceRole("unknown"): {credbound.PermissionAdminAccess},
	}
	if _, err := credbound.New(bad); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("unknown admin role error = %v", err)
	}
	brokenHasher := &fakePasswords{hashErr: errors.New("hasher offline")}
	bad = valid
	bad.Passwords = brokenHasher
	if _, err := credbound.New(bad); err == nil || !strings.Contains(err.Error(), "initialize dummy password") {
		t.Fatalf("dummy password failure = %v", err)
	}
	bad = valid
	bad.AdminPermissions = map[credbound.InstanceRole][]credbound.Permission{
		credbound.InstanceRoleSales: {credbound.PermissionAdminAccess},
	}
	if _, err := credbound.New(bad); err != nil {
		t.Fatalf("restrictive admin permission override = %v", err)
	}
	// A configured email cooldown must fail construction when the store
	// cannot back it — never degrade into a silent no-op. Embedding the store
	// behind the base interface strips the optional capabilities.
	bad = valid
	bad.Store = struct{ credbound.Store }{valid.Store}
	bad.EmailIssuanceCooldown = time.Minute
	if _, err := credbound.New(bad); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("inert email cooldown accepted = %v", err)
	}
	validProvider := &fakeSSOProvider{configurationID: credbound.MustParseUUID("0198b463-0000-7000-8000-0000000000aa"), kind: credbound.SSOProviderGoogle}
	bad = valid
	bad.SSOProviders = []credbound.SSOProvider{validProvider, validProvider}
	if _, err := credbound.New(bad); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("duplicate SSO provider = %v", err)
	}
	bad = valid
	bad.SSOProviders = []credbound.SSOProvider{&fakeSSOProvider{configurationID: credbound.MustParseUUID("0198b463-0000-4000-8000-0000000000aa"), kind: credbound.SSOProviderOIDC}}
	if _, err := credbound.New(bad); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("non UUIDv7 SSO provider = %v", err)
	}
	bad = valid
	bad.SSOProviders = []credbound.SSOProvider{&fakeSSOProvider{configurationID: credbound.MustParseUUID("0198b463-0000-7000-8000-0000000000ab"), kind: credbound.SSOProviderKind("ldap")}}
	if _, err := credbound.New(bad); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("unsupported SSO provider = %v", err)
	}
	var nilProvider *fakeSSOProvider
	bad = valid
	bad.SSOProviders = []credbound.SSOProvider{nilProvider}
	if _, err := credbound.New(bad); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("typed nil SSO provider = %v", err)
	}
}

type pageResult struct {
	items []credbound.PAT
	end   *credbound.PageEnd
}

func collectPage(t *testing.T, sequence func(func(credbound.PageEvent[credbound.PAT], error) bool)) pageResult {
	t.Helper()
	var result pageResult
	for event, err := range sequence {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			result.items = append(result.items, *event.Data)
		}
		if event.End != nil {
			result.end = event.End
		}
	}
	return result
}

type auditPageResult struct {
	items []credbound.AuditEvent
	end   *credbound.PageEnd
}

func collectAuditPage(t *testing.T, sequence func(func(credbound.PageEvent[credbound.AuditEvent], error) bool)) auditPageResult {
	t.Helper()
	var result auditPageResult
	for event, err := range sequence {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			result.items = append(result.items, *event.Data)
		}
		if event.End != nil {
			result.end = event.End
		}
	}
	return result
}

func firstPasskey(t *testing.T, sequence func(func(credbound.Passkey, error) bool)) credbound.Passkey {
	t.Helper()
	for value, err := range sequence {
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	t.Fatal("passkey not found")
	return credbound.Passkey{}
}

func aal2(userID credbound.UUID, at time.Time) credbound.Authentication {
	return credbound.Authentication{UserID: userID, Method: credbound.MethodTOTP, Level: credbound.AAL2, AuthenticatedAt: at}
}

// TestVerifyTOTPRejectsDisabledUser guards the second-factor promotion against
// an account disabled after the first factor: VerifyTOTP must not mint AAL2 for
// a disabled user.
func TestVerifyTOTPRejectsDisabledUser(t *testing.T) {
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
	if err := f.manager.DisableUser(ctx, root, credbound.TrustedRequest{Local: true}, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.VerifyTOTP(ctx, memberAuthn, "123456"); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("disabled user TOTP promotion = %v, want ErrForbidden", err)
	}
}

type fakePasswords struct {
	verifyCalls int
	rehash      bool
	verifyErr   error
	hashErr     error
	// onVerify, when set, runs at the start of every Verify call; tests use
	// it to interleave a concurrent mutation inside a sign-in's verification
	// window.
	onVerify func()
	// varyHashes makes every Hash call produce a distinct encoding of the
	// same password, the way a real salted hasher does, so rehash races can
	// be exercised.
	varyHashes bool
	hashCount  int
}

func (f *fakePasswords) Hash(password string) (string, error) {
	if f.hashErr != nil {
		return "", f.hashErr
	}
	if f.varyHashes {
		f.hashCount++
		return fmt.Sprintf("hash:%s#%d", password, f.hashCount), nil
	}
	return "hash:" + password, nil
}
func (f *fakePasswords) Verify(password, encoded string) (bool, bool, error) {
	f.verifyCalls++
	if f.onVerify != nil {
		f.onVerify()
	}
	if f.verifyErr != nil {
		return false, false, f.verifyErr
	}
	match := encoded == "hash:"+password || strings.HasPrefix(encoded, "hash:"+password+"#")
	return match, f.rehash, nil
}

type fakeTOTP struct{}

func (fakeTOTP) Generate(account string) (string, string, error) {
	return "SECRET", "otpauth://totp/Credbound:" + account, nil
}
func (fakeTOTP) Validate(code, _ string, at time.Time) (int64, bool) {
	return at.Unix() / 30, code == "123456"
}

type fakePasskeys struct {
	credentialJSON         []byte
	sawDecryptedCredential bool
}

func (f *fakePasskeys) BeginRegistration(context.Context, credbound.PasskeyUser) (json.RawMessage, []byte, error) {
	return json.RawMessage(`{"publicKey":{}}`), []byte("registration-session"), nil
}
func (f *fakePasskeys) FinishRegistration(_ context.Context, _ credbound.PasskeyUser, session, response []byte) ([]byte, []byte, error) {
	if string(session) != "registration-session" || string(response) != "valid" {
		return nil, nil, errors.New("invalid ceremony")
	}
	f.credentialJSON = []byte(`{"id":"credential","counter":0}`)
	return []byte("credential"), f.credentialJSON, nil
}
func (f *fakePasskeys) BeginAuthentication(_ context.Context, user credbound.PasskeyUser) (json.RawMessage, []byte, error) {
	for passkey, err := range user.Credentials {
		if err != nil {
			return nil, nil, err
		}
		f.sawDecryptedCredential = string(passkey.CredentialJSON) == string(f.credentialJSON)
	}
	return json.RawMessage(`{"publicKey":{}}`), []byte("authentication-session"), nil
}
func (f *fakePasskeys) BeginDecoyAuthentication(_ context.Context, _ []byte) (json.RawMessage, []byte, error) {
	return json.RawMessage(`{"publicKey":{}}`), []byte("decoy-session"), nil
}
func (f *fakePasskeys) FinishAuthentication(_ context.Context, _ credbound.PasskeyUser, session, response []byte) ([]byte, []byte, error) {
	if string(session) == "authentication-session" && string(response) == "cloned" {
		return nil, nil, credbound.ErrPasskeyCloneDetected
	}
	if string(session) != "authentication-session" || string(response) != "valid" {
		return nil, nil, errors.New("invalid ceremony")
	}
	return []byte("credential"), []byte(`{"id":"credential","counter":1}`), nil
}
func (f *fakePasskeys) BeginDiscoverableAuthentication(context.Context) (json.RawMessage, []byte, error) {
	return json.RawMessage(`{"publicKey":{}}`), []byte("discoverable-session"), nil
}
func (f *fakePasskeys) FinishDiscoverableAuthentication(ctx context.Context, session, response []byte, lookup credbound.PasskeyUserLookup) ([]byte, []byte, error) {
	if string(session) != "discoverable-session" {
		return nil, nil, errors.New("invalid ceremony")
	}
	credentialID := ""
	switch string(response) {
	case "valid", "cloned":
		credentialID = "credential"
	case "unknown":
		credentialID = "missing"
	default:
		return nil, nil, errors.New("invalid ceremony")
	}
	if _, err := lookup(ctx, []byte(credentialID)); err != nil {
		return nil, nil, err
	}
	if string(response) == "cloned" {
		return nil, nil, credbound.ErrPasskeyCloneDetected
	}
	return []byte(credentialID), []byte(`{"id":"credential","counter":2}`), nil
}

// legacyPasskeys narrows fakePasskeys to the base PasskeyProvider port, for
// the ErrNotSupported branch of the discoverable flow.
type legacyPasskeys struct{ inner *fakePasskeys }

func (l legacyPasskeys) BeginRegistration(ctx context.Context, user credbound.PasskeyUser) (json.RawMessage, []byte, error) {
	return l.inner.BeginRegistration(ctx, user)
}
func (l legacyPasskeys) FinishRegistration(ctx context.Context, user credbound.PasskeyUser, session, response []byte) ([]byte, []byte, error) {
	return l.inner.FinishRegistration(ctx, user, session, response)
}
func (l legacyPasskeys) BeginAuthentication(ctx context.Context, user credbound.PasskeyUser) (json.RawMessage, []byte, error) {
	return l.inner.BeginAuthentication(ctx, user)
}
func (l legacyPasskeys) BeginDecoyAuthentication(ctx context.Context, seed []byte) (json.RawMessage, []byte, error) {
	return l.inner.BeginDecoyAuthentication(ctx, seed)
}
func (l legacyPasskeys) FinishAuthentication(ctx context.Context, user credbound.PasskeyUser, session, response []byte) ([]byte, []byte, error) {
	return l.inner.FinishAuthentication(ctx, user, session, response)
}

type counterReader struct{ next byte }

func (r *counterReader) Read(value []byte) (int, error) {
	for index := range value {
		value[index] = r.next
		r.next++
	}
	return len(value), nil
}

func bytesOf(value byte, size int) []byte { return []byte(strings.Repeat(string([]byte{value}), size)) }

var _ io.Reader = (*counterReader)(nil)

func TestExportUserData(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	rootActor := aal2(authn.UserID, f.now)

	if _, err := f.manager.CreatePAT(ctx, rootActor, credbound.CreatePATInput{
		Name: "ci", WorkspaceID: workspace.ID, Scopes: []string{"read"},
	}); err != nil {
		t.Fatal(err)
	}

	// Self-export: profile, at least the primary email, the admin membership,
	// and the PAT, with the digest scrubbed.
	export, err := f.manager.ExportUserData(ctx, rootActor, credbound.UUID{})
	if err != nil {
		t.Fatalf("self export = %v", err)
	}
	if export.User.ID != authn.UserID || len(export.Emails) == 0 {
		t.Fatalf("export profile/emails = %#v", export)
	}
	if len(export.Workspaces) != 1 || export.Workspaces[0].Workspace.ID != workspace.ID ||
		export.Workspaces[0].Membership.Role != credbound.RoleAdmin {
		t.Fatalf("export workspaces = %#v", export.Workspaces)
	}
	if len(export.PATs) != 1 || export.PATs[0].Digest != nil {
		t.Fatalf("export PATs = %#v", export.PATs)
	}

	// An administrator can export another user; a non-admin member cannot.
	member, err := f.manager.CreateUser(ctx, rootActor, workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another secure password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	adminExport, err := f.manager.ExportUserData(ctx, rootActor, member.ID)
	if err != nil || adminExport.User.ID != member.ID {
		t.Fatalf("admin export = %#v, %v", adminExport, err)
	}
	memberActor := aal2(member.ID, f.now)
	if _, err := f.manager.ExportUserData(ctx, memberActor, authn.UserID); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("member cross-user export = %v", err)
	}

	// Privacy sections: a SCIM profile linked to the member and the invitation
	// the member accepted appear in the export, with the invitation digest
	// scrubbed (PRIV-002).
	exportCommit := func(id credbound.UUID, action string) credbound.Commit {
		return credbound.Commit{Audit: credbound.AuditEvent{
			ID: id, OccurredAt: f.now, ActorID: authn.UserID,
			Action: action, ResourceType: "test", ResourceID: member.ID.String(), WorkspaceID: workspace.ID, Outcome: credbound.AuditSucceeded,
		}}
	}
	configuration := credbound.SCIMConfiguration{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-0000000e5c01"), WorkspaceID: workspace.ID, Enabled: true, DefaultRole: credbound.RoleMember, CreatedAt: f.now, UpdatedAt: f.now}
	credential := credbound.SCIMCredential{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-0000000e5c02"), ConfigurationID: configuration.ID, Prefix: "abcdef012345", Digest: []byte("digest"), CreatedAt: f.now}
	if err := f.store.CreateSCIMConfiguration(ctx, configuration, credential, exportCommit(credbound.MustParseUUID("0198b463-0000-7000-8000-0000000e5c03"), "scim.configuration.create")); err != nil {
		t.Fatal(err)
	}
	membership, err := f.store.Membership(ctx, workspace.ID, member.ID)
	if err != nil {
		t.Fatal(err)
	}
	membership.ProvisioningSource, membership.UpdatedAt = configuration.ID.String(), f.now
	link := credbound.SCIMUser{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-0000000e5c04"), ConfigurationID: configuration.ID, UserID: member.ID, UserName: "member@example.com", DisplayName: "Member", Active: true, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.AdoptSCIMUser(ctx, membership, link, exportCommit(credbound.MustParseUUID("0198b463-0000-7000-8000-0000000e5c05"), "scim.user.adopt")); err != nil {
		t.Fatal(err)
	}
	invitation := credbound.WorkspaceInvitation{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-0000000e5c06"), WorkspaceID: workspace.ID, Email: "member@example.com", Role: credbound.RoleMember, InvitedBy: authn.UserID, Digest: []byte("digest"), CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	if err := f.store.CreateWorkspaceInvitation(ctx, invitation, exportCommit(credbound.MustParseUUID("0198b463-0000-7000-8000-0000000e5c07"), "invite.create")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.AcceptWorkspaceInvitation(ctx, invitation.ID, member.ID, f.now, membership, exportCommit(credbound.MustParseUUID("0198b463-0000-7000-8000-0000000e5c08"), "invite.accept")); err != nil {
		t.Fatal(err)
	}
	privacyExport, err := f.manager.ExportUserData(ctx, rootActor, member.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(privacyExport.SCIMUsers) != 1 || privacyExport.SCIMUsers[0].ID != link.ID || privacyExport.SCIMUsers[0].UserName != "member@example.com" {
		t.Fatalf("export SCIM profiles = %#v", privacyExport.SCIMUsers)
	}
	if len(privacyExport.Invitations) != 1 || privacyExport.Invitations[0].ID != invitation.ID || privacyExport.Invitations[0].Digest != nil {
		t.Fatalf("export invitations = %#v", privacyExport.Invitations)
	}
}
