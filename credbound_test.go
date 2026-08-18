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
	assurance := make(map[string]credbound.SSOAssurancePolicy, len(ssoProviders))
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
		TransactionHooks: []credbound.TransactionHook{credbound.UnimplementedTransactionHook{}},
		EventListeners:   []credbound.EventListener{credbound.UnimplementedEventListener{}},
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

func TestBootstrapPasswordAndUUIDv7(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	if !uuidV7.MatchString(authn.UserID) || !uuidV7.MatchString(workspace.ID) {
		t.Fatalf("non UUIDv7 ids: %q %q", authn.UserID, workspace.ID)
	}
	if authn.UserID >= workspace.ID {
		t.Fatalf("UUIDv7 ids are not monotonic: %q >= %q", authn.UserID, workspace.ID)
	}
	admin, err := f.store.InstanceAdministrator(context.Background(), authn.UserID)
	if err != nil || admin.Role != credbound.InstanceRoleRoot {
		t.Fatalf("bootstrap admin = %#v, %v", admin, err)
	}
	if _, _, err := f.manager.Bootstrap(context.Background(), credbound.BootstrapInput{
		Email: "other@example.com", DisplayName: "Other", Password: "correct horse battery", WorkspaceName: "Other",
	}); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("second bootstrap error = %v", err)
	}

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

	first := collectPage(t, f.manager.PATs(context.Background(), stepUp, credbound.PageRequest{Limit: 2}))
	if len(first.items) != 2 || first.end == nil || !first.end.HasMore || first.end.NextCursor == "" {
		t.Fatalf("first page = %#v", first)
	}
	second := collectPage(t, f.manager.PATs(context.Background(), stepUp, credbound.PageRequest{Limit: 2, Cursor: first.end.NextCursor}))
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

func TestPasskeyCeremoniesEncryptStoredCredential(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	challenge, err := f.manager.BeginPasskeyRegistration(context.Background(), authn, "MacBook")
	if err != nil || len(challenge.Options) == 0 || challenge.Continuation == "" {
		t.Fatalf("challenge = %#v, %v", challenge, err)
	}
	passkey, err := f.manager.FinishPasskeyRegistration(context.Background(), authn, challenge.Continuation, []byte("valid"))
	if err != nil || passkey.CredentialJSON != nil || !uuidV7.MatchString(passkey.ID) {
		t.Fatalf("passkey = %#v, %v", passkey, err)
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
	if err := f.manager.DeletePasskey(context.Background(), passkeyAuth, passkey.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.FinishPasskeyAuthentication(context.Background(), login.Continuation+"x", []byte("valid")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("tampered continuation error = %v", err)
	}
}

func TestAdministrationRolesAndAudit(t *testing.T) {
	f := newFixture(t)
	root, workspace := f.bootstrap(t)
	if err := f.manager.AuthorizeAdmin(context.Background(), root, credbound.PermissionAdminAccess); err != nil {
		t.Fatal(err)
	}
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
	page := collectPage(t, f.manager.PATs(context.Background(), authn, credbound.PageRequest{}))
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
	validProvider := &fakeSSOProvider{configurationID: "0198b463-0000-7000-8000-0000000000aa", kind: credbound.SSOProviderGoogle}
	bad = valid
	bad.SSOProviders = []credbound.SSOProvider{validProvider, validProvider}
	if _, err := credbound.New(bad); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("duplicate SSO provider = %v", err)
	}
	bad = valid
	bad.SSOProviders = []credbound.SSOProvider{&fakeSSOProvider{configurationID: "0198b463-0000-4000-8000-0000000000aa", kind: credbound.SSOProviderOIDC}}
	if _, err := credbound.New(bad); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("non UUIDv7 SSO provider = %v", err)
	}
	bad = valid
	bad.SSOProviders = []credbound.SSOProvider{&fakeSSOProvider{configurationID: "0198b463-0000-7000-8000-0000000000ab", kind: credbound.SSOProviderKind("ldap")}}
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

func aal2(userID string, at time.Time) credbound.Authentication {
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
}

func (f *fakePasswords) Hash(password string) (string, error) {
	if f.hashErr != nil {
		return "", f.hashErr
	}
	return "hash:" + password, nil
}
func (f *fakePasswords) Verify(password, encoded string) (bool, bool, error) {
	f.verifyCalls++
	if f.verifyErr != nil {
		return false, false, f.verifyErr
	}
	return encoded == "hash:"+password, f.rehash, nil
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
	if string(session) != "authentication-session" || string(response) != "valid" {
		return nil, nil, errors.New("invalid ceremony")
	}
	return []byte("credential"), []byte(`{"id":"credential","counter":1}`), nil
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
	export, err := f.manager.ExportUserData(ctx, rootActor, "")
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
}
