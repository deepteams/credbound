package credbound

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
)

// Config assembles the ports, keys and policies of a Manager. Store and
// Passwords are required; New validates every invariant and applies safe
// defaults to zero durations and limits. Cryptographic values have no weak
// fallback.
type Config struct {
	// Store is the required persistence port. A store that additionally
	// implements SCIMStore, OAuthStore, SignupStore, SessionStore, or
	// DomainStore unlocks the corresponding optional capability.
	Store Store
	// Passwords derives and verifies password hashes (Argon2id is the
	// intended algorithm). Required.
	Passwords PasswordHasher
	// TOTP is the optional TOTP provider; without it the TOTP enrollment and
	// verification operations return ErrNotSupported.
	TOTP TOTPProvider
	// Passkeys is the optional WebAuthn provider; without it the passkey
	// ceremonies return ErrNotSupported.
	Passkeys PasskeyProvider
	// DomainVerifier proves control of a workspace domain inside
	// ConfirmWorkspaceDomain; see DomainVerifier. Without one,
	// ConfirmWorkspaceDomain refuses with ErrNotSupported unless
	// TrustActorDomainVerification opts into trusting the actor instead.
	DomainVerifier DomainVerifier
	// TrustActorDomainVerification lets ConfirmWorkspaceDomain succeed
	// without a DomainVerifier, treating the call as the administrator's
	// assertion that DNS verification completed out of band. Dangerous
	// wherever ConfirmWorkspaceDomain is reachable from self-serve actors: a
	// confirmed domain governs SSO enforcement and JIT provisioning for every
	// address on it. Ignored when a DomainVerifier is registered.
	TrustActorDomainVerification bool
	// SecretKey is the 32-byte root key. Distinct AEAD and HMAC keys are
	// derived from it with HKDF to seal ceremony continuations and TOTP
	// secrets and to digest single-use tokens.
	SecretKey []byte
	// PATPepper keys the HMAC digests of PAT and SCIM credentials. At least
	// 32 bytes.
	PATPepper []byte
	// RecoveryPepper keys the HMAC digests of TOTP recovery codes. At least
	// 32 bytes.
	RecoveryPepper []byte
	// RetiredSecretKeys lists previously active SecretKeys that reads still
	// accept: sealed TOTP secrets and passkey credentials keep decrypting
	// and outstanding token digests (sessions included) keep matching after
	// a rotation, while everything new uses SecretKey. Each retired key is
	// exactly 32 bytes. Remove a retired key once nothing sealed or
	// digested under it remains.
	RetiredSecretKeys [][]byte
	// RetiredPATPeppers lists previously active PATPeppers that reads
	// still accept, so outstanding PATs and SCIM credentials survive a
	// pepper rotation; new tokens always digest under PATPepper.
	RetiredPATPeppers [][]byte
	// RetiredRecoveryPeppers lists previously active RecoveryPeppers that
	// reads still accept, so outstanding recovery codes survive a pepper
	// rotation; new codes always digest under RecoveryPepper.
	RetiredRecoveryPeppers [][]byte
	// StepUpMaxAge bounds how old an interactive AAL2 authentication may be
	// to satisfy RequireStepUp. Zero keeps the default of 10 minutes.
	StepUpMaxAge time.Duration
	// CeremonyTTL bounds the validity of sealed ceremony continuations
	// (WebAuthn, SSO, OAuth consent). Email OTP continuations follow
	// EmailAuthenticationTTL plus a one-minute audit grace instead. Zero
	// keeps the default of 5 minutes.
	CeremonyTTL time.Duration
	// MinPasswordLen is the minimum accepted password length in runes. Zero
	// keeps the default of 12; values below 10 are rejected.
	MinPasswordLen int
	// PasswordPolicy optionally vets candidate passwords beyond the built-in
	// length rules (for example against a breached-password corpus). Nil
	// keeps only the built-in validation.
	PasswordPolicy PasswordPolicy
	// MaxFailedLogins locks an account after that many consecutive password
	// or TOTP failures. Zero keeps the default of 10; a negative value
	// disables the built-in lockout for hosts that throttle upstream.
	MaxFailedLogins int
	// LockoutDuration is how long a locked account rejects authentication.
	// Zero keeps the default of 15 minutes.
	LockoutDuration time.Duration
	// Clock supplies the current time; nil uses time.Now. Injectable for
	// tests only — persisted timestamps are always converted to UTC.
	Clock func() time.Time
	// Random supplies cryptographic randomness; nil uses crypto/rand.
	// Injectable for tests only.
	Random io.Reader
	// Observer receives one Operation record per API call, transaction hook
	// and event listener invocation, for metrics and tracing. Nil disables
	// observation.
	Observer Observer
	// AdminPermissions restricts the default instance-role permission
	// matrix. A role may only be narrowed: granting a permission outside its
	// default set fails, and no role but root may hold instance-role write.
	AdminPermissions map[InstanceRole][]Permission
	// WorkspaceRoles registers additional workspace roles and permissions in
	// the immutable RBAC catalog. Definitions are validated during New; see
	// RoleDefinition.
	WorkspaceRoles []RoleDefinition
	// EmailVerificationTTL bounds the validity of an email addition token.
	// Zero keeps the default of 24 hours.
	EmailVerificationTTL time.Duration
	// PasswordResetTTL bounds the validity of a password reset token. Zero
	// keeps the default of 1 hour.
	PasswordResetTTL time.Duration
	// EmailAuthenticationTTL bounds the validity of magic-link tokens and
	// email OTP codes. Zero keeps the default of 15 minutes.
	EmailAuthenticationTTL time.Duration
	// InvitationTTL bounds the validity of a workspace invitation token.
	// Zero keeps the default of 7 days.
	InvitationTTL time.Duration
	// DomainClaimTTL bounds how long an unconfirmed workspace-domain claim
	// reserves its globally unique name. Once the window passes without
	// ConfirmWorkspaceDomain, a new CreateWorkspaceDomain for the same name —
	// from any workspace — replaces the stale pending claim, so an
	// unverified claim can never permanently deny the domain's real owner.
	// Confirmed domains never expire. Zero keeps the default of 7 days.
	DomainClaimTTL time.Duration
	// SessionTTL bounds the absolute lifetime of a server-side session issued
	// by CreateSession (ExpiresAt = CreatedAt + SessionTTL); activity never
	// extends it. Zero keeps the default of 30 days. Sessions additionally
	// require a SessionStore-capable store.
	SessionTTL time.Duration
	// SessionIdleTimeout expires a server-side session after this much
	// inactivity: AuthenticateSession refuses a session whose last-seen
	// timestamp is older than the timeout, in addition to the absolute
	// SessionTTL. Zero disables the idle check (absolute expiry only). Every
	// successful AuthenticateSession refreshes last-seen, so the window slides
	// with activity.
	SessionIdleTimeout time.Duration
	// SessionTouchInterval coarsens the write AuthenticateSession performs:
	// a successful validation whose session was already touched within the
	// interval skips the last-seen refresh and its audit event, turning the
	// per-request write transaction into at most one write per session per
	// interval. Revocation, expiry, idle and disabled-user checks still run
	// against the store on every call, so — unlike a host-side result cache —
	// a revoked session is refused on the very next request; the explicit
	// trade-offs are last-seen granularity, an audit log that records session
	// activity at most once per interval per session, and a revocation racing
	// one in-flight validation no longer being caught by the touch's
	// conflict check. Zero keeps the per-request write. When
	// SessionIdleTimeout is set, the interval must be shorter than it, or a
	// continuously active session could idle-expire; New rejects the
	// combination.
	SessionTouchInterval time.Duration
	// EmailIssuanceCooldown is the minimum interval between two token-issuing
	// emails to the same address for the same purpose (password reset,
	// magic-link, email OTP, verification resend). Within the window the flow
	// answers with its usual enumeration-safe decoy and issues no token, so a
	// user cannot be bombarded with mails. Zero disables the cooldown. It
	// requires an EmailThrottleStore-capable store; New fails construction
	// otherwise, so a configured protection can never be silently inert.
	EmailIssuanceCooldown time.Duration
	// SSOProviders registers the identity providers the host enables. Each
	// must expose a unique UUIDv7 configuration ID and a known kind.
	SSOProviders []SSOProvider
	// SSOAssurance sets, per provider configuration ID, the authentication
	// context a provider must assert before FinishSSO grants AAL2; see
	// SSOAssurancePolicy. A provider with no entry here grants only AAL1 —
	// SSO never mints AAL2 on the IdP's unverified word — so a provider whose
	// sign-ins must satisfy a RequireMFA workspace or a step-up needs a
	// policy (use TrustUnverified to trust an IdP that asserts no ACR or
	// AMR). Every key must name a registered provider and every policy must
	// require something.
	SSOAssurance map[UUID]SSOAssurancePolicy
	// TransactionHooks run inside every mutation's store transaction, after
	// the mutation and before the audit write. A hook error aborts the
	// commit. More hooks can be added later with AddTransactionHook.
	TransactionHooks []TransactionHook
	// EventListeners observe committed facts. Listener errors are recorded
	// for observability and never propagate. More listeners can be added
	// later with AddEventListener.
	EventListeners []EventListener
	// OAuth enables the OAuth/OIDC authorization server module when the
	// store also implements OAuthStore. Nil leaves the module disabled.
	OAuth *OAuthConfig
	// SignUp enables self-service registration when the store also
	// implements SignupStore. Nil leaves the operation disabled.
	SignUp *SignUpConfig
}

// SignUpConfig configures the optional self-service signup operation.
type SignUpConfig struct {
	// AutoVerifyEmail marks the primary address verified at creation instead
	// of issuing an email-verification token, and makes SignUp additionally
	// return an AAL1 password Authentication. Hosts enabling it accept that
	// mailbox control was never proven.
	AutoVerifyEmail bool
}

// OAuthConfig configures the optional OAuth/OIDC module.
type OAuthConfig struct {
	// Pepper keys the HMAC digests of OAuth codes, tokens and client
	// secrets, and the pairwise OIDC subjects. At least 32 bytes.
	Pepper []byte
	// MetadataFetcher resolves Client Identifier Metadata Documents; it is
	// required for CIMD client policies. oauthhttp.NewMetadataFetcher
	// provides a hardened implementation.
	MetadataFetcher OAuthClientMetadataFetcher
	// ClientAssertions verifies private_key_jwt client assertions; required
	// for that authentication method.
	ClientAssertions OAuthClientAssertionVerifier
	// OIDCSigner signs ID Tokens and publishes the JWKS; required for any
	// issuer with OIDC enabled.
	OIDCSigner OIDCSigner
}

// Manager is the façade over every Credbound capability. It is safe for
// concurrent use and is built once per process with New.
type Manager struct {
	store          Store
	passwords      PasswordHasher
	totp           TOTPProvider
	passkeys       PasskeyProvider
	secretKey      []byte
	sealKey        []byte
	digestKey      []byte
	patPepper      []byte
	recoveryPepper []byte
	// read* rings list every key accepted when reading, active first, so a
	// rotation with Retired* configured never invalidates existing data;
	// writes always use the single active key above.
	readSealKeys          [][]byte
	readDigestKeys        [][]byte
	readPATPeppers        [][]byte
	readRecoveryPeppers   [][]byte
	stepUpMaxAge          time.Duration
	ceremonyTTL           time.Duration
	minPasswordLen        int
	passwordPolicy        PasswordPolicy
	maxFailedLogins       int64
	lockoutDuration       time.Duration
	clock                 func() time.Time
	random                io.Reader
	observer              Observer
	adminPermissions      map[InstanceRole]map[Permission]struct{}
	workspaceRoles        *roleCatalog
	emailVerificationTTL  time.Duration
	passwordResetTTL      time.Duration
	emailAuthTTL          time.Duration
	invitationTTL         time.Duration
	domainClaimTTL        time.Duration
	sessionTTL            time.Duration
	sessionIdleTimeout    time.Duration
	sessionTouchInterval  time.Duration
	emailIssuanceCooldown time.Duration
	ssoProviders          map[UUID]SSOProvider
	ssoAssurance          map[UUID]SSOAssurancePolicy
	events                *eventRegistry
	scimStore             SCIMStore
	privacyStore          PrivacyStore
	oauthStore            OAuthStore
	oauth                 *OAuthConfig
	signupStore           SignupStore
	signup                *SignUpConfig
	sessionStore          SessionStore
	emailThrottle         EmailThrottleStore
	domainStore           DomainStore
	domainVerifier        DomainVerifier
	trustActorDomains     bool
	dummyHash             string
	idMu                  sync.Mutex
	idUnixMilli           int64
	idSequence            uint16
}

// New validates the configuration and builds a Manager. It rejects missing
// required ports, undersized keys and invalid role or provider definitions
// with errors matching ErrInvalidInput, and fills zero durations and limits
// with the documented defaults.
func New(cfg Config) (*Manager, error) {
	if cfg.Store == nil || cfg.Passwords == nil {
		return nil, fmt.Errorf("%w: store and passwords are required", ErrInvalidInput)
	}
	if len(cfg.SecretKey) != 32 {
		return nil, fmt.Errorf("%w: secret key must contain exactly 32 bytes", ErrInvalidInput)
	}
	if len(cfg.PATPepper) < 32 || len(cfg.RecoveryPepper) < 32 {
		return nil, fmt.Errorf("%w: peppers must contain at least 32 bytes", ErrInvalidInput)
	}
	for _, retired := range cfg.RetiredSecretKeys {
		if len(retired) != 32 {
			return nil, fmt.Errorf("%w: every retired secret key must contain exactly 32 bytes", ErrInvalidInput)
		}
	}
	for _, retired := range append(append([][]byte{}, cfg.RetiredPATPeppers...), cfg.RetiredRecoveryPeppers...) {
		if len(retired) < 32 {
			return nil, fmt.Errorf("%w: every retired pepper must contain at least 32 bytes", ErrInvalidInput)
		}
	}
	if cfg.StepUpMaxAge <= 0 {
		cfg.StepUpMaxAge = 10 * time.Minute
	}
	if cfg.CeremonyTTL <= 0 {
		cfg.CeremonyTTL = 5 * time.Minute
	}
	if cfg.EmailVerificationTTL <= 0 {
		cfg.EmailVerificationTTL = 24 * time.Hour
	}
	if cfg.PasswordResetTTL <= 0 {
		cfg.PasswordResetTTL = time.Hour
	}
	if cfg.EmailAuthenticationTTL <= 0 {
		cfg.EmailAuthenticationTTL = 15 * time.Minute
	}
	if cfg.InvitationTTL <= 0 {
		cfg.InvitationTTL = 7 * 24 * time.Hour
	}
	if cfg.DomainClaimTTL <= 0 {
		cfg.DomainClaimTTL = 7 * 24 * time.Hour
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 30 * 24 * time.Hour
	}
	if cfg.SessionTouchInterval < 0 {
		return nil, fmt.Errorf("%w: session touch interval cannot be negative", ErrInvalidInput)
	}
	if cfg.SessionTouchInterval > 0 && cfg.SessionIdleTimeout > 0 && cfg.SessionTouchInterval >= cfg.SessionIdleTimeout {
		return nil, fmt.Errorf("%w: session touch interval must be shorter than the idle timeout, or an active session could idle-expire", ErrInvalidInput)
	}
	if cfg.MinPasswordLen == 0 {
		cfg.MinPasswordLen = 12
	}
	if cfg.MaxFailedLogins == 0 {
		cfg.MaxFailedLogins = 10
	}
	if cfg.MaxFailedLogins < 0 {
		cfg.MaxFailedLogins = 0
	}
	if cfg.LockoutDuration <= 0 {
		cfg.LockoutDuration = 15 * time.Minute
	}
	if cfg.MinPasswordLen < 10 {
		return nil, fmt.Errorf("%w: minimum password length cannot be below 10", ErrInvalidInput)
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	if cfg.Observer == nil {
		cfg.Observer = nopObserver{}
	}
	adminPermissions, err := buildAdminPermissions(cfg.AdminPermissions)
	if err != nil {
		return nil, err
	}
	workspaceRoles, err := buildRoleCatalog(cfg.WorkspaceRoles)
	if err != nil {
		return nil, err
	}
	ssoProviders := make(map[UUID]SSOProvider, len(cfg.SSOProviders))
	for _, provider := range cfg.SSOProviders {
		if nilSSOProvider(provider) || !validUUIDv7(provider.ConfigurationID()) || !validSSOProviderKind(provider.Kind()) {
			return nil, fmt.Errorf("%w: invalid SSO provider registration", ErrInvalidInput)
		}
		if _, duplicate := ssoProviders[provider.ConfigurationID()]; duplicate {
			return nil, fmt.Errorf("%w: duplicate SSO provider configuration", ErrInvalidInput)
		}
		ssoProviders[provider.ConfigurationID()] = provider
	}
	ssoAssurance := make(map[UUID]SSOAssurancePolicy, len(cfg.SSOAssurance))
	for configurationID, policy := range cfg.SSOAssurance {
		if _, registered := ssoProviders[configurationID]; !registered {
			return nil, fmt.Errorf("%w: SSO assurance policy for unregistered provider configuration", ErrInvalidInput)
		}
		if policy.empty() {
			return nil, fmt.Errorf("%w: an SSO assurance policy must require an ACR or AMR, or set TrustUnverified", ErrInvalidInput)
		}
		// A blank ACR or AMR would accept an IdP that asserts an empty value —
		// effectively no assurance — so reject it rather than silently granting
		// AAL2 on nothing.
		for _, acr := range policy.AcceptedACR {
			if strings.TrimSpace(acr) == "" {
				return nil, fmt.Errorf("%w: an SSO assurance policy must not accept a blank ACR", ErrInvalidInput)
			}
		}
		for _, amr := range policy.RequiredAMR {
			if strings.TrimSpace(amr) == "" {
				return nil, fmt.Errorf("%w: an SSO assurance policy must not require a blank AMR", ErrInvalidInput)
			}
		}
		// Deep-copy the slices so a caller mutating its input after New cannot
		// change the enforced policy.
		ssoAssurance[configurationID] = SSOAssurancePolicy{
			AcceptedACR: slices.Clone(policy.AcceptedACR), RequiredAMR: slices.Clone(policy.RequiredAMR),
			TrustUnverified: policy.TrustUnverified,
		}
	}
	dummyHash, err := cfg.Passwords.Hash("credbound-dummy-password")
	if err != nil {
		return nil, fmt.Errorf("initialize dummy password: %w", err)
	}
	// The AEAD and HMAC keys are distinct HKDF derivations of SecretKey so the
	// two primitives never share key material. The raw SecretKey remains the
	// fallback for data sealed before this separation existed.
	sealKey, err := hkdf.Key(sha256.New, cfg.SecretKey, nil, "credbound/seal/v1", 32)
	if err != nil {
		return nil, fmt.Errorf("derive seal key: %w", err)
	}
	digestKey, err := hkdf.Key(sha256.New, cfg.SecretKey, nil, "credbound/digest/v1", 32)
	if err != nil {
		return nil, fmt.Errorf("derive digest key: %w", err)
	}
	readSealKeys, readDigestKeys := [][]byte{sealKey}, [][]byte{digestKey}
	for _, retired := range cfg.RetiredSecretKeys {
		retiredSeal, err := hkdf.Key(sha256.New, retired, nil, "credbound/seal/v1", 32)
		if err != nil {
			return nil, fmt.Errorf("derive retired seal key: %w", err)
		}
		retiredDigest, err := hkdf.Key(sha256.New, retired, nil, "credbound/digest/v1", 32)
		if err != nil {
			return nil, fmt.Errorf("derive retired digest key: %w", err)
		}
		readSealKeys, readDigestKeys = append(readSealKeys, retiredSeal), append(readDigestKeys, retiredDigest)
	}
	// Data sealed before the HKDF key separation used raw SecretKeys; the
	// raw active and retired keys close the ring until the v1 re-seal
	// migration removes the legacy fallback.
	readSealKeys = append(readSealKeys, append([]byte(nil), cfg.SecretKey...))
	readSealKeys = append(readSealKeys, clonePeppers(cfg.RetiredSecretKeys)...)
	readPATPeppers := append([][]byte{append([]byte(nil), cfg.PATPepper...)}, clonePeppers(cfg.RetiredPATPeppers)...)
	readRecoveryPeppers := append([][]byte{append([]byte(nil), cfg.RecoveryPepper...)}, clonePeppers(cfg.RetiredRecoveryPeppers)...)
	events, err := newEventRegistry(cfg.Observer, func() time.Time { return cfg.Clock().UTC() }, cfg.TransactionHooks, cfg.EventListeners)
	if err != nil {
		return nil, err
	}
	scimStore, _ := cfg.Store.(SCIMStore)
	privacyStore, _ := cfg.Store.(PrivacyStore)
	signupStore, _ := cfg.Store.(SignupStore)
	sessionStore, _ := cfg.Store.(SessionStore)
	emailThrottle, _ := cfg.Store.(EmailThrottleStore)
	domainStore, _ := cfg.Store.(DomainStore)
	// A configured cooldown is explicit intent, like SignUp and OAuth below:
	// an anti-mail-bombing protection must never be silently inert.
	if cfg.EmailIssuanceCooldown > 0 && emailThrottle == nil {
		return nil, fmt.Errorf("%w: Config.EmailIssuanceCooldown is set but Store does not implement EmailThrottleStore", ErrInvalidInput)
	}
	var signupConfig *SignUpConfig
	if cfg.SignUp != nil {
		// SignUp is an explicit opt-in, so a Store that cannot back it is a
		// configuration error, not a silently disabled capability.
		if _, ok := cfg.Store.(SignupStore); !ok {
			return nil, fmt.Errorf("%w: Config.SignUp is set but Store does not implement SignupStore", ErrInvalidInput)
		}
		signupConfig = &SignUpConfig{AutoVerifyEmail: cfg.SignUp.AutoVerifyEmail}
	}
	var oauthStore OAuthStore
	var oauthConfig *OAuthConfig
	if cfg.OAuth != nil {
		if len(cfg.OAuth.Pepper) < 32 {
			return nil, fmt.Errorf("%w: OAuth pepper must contain at least 32 bytes", ErrInvalidInput)
		}
		// Config.OAuth is explicit intent: fail construction rather than let
		// every OAuth operation surface ErrNotSupported at runtime.
		var ok bool
		oauthStore, ok = cfg.Store.(OAuthStore)
		if !ok {
			return nil, fmt.Errorf("%w: Config.OAuth is set but Store does not implement OAuthStore", ErrInvalidInput)
		}
		oauthConfig = &OAuthConfig{
			Pepper: append([]byte(nil), cfg.OAuth.Pepper...), MetadataFetcher: cfg.OAuth.MetadataFetcher,
			ClientAssertions: cfg.OAuth.ClientAssertions, OIDCSigner: cfg.OAuth.OIDCSigner,
		}
	}
	return &Manager{
		store:                 cfg.Store,
		passwords:             cfg.Passwords,
		totp:                  cfg.TOTP,
		passkeys:              cfg.Passkeys,
		secretKey:             append([]byte(nil), cfg.SecretKey...),
		sealKey:               sealKey,
		digestKey:             digestKey,
		patPepper:             append([]byte(nil), cfg.PATPepper...),
		recoveryPepper:        append([]byte(nil), cfg.RecoveryPepper...),
		readSealKeys:          readSealKeys,
		readDigestKeys:        readDigestKeys,
		readPATPeppers:        readPATPeppers,
		readRecoveryPeppers:   readRecoveryPeppers,
		stepUpMaxAge:          cfg.StepUpMaxAge,
		ceremonyTTL:           cfg.CeremonyTTL,
		minPasswordLen:        cfg.MinPasswordLen,
		passwordPolicy:        cfg.PasswordPolicy,
		maxFailedLogins:       int64(cfg.MaxFailedLogins),
		lockoutDuration:       cfg.LockoutDuration,
		clock:                 cfg.Clock,
		random:                cfg.Random,
		observer:              cfg.Observer,
		adminPermissions:      adminPermissions,
		workspaceRoles:        workspaceRoles,
		emailVerificationTTL:  cfg.EmailVerificationTTL,
		passwordResetTTL:      cfg.PasswordResetTTL,
		emailAuthTTL:          cfg.EmailAuthenticationTTL,
		invitationTTL:         cfg.InvitationTTL,
		domainClaimTTL:        cfg.DomainClaimTTL,
		sessionTTL:            cfg.SessionTTL,
		sessionIdleTimeout:    cfg.SessionIdleTimeout,
		sessionTouchInterval:  cfg.SessionTouchInterval,
		emailIssuanceCooldown: cfg.EmailIssuanceCooldown,
		ssoProviders:          ssoProviders,
		ssoAssurance:          ssoAssurance,
		events:                events,
		scimStore:             scimStore,
		privacyStore:          privacyStore,
		oauthStore:            oauthStore,
		oauth:                 oauthConfig,
		signupStore:           signupStore,
		signup:                signupConfig,
		sessionStore:          sessionStore,
		emailThrottle:         emailThrottle,
		domainStore:           domainStore,
		domainVerifier:        cfg.DomainVerifier,
		trustActorDomains:     cfg.TrustActorDomainVerification,
		dummyHash:             dummyHash,
	}, nil
}

func nilSSOProvider(provider SSOProvider) bool {
	if provider == nil {
		return true
	}
	value := reflect.ValueOf(provider)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (m *Manager) now() time.Time { return m.clock().UTC() }

func (m *Manager) observe(ctx context.Context, name string, started time.Time, err error) {
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	m.observer.Observe(ctx, Operation{Name: name, Outcome: outcome, Duration: m.now().Sub(started)})
}

// clonePeppers deep-copies a retired-pepper list so later caller mutations
// cannot reach the Manager's key material.
func clonePeppers(peppers [][]byte) [][]byte {
	cloned := make([][]byte, 0, len(peppers))
	for _, pepper := range peppers {
		cloned = append(cloned, append([]byte(nil), pepper...))
	}
	return cloned
}
