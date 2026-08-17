package credbound

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"reflect"
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
	// SessionTTL bounds the absolute lifetime of a server-side session issued
	// by CreateSession (ExpiresAt = CreatedAt + SessionTTL); activity never
	// extends it. Zero keeps the default of 30 days. Sessions additionally
	// require a SessionStore-capable store.
	SessionTTL time.Duration
	// SSOProviders registers the identity providers the host enables. Each
	// must expose a unique UUIDv7 configuration ID and a known kind.
	SSOProviders []SSOProvider
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
	store                Store
	passwords            PasswordHasher
	totp                 TOTPProvider
	passkeys             PasskeyProvider
	secretKey            []byte
	sealKey              []byte
	digestKey            []byte
	patPepper            []byte
	recoveryPepper       []byte
	stepUpMaxAge         time.Duration
	ceremonyTTL          time.Duration
	minPasswordLen       int
	passwordPolicy       PasswordPolicy
	maxFailedLogins      int64
	lockoutDuration      time.Duration
	clock                func() time.Time
	random               io.Reader
	observer             Observer
	adminPermissions     map[InstanceRole]map[Permission]struct{}
	workspaceRoles       *roleCatalog
	emailVerificationTTL time.Duration
	passwordResetTTL     time.Duration
	emailAuthTTL         time.Duration
	invitationTTL        time.Duration
	sessionTTL           time.Duration
	ssoProviders         map[string]SSOProvider
	events               *eventRegistry
	scimStore            SCIMStore
	oauthStore           OAuthStore
	oauth                *OAuthConfig
	signupStore          SignupStore
	signup               *SignUpConfig
	sessionStore         SessionStore
	domainStore          DomainStore
	dummyHash            string
	idMu                 sync.Mutex
	idUnixMilli          int64
	idSequence           uint16
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
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 30 * 24 * time.Hour
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
	ssoProviders := make(map[string]SSOProvider, len(cfg.SSOProviders))
	for _, provider := range cfg.SSOProviders {
		if nilSSOProvider(provider) || !validUUIDv7(provider.ConfigurationID()) || !validSSOProviderKind(provider.Kind()) {
			return nil, fmt.Errorf("%w: invalid SSO provider registration", ErrInvalidInput)
		}
		if _, duplicate := ssoProviders[provider.ConfigurationID()]; duplicate {
			return nil, fmt.Errorf("%w: duplicate SSO provider configuration", ErrInvalidInput)
		}
		ssoProviders[provider.ConfigurationID()] = provider
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
	events, err := newEventRegistry(cfg.Observer, func() time.Time { return cfg.Clock().UTC() }, cfg.TransactionHooks, cfg.EventListeners)
	if err != nil {
		return nil, err
	}
	scimStore, _ := cfg.Store.(SCIMStore)
	signupStore, _ := cfg.Store.(SignupStore)
	sessionStore, _ := cfg.Store.(SessionStore)
	domainStore, _ := cfg.Store.(DomainStore)
	var signupConfig *SignUpConfig
	if cfg.SignUp != nil {
		signupConfig = &SignUpConfig{AutoVerifyEmail: cfg.SignUp.AutoVerifyEmail}
	}
	var oauthStore OAuthStore
	var oauthConfig *OAuthConfig
	if cfg.OAuth != nil {
		if len(cfg.OAuth.Pepper) < 32 {
			return nil, fmt.Errorf("%w: OAuth pepper must contain at least 32 bytes", ErrInvalidInput)
		}
		oauthStore, _ = cfg.Store.(OAuthStore)
		oauthConfig = &OAuthConfig{
			Pepper: append([]byte(nil), cfg.OAuth.Pepper...), MetadataFetcher: cfg.OAuth.MetadataFetcher,
			ClientAssertions: cfg.OAuth.ClientAssertions, OIDCSigner: cfg.OAuth.OIDCSigner,
		}
	}
	return &Manager{
		store:                cfg.Store,
		passwords:            cfg.Passwords,
		totp:                 cfg.TOTP,
		passkeys:             cfg.Passkeys,
		secretKey:            append([]byte(nil), cfg.SecretKey...),
		sealKey:              sealKey,
		digestKey:            digestKey,
		patPepper:            append([]byte(nil), cfg.PATPepper...),
		recoveryPepper:       append([]byte(nil), cfg.RecoveryPepper...),
		stepUpMaxAge:         cfg.StepUpMaxAge,
		ceremonyTTL:          cfg.CeremonyTTL,
		minPasswordLen:       cfg.MinPasswordLen,
		passwordPolicy:       cfg.PasswordPolicy,
		maxFailedLogins:      int64(cfg.MaxFailedLogins),
		lockoutDuration:      cfg.LockoutDuration,
		clock:                cfg.Clock,
		random:               cfg.Random,
		observer:             cfg.Observer,
		adminPermissions:     adminPermissions,
		workspaceRoles:       workspaceRoles,
		emailVerificationTTL: cfg.EmailVerificationTTL,
		passwordResetTTL:     cfg.PasswordResetTTL,
		emailAuthTTL:         cfg.EmailAuthenticationTTL,
		invitationTTL:        cfg.InvitationTTL,
		sessionTTL:           cfg.SessionTTL,
		ssoProviders:         ssoProviders,
		events:               events,
		scimStore:            scimStore,
		oauthStore:           oauthStore,
		oauth:                oauthConfig,
		signupStore:          signupStore,
		signup:               signupConfig,
		sessionStore:         sessionStore,
		domainStore:          domainStore,
		dummyHash:            dummyHash,
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
