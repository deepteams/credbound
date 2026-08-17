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

type Config struct {
	Store          Store
	Passwords      PasswordHasher
	TOTP           TOTPProvider
	Passkeys       PasskeyProvider
	SecretKey      []byte
	PATPepper      []byte
	RecoveryPepper []byte
	StepUpMaxAge   time.Duration
	CeremonyTTL    time.Duration
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
	LockoutDuration      time.Duration
	Clock                func() time.Time
	Random               io.Reader
	Observer             Observer
	AdminPermissions     map[InstanceRole][]Permission
	WorkspaceRoles       []RoleDefinition
	EmailVerificationTTL time.Duration
	// PasswordResetTTL bounds the validity of a password reset token. Zero
	// keeps the default of 1 hour.
	PasswordResetTTL time.Duration
	// EmailAuthenticationTTL bounds the validity of a magic-link token. Zero
	// keeps the default of 15 minutes.
	EmailAuthenticationTTL time.Duration
	// InvitationTTL bounds the validity of a workspace invitation token.
	// Zero keeps the default of 7 days.
	InvitationTTL    time.Duration
	SSOProviders     []SSOProvider
	TransactionHooks []TransactionHook
	EventListeners   []EventListener
	OAuth            *OAuthConfig
}

type OAuthConfig struct {
	Pepper           []byte
	MetadataFetcher  OAuthClientMetadataFetcher
	ClientAssertions OAuthClientAssertionVerifier
	OIDCSigner       OIDCSigner
}

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
	ssoProviders         map[string]SSOProvider
	events               *eventRegistry
	scimStore            SCIMStore
	oauthStore           OAuthStore
	oauth                *OAuthConfig
	dummyHash            string
	idMu                 sync.Mutex
	idUnixMilli          int64
	idSequence           uint16
}

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
		ssoProviders:         ssoProviders,
		events:               events,
		scimStore:            scimStore,
		oauthStore:           oauthStore,
		oauth:                oauthConfig,
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
