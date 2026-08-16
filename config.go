package credbound

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"
)

type Config struct {
	Store                Store
	Passwords            PasswordHasher
	TOTP                 TOTPProvider
	Passkeys             PasskeyProvider
	SecretKey            []byte
	PATPepper            []byte
	RecoveryPepper       []byte
	StepUpMaxAge         time.Duration
	CeremonyTTL          time.Duration
	MinPasswordLen       int
	Clock                func() time.Time
	Random               io.Reader
	Observer             Observer
	AdminPermissions     map[InstanceRole][]Permission
	WorkspaceRoles       []RoleDefinition
	EmailVerificationTTL time.Duration
	SSOProviders         []SSOProvider
	TransactionHooks     []TransactionHook
	EventListeners       []EventListener
	OAuth                *OAuthConfig
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
	patPepper            []byte
	recoveryPepper       []byte
	stepUpMaxAge         time.Duration
	ceremonyTTL          time.Duration
	minPasswordLen       int
	clock                func() time.Time
	random               io.Reader
	observer             Observer
	adminPermissions     map[InstanceRole]map[Permission]struct{}
	workspaceRoles       *roleCatalog
	emailVerificationTTL time.Duration
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
	if cfg.Store == nil || cfg.Passwords == nil || cfg.TOTP == nil || cfg.Passkeys == nil {
		return nil, fmt.Errorf("%w: store, passwords, totp and passkeys are required", ErrInvalidInput)
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
	if cfg.MinPasswordLen == 0 {
		cfg.MinPasswordLen = 12
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
		patPepper:            append([]byte(nil), cfg.PATPepper...),
		recoveryPepper:       append([]byte(nil), cfg.RecoveryPepper...),
		stepUpMaxAge:         cfg.StepUpMaxAge,
		ceremonyTTL:          cfg.CeremonyTTL,
		minPasswordLen:       cfg.MinPasswordLen,
		clock:                cfg.Clock,
		random:               cfg.Random,
		observer:             cfg.Observer,
		adminPermissions:     adminPermissions,
		workspaceRoles:       workspaceRoles,
		emailVerificationTTL: cfg.EmailVerificationTTL,
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
