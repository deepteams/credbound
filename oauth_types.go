package credbound

import (
	"context"
	"encoding/json"
	"slices"
	"time"
)

type OAuthCIMDMode string

const (
	OAuthCIMDDisabled  OAuthCIMDMode = "disabled"
	OAuthCIMDAllowlist OAuthCIMDMode = "allowlist"
	OAuthCIMDPublicWeb OAuthCIMDMode = "public_web"
)

type OAuthDCRMode string

const (
	OAuthDCRDisabled  OAuthDCRMode = "disabled"
	OAuthDCRProtected OAuthDCRMode = "protected"
	OAuthDCROpen      OAuthDCRMode = "open"
)

type OAuthClientSource string

const (
	OAuthClientPreRegistered OAuthClientSource = "pre_registered"
	OAuthClientCIMD          OAuthClientSource = "cimd"
	OAuthClientDCR           OAuthClientSource = "dcr"
)

type OAuthApplicationType string

const (
	OAuthApplicationWeb    OAuthApplicationType = "web"
	OAuthApplicationNative OAuthApplicationType = "native"
)

type OAuthTokenEndpointAuthMethod string

const (
	OAuthAuthNone              OAuthTokenEndpointAuthMethod = "none"
	OAuthAuthPrivateKeyJWT     OAuthTokenEndpointAuthMethod = "private_key_jwt"
	OAuthAuthClientSecretBasic OAuthTokenEndpointAuthMethod = "client_secret_basic"
)

type OAuthTokenKind string

const (
	OAuthAccessTokenKind  OAuthTokenKind = "access_token"
	OAuthRefreshTokenKind OAuthTokenKind = "refresh_token"
)

type OAuthScopeDefinition struct {
	Name        string
	Description string
	Permissions []WorkspacePermission
	MinimumAAL  AssuranceLevel
	MaxAuthAge  time.Duration
}

type OAuthIssuer struct {
	ID                       string
	Issuer                   string
	OIDCEnabled              bool
	CIMDMode                 OAuthCIMDMode
	CIMDAllowedOrigins       []string
	DCRMode                  OAuthDCRMode
	DCRAllowClientSecrets    bool
	DCROpenRegistrationLimit int
	CodeTTL                  time.Duration
	AccessTokenTTL           time.Duration
	RefreshTokenTTL          time.Duration
	CreatedAt                time.Time
	UpdatedAt                time.Time
	DisabledAt               *time.Time
}

type OAuthProtectedResource struct {
	ID          string
	IssuerID    string
	WorkspaceID string
	Resource    string
	Scopes      []OAuthScopeDefinition
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DisabledAt  *time.Time
}

type OAuthClient struct {
	ID                      string
	IssuerID                string
	ClientID                string
	Source                  OAuthClientSource
	Name                    string
	ApplicationType         OAuthApplicationType
	RedirectURIs            []string
	SectorIdentifier        string
	GrantTypes              []string
	ResponseTypes           []string
	Scopes                  []string
	TokenEndpointAuthMethod OAuthTokenEndpointAuthMethod
	JWKSURI                 string
	JWKS                    json.RawMessage
	Trusted                 bool
	SecretDigest            []byte
	MetadataHash            []byte
	MetadataExpiresAt       *time.Time
	CreatedAt               time.Time
	UpdatedAt               time.Time
	DisabledAt              *time.Time
}

type IssuedOAuthClient struct {
	Client       OAuthClient
	ClientSecret string
}

type OAuthInitialAccessToken struct {
	ID                string
	IssuerID          string
	Prefix            string
	Digest            []byte
	MaxRegistrations  int
	RegistrationCount int
	CreatedAt         time.Time
	ExpiresAt         time.Time
	RevokedAt         *time.Time
}

type IssuedOAuthInitialAccessToken struct {
	Credential OAuthInitialAccessToken
	Token      string
}

type OAuthGrant struct {
	ID             string
	IssuerID       string
	ClientRecordID string
	UserID         string
	WorkspaceID    string
	ResourceID     string
	Scopes         []string
	MetadataHash   []byte
	AuthTime       time.Time
	AuthMethod     AuthMethod
	AAL            AssuranceLevel
	CreatedAt      time.Time
	UpdatedAt      time.Time
	RevokedAt      *time.Time
}

type OAuthAuthorizationCode struct {
	ID             string
	Prefix         string
	Digest         []byte
	GrantID        string
	ClientRecordID string
	RedirectURI    string
	ResourceID     string
	Scopes         []string
	CodeChallenge  string
	Nonce          string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	UsedAt         *time.Time
}

type OAuthAccessToken struct {
	ID             string
	Prefix         string
	Digest         []byte
	GrantID        string
	ClientRecordID string
	UserID         string
	WorkspaceID    string
	ResourceID     string
	Scopes         []string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	RevokedAt      *time.Time
}

type OAuthRefreshToken struct {
	ID             string
	FamilyID       string
	Prefix         string
	Digest         []byte
	GrantID        string
	ClientRecordID string
	UserID         string
	WorkspaceID    string
	ResourceID     string
	Scopes         []string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	UsedAt         *time.Time
	ReplacedByID   string
	RevokedAt      *time.Time
}

type OAuthAuthentication struct {
	TokenID         string
	GrantID         string
	ClientRecordID  string
	ClientID        string
	UserID          string
	WorkspaceID     string
	Resource        string
	Scopes          []string
	AuthenticatedAt time.Time
}

func (a OAuthAuthentication) HasScope(required string) bool {
	return required == "" || slices.Contains(a.Scopes, required)
}

type OAuthClientMetadataDocument struct {
	ClientID                string
	ClientName              string
	ApplicationType         OAuthApplicationType
	RedirectURIs            []string
	GrantTypes              []string
	ResponseTypes           []string
	Scope                   string
	TokenEndpointAuthMethod OAuthTokenEndpointAuthMethod
	JWKSURI                 string
	JWKS                    json.RawMessage
	FetchedAt               time.Time
	ExpiresAt               time.Time
}

type OAuthClientMetadataFetcher interface {
	Fetch(context.Context, string) (OAuthClientMetadataDocument, error)
}

type OAuthClientAssertionVerifier interface {
	Verify(context.Context, OAuthClient, string, string, time.Time) error
}

type OIDCClaims struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Audience      string   `json:"aud"`
	ExpiresAt     int64    `json:"exp"`
	IssuedAt      int64    `json:"iat"`
	AuthTime      int64    `json:"auth_time,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
	ACR           string   `json:"acr,omitempty"`
	AMR           []string `json:"amr,omitempty"`
	Email         string   `json:"email,omitempty"`
	EmailVerified *bool    `json:"email_verified,omitempty"`
}

type OIDCSigner interface {
	SignIDToken(context.Context, OIDCClaims) (string, error)
	JWKS(context.Context) (json.RawMessage, error)
	Algorithms() []string
}

type OIDCUserInfo struct {
	Subject       string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
}

type CreateOAuthIssuerInput struct {
	Issuer                   string
	OIDCEnabled              bool
	CIMDMode                 OAuthCIMDMode
	CIMDAllowedOrigins       []string
	DCRMode                  OAuthDCRMode
	DCRAllowClientSecrets    bool
	DCROpenRegistrationLimit int
	CodeTTL                  time.Duration
	AccessTokenTTL           time.Duration
	RefreshTokenTTL          time.Duration
}

type CreateOAuthProtectedResourceInput struct {
	IssuerID string
	Resource string
	Scopes   []OAuthScopeDefinition
}

type UpdateOAuthIssuerInput struct {
	OIDCEnabled              bool
	CIMDMode                 OAuthCIMDMode
	CIMDAllowedOrigins       []string
	DCRMode                  OAuthDCRMode
	DCRAllowClientSecrets    bool
	DCROpenRegistrationLimit int
	CodeTTL                  time.Duration
	AccessTokenTTL           time.Duration
	RefreshTokenTTL          time.Duration
}

type OAuthClientRegistrationInput struct {
	Name                    string
	ApplicationType         OAuthApplicationType
	RedirectURIs            []string
	GrantTypes              []string
	ResponseTypes           []string
	Scopes                  []string
	TokenEndpointAuthMethod OAuthTokenEndpointAuthMethod
	JWKSURI                 string
	JWKS                    json.RawMessage
	Trusted                 bool
}

type CreateOAuthInitialAccessTokenInput struct {
	ExpiresAt        time.Time
	MaxRegistrations int
}

type BeginOAuthAuthorizationInput struct {
	Issuer              string
	ClientID            string
	RedirectURI         string
	Resource            string
	Scopes              []string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
}

type OAuthConsentScope struct {
	Name        string
	Description string
}

type OAuthConsent struct {
	Continuation      string
	ClientID          string
	ClientName        string
	ClientHost        string
	RedirectURI       string
	RedirectHost      string
	Resource          string
	WorkspaceID       string
	Scopes            []OAuthConsentScope
	RequiresStepUp    bool
	LocalhostRedirect bool
}

type OAuthAuthorizationResult struct {
	RedirectURI string
	Code        string
	State       string
	Issuer      string
	Error       string
}

type ExchangeOAuthAuthorizationCodeInput struct {
	Issuer              string
	ClientID            string
	ClientSecret        string
	ClientAssertion     string
	ClientAssertionType string
	Code                string
	RedirectURI         string
	CodeVerifier        string
	Resource            string
}

type RefreshOAuthTokenInput struct {
	Issuer              string
	ClientID            string
	ClientSecret        string
	ClientAssertion     string
	ClientAssertionType string
	RefreshToken        string
	Resource            string
	Scopes              []string
}

type RevokeOAuthTokenInput struct {
	Issuer              string
	ClientID            string
	ClientSecret        string
	ClientAssertion     string
	ClientAssertionType string
	Token               string
}

type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token,omitempty"`
}

type OAuthAuthorizationServerMetadata struct {
	Issuer                                      string   `json:"issuer"`
	AuthorizationEndpoint                       string   `json:"authorization_endpoint"`
	TokenEndpoint                               string   `json:"token_endpoint"`
	RevocationEndpoint                          string   `json:"revocation_endpoint"`
	RegistrationEndpoint                        string   `json:"registration_endpoint,omitempty"`
	JWKSURI                                     string   `json:"jwks_uri,omitempty"`
	UserInfoEndpoint                            string   `json:"userinfo_endpoint,omitempty"`
	ScopesSupported                             []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                      []string `json:"response_types_supported"`
	GrantTypesSupported                         []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported           []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported               []string `json:"code_challenge_methods_supported"`
	AuthorizationResponseIssuerParameterSupport bool     `json:"authorization_response_iss_parameter_supported"`
	ClientIDMetadataDocumentSupported           bool     `json:"client_id_metadata_document_supported"`
	SubjectTypesSupported                       []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported            []string `json:"id_token_signing_alg_values_supported,omitempty"`
}

type OAuthProtectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
	BearerMethods        []string `json:"bearer_methods_supported"`
}
