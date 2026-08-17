package credbound

import (
	"context"
	"encoding/json"
	"slices"
	"time"
)

// OAuthCIMDMode is an issuer's policy for Client Identifier Metadata
// Document clients: disabled, restricted to an origin allowlist, or open to
// any HTTPS Client Identifier URL on the public web.
type OAuthCIMDMode string

const (
	OAuthCIMDDisabled  OAuthCIMDMode = "disabled"
	OAuthCIMDAllowlist OAuthCIMDMode = "allowlist"
	OAuthCIMDPublicWeb OAuthCIMDMode = "public_web"
)

// OAuthDCRMode is an issuer's dynamic client registration policy: disabled,
// protected by an initial access token, or open with a registration limit.
// It is independent of the CIMD policy.
type OAuthDCRMode string

const (
	OAuthDCRDisabled  OAuthDCRMode = "disabled"
	OAuthDCRProtected OAuthDCRMode = "protected"
	OAuthDCROpen      OAuthDCRMode = "open"
)

// OAuthClientSource records how a client record came to exist:
// administrative pre-registration, CIMD resolution, or DCR.
type OAuthClientSource string

const (
	OAuthClientPreRegistered OAuthClientSource = "pre_registered"
	OAuthClientCIMD          OAuthClientSource = "cimd"
	OAuthClientDCR           OAuthClientSource = "dcr"
)

// OAuthApplicationType distinguishes web clients (HTTPS redirect URIs only)
// from native clients (HTTPS, or plain HTTP on a loopback host).
type OAuthApplicationType string

const (
	OAuthApplicationWeb    OAuthApplicationType = "web"
	OAuthApplicationNative OAuthApplicationType = "native"
)

// OAuthTokenEndpointAuthMethod is how a client authenticates at the token
// endpoint. private_key_jwt requires Config.OAuth.ClientAssertions;
// client_secret_basic is only granted where the issuer policy allows it.
type OAuthTokenEndpointAuthMethod string

const (
	OAuthAuthNone              OAuthTokenEndpointAuthMethod = "none"
	OAuthAuthPrivateKeyJWT     OAuthTokenEndpointAuthMethod = "private_key_jwt"
	OAuthAuthClientSecretBasic OAuthTokenEndpointAuthMethod = "client_secret_basic"
)

// OAuthTokenKind distinguishes the two opaque bearer token families.
type OAuthTokenKind string

const (
	OAuthAccessTokenKind  OAuthTokenKind = "access_token"
	OAuthRefreshTokenKind OAuthTokenKind = "refresh_token"
)

// OAuthScopeDefinition declares one scope of a protected resource and its
// assurance policy. The workspace permissions behind the scope are
// re-evaluated on every bearer validation, not only at consent time.
type OAuthScopeDefinition struct {
	Name        string
	Description string
	// Permissions are the registered workspace permissions the grant's user
	// must hold for this scope. At least one is required.
	Permissions []WorkspacePermission
	// MinimumAAL is the assurance the authorizing session must have reached;
	// zero means AAL1.
	MinimumAAL AssuranceLevel
	// MaxAuthAge bounds how old the authorizing authentication may be; zero
	// disables the freshness requirement.
	MaxAuthAge time.Duration
}

// OAuthIssuer is one authorization server: its HTTPS issuer URL, CIMD, DCR
// and OIDC policy, and token lifetimes. A disabled issuer refuses every
// discovery, authorization and token operation.
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

// OAuthProtectedResource is a tenant-scoped MCP resource under an issuer.
// Access tokens are bound to its Resource URI and workspace and cannot be
// replayed elsewhere.
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

// OAuthClient is a persisted application identity under an issuer. ID is
// Credbound's record identifier while ClientID is the protocol client_id
// (equal to ID for pre-registered and DCR clients, the Client Identifier URL
// for CIMD clients).
type OAuthClient struct {
	ID              string
	IssuerID        string
	ClientID        string
	Source          OAuthClientSource
	Name            string
	ApplicationType OAuthApplicationType
	RedirectURIs    []string
	// SectorIdentifier is the single redirect-URI host used to derive
	// pairwise OIDC subjects.
	SectorIdentifier        string
	GrantTypes              []string
	ResponseTypes           []string
	Scopes                  []string
	TokenEndpointAuthMethod OAuthTokenEndpointAuthMethod
	JWKSURI                 string
	JWKS                    json.RawMessage
	// Trusted may only be set on pre-registered clients; CIMD and DCR
	// clients are never trusted.
	Trusted      bool
	SecretDigest []byte
	// MetadataHash fingerprints the client metadata. Grants pin it, so a
	// changed CIMD document invalidates the delegations approved under the
	// previous metadata.
	MetadataHash []byte
	// MetadataExpiresAt bounds a cached CIMD document; a stale record is
	// re-fetched on next resolution.
	MetadataExpiresAt *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DisabledAt        *time.Time
}

// IssuedOAuthClient carries the client secret exactly once, when a
// registration requested client_secret_basic; ClientSecret is empty
// otherwise. The public Client value has no secret digest.
type IssuedOAuthClient struct {
	Client       OAuthClient
	ClientSecret string
}

// OAuthInitialAccessToken is the persisted metadata of a protected-DCR
// bootstrap credential: expiring, revocable, limited to MaxRegistrations
// registrations, and granting no authority over any resource. Only the HMAC
// Digest of the raw token is stored.
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

// IssuedOAuthInitialAccessToken carries the raw DCR bootstrap token exactly
// once, from CreateOAuthInitialAccessToken.
type IssuedOAuthInitialAccessToken struct {
	Credential OAuthInitialAccessToken
	Token      string
}

// OAuthGrant is a persisted delegation from a user to a client for one
// resource and scope set. AuthTime, AuthMethod and AAL snapshot the
// authorizing session for OIDC claims, and MetadataHash pins the client
// metadata that was consented to. Revoking the grant kills its tokens.
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

// OAuthAuthorizationCode is the persisted single-use code of an approved
// authorization, stored as an HMAC digest with its PKCE challenge and exact
// redirect URI.
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

// OAuthAccessToken is the persisted metadata of an opaque access token,
// bound to one grant, resource and workspace. Only the HMAC Digest of the
// raw token is stored.
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

// OAuthRefreshToken is the persisted metadata of a rotating refresh token.
// Tokens descending from the same initial issuance share a FamilyID; reuse
// of a rotated token revokes the whole family.
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

// OAuthAuthentication is the validated bearer capability returned by
// AuthenticateOAuthAccessToken: the token, grant, client, user, workspace,
// resource and scopes a request may act with. Like Authentication, it must
// never be rebuilt from client-supplied data.
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

// HasScope reports whether the token carries the required scope; an empty
// requirement always passes.
func (a OAuthAuthentication) HasScope(required string) bool {
	return required == "" || slices.Contains(a.Scopes, required)
}

// OAuthClientMetadataDocument is a validated CIMD document as returned by an
// OAuthClientMetadataFetcher, with the fetch time and cache expiry that
// bound how long the resolved client may be reused.
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

// OAuthClientMetadataFetcher retrieves the CIMD document behind a Client
// Identifier URL. Implementations must defend against SSRF, DNS rebinding,
// redirects and oversized responses; oauthhttp.NewMetadataFetcher provides
// a hardened implementation.
type OAuthClientMetadataFetcher interface {
	Fetch(context.Context, string) (OAuthClientMetadataDocument, error)
}

// OAuthClientAssertionVerifier validates a private_key_jwt client assertion
// against the client's registered keys for the given token-endpoint
// audience at the given time. Implementations must provide atomic jti
// replay protection; oauthclientadapter.NewJWTAssertionVerifier is the
// bundled implementation.
type OAuthClientAssertionVerifier interface {
	Verify(context.Context, OAuthClient, string, string, time.Time) error
}

// OIDCClaims is the minimal ID Token claim set Credbound asks an OIDCSigner
// to sign. Subject is pairwise and never the user's global UUID.
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

// OIDCSigner signs ID Tokens and publishes the verification keys of an OIDC
// issuer. Algorithms advertises the actual signing algorithms for
// discovery; "none" is rejected. The bundled ES256 signer keeps one active
// signing key plus verification-only retiring keys.
type OIDCSigner interface {
	SignIDToken(context.Context, OIDCClaims) (string, error)
	JWKS(context.Context) (json.RawMessage, error)
	Algorithms() []string
}

// OIDCUserInfo is the minimal UserInfo response: the pairwise subject, and
// email claims only when the token carries the email scope.
type OIDCUserInfo struct {
	Subject       string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
}

// CreateOAuthIssuerInput describes a new issuer. Zero TTLs fall back to the
// defaults (5 minute codes, 15 minute access tokens, 30 day refresh
// tokens), each bounded by a hard maximum.
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

// CreateOAuthProtectedResourceInput describes a new MCP resource: its
// issuer, HTTPS resource URI and scope definitions.
type CreateOAuthProtectedResourceInput struct {
	IssuerID string
	Resource string
	Scopes   []OAuthScopeDefinition
}

// UpdateOAuthIssuerInput replaces an issuer's policy; the issuer URL itself
// is immutable. Zero TTLs fall back to the defaults.
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

// OAuthClientRegistrationInput is the client metadata accepted by
// pre-registration and DCR. Empty grant and response types default to
// authorization_code with code; Trusted is honored only for
// pre-registration.
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

// CreateOAuthInitialAccessTokenInput describes a protected-DCR bootstrap
// token: an expiry within 30 days and a registration limit between 1 and
// 100 (zero means 1).
type CreateOAuthInitialAccessTokenInput struct {
	ExpiresAt        time.Time
	MaxRegistrations int
}

// BeginOAuthAuthorizationInput is a parsed authorization request. Resource
// and State are mandatory, and only PKCE S256 is accepted.
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

// OAuthConsentScope is one scope of a pending consent with its
// human-readable description for the consent page.
type OAuthConsentScope struct {
	Name        string
	Description string
}

// OAuthConsent is a validated, sealed authorization awaiting the user's
// decision in the host UI. Only CompleteOAuthAuthorization can turn the
// Continuation into an approval or denial; the display fields let the host
// render an honest consent page.
type OAuthConsent struct {
	Continuation string
	ClientID     string
	ClientName   string
	ClientHost   string
	RedirectURI  string
	RedirectHost string
	Resource     string
	WorkspaceID  string
	Scopes       []OAuthConsentScope
	// RequiresStepUp signals that a requested scope demands a stronger or
	// fresher authentication than the current session; the host should
	// re-authenticate before completing.
	RequiresStepUp bool
	// LocalhostRedirect flags a localhost redirect target so the UI can warn
	// that the code will be delivered to a program on the user's machine.
	LocalhostRedirect bool
}

// OAuthAuthorizationResult is the outcome of a completed authorization: the
// redirect target with either the single-use Code (returned only once) or an
// OAuth error code such as access_denied.
type OAuthAuthorizationResult struct {
	RedirectURI string
	Code        string
	State       string
	Issuer      string
	Error       string
}

// ExchangeOAuthAuthorizationCodeInput is a parsed token-endpoint request for
// the authorization_code grant, including the client credentials or
// assertion and the PKCE verifier.
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

// RefreshOAuthTokenInput is a parsed token-endpoint request for the
// refresh_token grant. Scopes optionally narrows the issue to a subset of
// the granted scopes.
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

// RevokeOAuthTokenInput is a parsed RFC 7009 revocation request; Token may
// be an access or refresh token.
type RevokeOAuthTokenInput struct {
	Issuer              string
	ClientID            string
	ClientSecret        string
	ClientAssertion     string
	ClientAssertionType string
	Token               string
}

// OAuthTokenResponse is the token-endpoint success payload. The tokens are
// opaque, returned only once, and never recoverable from persisted models.
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token,omitempty"`
}

// OAuthAuthorizationServerMetadata is the RFC 8414 discovery document of an
// issuer.
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

// OAuthProtectedResourceMetadata is the RFC 9728 metadata document of a
// protected resource.
type OAuthProtectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
	BearerMethods        []string `json:"bearer_methods_supported"`
}
