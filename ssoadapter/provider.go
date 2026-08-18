package ssoadapter

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/deepteams/credbound"
	"golang.org/x/oauth2"
)

const (
	// defaultTimeout bounds every network call when the host does not supply
	// an HTTP client, and is applied to supplied clients that carry no
	// timeout of their own so a stalled issuer cannot hold a ceremony open.
	defaultTimeout = 10 * time.Second
	// maxClaimLength mirrors the issuer and subject cap enforced by
	// credbound in sso.go; the adapter fails fast with a descriptive error
	// instead of letting the library collapse it into ErrInvalidCredentials.
	maxClaimLength = 500
	// maxEmailLength mirrors credbound's email validation cap. An oversized
	// email claim is dropped rather than failing the ceremony, because SSO
	// identities are keyed on issuer and subject, never on email.
	maxEmailLength = 320
	// reauthenticationLeeway absorbs clock skew between the issuer and the
	// host when validating auth_time during forced re-authentication.
	reauthenticationLeeway = 5 * time.Minute
	// maxErrorDescription caps how much issuer-controlled error text is
	// echoed into adapter errors.
	maxErrorDescription = 200
)

// Sentinel errors for the two verification failures hosts most often want to
// distinguish in logs. Credbound maps every Finish error to
// ErrInvalidCredentials before it reaches the end user.
var (
	// ErrStateMismatch reports that the state parameter returned by the
	// issuer does not match the one issued in Begin.
	ErrStateMismatch = errors.New("ssoadapter: state parameter mismatch")
	// ErrNonceMismatch reports that the ID token nonce is missing or does
	// not match the one issued in Begin.
	ErrNonceMismatch = errors.New("ssoadapter: id token nonce mismatch")
)

// Config describes one OIDC provider registration.
type Config struct {
	// ConfigurationID is the host-chosen UUIDv7 under which credbound
	// indexes this provider and its linked identities. Required.
	ConfigurationID string
	// Kind is the credbound provider kind. Defaults to
	// credbound.SSOProviderOIDC; credbound.SSOProviderGoogle and
	// credbound.SSOProviderMicrosoft are also accepted since both speak
	// plain OIDC. Other kinds are rejected.
	Kind credbound.SSOProviderKind
	// IssuerURL is the OIDC issuer used for discovery and strict issuer
	// validation. Required. HTTPS is mandatory except for loopback hosts,
	// which may use HTTP for local development and tests.
	IssuerURL string
	// ClientID is the OAuth 2.0 client identifier. Required.
	ClientID string
	// ClientSecret authenticates the client at the token endpoint. Required
	// unless PublicClient is set; the default posture is a confidential
	// client.
	ClientSecret string
	// PublicClient marks this registration as a PKCE-only public client
	// without a client secret. When set, ClientSecret must be empty.
	PublicClient bool
	// RedirectURL is the callback URL registered at the issuer. Required.
	// HTTPS is mandatory except for loopback hosts.
	RedirectURL string
	// Scopes defaults to "openid email profile". The openid scope is always
	// enforced.
	Scopes []string
	// HTTPClient is used for discovery, key fetching, and the code
	// exchange. Defaults to a client with a 10 second timeout; a supplied
	// client without a timeout is shallow-copied and given the default.
	HTTPClient *http.Client
	// MetadataRefreshInterval bounds how long a discovered issuer document is
	// cached before it is re-discovered, so a rotated endpoint or jwks_uri is
	// picked up without a redeploy — the same posture as the SAML adapter's
	// metadata TTL. Zero uses a default of 12 hours.
	MetadataRefreshInterval time.Duration
	// Clock supplies the current time for token validation and step-up
	// freshness checks. Defaults to time.Now.
	Clock func() time.Time
}

// Provider is a generic OIDC implementation of credbound.SSOProvider. It is
// stateless across ceremonies: everything a Finish needs travels inside the
// opaque Session bytes that credbound seals into its continuation.
type Provider struct {
	configurationID string
	kind            credbound.SSOProviderKind
	issuerURL       string
	clientID        string
	clientSecret    string
	redirectURL     string
	scopes          []string
	client          *http.Client
	now             func() time.Time

	mu            sync.Mutex
	remote        *oidc.Provider
	remoteFetched time.Time
	metadataTTL   time.Duration
}

// session is the opaque payload carried through credbound's sealed
// continuation between Begin and Finish. It never reaches the browser in
// clear text: credbound encrypts it with its AEAD seal.
type session struct {
	State                 string    `json:"state"`
	Nonce                 string    `json:"nonce"`
	Verifier              string    `json:"verifier"`
	ForceReauthentication bool      `json:"force_reauthentication,omitempty"`
	IssuedAt              time.Time `json:"issued_at"`
}

// New validates the configuration and returns a Provider ready to register in
// credbound.Config.SSOProviders. Discovery is performed lazily on first use so
// construction does not require the issuer to be reachable.
func New(config Config) (*Provider, error) {
	if !validUUIDv7(config.ConfigurationID) {
		return nil, errors.New("ssoadapter: configuration id must be a UUIDv7")
	}
	kind := config.Kind
	if kind == "" {
		kind = credbound.SSOProviderOIDC
	}
	switch kind {
	case credbound.SSOProviderOIDC, credbound.SSOProviderGoogle, credbound.SSOProviderMicrosoft:
	default:
		return nil, fmt.Errorf("ssoadapter: kind %q is not an OIDC kind", kind)
	}
	issuerURL := strings.TrimSpace(config.IssuerURL)
	if err := validEndpointURL(issuerURL); err != nil {
		return nil, fmt.Errorf("ssoadapter: issuer url: %w", err)
	}
	redirectURL := strings.TrimSpace(config.RedirectURL)
	if err := validEndpointURL(redirectURL); err != nil {
		return nil, fmt.Errorf("ssoadapter: redirect url: %w", err)
	}
	clientID := strings.TrimSpace(config.ClientID)
	if clientID == "" {
		return nil, errors.New("ssoadapter: client id is required")
	}
	if config.PublicClient && config.ClientSecret != "" {
		return nil, errors.New("ssoadapter: a public client must not carry a client secret")
	}
	if !config.PublicClient && config.ClientSecret == "" {
		return nil, errors.New("ssoadapter: client secret is required for a confidential client (set PublicClient for a PKCE-only client)")
	}
	scopes, err := normalizeScopes(config.Scopes)
	if err != nil {
		return nil, err
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	metadataTTL := config.MetadataRefreshInterval
	if metadataTTL <= 0 {
		metadataTTL = 12 * time.Hour
	}
	return &Provider{
		configurationID: config.ConfigurationID,
		kind:            kind,
		issuerURL:       issuerURL,
		clientID:        clientID,
		clientSecret:    config.ClientSecret,
		redirectURL:     redirectURL,
		scopes:          scopes,
		client:          httpClient(config.HTTPClient),
		now:             clock,
		metadataTTL:     metadataTTL,
	}, nil
}

// ConfigurationID implements credbound.SSOProvider.
func (p *Provider) ConfigurationID() string { return p.configurationID }

// Kind implements credbound.SSOProvider.
func (p *Provider) Kind() credbound.SSOProviderKind { return p.kind }

// Begin implements credbound.SSOProvider. It generates fresh state, nonce,
// and PKCE S256 verifier material, builds the authorization code URL, and
// returns the material as opaque Session bytes for credbound to seal into its
// continuation. When ForceReauthentication is set the URL additionally
// carries prompt=login and max_age=0 so the issuer re-runs its own
// authentication (and MFA) policy.
func (p *Provider) Begin(ctx context.Context, request credbound.SSORequest) (credbound.SSOProviderChallenge, error) {
	remote, err := p.discover(ctx)
	if err != nil {
		return credbound.SSOProviderChallenge{}, err
	}
	state, err := randomToken()
	if err != nil {
		return credbound.SSOProviderChallenge{}, err
	}
	nonce, err := randomToken()
	if err != nil {
		return credbound.SSOProviderChallenge{}, err
	}
	verifier := oauth2.GenerateVerifier()
	options := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)}
	if request.ForceReauthentication {
		options = append(options,
			oauth2.SetAuthURLParam("prompt", "login"),
			oauth2.SetAuthURLParam("max_age", "0"),
		)
	}
	payload, err := json.Marshal(session{
		State: state, Nonce: nonce, Verifier: verifier,
		ForceReauthentication: request.ForceReauthentication,
		IssuedAt:              p.now().UTC(),
	})
	if err != nil {
		return credbound.SSOProviderChallenge{}, fmt.Errorf("ssoadapter: encode session: %w", err)
	}
	return credbound.SSOProviderChallenge{
		RedirectURL: p.oauthConfig(remote).AuthCodeURL(state, options...),
		Session:     payload,
	}, nil
}

// Finish implements credbound.SSOProvider. sessionBytes is the Session issued
// by Begin (returned by credbound from its sealed continuation) and response
// is the raw callback payload from the host: the full callback URL, the bare
// query string, or a JSON object with code and state fields.
//
// Finish verifies the state with a constant-time comparison, exchanges the
// code with the PKCE verifier, verifies the ID token (issuer, audience,
// expiry, RS256/ES256 allowlist — "none" and HMAC algorithms are rejected by
// construction), and requires a constant-time nonce match. Replay of a
// callback is bounded by credbound's continuation TTL and by the issuer's
// single-use authorization code; the adapter itself keeps no state.
func (p *Provider) Finish(ctx context.Context, sessionBytes, response []byte) (credbound.SSOClaims, error) {
	var state session
	if err := json.Unmarshal(sessionBytes, &state); err != nil {
		return credbound.SSOClaims{}, fmt.Errorf("ssoadapter: decode session: %w", err)
	}
	if state.State == "" || state.Nonce == "" || state.Verifier == "" {
		return credbound.SSOClaims{}, errors.New("ssoadapter: incomplete session")
	}
	values, err := callbackValues(response)
	if err != nil {
		return credbound.SSOClaims{}, err
	}
	if code := values.Get("error"); code != "" {
		return credbound.SSOClaims{}, fmt.Errorf("ssoadapter: authorization failed: %s: %s", code, truncate(values.Get("error_description"), maxErrorDescription))
	}
	if subtle.ConstantTimeCompare([]byte(values.Get("state")), []byte(state.State)) != 1 {
		return credbound.SSOClaims{}, ErrStateMismatch
	}
	code := values.Get("code")
	if code == "" {
		return credbound.SSOClaims{}, errors.New("ssoadapter: callback carries no authorization code")
	}
	remote, err := p.discover(ctx)
	if err != nil {
		return credbound.SSOClaims{}, err
	}
	clientCtx := oidc.ClientContext(ctx, p.client)
	token, err := p.oauthConfig(remote).Exchange(clientCtx, code, oauth2.VerifierOption(state.Verifier))
	if err != nil {
		return credbound.SSOClaims{}, fmt.Errorf("ssoadapter: exchange authorization code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return credbound.SSOClaims{}, errors.New("ssoadapter: token response carries no id_token")
	}
	verifier := remote.VerifierContext(clientCtx, &oidc.Config{
		ClientID:             p.clientID,
		SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256},
		Now:                  p.now,
	})
	idToken, err := verifier.Verify(clientCtx, rawIDToken)
	if err != nil {
		return credbound.SSOClaims{}, fmt.Errorf("ssoadapter: verify id token: %w", err)
	}
	if idToken.Nonce == "" || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(state.Nonce)) != 1 {
		return credbound.SSOClaims{}, ErrNonceMismatch
	}
	var extra struct {
		Email         string       `json:"email"`
		EmailVerified assertedBool `json:"email_verified"`
		AuthTime      float64      `json:"auth_time"`
		ACR           string       `json:"acr"`
		AMR           []string     `json:"amr"`
	}
	if err := idToken.Claims(&extra); err != nil {
		return credbound.SSOClaims{}, fmt.Errorf("ssoadapter: decode id token claims: %w", err)
	}
	if state.ForceReauthentication {
		if err := verifyReauthentication(extra.AuthTime, state.IssuedAt); err != nil {
			return credbound.SSOClaims{}, err
		}
	}
	issuer, subject := strings.TrimSpace(idToken.Issuer), strings.TrimSpace(idToken.Subject)
	if issuer == "" || subject == "" || len(issuer) > maxClaimLength || len(subject) > maxClaimLength {
		return credbound.SSOClaims{}, errors.New("ssoadapter: issuer or subject claim is empty or exceeds 500 characters")
	}
	claims := credbound.SSOClaims{Issuer: issuer, Subject: subject}
	// The asserted authentication context is forwarded, bounded, so the
	// host's Config.SSOAssurance policy can verify MFA instead of assuming
	// it.
	if acr := strings.TrimSpace(extra.ACR); acr != "" && len(acr) <= maxClaimLength {
		claims.ACR = acr
	}
	for _, method := range extra.AMR {
		if method = strings.TrimSpace(method); method != "" && len(method) <= maxClaimLength && len(claims.AMR) < 16 {
			claims.AMR = append(claims.AMR, method)
		}
	}
	// Only a verified email is forwarded: at many issuers the profile email
	// is user-typed and unproven, so an unverified value would let a hostile
	// account plant a victim's address in credbound's identity records.
	if email := strings.TrimSpace(extra.Email); bool(extra.EmailVerified) && email != "" && len(email) <= maxEmailLength {
		claims.Email, claims.EmailVerified = email, true
	}
	return claims, nil
}

// discover resolves and caches the issuer metadata. A successful discovery
// is reused until metadataTTL elapses, then re-discovered so a rotated
// endpoint or jwks_uri is picked up without a redeploy; a failed refresh
// keeps serving the last good document rather than breaking authentication.
// Initial failures are retried on
// the next call.
func (p *Provider) discover(ctx context.Context) (*oidc.Provider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.remote != nil && p.now().Before(p.remoteFetched.Add(p.metadataTTL)) {
		return p.remote, nil
	}
	remote, err := oidc.NewProvider(oidc.ClientContext(ctx, p.client), p.issuerURL)
	if err != nil {
		if p.remote != nil {
			return p.remote, nil
		}
		return nil, fmt.Errorf("ssoadapter: discover issuer: %w", err)
	}
	p.remote, p.remoteFetched = remote, p.now()
	return remote, nil
}

func (p *Provider) oauthConfig(remote *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		Endpoint:     remote.Endpoint(),
		RedirectURL:  p.redirectURL,
		Scopes:       p.scopes,
	}
}

// verifyReauthentication enforces that a forced re-authentication actually
// happened. With max_age the OIDC spec requires auth_time in the ID token,
// and a fresh login must not predate the ceremony (minus clock-skew leeway).
func verifyReauthentication(authTime float64, issuedAt time.Time) error {
	if authTime <= 0 {
		return errors.New("ssoadapter: forced re-authentication requires an auth_time claim")
	}
	if issuedAt.IsZero() {
		return nil
	}
	authenticatedAt := time.Unix(int64(authTime), 0)
	if authenticatedAt.Add(reauthenticationLeeway).Before(issuedAt) {
		return errors.New("ssoadapter: issuer did not re-authenticate the user for step-up")
	}
	return nil
}

// callbackValues extracts the OAuth response parameters from the host's raw
// callback payload: a full URL, a bare query string, or a JSON object.
func callbackValues(response []byte) (url.Values, error) {
	raw := strings.TrimSpace(string(response))
	if raw == "" {
		return nil, errors.New("ssoadapter: empty callback response")
	}
	switch {
	case strings.HasPrefix(raw, "{"):
		var body struct {
			Code             string `json:"code"`
			State            string `json:"state"`
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.Unmarshal(response, &body); err != nil {
			return nil, fmt.Errorf("ssoadapter: decode callback response: %w", err)
		}
		values := url.Values{}
		for key, value := range map[string]string{
			"code": body.Code, "state": body.State,
			"error": body.Error, "error_description": body.ErrorDescription,
		} {
			if value != "" {
				values.Set(key, value)
			}
		}
		return values, nil
	case strings.Contains(raw, "?") || strings.Contains(raw, "://"):
		parsed, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("ssoadapter: parse callback url: %w", err)
		}
		values, err := url.ParseQuery(parsed.RawQuery)
		if err != nil {
			return nil, fmt.Errorf("ssoadapter: parse callback query: %w", err)
		}
		return values, nil
	default:
		values, err := url.ParseQuery(raw)
		if err != nil {
			return nil, fmt.Errorf("ssoadapter: parse callback query: %w", err)
		}
		return values, nil
	}
}

// assertedBool decodes the email_verified claim, which issuers emit as a JSON
// bool or, at some IdPs, the strings "true"/"false". Anything unrecognized
// decodes to false so a malformed assertion fails closed to "unverified"
// instead of failing the ceremony.
type assertedBool bool

func (b *assertedBool) UnmarshalJSON(data []byte) error {
	*b = strings.Trim(strings.ToLower(strings.TrimSpace(string(data))), `"`) == "true"
	return nil
}

func normalizeScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return []string{oidc.ScopeOpenID, "email", "profile"}, nil
	}
	normalized := make([]string, 0, len(scopes)+1)
	hasOpenID := false
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return nil, errors.New("ssoadapter: scopes must not be blank")
		}
		if scope == oidc.ScopeOpenID {
			hasOpenID = true
		}
		normalized = append(normalized, scope)
	}
	if !hasOpenID {
		normalized = append([]string{oidc.ScopeOpenID}, normalized...)
	}
	return normalized, nil
}

func httpClient(client *http.Client) *http.Client {
	if client == nil {
		return &http.Client{Timeout: defaultTimeout}
	}
	if client.Timeout == 0 {
		clone := *client
		clone.Timeout = defaultTimeout
		return &clone
	}
	return client
}

func randomToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("ssoadapter: read secure randomness: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func validEndpointURL(value string) error {
	if value == "" {
		return errors.New("required")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return err
	}
	host := parsed.Hostname()
	switch parsed.Scheme {
	case "https":
	case "http":
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return errors.New("http is only allowed for loopback hosts")
		}
	default:
		return fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if host == "" {
		return errors.New("missing host")
	}
	return nil
}

// validUUIDv7 mirrors credbound's registration rule so misconfiguration
// surfaces at adapter construction instead of at credbound.New.
func validUUIDv7(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || value[14] != '7' {
		return false
	}
	if !strings.ContainsRune("89ab", rune(value[19])) {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
