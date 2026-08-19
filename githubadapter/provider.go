package githubadapter

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/deepteams/credbound"
)

const (
	// defaultTimeout bounds every network call when the host does not supply
	// an HTTP client, and is applied to supplied clients that carry no
	// timeout of their own so a stalled GitHub cannot hold a ceremony open.
	defaultTimeout = 10 * time.Second
	// maxClaimLength mirrors the issuer and subject cap enforced by
	// credbound in sso.go; the adapter fails fast with a descriptive error
	// instead of letting the library collapse it into ErrInvalidCredentials.
	maxClaimLength = 500
	// maxEmailLength mirrors credbound's email validation cap. An oversized
	// email is dropped rather than failing the ceremony, because SSO
	// identities are keyed on issuer and subject, never on email.
	maxEmailLength = 320
	// maxErrorDescription caps how much provider-controlled error text is
	// echoed into adapter errors.
	maxErrorDescription = 200
	// maxResponseBody caps how much of a token or REST response body the
	// adapter is willing to read.
	maxResponseBody = 1 << 20

	// issuer is the constant credbound issuer claim for every GitHub
	// identity. GitHub is not an OIDC issuer; this fixed value plus the
	// numeric account id forms the stable link key.
	issuer = "https://github.com"

	defaultAuthorizeURL = "https://github.com/login/oauth/authorize"
	defaultTokenURL     = "https://github.com/login/oauth/access_token"
	defaultAPIBaseURL   = "https://api.github.com"

	// apiVersion pins the GitHub REST API revision the adapter is written
	// against, per GitHub's versioning guidance.
	apiVersion = "2022-11-28"
)

// Sentinel errors for the failures hosts most often want to distinguish in
// logs. Credbound maps every Begin/Finish error to ErrInvalidCredentials
// before it reaches the end user.
var (
	// ErrStateMismatch reports that the state parameter returned by GitHub
	// does not match the one issued in Begin.
	ErrStateMismatch = errors.New("githubadapter: state parameter mismatch")
	// ErrStepUpUnsupported reports a Begin with ForceReauthentication set:
	// GitHub's authorization endpoint cannot force a fresh login, so the
	// adapter refuses to run a step-up ceremony it cannot honor rather than
	// silently reusing GitHub's existing browser session.
	ErrStepUpUnsupported = errors.New("githubadapter: github cannot force re-authentication; step-up ceremonies must use another provider")
)

// Config describes one GitHub OAuth app registration.
type Config struct {
	// ConfigurationID is the host-chosen UUIDv7 under which credbound
	// indexes this provider and its linked identities. Required.
	ConfigurationID credbound.UUID
	// ClientID is the OAuth app's client identifier. Required.
	ClientID string
	// ClientSecret authenticates the client at the token endpoint.
	// Required: GitHub OAuth apps are confidential clients.
	ClientSecret string
	// RedirectURL is the callback URL registered at GitHub. Required.
	// HTTPS is mandatory except for loopback hosts, which may use HTTP for
	// local development and tests.
	RedirectURL string
	// Scopes defaults to "read:user user:email" — enough to read the stable
	// numeric account id and the primary email with its verified flag.
	Scopes []string
	// HTTPClient is used for the code exchange and the REST calls. Defaults
	// to a client with a 10 second timeout; a supplied client without a
	// timeout is shallow-copied and given the default.
	HTTPClient *http.Client
	// AuthorizeURL overrides GitHub's authorization endpoint, for tests.
	// Defaults to https://github.com/login/oauth/authorize.
	AuthorizeURL string
	// TokenURL overrides GitHub's token endpoint, for tests. Defaults to
	// https://github.com/login/oauth/access_token.
	TokenURL string
	// APIBaseURL overrides the GitHub REST API base, for tests. Defaults to
	// https://api.github.com.
	APIBaseURL string
}

// Provider is the GitHub implementation of credbound.SSOProvider. It is
// stateless across ceremonies: everything a Finish needs travels inside the
// opaque Session bytes that credbound seals into its continuation.
type Provider struct {
	configurationID credbound.UUID
	clientID        string
	clientSecret    string
	redirectURL     string
	scopes          []string
	authorizeURL    string
	tokenURL        string
	apiBaseURL      string
	client          *http.Client
}

// session is the opaque payload carried through credbound's sealed
// continuation between Begin and Finish. It never reaches the browser in
// clear text: credbound encrypts it with its AEAD seal.
type session struct {
	State string `json:"state"`
	// Verifier is the PKCE code verifier whose S256 challenge Begin sent to
	// the authorization endpoint. Empty only for a continuation sealed by a
	// pre-PKCE Begin; Finish then omits code_verifier, matching the
	// challenge-less authorization it belongs to.
	Verifier string `json:"verifier,omitempty"`
}

// New validates the configuration and returns a Provider ready to register in
// credbound.Config.SSOProviders. Construction performs no network calls.
func New(config Config) (*Provider, error) {
	if !validUUIDv7(config.ConfigurationID) {
		return nil, errors.New("githubadapter: configuration id must be a UUIDv7")
	}
	clientID := strings.TrimSpace(config.ClientID)
	if clientID == "" {
		return nil, errors.New("githubadapter: client id is required")
	}
	if config.ClientSecret == "" {
		return nil, errors.New("githubadapter: client secret is required (github oauth apps are confidential clients)")
	}
	redirectURL := strings.TrimSpace(config.RedirectURL)
	if err := validEndpointURL(redirectURL); err != nil {
		return nil, fmt.Errorf("githubadapter: redirect url: %w", err)
	}
	authorizeURL, err := endpointOrDefault(config.AuthorizeURL, defaultAuthorizeURL)
	if err != nil {
		return nil, fmt.Errorf("githubadapter: authorize url: %w", err)
	}
	tokenURL, err := endpointOrDefault(config.TokenURL, defaultTokenURL)
	if err != nil {
		return nil, fmt.Errorf("githubadapter: token url: %w", err)
	}
	apiBaseURL, err := endpointOrDefault(config.APIBaseURL, defaultAPIBaseURL)
	if err != nil {
		return nil, fmt.Errorf("githubadapter: api base url: %w", err)
	}
	scopes, err := normalizeScopes(config.Scopes)
	if err != nil {
		return nil, err
	}
	return &Provider{
		configurationID: config.ConfigurationID,
		clientID:        clientID,
		clientSecret:    config.ClientSecret,
		redirectURL:     redirectURL,
		scopes:          scopes,
		authorizeURL:    authorizeURL,
		tokenURL:        tokenURL,
		apiBaseURL:      strings.TrimRight(apiBaseURL, "/"),
		client:          httpClient(config.HTTPClient),
	}, nil
}

// ConfigurationID implements credbound.SSOProvider.
func (p *Provider) ConfigurationID() credbound.UUID { return p.configurationID }

// Kind implements credbound.SSOProvider.
func (p *Provider) Kind() credbound.SSOProviderKind { return credbound.SSOProviderGitHub }

// Begin implements credbound.SSOProvider. It generates a fresh state and a
// PKCE S256 challenge, builds the GitHub authorization URL (with
// allow_signup=false so the ceremony only authenticates existing GitHub
// accounts), and returns the state and verifier as opaque Session bytes for
// credbound to seal into its continuation.
//
// A request with ForceReauthentication set fails with ErrStepUpUnsupported:
// GitHub's authorization endpoint has no prompt/max_age equivalent, so the
// adapter cannot make GitHub re-verify the user, and a step-up ceremony must
// not pretend it did.
func (p *Provider) Begin(_ context.Context, request credbound.SSORequest) (credbound.SSOProviderChallenge, error) {
	if request.ForceReauthentication {
		return credbound.SSOProviderChallenge{}, ErrStepUpUnsupported
	}
	state, err := randomToken()
	if err != nil {
		return credbound.SSOProviderChallenge{}, err
	}
	verifier, err := randomToken()
	if err != nil {
		return credbound.SSOProviderChallenge{}, err
	}
	payload, err := json.Marshal(session{State: state, Verifier: verifier})
	if err != nil {
		return credbound.SSOProviderChallenge{}, fmt.Errorf("githubadapter: encode session: %w", err)
	}
	challenge := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"client_id":             {p.clientID},
		"redirect_uri":          {p.redirectURL},
		"scope":                 {strings.Join(p.scopes, " ")},
		"state":                 {state},
		"allow_signup":          {"false"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	return credbound.SSOProviderChallenge{
		RedirectURL: p.authorizeURL + "?" + query.Encode(),
		Session:     payload,
	}, nil
}

// Finish implements credbound.SSOProvider. sessionBytes is the Session issued
// by Begin (returned by credbound from its sealed continuation) and response
// is the raw callback payload from the host: the full callback URL, the bare
// query string, or a JSON object with code and state fields.
//
// Finish verifies the state with a constant-time comparison, exchanges the
// code at the token endpoint, then reads the account through the REST API:
// the numeric account id becomes the subject (logins are renameable and never
// used) and the primary email is forwarded with GitHub's own verified flag.
// Replay of a callback is bounded by credbound's continuation TTL and by
// GitHub's single-use authorization code; the adapter itself keeps no state.
func (p *Provider) Finish(ctx context.Context, sessionBytes, response []byte) (credbound.SSOClaims, error) {
	var state session
	if err := json.Unmarshal(sessionBytes, &state); err != nil {
		return credbound.SSOClaims{}, fmt.Errorf("githubadapter: decode session: %w", err)
	}
	if state.State == "" {
		return credbound.SSOClaims{}, errors.New("githubadapter: incomplete session")
	}
	values, err := callbackValues(response)
	if err != nil {
		return credbound.SSOClaims{}, err
	}
	if code := values.Get("error"); code != "" {
		return credbound.SSOClaims{}, fmt.Errorf("githubadapter: authorization failed: %s: %s", code, truncate(values.Get("error_description"), maxErrorDescription))
	}
	if subtle.ConstantTimeCompare([]byte(values.Get("state")), []byte(state.State)) != 1 {
		return credbound.SSOClaims{}, ErrStateMismatch
	}
	code := values.Get("code")
	if code == "" {
		return credbound.SSOClaims{}, errors.New("githubadapter: callback carries no authorization code")
	}
	accessToken, err := p.exchange(ctx, code, state.Verifier)
	if err != nil {
		return credbound.SSOClaims{}, err
	}
	account, err := p.fetchUser(ctx, accessToken)
	if err != nil {
		return credbound.SSOClaims{}, err
	}
	subject := strconv.FormatInt(account.ID, 10)
	if len(subject) > maxClaimLength || len(issuer) > maxClaimLength {
		return credbound.SSOClaims{}, errors.New("githubadapter: issuer or subject claim exceeds 500 characters")
	}
	claims := credbound.SSOClaims{Issuer: issuer, Subject: subject}
	email, verified, err := p.fetchPrimaryEmail(ctx, accessToken)
	if err != nil {
		return credbound.SSOClaims{}, err
	}
	if email == "" {
		// The user:email scope was declined or the account exposes no
		// primary address: fall back to the public profile email, which
		// GitHub does not assert as verified.
		email, verified = account.Email, false
	}
	// An oversized email is dropped, never fatal — credbound keys SSO
	// identities on issuer and subject, never on email.
	if email = strings.TrimSpace(email); email != "" && len(email) <= maxEmailLength {
		claims.Email, claims.EmailVerified = email, verified
	}
	return claims, nil
}

// exchange redeems the authorization code at the token endpoint, presenting
// the PKCE verifier matching the challenge Begin sent. GitHub answers HTTP
// 200 even for protocol errors, carrying error/error_description in the JSON
// body, so both channels are checked.
func (p *Provider) exchange(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"code":          {code},
		"redirect_uri":  {p.redirectURL},
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("githubadapter: build token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	body, status, err := p.do(request)
	if err != nil {
		return "", fmt.Errorf("githubadapter: exchange authorization code: %w", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("githubadapter: exchange authorization code: token endpoint answered status %d", status)
	}
	var token struct {
		AccessToken      string `json:"access_token"`
		TokenType        string `json:"token_type"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		return "", fmt.Errorf("githubadapter: decode token response: %w", err)
	}
	if token.Error != "" {
		return "", fmt.Errorf("githubadapter: exchange authorization code: %s: %s", token.Error, truncate(token.ErrorDescription, maxErrorDescription))
	}
	if token.AccessToken == "" {
		return "", errors.New("githubadapter: token response carries no access token")
	}
	if token.TokenType != "" && !strings.EqualFold(token.TokenType, "bearer") {
		return "", fmt.Errorf("githubadapter: unexpected token type %q", truncate(token.TokenType, maxErrorDescription))
	}
	return token.AccessToken, nil
}

// githubAccount is the subset of GET /user the adapter reads: the stable
// numeric id and the public profile email (unproven, used only as the
// fallback when /user/emails is unavailable).
type githubAccount struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
}

func (p *Provider) fetchUser(ctx context.Context, accessToken string) (githubAccount, error) {
	body, status, err := p.api(ctx, accessToken, "/user")
	if err != nil {
		return githubAccount{}, fmt.Errorf("githubadapter: fetch user: %w", err)
	}
	if status != http.StatusOK {
		return githubAccount{}, fmt.Errorf("githubadapter: fetch user: api answered status %d", status)
	}
	var account githubAccount
	if err := json.Unmarshal(body, &account); err != nil {
		return githubAccount{}, fmt.Errorf("githubadapter: decode user response: %w", err)
	}
	if account.ID <= 0 {
		return githubAccount{}, errors.New("githubadapter: user response carries no account id")
	}
	return account, nil
}

// fetchPrimaryEmail reads GET /user/emails and returns the primary address
// with GitHub's verified flag. A 403 or 404 means the user:email scope was
// declined (GitHub answers 404 for a missing scope on this endpoint); the
// caller then falls back to the unproven profile email.
func (p *Provider) fetchPrimaryEmail(ctx context.Context, accessToken string) (string, bool, error) {
	body, status, err := p.api(ctx, accessToken, "/user/emails")
	if err != nil {
		return "", false, fmt.Errorf("githubadapter: fetch user emails: %w", err)
	}
	switch status {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusNotFound:
		return "", false, nil
	default:
		return "", false, fmt.Errorf("githubadapter: fetch user emails: api answered status %d", status)
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", false, fmt.Errorf("githubadapter: decode user emails response: %w", err)
	}
	for _, email := range emails {
		if email.Primary {
			return email.Email, email.Verified, nil
		}
	}
	return "", false, nil
}

// api performs one authenticated GET against the REST base with the headers
// GitHub's documentation requires.
func (p *Provider) api(ctx context.Context, accessToken, path string) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiBaseURL+path, nil)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	return p.do(request)
}

// do executes the request and reads at most maxResponseBody bytes of the
// answer, so a hostile or broken endpoint cannot balloon memory.
func (p *Provider) do(request *http.Request) ([]byte, int, error) {
	response, err := p.client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > maxResponseBody {
		return nil, 0, fmt.Errorf("response body exceeds %d bytes", maxResponseBody)
	}
	return body, response.StatusCode, nil
}

// callbackValues extracts the OAuth response parameters from the host's raw
// callback payload: a full URL, a bare query string, or a JSON object.
func callbackValues(response []byte) (url.Values, error) {
	raw := strings.TrimSpace(string(response))
	if raw == "" {
		return nil, errors.New("githubadapter: empty callback response")
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
			return nil, fmt.Errorf("githubadapter: decode callback response: %w", err)
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
			return nil, fmt.Errorf("githubadapter: parse callback url: %w", err)
		}
		values, err := url.ParseQuery(parsed.RawQuery)
		if err != nil {
			return nil, fmt.Errorf("githubadapter: parse callback query: %w", err)
		}
		return values, nil
	default:
		values, err := url.ParseQuery(raw)
		if err != nil {
			return nil, fmt.Errorf("githubadapter: parse callback query: %w", err)
		}
		return values, nil
	}
}

func normalizeScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return []string{"read:user", "user:email"}, nil
	}
	normalized := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return nil, errors.New("githubadapter: scopes must not be blank")
		}
		normalized = append(normalized, scope)
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
		return "", fmt.Errorf("githubadapter: read secure randomness: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func endpointOrDefault(value, fallback string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	if err := validEndpointURL(value); err != nil {
		return "", err
	}
	return value, nil
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
// validUUIDv7 reports whether the identifier was minted by Credbound: present,
// version 7, and carrying the RFC 9562 variant.
func validUUIDv7(id credbound.UUID) bool {
	return id[6]&0xf0 == 0x70 && id[8]&0xc0 == 0x80
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
