package ssoadapter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

const testConfigurationID = "0198b463-51a2-7cde-8000-0123456789ab"

func testConfig(issuerURL string) Config {
	return Config{
		ConfigurationID: testConfigurationID,
		IssuerURL:       issuerURL,
		ClientID:        "test-client",
		ClientSecret:    "test-secret",
		RedirectURL:     "https://app.example.com/sso/callback",
	}
}

func newTestProvider(t *testing.T, issuer *testIssuer, mutate func(*Config)) *Provider {
	t.Helper()
	config := testConfig(issuer.url())
	if mutate != nil {
		mutate(&config)
	}
	provider, err := New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return provider
}

// begin runs Begin, wires the generated nonce into the issuer, and returns
// the challenge plus the parsed authorization URL query.
func begin(t *testing.T, issuer *testIssuer, provider *Provider, force bool) (credbound.SSOProviderChallenge, map[string]string) {
	t.Helper()
	challenge, err := provider.Begin(context.Background(), credbound.SSORequest{ForceReauthentication: force})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	query := mustParseURL(t, challenge.RedirectURL).Query()
	params := map[string]string{}
	for key := range query {
		params[key] = query.Get(key)
	}
	issuer.setNonce(params["nonce"])
	return challenge, params
}

func callbackURL(state string) []byte {
	return []byte("https://app.example.com/sso/callback?code=test-code&state=" + state)
}

func TestBeginBuildsHardenedAuthorizationURL(t *testing.T) {
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)
	challenge, params := begin(t, issuer, provider, false)

	if !strings.HasPrefix(challenge.RedirectURL, issuer.url()+"/authorize?") {
		t.Fatalf("redirect url = %q, want authorization endpoint", challenge.RedirectURL)
	}
	if params["response_type"] != "code" || params["client_id"] != "test-client" {
		t.Fatalf("unexpected core params: %v", params)
	}
	if params["redirect_uri"] != "https://app.example.com/sso/callback" {
		t.Fatalf("redirect_uri = %q", params["redirect_uri"])
	}
	if params["scope"] != "openid email profile" {
		t.Fatalf("scope = %q, want default openid email profile", params["scope"])
	}
	if params["code_challenge_method"] != "S256" || params["code_challenge"] == "" {
		t.Fatalf("missing PKCE S256 challenge: %v", params)
	}
	if params["state"] == "" || params["nonce"] == "" {
		t.Fatal("state and nonce must be present")
	}
	if params["prompt"] != "" || params["max_age"] != "" {
		t.Fatal("prompt/max_age must be absent without forced re-authentication")
	}

	var s session
	if err := json.Unmarshal(challenge.Session, &s); err != nil {
		t.Fatalf("session must be JSON: %v", err)
	}
	if s.State != params["state"] || s.Nonce != params["nonce"] {
		t.Fatal("session must carry the state and nonce from the URL")
	}
	if challengeFor(s.Verifier) != params["code_challenge"] {
		t.Fatal("code_challenge must be the S256 digest of the session verifier")
	}
	if s.ForceReauthentication || s.IssuedAt.IsZero() {
		t.Fatalf("unexpected session flags: %+v", s)
	}

	// Two ceremonies never share material.
	_, second := begin(t, issuer, provider, false)
	if second["state"] == params["state"] || second["nonce"] == params["nonce"] {
		t.Fatal("state and nonce must be fresh per ceremony")
	}
}

func TestBeginForceReauthentication(t *testing.T) {
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)
	challenge, params := begin(t, issuer, provider, true)

	if params["prompt"] != "login" || params["max_age"] != "0" {
		t.Fatalf("forced re-authentication must add prompt=login and max_age=0, got %v", params)
	}
	var s session
	if err := json.Unmarshal(challenge.Session, &s); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if !s.ForceReauthentication {
		t.Fatal("session must record forced re-authentication")
	}
}

func TestFinishHappyPathWithVerifiedEmail(t *testing.T) {
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)
	issuer.setClaim("email", "User@Example.com")
	issuer.setClaim("email_verified", true)
	challenge, params := begin(t, issuer, provider, false)

	claims, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if claims.Issuer != issuer.url() || claims.Subject != "user-123" {
		t.Fatalf("claims = %+v", claims)
	}
	if claims.Email != "User@Example.com" || !claims.EmailVerified {
		t.Fatalf("verified email must be forwarded, got %+v", claims)
	}

	form := issuer.tokenRequest()
	if form.Get("code") != "test-code" || form.Get("grant_type") != "authorization_code" {
		t.Fatalf("token request = %v", form)
	}
	if challengeFor(form.Get("code_verifier")) != params["code_challenge"] {
		t.Fatal("exchange must send the PKCE verifier matching the challenge")
	}
}

func TestFinishAcceptsBareQueryAndJSONCallbacks(t *testing.T) {
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)

	challenge, params := begin(t, issuer, provider, false)
	if _, err := provider.Finish(context.Background(), challenge.Session, []byte("code=test-code&state="+params["state"])); err != nil {
		t.Fatalf("bare query callback: %v", err)
	}

	challenge, params = begin(t, issuer, provider, false)
	payload := []byte(`{"code":"test-code","state":"` + params["state"] + `"}`)
	if _, err := provider.Finish(context.Background(), challenge.Session, payload); err != nil {
		t.Fatalf("json callback: %v", err)
	}
}

func TestFinishDropsUnverifiedEmail(t *testing.T) {
	for name, verified := range map[string]any{
		"bool false":     false,
		"string false":   "false",
		"absent":         nil,
		"garbage number": 1,
	} {
		t.Run(name, func(t *testing.T) {
			issuer := newTestIssuer(t)
			provider := newTestProvider(t, issuer, nil)
			issuer.setClaim("email", "victim@example.com")
			if verified != nil {
				issuer.setClaim("email_verified", verified)
			}
			challenge, params := begin(t, issuer, provider, false)
			claims, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
			if err != nil {
				t.Fatalf("Finish: %v", err)
			}
			if claims.Email != "" || claims.EmailVerified {
				t.Fatalf("unverified email must be dropped, got %+v", claims)
			}
			if claims.Issuer == "" || claims.Subject == "" {
				t.Fatal("issuer and subject must survive without email")
			}
		})
	}
}

func TestFinishAcceptsStringTrueEmailVerified(t *testing.T) {
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)
	issuer.setClaim("email", "user@example.com")
	issuer.setClaim("email_verified", "true")
	challenge, params := begin(t, issuer, provider, false)
	claims, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if claims.Email != "user@example.com" || !claims.EmailVerified {
		t.Fatalf("string-true email_verified must be accepted, got %+v", claims)
	}
}

func TestFinishRejectsStateMismatch(t *testing.T) {
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)
	challenge, _ := begin(t, issuer, provider, false)

	_, err := provider.Finish(context.Background(), challenge.Session, callbackURL("attacker-state"))
	if !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("err = %v, want ErrStateMismatch", err)
	}
	if issuer.tokenRequest() != nil {
		t.Fatal("state mismatch must be rejected before any code exchange")
	}
}

func TestFinishRejectsNonceMismatch(t *testing.T) {
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)
	challenge, params := begin(t, issuer, provider, false)
	issuer.setNonce("attacker-nonce")

	_, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
	if !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("err = %v, want ErrNonceMismatch", err)
	}
}

func TestFinishRejectsMissingNonce(t *testing.T) {
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)
	challenge, params := begin(t, issuer, provider, false)
	issuer.setNonce("") // ID token without a nonce claim

	_, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
	if !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("err = %v, want ErrNonceMismatch", err)
	}
}

func TestFinishRejectsExpiredToken(t *testing.T) {
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)
	issuer.setTokenTTL(-time.Hour)
	challenge, params := begin(t, issuer, provider, false)

	_, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
	if err == nil || !strings.Contains(err.Error(), "verify id token") {
		t.Fatalf("err = %v, want id token verification failure", err)
	}
}

func TestFinishRejectsWrongAudience(t *testing.T) {
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)
	issuer.setClaim("aud", "another-client")
	challenge, params := begin(t, issuer, provider, false)

	_, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
	if err == nil || !strings.Contains(err.Error(), "verify id token") {
		t.Fatalf("err = %v, want audience rejection", err)
	}
}

func TestFinishStepUpRequiresFreshAuthTime(t *testing.T) {
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)

	// Missing auth_time on a forced re-authentication is rejected.
	challenge, params := begin(t, issuer, provider, true)
	if _, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"])); err == nil || !strings.Contains(err.Error(), "auth_time") {
		t.Fatalf("err = %v, want missing auth_time rejection", err)
	}

	// A stale auth_time (older than the ceremony minus leeway) is rejected.
	issuer.setClaim("auth_time", time.Now().Add(-2*time.Hour).Unix())
	challenge, params = begin(t, issuer, provider, true)
	if _, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"])); err == nil || !strings.Contains(err.Error(), "re-authenticate") {
		t.Fatalf("err = %v, want stale re-authentication rejection", err)
	}

	// A fresh auth_time passes.
	issuer.setClaim("auth_time", time.Now().Unix())
	challenge, params = begin(t, issuer, provider, true)
	if _, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"])); err != nil {
		t.Fatalf("fresh step-up Finish: %v", err)
	}
}

func TestFinishRejectsOversizedSubjectClaim(t *testing.T) {
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)
	issuer.setClaim("sub", strings.Repeat("s", maxClaimLength+1))
	challenge, params := begin(t, issuer, provider, false)

	_, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
	if err == nil || !strings.Contains(err.Error(), "500 characters") {
		t.Fatalf("err = %v, want claim length rejection", err)
	}
}

func TestFinishDropsOversizedEmail(t *testing.T) {
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)
	issuer.setClaim("email", strings.Repeat("a", maxEmailLength)+"@example.com")
	issuer.setClaim("email_verified", true)
	challenge, params := begin(t, issuer, provider, false)

	claims, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if claims.Email != "" || claims.EmailVerified {
		t.Fatalf("oversized email must be dropped, got %+v", claims)
	}
}

func TestFinishRejectsProviderErrorCallback(t *testing.T) {
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)
	challenge, _ := begin(t, issuer, provider, false)

	response := []byte("https://app.example.com/sso/callback?error=access_denied&error_description=user+cancelled")
	_, err := provider.Finish(context.Background(), challenge.Session, response)
	if err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("err = %v, want access_denied", err)
	}
}

func TestFinishRejectsMalformedInputs(t *testing.T) {
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)
	challenge, params := begin(t, issuer, provider, false)

	cases := map[string]struct {
		session  []byte
		response []byte
	}{
		"garbage session":    {[]byte("not-json"), callbackURL(params["state"])},
		"incomplete session": {[]byte(`{"state":"only"}`), callbackURL(params["state"])},
		"empty response":     {challenge.Session, []byte("   ")},
		"missing code":       {challenge.Session, []byte("state=" + params["state"])},
		"bad json response":  {challenge.Session, []byte("{not json")},
		"bad query encoding": {challenge.Session, []byte("state=%zz")},
	}
	for name, tc := range cases {
		if _, err := provider.Finish(context.Background(), tc.session, tc.response); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestFinishPropagatesExchangeFailure(t *testing.T) {
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)
	challenge, params := begin(t, issuer, provider, false)
	issuer.mu.Lock()
	issuer.tokenStatus = http.StatusBadRequest
	issuer.mu.Unlock()

	_, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
	if err == nil || !strings.Contains(err.Error(), "exchange authorization code") {
		t.Fatalf("err = %v, want exchange failure", err)
	}
}

func TestNewValidatesConfiguration(t *testing.T) {
	issuer := newTestIssuer(t)
	cases := map[string]func(*Config){
		"bad uuid":                  func(c *Config) { c.ConfigurationID = "not-a-uuid" },
		"uuid v4":                   func(c *Config) { c.ConfigurationID = "0198b463-0000-4000-8000-0000000000aa" },
		"non-oidc kind github":      func(c *Config) { c.Kind = credbound.SSOProviderGitHub },
		"non-oidc kind saml":        func(c *Config) { c.Kind = credbound.SSOProviderSAML },
		"missing issuer":            func(c *Config) { c.IssuerURL = "" },
		"plain http issuer":         func(c *Config) { c.IssuerURL = "http://idp.example.com" },
		"bad scheme":                func(c *Config) { c.IssuerURL = "ftp://idp.example.com" },
		"hostless issuer":           func(c *Config) { c.IssuerURL = "https://" },
		"missing redirect":          func(c *Config) { c.RedirectURL = "" },
		"plain http redirect":       func(c *Config) { c.RedirectURL = "http://app.example.com/cb" },
		"missing client id":         func(c *Config) { c.ClientID = "  " },
		"missing secret":            func(c *Config) { c.ClientSecret = "" },
		"public client with secret": func(c *Config) { c.PublicClient = true },
		"blank scope":               func(c *Config) { c.Scopes = []string{"openid", " "} },
	}
	for name, mutate := range cases {
		config := testConfig(issuer.url())
		mutate(&config)
		if _, err := New(config); err == nil {
			t.Fatalf("%s: expected configuration error", name)
		}
	}
}

func TestNewDefaultsAndOverrides(t *testing.T) {
	issuer := newTestIssuer(t)

	provider := newTestProvider(t, issuer, nil)
	if provider.Kind() != credbound.SSOProviderOIDC {
		t.Fatalf("default kind = %q, want oidc", provider.Kind())
	}
	if provider.ConfigurationID() != testConfigurationID {
		t.Fatalf("configuration id = %q", provider.ConfigurationID())
	}
	if provider.client.Timeout != defaultTimeout {
		t.Fatalf("default client timeout = %v", provider.client.Timeout)
	}

	google := newTestProvider(t, issuer, func(c *Config) { c.Kind = credbound.SSOProviderGoogle })
	if google.Kind() != credbound.SSOProviderGoogle {
		t.Fatalf("kind = %q, want google", google.Kind())
	}

	custom := &http.Client{}
	provider = newTestProvider(t, issuer, func(c *Config) {
		c.HTTPClient = custom
		c.Scopes = []string{"email"}
	})
	if provider.client == custom || provider.client.Timeout != defaultTimeout {
		t.Fatal("a caller client without a timeout must be copied and given the default timeout")
	}
	if custom.Timeout != 0 {
		t.Fatal("the caller's client must not be mutated")
	}
	if got := strings.Join(provider.scopes, " "); got != "openid email" {
		t.Fatalf("scopes = %q, want openid forced first", got)
	}

	timed := &http.Client{Timeout: time.Minute}
	provider = newTestProvider(t, issuer, func(c *Config) { c.HTTPClient = timed })
	if provider.client != timed {
		t.Fatal("a caller client with a timeout must be used as-is")
	}

	public := newTestProvider(t, issuer, func(c *Config) {
		c.PublicClient = true
		c.ClientSecret = ""
	})
	if public.clientSecret != "" {
		t.Fatal("public client must carry no secret")
	}
}

func TestBeginFailsWhenDiscoveryFails(t *testing.T) {
	issuer := newTestIssuer(t)
	config := testConfig(issuer.url())
	issuer.server.Close()
	provider, err := New(config)
	if err != nil {
		t.Fatalf("New must not require network: %v", err)
	}
	if _, err := provider.Begin(context.Background(), credbound.SSORequest{}); err == nil || !strings.Contains(err.Error(), "discover issuer") {
		t.Fatalf("err = %v, want discovery failure", err)
	}
}

// TestProviderSatisfiesPortRegistration wires the adapter through
// credbound.New to prove the registration contract (UUIDv7 + valid kind)
// holds end to end.
func TestProviderSatisfiesPortRegistration(t *testing.T) {
	var _ credbound.SSOProvider = (*Provider)(nil)
	issuer := newTestIssuer(t)
	provider := newTestProvider(t, issuer, nil)
	if !validUUIDv7(provider.ConfigurationID()) {
		t.Fatal("configuration id must satisfy credbound's UUIDv7 registration rule")
	}
}

func TestVerifyReauthentication(t *testing.T) {
	now := time.Now()
	if err := verifyReauthentication(0, now); err == nil {
		t.Fatal("missing auth_time must be rejected")
	}
	if err := verifyReauthentication(float64(now.Add(-time.Hour).Unix()), now); err == nil {
		t.Fatal("stale auth_time must be rejected")
	}
	if err := verifyReauthentication(float64(now.Unix()), now); err != nil {
		t.Fatalf("fresh auth_time rejected: %v", err)
	}
	if err := verifyReauthentication(float64(now.Unix()), time.Time{}); err != nil {
		t.Fatalf("zero issuance time must skip the staleness check: %v", err)
	}
}
