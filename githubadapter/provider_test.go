package githubadapter

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

var testConfigurationID = credbound.MustParseUUID("0198b463-51a2-7cde-8000-0123456789ab")

func testConfig(github *testGitHub) Config {
	return Config{
		ConfigurationID: testConfigurationID,
		ClientID:        "test-client",
		ClientSecret:    "test-secret",
		RedirectURL:     "https://app.example.com/sso/callback",
		TokenURL:        github.url() + "/login/oauth/access_token",
		APIBaseURL:      github.url(),
	}
}

func newTestProvider(t *testing.T, github *testGitHub, mutate func(*Config)) *Provider {
	t.Helper()
	config := testConfig(github)
	if mutate != nil {
		mutate(&config)
	}
	provider, err := New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return provider
}

// begin runs Begin and returns the challenge plus the parsed authorization
// URL query.
func begin(t *testing.T, provider *Provider) (credbound.SSOProviderChallenge, map[string]string) {
	t.Helper()
	challenge, err := provider.Begin(context.Background(), credbound.SSORequest{})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	parsed, err := url.Parse(challenge.RedirectURL)
	if err != nil {
		t.Fatalf("parse redirect url %q: %v", challenge.RedirectURL, err)
	}
	query := parsed.Query()
	params := map[string]string{}
	for key := range query {
		params[key] = query.Get(key)
	}
	return challenge, params
}

func callbackURL(state string) []byte {
	return []byte("https://app.example.com/sso/callback?code=test-code&state=" + state)
}

func TestBeginBuildsAuthorizationURL(t *testing.T) {
	github := newTestGitHub(t)
	provider := newTestProvider(t, github, nil)
	challenge, params := begin(t, provider)

	if !strings.HasPrefix(challenge.RedirectURL, defaultAuthorizeURL+"?") {
		t.Fatalf("redirect url = %q, want github authorization endpoint", challenge.RedirectURL)
	}
	if params["client_id"] != "test-client" {
		t.Fatalf("client_id = %q", params["client_id"])
	}
	if params["redirect_uri"] != "https://app.example.com/sso/callback" {
		t.Fatalf("redirect_uri = %q", params["redirect_uri"])
	}
	if params["scope"] != "read:user user:email" {
		t.Fatalf("scope = %q, want default read:user user:email", params["scope"])
	}
	if params["allow_signup"] != "false" {
		t.Fatalf("allow_signup = %q, want false", params["allow_signup"])
	}
	if params["state"] == "" {
		t.Fatal("state must be present")
	}

	var s session
	if err := json.Unmarshal(challenge.Session, &s); err != nil {
		t.Fatalf("session must be JSON: %v", err)
	}
	if s.State != params["state"] {
		t.Fatal("session must carry the state from the URL")
	}
	if params["code_challenge_method"] != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", params["code_challenge_method"])
	}
	if s.Verifier == "" {
		t.Fatal("session must carry the PKCE verifier")
	}
	digest := sha256.Sum256([]byte(s.Verifier))
	if params["code_challenge"] != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatal("code_challenge must be the S256 digest of the session verifier")
	}

	// Two ceremonies never share material.
	secondChallenge, second := begin(t, provider)
	if second["state"] == params["state"] {
		t.Fatal("state must be fresh per ceremony")
	}
	var secondSession session
	if err := json.Unmarshal(secondChallenge.Session, &secondSession); err != nil {
		t.Fatalf("second session must be JSON: %v", err)
	}
	if secondSession.Verifier == s.Verifier {
		t.Fatal("verifier must be fresh per ceremony")
	}
}

func TestBeginRefusesForcedReauthentication(t *testing.T) {
	github := newTestGitHub(t)
	provider := newTestProvider(t, github, nil)

	_, err := provider.Begin(context.Background(), credbound.SSORequest{ForceReauthentication: true})
	if !errors.Is(err, ErrStepUpUnsupported) {
		t.Fatalf("err = %v, want ErrStepUpUnsupported", err)
	}
}

func TestFinishHappyPathWithVerifiedPrimaryEmail(t *testing.T) {
	github := newTestGitHub(t)
	provider := newTestProvider(t, github, nil)
	challenge, params := begin(t, provider)

	claims, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	want := credbound.SSOClaims{
		Issuer: "https://github.com", Subject: "581348",
		Email: "primary@example.com", EmailVerified: true,
	}
	if claims.Issuer != want.Issuer || claims.Subject != want.Subject || claims.Email != want.Email || claims.EmailVerified != want.EmailVerified {
		t.Fatalf("claims = %#v, want %#v", claims, want)
	}
	if claims.ACR != "" || len(claims.AMR) != 0 {
		t.Fatalf("github must assert no authentication context, got %#v", claims)
	}

	form := github.tokenRequest()
	if form.Get("code") != "test-code" || form.Get("client_id") != "test-client" || form.Get("client_secret") != "test-secret" {
		t.Fatalf("token request = %v", form)
	}
	if form.Get("redirect_uri") != "https://app.example.com/sso/callback" {
		t.Fatalf("token redirect_uri = %q", form.Get("redirect_uri"))
	}
	var s session
	if err := json.Unmarshal(challenge.Session, &s); err != nil {
		t.Fatalf("session must be JSON: %v", err)
	}
	if got := form.Get("code_verifier"); got == "" || got != s.Verifier {
		t.Fatalf("code_verifier = %q, want the session verifier", got)
	}

	user := github.userRequest()
	if got := user.Header.Get("Authorization"); got != "Bearer gho_test-token" {
		t.Fatalf("user Authorization = %q", got)
	}
	if got := user.Header.Get("Accept"); got != "application/vnd.github+json" {
		t.Fatalf("user Accept = %q", got)
	}
	if got := user.Header.Get("X-GitHub-Api-Version"); got != apiVersion {
		t.Fatalf("user X-GitHub-Api-Version = %q", got)
	}
}

func TestFinishOmitsVerifierForPrePKCESession(t *testing.T) {
	github := newTestGitHub(t)
	provider := newTestProvider(t, github, nil)
	challenge, params := begin(t, provider)

	// A continuation sealed by a pre-PKCE Begin carries no verifier; the
	// exchange must then omit code_verifier, matching the challenge-less
	// authorization it belongs to.
	var s session
	if err := json.Unmarshal(challenge.Session, &s); err != nil {
		t.Fatalf("session must be JSON: %v", err)
	}
	legacy, err := json.Marshal(session{State: s.State})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Finish(context.Background(), legacy, callbackURL(params["state"])); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if form := github.tokenRequest(); form.Has("code_verifier") {
		t.Fatalf("legacy session must not send code_verifier: %v", form)
	}
}

func TestFinishAcceptsBareQueryAndJSONCallbacks(t *testing.T) {
	github := newTestGitHub(t)
	provider := newTestProvider(t, github, nil)

	challenge, params := begin(t, provider)
	if _, err := provider.Finish(context.Background(), challenge.Session, []byte("code=test-code&state="+params["state"])); err != nil {
		t.Fatalf("bare query callback: %v", err)
	}

	challenge, params = begin(t, provider)
	payload := []byte(`{"code":"test-code","state":"` + params["state"] + `"}`)
	if _, err := provider.Finish(context.Background(), challenge.Session, payload); err != nil {
		t.Fatalf("json callback: %v", err)
	}
}

func TestFinishForwardsUnverifiedPrimaryEmail(t *testing.T) {
	github := newTestGitHub(t)
	provider := newTestProvider(t, github, nil)
	github.setEmails(t, map[string]any{"email": "primary@example.com", "primary": true, "verified": false})
	challenge, params := begin(t, provider)

	claims, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if claims.Email != "primary@example.com" || claims.EmailVerified {
		t.Fatalf("unverified primary must be forwarded unverified, got %#v", claims)
	}
}

func TestFinishFallsBackToProfileEmailWhenScopeDeclined(t *testing.T) {
	// GitHub answers 404 for a missing user:email scope on /user/emails;
	// fine-grained tokens answer 403. Both fall back to the unproven
	// profile email.
	for name, status := range map[credbound.UUID]int{credbound.MustParseUUID("0198b463-0000-7000-8000-43ed5c457b79"): http.StatusForbidden, credbound.MustParseUUID("0198b463-0000-7000-8000-907ba78b4545"): http.StatusNotFound} {
		t.Run(name.String(), func(t *testing.T) {
			github := newTestGitHub(t)
			provider := newTestProvider(t, github, nil)
			github.setStatus(&github.emailsStatus, status)
			challenge, params := begin(t, provider)

			claims, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
			if err != nil {
				t.Fatalf("Finish: %v", err)
			}
			if claims.Email != "public@example.com" || claims.EmailVerified {
				t.Fatalf("fallback email must be the profile email, unverified, got %#v", claims)
			}
			if claims.Issuer != "https://github.com" || claims.Subject != "581348" {
				t.Fatalf("issuer and subject must survive the fallback, got %#v", claims)
			}
		})
	}
}

func TestFinishWithoutPrimaryEmailFallsBackUnverified(t *testing.T) {
	github := newTestGitHub(t)
	provider := newTestProvider(t, github, nil)
	github.setEmails(t, map[string]any{"email": "secondary@example.com", "primary": false, "verified": true})
	challenge, params := begin(t, provider)

	claims, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if claims.Email != "public@example.com" || claims.EmailVerified {
		t.Fatalf("without a primary the profile email must be forwarded unverified, got %#v", claims)
	}
}

func TestFinishRejectsStateMismatch(t *testing.T) {
	github := newTestGitHub(t)
	provider := newTestProvider(t, github, nil)
	challenge, _ := begin(t, provider)

	_, err := provider.Finish(context.Background(), challenge.Session, callbackURL("attacker-state"))
	if !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("err = %v, want ErrStateMismatch", err)
	}
	if github.tokenRequest() != nil {
		t.Fatal("state mismatch must be rejected before any code exchange")
	}
}

func TestFinishRejectsProviderErrorCallback(t *testing.T) {
	github := newTestGitHub(t)
	provider := newTestProvider(t, github, nil)
	challenge, _ := begin(t, provider)

	response := []byte("https://app.example.com/sso/callback?error=access_denied&error_description=" + url.QueryEscape(strings.Repeat("d", 300)))
	_, err := provider.Finish(context.Background(), challenge.Session, response)
	if err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("err = %v, want access_denied", err)
	}
	if strings.Contains(err.Error(), strings.Repeat("d", 201)) {
		t.Fatal("error_description must be truncated to 200 characters")
	}
}

func TestFinishTokenExchangeFailures(t *testing.T) {
	cases := map[string]struct {
		prepare func(*testGitHub)
		want    string
	}{
		"http error status": {
			func(g *testGitHub) { g.setStatus(&g.tokenStatus, http.StatusInternalServerError) },
			"status 500",
		},
		"error body": {
			// GitHub answers 200 with an error field for protocol errors.
			func(g *testGitHub) {
				g.set(&g.tokenBody, `{"error":"bad_verification_code","error_description":"the code is wrong"}`)
			},
			"bad_verification_code",
		},
		"missing access token": {
			func(g *testGitHub) { g.set(&g.tokenBody, `{"token_type":"bearer"}`) },
			"no access token",
		},
		"unexpected token type": {
			func(g *testGitHub) { g.set(&g.tokenBody, `{"access_token":"gho_x","token_type":"mac"}`) },
			`unexpected token type "mac"`,
		},
		"garbage body": {
			func(g *testGitHub) { g.set(&g.tokenBody, "not-json") },
			"decode token response",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			github := newTestGitHub(t)
			provider := newTestProvider(t, github, nil)
			tc.prepare(github)
			challenge, params := begin(t, provider)

			_, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestFinishTokenTypeBearerIsCaseInsensitive(t *testing.T) {
	github := newTestGitHub(t)
	provider := newTestProvider(t, github, nil)
	github.set(&github.tokenBody, `{"access_token":"gho_test-token","token_type":"Bearer"}`)
	challenge, params := begin(t, provider)

	if _, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"])); err != nil {
		t.Fatalf("Finish: %v", err)
	}
}

func TestFinishUserAPIFailures(t *testing.T) {
	cases := map[string]struct {
		prepare func(*testGitHub)
		want    string
	}{
		"http error status": {
			func(g *testGitHub) { g.setStatus(&g.userStatus, http.StatusUnauthorized) },
			"fetch user: api answered status 401",
		},
		"missing account id": {
			func(g *testGitHub) { g.set(&g.userBody, `{"login":"octocat"}`) },
			"no account id",
		},
		"garbage body": {
			func(g *testGitHub) { g.set(&g.userBody, "not-json") },
			"decode user response",
		},
		"emails endpoint broken": {
			func(g *testGitHub) { g.setStatus(&g.emailsStatus, http.StatusInternalServerError) },
			"fetch user emails: api answered status 500",
		},
		"emails garbage body": {
			func(g *testGitHub) { g.set(&g.emailsBody, "not-json") },
			"decode user emails response",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			github := newTestGitHub(t)
			provider := newTestProvider(t, github, nil)
			tc.prepare(github)
			challenge, params := begin(t, provider)

			_, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestFinishDropsOversizedEmail(t *testing.T) {
	github := newTestGitHub(t)
	provider := newTestProvider(t, github, nil)
	oversized := strings.Repeat("a", maxEmailLength) + "@example.com"
	github.setEmails(t, map[string]any{"email": oversized, "primary": true, "verified": true})
	challenge, params := begin(t, provider)

	claims, err := provider.Finish(context.Background(), challenge.Session, callbackURL(params["state"]))
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if claims.Email != "" || claims.EmailVerified {
		t.Fatalf("oversized email must be dropped, got %#v", claims)
	}
	if claims.Issuer == "" || claims.Subject == "" {
		t.Fatal("issuer and subject must survive without email")
	}
}

func TestFinishRejectsMalformedInputs(t *testing.T) {
	github := newTestGitHub(t)
	provider := newTestProvider(t, github, nil)
	challenge, params := begin(t, provider)

	cases := map[string]struct {
		session  []byte
		response []byte
	}{
		"garbage session":    {[]byte("not-json"), callbackURL(params["state"])},
		"incomplete session": {[]byte(`{}`), callbackURL(params["state"])},
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

func TestNewValidatesConfiguration(t *testing.T) {
	github := newTestGitHub(t)
	cases := map[string]func(*Config){
		"bad uuid":            func(c *Config) { c.ConfigurationID = credbound.MustParseUUID("00000000-0000-4000-8000-000000000000") },
		"uuid v4":             func(c *Config) { c.ConfigurationID = credbound.MustParseUUID("0198b463-0000-4000-8000-0000000000aa") },
		"missing client id":   func(c *Config) { c.ClientID = "  " },
		"missing secret":      func(c *Config) { c.ClientSecret = "" },
		"missing redirect":    func(c *Config) { c.RedirectURL = "" },
		"plain http redirect": func(c *Config) { c.RedirectURL = "http://app.example.com/cb" },
		"bad scheme redirect": func(c *Config) { c.RedirectURL = "ftp://app.example.com/cb" },
		"hostless redirect":   func(c *Config) { c.RedirectURL = "https://" },
		"plain http authorize": func(c *Config) {
			c.AuthorizeURL = "http://github.example.com/authorize"
		},
		"plain http token": func(c *Config) { c.TokenURL = "http://github.example.com/token" },
		"plain http api":   func(c *Config) { c.APIBaseURL = "http://github.example.com" },
		"blank scope":      func(c *Config) { c.Scopes = []string{"read:user", " "} },
	}
	for name, mutate := range cases {
		config := testConfig(github)
		mutate(&config)
		if _, err := New(config); err == nil {
			t.Fatalf("%s: expected configuration error", name)
		}
	}
}

func TestNewDefaultsAndOverrides(t *testing.T) {
	github := newTestGitHub(t)

	provider := newTestProvider(t, github, nil)
	if provider.Kind() != credbound.SSOProviderGitHub {
		t.Fatalf("kind = %q, want github", provider.Kind())
	}
	if provider.ConfigurationID() != testConfigurationID {
		t.Fatalf("configuration id = %q", provider.ConfigurationID())
	}
	if provider.client.Timeout != defaultTimeout {
		t.Fatalf("default client timeout = %v", provider.client.Timeout)
	}
	if provider.authorizeURL != defaultAuthorizeURL {
		t.Fatalf("authorize url = %q, want github default", provider.authorizeURL)
	}
	if got := strings.Join(provider.scopes, " "); got != "read:user user:email" {
		t.Fatalf("scopes = %q, want default read:user user:email", got)
	}

	defaults, err := New(Config{
		ConfigurationID: testConfigurationID,
		ClientID:        "test-client",
		ClientSecret:    "test-secret",
		RedirectURL:     "https://app.example.com/sso/callback",
	})
	if err != nil {
		t.Fatalf("New with defaults: %v", err)
	}
	if defaults.tokenURL != defaultTokenURL || defaults.apiBaseURL != defaultAPIBaseURL {
		t.Fatalf("endpoint defaults = %q, %q", defaults.tokenURL, defaults.apiBaseURL)
	}

	custom := &http.Client{}
	provider = newTestProvider(t, github, func(c *Config) {
		c.HTTPClient = custom
		c.Scopes = []string{" read:user "}
	})
	if provider.client == custom || provider.client.Timeout != defaultTimeout {
		t.Fatal("a caller client without a timeout must be copied and given the default timeout")
	}
	if custom.Timeout != 0 {
		t.Fatal("the caller's client must not be mutated")
	}
	if got := strings.Join(provider.scopes, " "); got != "read:user" {
		t.Fatalf("scopes = %q, want trimmed override", got)
	}

	timed := &http.Client{Timeout: time.Minute}
	provider = newTestProvider(t, github, func(c *Config) { c.HTTPClient = timed })
	if provider.client != timed {
		t.Fatal("a caller client with a timeout must be used as-is")
	}
}

// TestProviderSatisfiesPortRegistration proves the registration contract
// (UUIDv7 + valid kind) holds for credbound.Config.SSOProviders.
func TestProviderSatisfiesPortRegistration(t *testing.T) {
	var _ credbound.SSOProvider = (*Provider)(nil)
	github := newTestGitHub(t)
	provider := newTestProvider(t, github, nil)
	if !validUUIDv7(provider.ConfigurationID()) {
		t.Fatal("configuration id must satisfy credbound's UUIDv7 registration rule")
	}
	if provider.Kind() != credbound.SSOProviderGitHub {
		t.Fatalf("kind = %q, want the github kind credbound accepts", provider.Kind())
	}
}
