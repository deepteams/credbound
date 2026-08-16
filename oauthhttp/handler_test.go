package oauthhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
)

const (
	testIssuer   = "https://auth.example.com/tenant"
	testResource = "https://mcp.example.com/workspaces/acme"
)

type handlerHasher struct{}

func (handlerHasher) Hash(password string) (string, error) { return "hash:" + password, nil }
func (handlerHasher) Verify(hash, password string) (bool, bool, error) {
	return hash == "hash:"+password, false, nil
}

type handlerTOTP struct{}

func (handlerTOTP) Generate(string) (string, string, error) { return "secret", "otpauth://test", nil }
func (handlerTOTP) Validate(string, string, time.Time) (int64, bool) {
	return 1, true
}

type handlerPasskeys struct{}

func (handlerPasskeys) BeginRegistration(context.Context, credbound.PasskeyUser) (json.RawMessage, []byte, error) {
	return nil, nil, errors.New("unused")
}
func (handlerPasskeys) FinishRegistration(context.Context, credbound.PasskeyUser, []byte, []byte) ([]byte, []byte, error) {
	return nil, nil, errors.New("unused")
}
func (handlerPasskeys) BeginAuthentication(context.Context, credbound.PasskeyUser) (json.RawMessage, []byte, error) {
	return nil, nil, errors.New("unused")
}
func (handlerPasskeys) FinishAuthentication(context.Context, credbound.PasskeyUser, []byte, []byte) ([]byte, []byte, error) {
	return nil, nil, errors.New("unused")
}

type handlerOIDC struct{}

func (handlerOIDC) Algorithms() []string { return []string{"ES256"} }
func (handlerOIDC) SignIDToken(context.Context, credbound.OIDCClaims) (string, error) {
	return "signed-id-token", nil
}
func (handlerOIDC) JWKS(context.Context) (json.RawMessage, error) {
	return json.RawMessage(`{"keys":[]}`), nil
}

type incrementingReader struct{ value byte }

func (r *incrementingReader) Read(target []byte) (int, error) {
	for index := range target {
		target[index] = r.value
		r.value++
	}
	return len(target), nil
}

type handlerFixture struct {
	manager   *credbound.Manager
	handler   *Handler
	actor     credbound.Authentication
	issuerID  string
	clientID  string
	consent   credbound.OAuthConsent
	verifier  string
	challenge string
}

func newHandlerFixture(t *testing.T) *handlerFixture {
	t.Helper()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	manager, err := credbound.New(credbound.Config{
		Store: memory.New(), Passwords: handlerHasher{}, TOTP: handlerTOTP{}, Passkeys: handlerPasskeys{},
		SecretKey: bytes.Repeat([]byte{1}, 32), PATPepper: bytes.Repeat([]byte{2}, 32), RecoveryPepper: bytes.Repeat([]byte{3}, 32),
		Clock: func() time.Time { return now }, Random: &incrementingReader{value: 1},
		OAuth: &credbound.OAuthConfig{Pepper: bytes.Repeat([]byte{4}, 32), OIDCSigner: handlerOIDC{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	actor, workspace, err := manager.Bootstrap(t.Context(), credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	actor.Level, actor.Method, actor.AuthenticatedAt = credbound.AAL2, credbound.MethodTOTP, now
	issuer, err := manager.CreateOAuthIssuer(t.Context(), actor, credbound.TrustedRequest{Local: true}, credbound.CreateOAuthIssuerInput{
		Issuer: testIssuer, OIDCEnabled: true, DCRMode: credbound.OAuthDCROpen,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CreateOAuthProtectedResource(t.Context(), actor, workspace.ID, credbound.CreateOAuthProtectedResourceInput{
		IssuerID: issuer.ID, Resource: testResource,
		Scopes: []credbound.OAuthScopeDefinition{{Name: "documents.read", Description: "Read documents", Permissions: []credbound.WorkspacePermission{credbound.PermissionWorkspaceAccess}}},
	}); err != nil {
		t.Fatal(err)
	}
	client, err := manager.PreRegisterOAuthClient(t.Context(), actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.OAuthClientRegistrationInput{
		Name: "MCP client", ApplicationType: credbound.OAuthApplicationWeb,
		RedirectURIs: []string{"https://client.example.com/callback"}, GrantTypes: []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"}, Scopes: []string{"documents.read", "openid"}, TokenEndpointAuthMethod: credbound.OAuthAuthNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &handlerFixture{manager: manager, actor: actor, issuerID: issuer.ID, clientID: client.Client.ClientID}
	fixture.verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	digest := sha256.Sum256([]byte(fixture.verifier))
	fixture.challenge = base64.RawURLEncoding.EncodeToString(digest[:])
	fixture.handler, err = New(manager, HandlerConfig{
		Issuer: testIssuer, Resource: testResource,
		Authenticate: func(*http.Request) (credbound.Authentication, error) { return actor, nil },
		PresentConsent: func(w http.ResponseWriter, _ *http.Request, consent credbound.OAuthConsent) {
			fixture.consent = consent
			w.WriteHeader(http.StatusNoContent)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f *handlerFixture) request(method, target, body, contentType string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	return response
}

func TestHandlerDiscoveryAuthorizationTokensAndProtection(t *testing.T) {
	if _, err := New(nil, HandlerConfig{}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid handler = %v", err)
	}
	f := newHandlerFixture(t)
	for _, config := range []HandlerConfig{
		{Issuer: "http://auth.example.com"},
		{Issuer: "https://auth.example.com/"},
		{Issuer: testIssuer + "/"},
		{Issuer: testIssuer, Resource: "http://mcp.example.com"},
	} {
		if _, err := New(f.manager, config); !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("invalid public URL config %#v = %v", config, err)
		}
	}
	for _, target := range []string{
		"/.well-known/oauth-authorization-server/tenant",
		"/tenant/.well-known/openid-configuration",
		"/.well-known/oauth-protected-resource/workspaces/acme",
		"/tenant/.well-known/jwks.json",
	} {
		if response := f.request(http.MethodGet, target, "", ""); response.Code != http.StatusOK {
			t.Fatalf("GET %s = %d %s", target, response.Code, response.Body.String())
		}
	}
	if response := f.request(http.MethodPost, "/tenant/.well-known/openid-configuration", "", ""); response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("discovery method = %d %#v", response.Code, response.Header())
	}
	if response := f.request(http.MethodGet, "/missing", "", ""); response.Code != http.StatusNotFound {
		t.Fatalf("missing = %d", response.Code)
	}

	authorize := "/tenant/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {f.clientID}, "redirect_uri": {"https://client.example.com/callback"},
		"resource": {testResource}, "scope": {"documents.read openid"}, "state": {"opaque-state"},
		"code_challenge": {f.challenge}, "code_challenge_method": {"S256"}, "nonce": {"nonce"},
	}.Encode()
	if response := f.request(http.MethodGet, authorize, "", ""); response.Code != http.StatusNoContent || f.consent.Continuation == "" {
		t.Fatalf("authorize = %d %s, consent=%#v", response.Code, response.Body.String(), f.consent)
	}
	approved, err := f.manager.CompleteOAuthAuthorization(t.Context(), f.actor, f.consent.Continuation, true)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {f.clientID}, "code": {approved.Code},
		"redirect_uri": {"https://client.example.com/callback"}, "code_verifier": {f.verifier}, "resource": {testResource},
	}
	response := f.request(http.MethodPost, "/tenant/token", form.Encode(), "application/x-www-form-urlencoded")
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("token = %d %s", response.Code, response.Body.String())
	}
	var tokens credbound.OAuthTokenResponse
	if err := json.Unmarshal(response.Body.Bytes(), &tokens); err != nil || tokens.AccessToken == "" || tokens.IDToken == "" {
		t.Fatalf("tokens = %#v, %v", tokens, err)
	}

	request := httptest.NewRequest(http.MethodGet, "/tenant/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	response = httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"sub"`) {
		t.Fatalf("userinfo = %d %s", response.Code, response.Body.String())
	}

	called := false
	protected := Protect(f.manager, testResource, "documents.read", "https://mcp.example.com/.well-known/oauth-protected-resource", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := AuthenticationFromContext(r); !ok {
			t.Error("OAuth authentication missing from context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request = httptest.NewRequest(http.MethodGet, "/mcp", nil)
	request.Header.Set("Authorization", "bearer "+tokens.AccessToken)
	response = httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || !called {
		t.Fatalf("protected = %d, called=%v", response.Code, called)
	}
	insufficient := Protect(f.manager, testResource, "documents.write", "metadata\"ignored", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("insufficient token reached handler") }))
	response = httptest.NewRecorder()
	insufficient.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Header().Get("WWW-Authenticate"), "insufficient_scope") {
		t.Fatalf("insufficient = %d %#v", response.Code, response.Header())
	}
	response = httptest.NewRecorder()
	protected.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/mcp", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer token = %d", response.Code)
	}

	revoke := url.Values{"client_id": {f.clientID}, "token": {tokens.AccessToken}}
	if response := f.request(http.MethodPost, "/tenant/revoke", revoke.Encode(), "application/x-www-form-urlencoded"); response.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", response.Code, response.Body.String())
	}
}

func TestHandlerProtocolErrorsAndDCR(t *testing.T) {
	f := newHandlerFixture(t)
	badResponseType := "/tenant/authorize?" + url.Values{
		"response_type": {"token"}, "client_id": {f.clientID}, "redirect_uri": {"https://client.example.com/callback"}, "state": {"keep-me"},
	}.Encode()
	response := f.request(http.MethodGet, badResponseType, "", "")
	location, _ := url.Parse(response.Header().Get("Location"))
	if response.Code != http.StatusFound || location.Query().Get("state") != "keep-me" || location.Query().Get("iss") != testIssuer {
		t.Fatalf("authorization error = %d %q", response.Code, response.Header().Get("Location"))
	}
	invalidRedirect := strings.Replace(badResponseType, url.QueryEscape("https://client.example.com/callback"), url.QueryEscape("https://evil.example.com/callback"), 1)
	if response := f.request(http.MethodGet, invalidRedirect, "", ""); response.Code != http.StatusBadRequest || response.Header().Get("Location") != "" {
		t.Fatalf("invalid redirect = %d %#v", response.Code, response.Header())
	}
	if response := f.request(http.MethodPost, "/tenant/token", "grant_type=client_credentials", "application/x-www-form-urlencoded"); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "unsupported_grant_type") {
		t.Fatalf("unsupported grant = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(http.MethodPost, "/tenant/token", strings.Repeat("x", maxProtocolBody+1), "application/x-www-form-urlencoded"); response.Code != http.StatusBadRequest {
		t.Fatalf("oversized form = %d", response.Code)
	}
	registration := `{"client_name":"Dynamic","application_type":"web","redirect_uris":["https://dynamic.example.com/callback"],"scope":"documents.read","token_endpoint_auth_method":"none"}`
	if response := f.request(http.MethodPost, "/tenant/register", registration, "application/json"); response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"client_id"`) {
		t.Fatalf("DCR = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(http.MethodPost, "/tenant/register", registration+` {}`, "application/json"); response.Code != http.StatusBadRequest {
		t.Fatalf("trailing DCR JSON = %d", response.Code)
	}
	if response := f.request(http.MethodPut, "/tenant/userinfo", "", ""); response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, POST" {
		t.Fatalf("userinfo method = %d %#v", response.Code, response.Header())
	}

	for input, code := range map[error]string{
		credbound.ErrForbidden: "invalid_scope", credbound.ErrUnauthorized: "login_required", credbound.ErrStepUpRequired: "interaction_required", errors.New("other"): "invalid_request",
	} {
		if got, _ := authorizationError(input); got != code {
			t.Fatalf("authorizationError(%v) = %q", input, got)
		}
	}
	if endpointPath("://bad") != "" || endpointPath("https://example.com/") != "" || endpointPath(testIssuer) != "/tenant" {
		t.Fatal("endpoint path normalization failed")
	}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("client_id=form&client_secret=form-secret"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("basic", "basic-secret")
	if id, secret := clientCredentials(request, url.Values{}); id != "basic" || secret != "basic-secret" {
		t.Fatalf("basic credentials = %q, %q", id, secret)
	}
	contextRequest := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(WithAuthentication(context.Background(), credbound.OAuthAuthentication{UserID: "user"}))
	if value, ok := AuthenticationFromContext(contextRequest); !ok || value.UserID != "user" {
		t.Fatalf("context authentication = %#v, %v", value, ok)
	}
}

func TestHandlerAdditionalProtocolBranches(t *testing.T) {
	f := newHandlerFixture(t)
	for target, allow := range map[string]string{
		"/tenant/authorize":             http.MethodGet,
		"/tenant/token":                 http.MethodPost,
		"/tenant/revoke":                http.MethodPost,
		"/tenant/register":              http.MethodPost,
		"/tenant/.well-known/jwks.json": http.MethodGet,
		"/.well-known/oauth-protected-resource/workspaces/acme": http.MethodGet,
	} {
		if response := f.request(http.MethodPut, target, "", ""); response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != allow {
			t.Fatalf("PUT %s = %d, allow %q", target, response.Code, response.Header().Get("Allow"))
		}
	}
	for _, target := range []string{"/tenant/token", "/tenant/revoke"} {
		if response := f.request(http.MethodPost, target, "%zz", "application/x-www-form-urlencoded"); response.Code != http.StatusBadRequest {
			t.Fatalf("invalid form %s = %d", target, response.Code)
		}
	}
	if response := f.request(http.MethodPost, "/tenant/token", "grant_type=authorization_code&client_id=missing&code=bad", "application/x-www-form-urlencoded"); response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token client = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(http.MethodPost, "/tenant/revoke", "client_id=missing&token=bad", "application/x-www-form-urlencoded"); response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid revoke client = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(http.MethodPost, "/tenant/register", `{"unknown":true}`, "application/json"); response.Code != http.StatusBadRequest {
		t.Fatalf("unknown registration field = %d", response.Code)
	}
	if response := f.request(http.MethodPost, "/tenant/register", `{`, "application/json"); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid registration JSON = %d", response.Code)
	}
	if response := f.request(http.MethodGet, "/tenant/userinfo", "", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("missing UserInfo token = %d", response.Code)
	}

	noCallbacks, err := New(f.manager, HandlerConfig{Issuer: testIssuer, Resource: testResource})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/tenant/authorize", nil)
	response := httptest.NewRecorder()
	noCallbacks.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing authorization callbacks = %d", response.Code)
	}
	emptyResource, err := New(f.manager, HandlerConfig{Issuer: testIssuer})
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	emptyResource.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("empty resource metadata = %d", response.Code)
	}

	authFailure, err := New(f.manager, HandlerConfig{
		Issuer: testIssuer, Resource: testResource,
		Authenticate: func(*http.Request) (credbound.Authentication, error) {
			return credbound.Authentication{}, errors.New("login required")
		},
		PresentConsent: func(http.ResponseWriter, *http.Request, credbound.OAuthConsent) {
			t.Fatal("consent unexpectedly presented")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	authorize := "/tenant/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {f.clientID}, "redirect_uri": {"https://client.example.com/callback"}, "state": {"state"},
	}.Encode()
	response = httptest.NewRecorder()
	authFailure.ServeHTTP(response, httptest.NewRequest(http.MethodGet, authorize, nil))
	if response.Code != http.StatusFound || !strings.Contains(response.Header().Get("Location"), "login_required") {
		t.Fatalf("authentication failure = %d %q", response.Code, response.Header().Get("Location"))
	}
	invalidAuthorization := strings.Replace(authorize, "response_type=code", "response_type=code&resource=https%3A%2F%2Fmissing.example.com", 1)
	response = f.request(http.MethodGet, invalidAuthorization, "", "")
	if response.Code != http.StatusFound || !strings.Contains(response.Header().Get("Location"), "invalid_scope") {
		t.Fatalf("authorization manager failure = %d %q", response.Code, response.Header().Get("Location"))
	}

	for name, problem := range map[string]error{
		"not supported": credbound.ErrNotSupported,
		"credentials":   credbound.ErrInvalidCredentials,
		"unauthorized":  credbound.ErrUnauthorized,
		"forbidden":     credbound.ErrForbidden,
		"expired":       credbound.ErrExpired,
		"generic":       errors.New("boom"),
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			f.handler.writeError(response, problem)
			if response.Code < 400 || response.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("writeError(%v) = %d", problem, response.Code)
			}
		})
	}
	response = httptest.NewRecorder()
	f.handler.writeAuthorizationError(response, "://bad", "state", "invalid_request", "bad")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid authorization redirect = %d", response.Code)
	}
	if bearerToken(httptest.NewRequest(http.MethodGet, "/", nil)) != "" {
		t.Fatal("missing bearer token accepted")
	}
	badBearer := httptest.NewRequest(http.MethodGet, "/", nil)
	badBearer.Header.Set("Authorization", "Basic secret")
	if bearerToken(badBearer) != "" {
		t.Fatal("Basic token accepted as bearer")
	}
	if bearerChallenge("", "", "") != "Bearer" || !strings.Contains(bearerChallenge("meta", "scope\"", "problem"), `scope="scope"`) {
		t.Fatal("bearer challenge escaping failed")
	}
	if _, ok := AuthenticationFromContext(httptest.NewRequest(http.MethodGet, "/", nil)); ok {
		t.Fatal("empty request context contained OAuth authentication")
	}
	oauthOnlyIssuer, err := f.manager.CreateOAuthIssuer(t.Context(), f.actor, credbound.TrustedRequest{Local: true}, credbound.CreateOAuthIssuerInput{Issuer: "https://auth.example.com/oauth-only"})
	if err != nil {
		t.Fatal(err)
	}
	oauthOnly, err := New(f.manager, HandlerConfig{Issuer: oauthOnlyIssuer.Issuer})
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	oauthOnly.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server/oauth-only", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("OAuth-only discovery = %d", response.Code)
	}
	response = httptest.NewRecorder()
	oauthOnly.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oauth-only/.well-known/openid-configuration", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled OIDC discovery = %d", response.Code)
	}
	if _, err := New(f.manager, HandlerConfig{Issuer: "http://invalid.example.com", Resource: "http://invalid.example.com"}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid metadata configuration = %v", err)
	}
	if err := f.manager.DisableOAuthIssuer(t.Context(), f.actor, credbound.TrustedRequest{Local: true}, f.issuerID); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"/.well-known/oauth-authorization-server/tenant",
		"/.well-known/oauth-protected-resource/workspaces/acme",
		"/tenant/.well-known/jwks.json",
		"/tenant/register",
	} {
		method := http.MethodGet
		if strings.HasSuffix(target, "/register") {
			method = http.MethodPost
		}
		if response := f.request(method, target, `{}`, "application/json"); response.Code != http.StatusNotFound {
			t.Fatalf("disabled issuer endpoint %s = %d", target, response.Code)
		}
	}
}
