package credbound

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestOAuthProtocolValidationHelpers(t *testing.T) {
	if got, err := validateIssuerURL("https://auth.example.com/"); err != nil || got != "https://auth.example.com" {
		t.Fatalf("issuer = %q, %v", got, err)
	}
	for _, raw := range []string{"", "http://auth.example.com", "https://user@auth.example.com", "https://auth.example.com?query=1", "https://auth.example.com/#fragment"} {
		if _, err := validateIssuerURL(raw); err == nil {
			t.Fatalf("invalid issuer accepted: %q", raw)
		}
	}
	if _, err := validateResourceURL("https://mcp.example.com/acme"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"http://mcp.example.com", "https://mcp.example.com/acme?q=1"} {
		if _, err := validateResourceURL(raw); err == nil {
			t.Fatalf("invalid resource accepted: %q", raw)
		}
	}
	validClient := "https://client.example.com/oauth/client.json"
	clientURL, err := validateCIMDClientID(validClient)
	if err != nil || clientURL.String() != validClient {
		t.Fatalf("CIMD URL = %v, %v", clientURL, err)
	}
	for _, raw := range []string{"https://client.example.com", "https://client.example.com/a/../b", "https://client.example.com/a%2F..", "https://client.example.com/client?q=1"} {
		if _, err := validateCIMDClientID(raw); err == nil {
			t.Fatalf("invalid CIMD URL accepted: %q", raw)
		}
	}
	if origin, err := normalizeHTTPSOrigin("https://CLIENT.example.com/"); err != nil || origin != "https://client.example.com" {
		t.Fatalf("origin = %q, %v", origin, err)
	}
	if _, err := normalizeHTTPSOrigin("https://client.example.com/path"); err == nil {
		t.Fatal("origin path accepted")
	}
	if issuerAllowsCIMD(OAuthIssuer{CIMDMode: OAuthCIMDDisabled}, clientURL) {
		t.Fatal("disabled CIMD accepted")
	}
	if issuerAllowsCIMD(OAuthIssuer{CIMDMode: OAuthCIMDPublicWeb}, nil) {
		t.Fatal("nil CIMD URL accepted")
	}
	if !issuerAllowsCIMD(OAuthIssuer{CIMDMode: OAuthCIMDPublicWeb}, clientURL) {
		t.Fatal("public CIMD rejected")
	}
	if !issuerAllowsCIMD(OAuthIssuer{CIMDMode: OAuthCIMDAllowlist, CIMDAllowedOrigins: []string{"https://client.example.com"}}, clientURL) {
		t.Fatal("allowlisted CIMD rejected")
	}
	if issuerAllowsCIMD(OAuthIssuer{CIMDMode: OAuthCIMDAllowlist, CIMDAllowedOrigins: []string{"https://other.example.com"}}, clientURL) {
		t.Fatal("non-allowlisted CIMD accepted")
	}

	if redirects, err := normalizeRedirectURIs(OAuthApplicationWeb, []string{"https://client.example.com/callback"}); err != nil || len(redirects) != 1 {
		t.Fatalf("web redirects = %v, %v", redirects, err)
	}
	if _, err := normalizeRedirectURIs(OAuthApplicationWeb, []string{"http://client.example.com/callback"}); err == nil {
		t.Fatal("insecure web redirect accepted")
	}
	if _, err := normalizeRedirectURIs(OAuthApplicationNative, []string{"http://127.0.0.1:49152/callback"}); err != nil {
		t.Fatal(err)
	}
	if _, err := normalizeRedirectURIs(OAuthApplicationNative, []string{"http://client.example.com/callback"}); err == nil {
		t.Fatal("remote native HTTP redirect accepted")
	}
	if _, err := normalizeRedirectURIs(OAuthApplicationWeb, []string{"https://client.example.com/callback", "https://client.example.com/callback"}); err == nil {
		t.Fatal("duplicate redirect accepted")
	}
	if _, err := normalizeRedirectURIs(OAuthApplicationWeb, nil); err == nil {
		t.Fatal("empty redirects accepted")
	}
	if _, err := normalizeRedirectURIs(OAuthApplicationWeb, []string{"https://client.example.com/callback#fragment"}); err == nil {
		t.Fatal("redirect fragment accepted")
	}
	if _, err := normalizeRedirectURIs(OAuthApplicationNative, []string{"https://client.example.com/callback"}); err != nil {
		t.Fatal(err)
	}

	grants, responses, err := normalizeOAuthFlowMetadata(nil, nil)
	if err != nil || len(grants) != 1 || responses[0] != "code" {
		t.Fatalf("default flow = %v/%v, %v", grants, responses, err)
	}
	for _, grants := range [][]string{{"client_credentials"}, {"refresh_token"}} {
		if _, _, err := normalizeOAuthFlowMetadata(grants, nil); err == nil {
			t.Fatalf("invalid grants accepted: %v", grants)
		}
	}
	if _, _, err := normalizeOAuthFlowMetadata([]string{"authorization_code"}, []string{"token"}); err == nil {
		t.Fatal("implicit response accepted")
	}
	if scopes, err := normalizeOptionalOAuthScopes([]string{"z.read", "a.read", "a.read"}); err != nil || strings.Join(scopes, ",") != "a.read,z.read" {
		t.Fatalf("scopes = %v, %v", scopes, err)
	}
	if _, err := normalizeOptionalOAuthScopes([]string{"bad scope"}); err == nil {
		t.Fatal("invalid scope accepted")
	}
	if _, err := normalizeOptionalOAuthScopes(make([]string, 101)); err == nil {
		t.Fatal("too many scopes accepted")
	}
	if !oauthReservedScope("openid") || oauthReservedScope("documents.read") {
		t.Fatal("reserved scope classification failed")
	}
	for _, scope := range []string{"openid", "profile", "email", "offline_access", "custom"} {
		if oauthReservedScopeDescription(scope) == "" {
			t.Fatalf("empty description for %s", scope)
		}
	}
	if _, ok := oauthScopeDefinition([]OAuthScopeDefinition{{Name: "documents.read"}}, "documents.read"); !ok {
		t.Fatal("scope definition missing")
	}
	if _, ok := oauthScopeDefinition(nil, "documents.read"); ok {
		t.Fatal("unknown scope definition found")
	}

	raw := "cbr_0123456789ab_" + strings.Repeat("A", 20) + "_" + strings.Repeat("B", 22)
	if prefix, ok := parseOAuthBearer("cbr", raw); !ok || prefix != "0123456789ab" {
		t.Fatalf("token with underscore = %q, %v", prefix, ok)
	}
	for _, raw := range []string{"", "cba_short_abc", "cbr_0123456789zz_" + strings.Repeat("A", 43)} {
		if _, ok := parseOAuthBearer("cbr", raw); ok {
			t.Fatalf("invalid bearer accepted: %q", raw)
		}
	}
	now := time.Now().UTC()
	if !freshAuthentication(now, now.Add(-time.Minute), 2*time.Minute) || freshAuthentication(now, now.Add(time.Minute), 2*time.Minute) || freshAuthentication(now, now.Add(-3*time.Minute), 2*time.Minute) {
		t.Fatal("authentication freshness failed")
	}
	if !scopesSubset([]string{"a"}, []string{"a", "b"}) || scopesSubset([]string{"c"}, []string{"a", "b"}) {
		t.Fatal("scope subset failed")
	}
	if (OAuthAuthentication{}).HasScope("documents.read") {
		t.Fatal("missing scope accepted")
	}
	if validPKCEChallenge("invalid") {
		t.Fatal("invalid PKCE challenge accepted")
	}
}

func TestOAuthPolicyAndClientValidation(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	roles, err := buildRoleCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	manager := &Manager{
		oauth: &OAuthConfig{Pepper: bytes.Repeat([]byte{4}, 32)}, workspaceRoles: roles,
		clock: func() time.Time { return now }, random: bytes.NewReader(bytes.Repeat([]byte{7}, 8192)),
		secretKey: bytes.Repeat([]byte{1}, 32), sealKey: bytes.Repeat([]byte{1}, 32), ceremonyTTL: 5 * time.Minute, observer: nopObserver{},
	}
	invalidPolicies := []UpdateOAuthIssuerInput{
		{CIMDMode: "unknown"}, {DCRMode: "unknown"},
		{DCRMode: OAuthDCROpen, DCRAllowClientSecrets: true},
		{OIDCEnabled: true}, {CIMDMode: OAuthCIMDAllowlist},
		{CIMDMode: OAuthCIMDAllowlist, CIMDAllowedOrigins: []string{"http://client.example.com"}},
		{CodeTTL: 11 * time.Minute}, {AccessTokenTTL: 2 * time.Hour}, {RefreshTokenTTL: 100 * 24 * time.Hour},
	}
	for _, policy := range invalidPolicies {
		if _, err := manager.normalizeOAuthIssuerPolicy(policy); err == nil {
			t.Fatalf("invalid policy accepted: %#v", policy)
		}
	}
	manager.oauth.OIDCSigner = internalTestSigner{}
	policy, err := manager.normalizeOAuthIssuerPolicy(UpdateOAuthIssuerInput{
		OIDCEnabled: true, CIMDMode: OAuthCIMDAllowlist,
		CIMDAllowedOrigins: []string{"https://CLIENT.example.com", "https://client.example.com"}, DCRMode: OAuthDCRProtected,
	})
	if err != nil || len(policy.CIMDAllowedOrigins) != 1 || policy.CodeTTL != defaultOAuthCodeTTL {
		t.Fatalf("policy = %#v, %v", policy, err)
	}

	invalidScopes := [][]OAuthScopeDefinition{
		nil,
		make([]OAuthScopeDefinition, 101),
		{{Name: "openid", Description: "reserved", Permissions: []WorkspacePermission{PermissionWorkspaceAccess}}},
		{{Name: "bad scope", Description: "bad", Permissions: []WorkspacePermission{PermissionWorkspaceAccess}}},
		{{Name: "documents.read", Permissions: []WorkspacePermission{PermissionWorkspaceAccess}}},
		{{Name: "documents.read", Description: "Read", Permissions: nil}},
		{{Name: "documents.read", Description: "Read", Permissions: []WorkspacePermission{"unknown.permission"}}},
		{{Name: "documents.read", Description: "Read", Permissions: []WorkspacePermission{PermissionWorkspaceAccess}, MinimumAAL: 3}},
		{{Name: "documents.read", Description: "Read", Permissions: []WorkspacePermission{PermissionWorkspaceAccess}, MaxAuthAge: -time.Second}},
		{{Name: "documents.read", Description: "Read", Permissions: []WorkspacePermission{PermissionWorkspaceAccess}}, {Name: "documents.read", Description: "Again", Permissions: []WorkspacePermission{PermissionWorkspaceAccess}}},
	}
	for _, scopes := range invalidScopes {
		if _, err := manager.normalizeOAuthScopeDefinitions(scopes); err == nil {
			t.Fatalf("invalid scope catalog accepted: %#v", scopes)
		}
	}
	scopes, err := manager.normalizeOAuthScopeDefinitions([]OAuthScopeDefinition{{Name: "documents.read", Description: "Read", Permissions: []WorkspacePermission{PermissionWorkspaceAccess}}})
	if err != nil || scopes[0].MinimumAAL != AAL1 {
		t.Fatalf("scope catalog = %#v, %v", scopes, err)
	}

	issuer := OAuthIssuer{ID: "0198b463-0000-7000-8000-000000000001"}
	base := OAuthClientRegistrationInput{
		Name: "Client", ApplicationType: OAuthApplicationWeb, RedirectURIs: []string{"https://client.example.com/callback"},
		GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: OAuthAuthNone,
	}
	invalidClients := []struct {
		input       OAuthClientRegistrationInput
		allowSecret bool
	}{
		{func() OAuthClientRegistrationInput { v := base; v.Name = ""; return v }(), false},
		{func() OAuthClientRegistrationInput { v := base; v.ApplicationType = "desktop"; return v }(), false},
		{func() OAuthClientRegistrationInput { v := base; v.RedirectURIs = nil; return v }(), false},
		{func() OAuthClientRegistrationInput {
			v := base
			v.GrantTypes = []string{"client_credentials"}
			return v
		}(), false},
		{func() OAuthClientRegistrationInput { v := base; v.Scopes = []string{"bad scope"}; return v }(), false},
		{func() OAuthClientRegistrationInput { v := base; v.TokenEndpointAuthMethod = "password"; return v }(), false},
		{func() OAuthClientRegistrationInput {
			v := base
			v.TokenEndpointAuthMethod = OAuthAuthPrivateKeyJWT
			return v
		}(), false},
		{func() OAuthClientRegistrationInput {
			v := base
			v.TokenEndpointAuthMethod = OAuthAuthClientSecretBasic
			return v
		}(), false},
		{func() OAuthClientRegistrationInput { v := base; v.JWKSURI = "http://keys.example.com"; return v }(), false},
		{func() OAuthClientRegistrationInput { v := base; v.JWKS = json.RawMessage(`{`); return v }(), false},
	}
	for _, test := range invalidClients {
		if _, _, err := manager.newOAuthClient(issuer, OAuthClientDCR, test.input, test.allowSecret); err == nil {
			t.Fatalf("invalid client accepted: %#v", test.input)
		}
	}
	confidential := base
	confidential.TokenEndpointAuthMethod = OAuthAuthClientSecretBasic
	client, secret, err := manager.newOAuthClient(issuer, OAuthClientPreRegistered, confidential, true)
	if err != nil || secret == "" || len(client.SecretDigest) == 0 {
		t.Fatalf("confidential client = %#v/%q, %v", client, secret, err)
	}
	privateKey := base
	privateKey.TokenEndpointAuthMethod, privateKey.JWKS = OAuthAuthPrivateKeyJWT, json.RawMessage(`{"keys":[]}`)
	if _, secret, err := manager.newOAuthClient(issuer, OAuthClientPreRegistered, privateKey, true); err != nil || secret != "" {
		t.Fatalf("private key client secret=%q, %v", secret, err)
	}

	continuation := oauthAuthorizationContinuation{UserID: "u", ClientRecordID: "c", ResourceID: "r", ExpiresAt: now.Add(time.Minute)}
	raw, err := manager.encodeOAuthContinuation(continuation)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := manager.decodeOAuthContinuation(raw); err != nil || decoded.UserID != "u" {
		t.Fatalf("continuation = %#v, %v", decoded, err)
	}
	if _, err := manager.decodeOAuthContinuation(raw + "tampered"); err == nil {
		t.Fatal("tampered continuation accepted")
	}
	if _, err := manager.decodeOAuthContinuation("not-base64!"); err == nil {
		t.Fatal("invalid continuation encoding accepted")
	}
	emptyRaw, err := manager.encodeOAuthContinuation(oauthAuthorizationContinuation{ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.decodeOAuthContinuation(emptyRaw); err == nil {
		t.Fatal("empty continuation accepted")
	}
	manager.clock = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := manager.decodeOAuthContinuation(raw); err != ErrExpired {
		t.Fatalf("expired continuation = %v", err)
	}

	_ = cloneOAuthGrant(OAuthGrant{Scopes: []string{"a"}, MetadataHash: []byte{1}})
	_ = cloneOAuthAuthorizationCode(OAuthAuthorizationCode{Digest: []byte{1}, Scopes: []string{"a"}})
	_ = cloneOAuthAccessToken(OAuthAccessToken{Digest: []byte{1}, Scopes: []string{"a"}})
	_ = cloneOAuthRefreshToken(OAuthRefreshToken{Digest: []byte{1}, Scopes: []string{"a"}})
	manager.oauthStore = nil
	if _, _, err := manager.requireOAuth(); err != ErrNotSupported {
		t.Fatalf("missing OAuth store = %v", err)
	}
	unsupportedContext := context.Background()
	_, _ = manager.CreateOAuthIssuer(unsupportedContext, Authentication{}, TrustedRequest{}, CreateOAuthIssuerInput{})
	_, _ = manager.UpdateOAuthIssuer(unsupportedContext, Authentication{}, TrustedRequest{}, "", UpdateOAuthIssuerInput{})
	_, _ = manager.CreateOAuthProtectedResource(unsupportedContext, Authentication{}, "", CreateOAuthProtectedResourceInput{})
	_, _ = manager.PreRegisterOAuthClient(unsupportedContext, Authentication{}, TrustedRequest{}, "", OAuthClientRegistrationInput{})
	_, _ = manager.CreateOAuthInitialAccessToken(unsupportedContext, Authentication{}, TrustedRequest{}, "", CreateOAuthInitialAccessTokenInput{})
	_ = manager.RevokeOAuthInitialAccessToken(unsupportedContext, Authentication{}, TrustedRequest{}, "")
	_, _ = manager.RegisterOAuthClient(unsupportedContext, "", "", OAuthClientRegistrationInput{})
	_, _ = manager.BeginOAuthAuthorization(unsupportedContext, Authentication{}, BeginOAuthAuthorizationInput{})
	_, _ = manager.CompleteOAuthAuthorization(unsupportedContext, Authentication{}, "", false)
	_, _ = manager.ExchangeOAuthAuthorizationCode(unsupportedContext, ExchangeOAuthAuthorizationCodeInput{})
	_, _ = manager.RefreshOAuthToken(unsupportedContext, RefreshOAuthTokenInput{})
	_ = manager.RevokeOAuthToken(unsupportedContext, RevokeOAuthTokenInput{})
	_, _ = manager.AuthenticateOAuthAccessToken(unsupportedContext, "", "")
	_, _ = manager.OAuthUserInfo(unsupportedContext, "", "")
	_, _ = manager.OAuthAuthorizationServerMetadata(unsupportedContext, "")
	_, _ = manager.OAuthProtectedResourceMetadata(unsupportedContext, "")
	_, _ = manager.OAuthJWKS(unsupportedContext, "")
	if err := manager.mapOAuthCredentialStoreError(context.Background(), "test", ErrConflict); err != ErrInvalidCredentials {
		t.Fatalf("credential conflict mapping = %v", err)
	}
	if err := manager.mapOAuthCredentialStoreError(context.Background(), "test", ErrExpired); err != ErrInvalidCredentials {
		t.Fatalf("credential expiry mapping = %v", err)
	}
	if err := manager.mapOAuthCredentialStoreError(context.Background(), "test", ErrForbidden); err != ErrForbidden {
		t.Fatalf("credential store mapping = %v", err)
	}
	if _, err := manager.resolveOAuthClient(context.Background(), issuer, ""); err != ErrInvalidCredentials {
		t.Fatalf("empty client id = %v", err)
	}
	policyResource := OAuthProtectedResource{WorkspaceID: "workspace", Scopes: []OAuthScopeDefinition{{
		Name: "documents.read", Description: "Read", Permissions: []WorkspacePermission{PermissionWorkspaceAccess},
	}}}
	if _, _, err := manager.authorizedOAuthScopes(context.Background(), Authentication{}, OAuthIssuer{}, policyResource, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty authorization scopes = %v", err)
	}
	if _, _, err := manager.authorizedOAuthScopes(context.Background(), Authentication{}, OAuthIssuer{}, policyResource, []string{"openid"}); err != ErrForbidden {
		t.Fatalf("OIDC-disabled scope = %v", err)
	}
	if _, _, err := manager.authorizedOAuthScopes(context.Background(), Authentication{}, OAuthIssuer{OIDCEnabled: true}, policyResource, []string{"profile"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("claim scope without openid = %v", err)
	}
	if _, _, err := manager.authorizedOAuthScopes(context.Background(), Authentication{}, OAuthIssuer{}, policyResource, []string{"documents.unknown"}); err != ErrForbidden {
		t.Fatalf("unknown resource scope = %v", err)
	}
	if _, _, err := manager.authorizedOAuthScopes(context.Background(), Authentication{}, OAuthIssuer{}, policyResource, []string{"documents.read"}); err != ErrForbidden {
		t.Fatalf("unauthorized resource scope = %v", err)
	}
	manager.oauth.OIDCSigner = nil
	if _, err := manager.oauthIDToken(context.Background(), OAuthIssuer{OIDCEnabled: true}, OAuthClient{}, OAuthGrant{Scopes: []string{"openid"}}, "", now.Add(time.Minute)); err != ErrNotSupported {
		t.Fatalf("missing OIDC signer = %v", err)
	}
	manager.sealKey = []byte("invalid")
	if _, err := manager.encodeOAuthContinuation(oauthAuthorizationContinuation{}); err == nil {
		t.Fatal("continuation encryption failure ignored")
	}
	manager.sealKey = bytes.Repeat([]byte{1}, 32)
	manager.random = bytes.NewReader(nil)
	if _, _, err := manager.newOAuthChange(EventOAuthTokenIssued, "test", AuditEvent{}, OAuthClient{}, "", "", "", "", nil); err == nil {
		t.Fatal("OAuth event entropy failure ignored")
	}
	manager.random = bytes.NewReader(bytes.Repeat([]byte{7}, 8192))

	manager.clock = func() time.Time { return now }
	issuer.CIMDMode = OAuthCIMDPublicWeb
	if _, err := manager.oauthClientFromMetadata(issuer, OAuthClientMetadataDocument{ClientID: "bad"}); err == nil {
		t.Fatal("invalid metadata client id accepted")
	}
	if _, err := manager.oauthClientFromMetadata(issuer, OAuthClientMetadataDocument{ClientID: "https://client.example.com/client.json", FetchedAt: now, ExpiresAt: now}); err == nil {
		t.Fatal("expired metadata accepted")
	}
	if _, err := manager.oauthClientFromMetadata(issuer, OAuthClientMetadataDocument{ClientID: "https://client.example.com/client.json", ClientName: "", FetchedAt: now, ExpiresAt: now.Add(time.Minute)}); err == nil {
		t.Fatal("nameless metadata accepted")
	}
	manager.random = bytes.NewReader(nil)
	if _, _, err := manager.newOAuthAccessToken(OAuthGrant{}, time.Minute); err == nil {
		t.Fatal("access token entropy failure ignored")
	}
	manager.random = bytes.NewReader(make([]byte, 16))
	if _, _, err := manager.newOAuthAccessToken(OAuthGrant{}, time.Minute); err == nil {
		t.Fatal("access bearer entropy failure ignored")
	}
	manager.random = bytes.NewReader(nil)
	if _, _, err := manager.newOAuthRefreshToken(OAuthGrant{}, "family", time.Minute); err == nil {
		t.Fatal("refresh token entropy failure ignored")
	}
	manager.random = bytes.NewReader(make([]byte, 16))
	if _, _, err := manager.newOAuthRefreshToken(OAuthGrant{}, "family", time.Minute); err == nil {
		t.Fatal("refresh bearer entropy failure ignored")
	}
	manager.random = bytes.NewReader(nil)
	if _, _, err := manager.newOAuthBearer("test"); err == nil {
		t.Fatal("bearer prefix entropy failure ignored")
	}
	manager.random = bytes.NewReader(make([]byte, 6))
	if _, _, err := manager.newOAuthBearer("test"); err == nil {
		t.Fatal("bearer secret entropy failure ignored")
	}
}

type internalTestSigner struct{}

func (internalTestSigner) Algorithms() []string { return []string{"ES256"} }

func (internalTestSigner) SignIDToken(context.Context, OIDCClaims) (string, error) {
	return "token", nil
}
func (internalTestSigner) JWKS(context.Context) (json.RawMessage, error) {
	return json.RawMessage(`{"keys":[]}`), nil
}
