package credbound_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
)

func newOAuthFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		store: memory.New(), now: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
		passwords: &fakePasswords{}, passkeys: &fakePasskeys{},
	}
	manager, err := credbound.New(credbound.Config{
		Store: f.store, Passwords: f.passwords, TOTP: fakeTOTP{}, Passkeys: f.passkeys,
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return f.now }, Random: &counterReader{next: 0x42},
		StepUpMaxAge: 10 * time.Minute, CeremonyTTL: 5 * time.Minute,
		OAuth: &credbound.OAuthConfig{
			Pepper: bytesOf(4, 32), OIDCSigner: fakeOIDCSigner{},
			MetadataFetcher:  fakeOAuthMetadataFetcher{now: func() time.Time { return f.now }},
			ClientAssertions: fakeOAuthAssertionVerifier{},
		},
		TransactionHooks: []credbound.TransactionHook{credbound.UnimplementedTransactionHook{}},
		EventListeners:   []credbound.EventListener{credbound.UnimplementedEventListener{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.manager = manager
	return f
}

func TestOAuthAPIsRequireConfiguration(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	actor := credbound.Authentication{}
	trusted := credbound.TrustedRequest{Local: true}
	mutations := []func() error{
		func() error {
			return f.manager.ValidateOAuthAuthorizationRedirect(ctx, "https://auth.example.com", "client", "https://client.example.com/callback")
		},
		func() error {
			_, err := f.manager.CreateOAuthIssuer(ctx, actor, trusted, credbound.CreateOAuthIssuerInput{})
			return err
		},
		func() error {
			_, err := f.manager.UpdateOAuthIssuer(ctx, actor, trusted, "id", credbound.UpdateOAuthIssuerInput{})
			return err
		},
		func() error {
			_, err := f.manager.CreateOAuthProtectedResource(ctx, actor, "workspace", credbound.CreateOAuthProtectedResourceInput{})
			return err
		},
		func() error {
			_, err := f.manager.PreRegisterOAuthClient(ctx, actor, trusted, "issuer", credbound.OAuthClientRegistrationInput{})
			return err
		},
		func() error {
			_, err := f.manager.CreateOAuthInitialAccessToken(ctx, actor, trusted, "issuer", credbound.CreateOAuthInitialAccessTokenInput{})
			return err
		},
		func() error { return f.manager.RevokeOAuthInitialAccessToken(ctx, actor, trusted, "token") },
		func() error {
			_, err := f.manager.RegisterOAuthClient(ctx, "https://auth.example.com", "", credbound.OAuthClientRegistrationInput{})
			return err
		},
		func() error {
			_, err := f.manager.BeginOAuthAuthorization(ctx, actor, credbound.BeginOAuthAuthorizationInput{})
			return err
		},
		func() error {
			_, err := f.manager.CompleteOAuthAuthorization(ctx, actor, "continuation", true)
			return err
		},
		func() error { return f.manager.DisableOAuthIssuer(ctx, actor, trusted, "issuer") },
		func() error { return f.manager.EnableOAuthIssuer(ctx, actor, trusted, "issuer") },
		func() error { return f.manager.DisableOAuthProtectedResource(ctx, actor, "workspace", "resource") },
		func() error { return f.manager.EnableOAuthProtectedResource(ctx, actor, "workspace", "resource") },
		func() error { return f.manager.DisableOAuthClient(ctx, actor, trusted, "client") },
		func() error { return f.manager.EnableOAuthClient(ctx, actor, trusted, "client") },
		func() error { return f.manager.RevokeOAuthGrant(ctx, actor, "grant") },
		func() error {
			_, err := f.manager.ExchangeOAuthAuthorizationCode(ctx, credbound.ExchangeOAuthAuthorizationCodeInput{})
			return err
		},
		func() error {
			_, err := f.manager.RefreshOAuthToken(ctx, credbound.RefreshOAuthTokenInput{})
			return err
		},
		func() error { return f.manager.RevokeOAuthToken(ctx, credbound.RevokeOAuthTokenInput{}) },
		func() error { _, err := f.manager.AuthenticateOAuthAccessToken(ctx, "resource", "token"); return err },
		func() error { _, err := f.manager.OAuthUserInfo(ctx, "issuer", "token"); return err },
		func() error { _, err := f.manager.OAuthAuthorizationServerMetadata(ctx, "issuer"); return err },
		func() error { _, err := f.manager.OAuthProtectedResourceMetadata(ctx, "resource"); return err },
		func() error { _, err := f.manager.OAuthJWKS(ctx, "issuer"); return err },
	}
	for index, mutation := range mutations {
		if err := mutation(); !errors.Is(err, credbound.ErrNotSupported) {
			t.Fatalf("OAuth API %d = %v", index, err)
		}
	}
	assertLifecycleError(t, f.manager.OAuthIssuers(ctx, actor, credbound.PageRequest{}), credbound.ErrNotSupported)
	assertLifecycleError(t, f.manager.OAuthProtectedResources(ctx, actor, "workspace", credbound.PageRequest{}), credbound.ErrNotSupported)
	assertLifecycleError(t, f.manager.OAuthClients(ctx, actor, "issuer", credbound.PageRequest{}), credbound.ErrNotSupported)
	assertLifecycleError(t, f.manager.OAuthGrants(ctx, actor, "workspace", credbound.PageRequest{}), credbound.ErrNotSupported)
}

// TestOAuthConfigRequiresCapableStore checks that enabling Config.OAuth with a
// Store that cannot back it fails construction instead of surfacing
// ErrNotSupported from every OAuth call at runtime.
func TestOAuthConfigRequiresCapableStore(t *testing.T) {
	_, err := credbound.New(credbound.Config{
		Store: coreStore{Store: memory.New()}, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		OAuth: &credbound.OAuthConfig{Pepper: bytesOf(4, 32), OIDCSigner: fakeOIDCSigner{}},
	})
	if !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("Config.OAuth with incapable store = %v, want ErrInvalidInput", err)
	}
}

func TestOAuthAuthorizationRefreshAndDCR(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := context.Background()
	actor, workspace := f.bootstrap(t)
	actor.Level, actor.Method = credbound.AAL2, credbound.MethodTOTP

	issuer, err := f.manager.CreateOAuthIssuer(ctx, actor, credbound.TrustedRequest{Local: true}, credbound.CreateOAuthIssuerInput{
		Issuer: "https://auth.example.com", OIDCEnabled: true, CIMDMode: credbound.OAuthCIMDDisabled,
		DCRMode: credbound.OAuthDCRProtected,
	})
	if err != nil || !uuidV7.MatchString(issuer.ID) {
		t.Fatalf("issuer = %#v, %v", issuer, err)
	}
	resource, err := f.manager.CreateOAuthProtectedResource(ctx, actor, workspace.ID, credbound.CreateOAuthProtectedResourceInput{
		IssuerID: issuer.ID, Resource: "https://mcp.example.com/workspaces/acme",
		Scopes: []credbound.OAuthScopeDefinition{{Name: "documents.read", Description: "Read documents", Permissions: []credbound.WorkspacePermission{credbound.PermissionWorkspaceAccess}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	issuedClient, err := f.manager.PreRegisterOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.OAuthClientRegistrationInput{
		Name: "MCP Client", ApplicationType: credbound.OAuthApplicationWeb,
		RedirectURIs: []string{"https://client.example.com/callback"}, GrantTypes: []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"}, Scopes: []string{"documents.read", "offline_access", "openid", "email"}, TokenEndpointAuthMethod: credbound.OAuthAuthNone,
	})
	if err != nil || issuedClient.Client.ClientID == "" || issuedClient.ClientSecret != "" {
		t.Fatalf("client = %#v, %v", issuedClient, err)
	}
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	consent, err := f.manager.BeginOAuthAuthorization(ctx, actor, credbound.BeginOAuthAuthorizationInput{
		Issuer: issuer.Issuer, ClientID: issuedClient.Client.ClientID,
		RedirectURI: "https://client.example.com/callback", Resource: resource.Resource,
		Scopes: []string{"documents.read", "offline_access", "openid", "email"}, State: "state", CodeChallenge: challenge, CodeChallengeMethod: "S256", Nonce: "nonce",
	})
	if err != nil || consent.RequiresStepUp {
		t.Fatalf("consent = %#v, %v", consent, err)
	}
	// A client max_age shorter than the actor's authentication age forces
	// step-up, and completion refuses until the host re-authenticates.
	staleActor := actor
	staleActor.AuthenticatedAt = actor.AuthenticatedAt.Add(-time.Hour)
	stale, err := f.manager.BeginOAuthAuthorization(ctx, staleActor, credbound.BeginOAuthAuthorizationInput{
		Issuer: issuer.Issuer, ClientID: issuedClient.Client.ClientID,
		RedirectURI: "https://client.example.com/callback", Resource: resource.Resource,
		Scopes: []string{"documents.read", "offline_access", "openid", "email"}, State: "state", CodeChallenge: challenge, CodeChallengeMethod: "S256", Nonce: "nonce",
		MaxAge: time.Minute,
	})
	if err != nil || !stale.RequiresStepUp {
		t.Fatalf("max_age consent = %#v, %v", stale, err)
	}
	if _, err := f.manager.CompleteOAuthAuthorization(ctx, staleActor, stale.Continuation, true); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("max_age completion = %v", err)
	}
	authorized, err := f.manager.CompleteOAuthAuthorization(ctx, actor, consent.Continuation, true)
	if err != nil || authorized.Code == "" || authorized.State != "state" {
		t.Fatalf("authorization = %#v, %v", authorized, err)
	}
	tokens, err := f.manager.ExchangeOAuthAuthorizationCode(ctx, credbound.ExchangeOAuthAuthorizationCodeInput{
		Issuer: issuer.Issuer, ClientID: issuedClient.Client.ClientID, Code: authorized.Code,
		RedirectURI: "https://client.example.com/callback", CodeVerifier: verifier, Resource: resource.Resource,
	})
	if err != nil || tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.TokenType != "Bearer" || tokens.IDToken != "signed-id-token" {
		t.Fatalf("tokens = %#v, %v", tokens, err)
	}
	if _, err := f.manager.ExchangeOAuthAuthorizationCode(ctx, credbound.ExchangeOAuthAuthorizationCodeInput{
		Issuer: issuer.Issuer, ClientID: issuedClient.Client.ClientID, Code: authorized.Code,
		RedirectURI: "https://client.example.com/callback", CodeVerifier: verifier, Resource: resource.Resource,
	}); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("authorization code reuse = %v", err)
	}
	principal, err := f.manager.AuthenticateOAuthAccessToken(ctx, resource.Resource, tokens.AccessToken)
	if err != nil || principal.UserID != actor.UserID || !principal.HasScope("documents.read") {
		t.Fatalf("principal = %#v, %v", principal, err)
	}
	if _, err := f.manager.RefreshOAuthToken(ctx, credbound.RefreshOAuthTokenInput{
		Issuer: issuer.Issuer, ClientID: issuedClient.Client.ClientID, RefreshToken: tokens.RefreshToken,
		Resource: resource.Resource, Scopes: []string{"documents.write"},
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("refresh scope escalation = %v", err)
	}
	refreshed, err := f.manager.RefreshOAuthToken(ctx, credbound.RefreshOAuthTokenInput{
		Issuer: issuer.Issuer, ClientID: issuedClient.Client.ClientID, RefreshToken: tokens.RefreshToken, Resource: resource.Resource,
	})
	if err != nil || refreshed.RefreshToken == tokens.RefreshToken {
		t.Fatalf("refresh = %#v, %v", refreshed, err)
	}
	if _, err := f.manager.RefreshOAuthToken(ctx, credbound.RefreshOAuthTokenInput{
		Issuer: issuer.Issuer, ClientID: issuedClient.Client.ClientID, RefreshToken: tokens.RefreshToken, Resource: resource.Resource,
	}); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("refresh reuse = %v", err)
	}
	if _, err := f.manager.RefreshOAuthToken(ctx, credbound.RefreshOAuthTokenInput{
		Issuer: issuer.Issuer, ClientID: issuedClient.Client.ClientID, RefreshToken: refreshed.RefreshToken, Resource: resource.Resource,
	}); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("revoked refresh family = %v", err)
	}
	if err := f.manager.RevokeOAuthToken(ctx, credbound.RevokeOAuthTokenInput{Issuer: issuer.Issuer, ClientID: issuedClient.Client.ClientID, Token: refreshed.RefreshToken}); err != nil {
		t.Fatalf("refresh revocation = %v", err)
	}
	info, err := f.manager.OAuthUserInfo(ctx, issuer.Issuer, tokens.AccessToken)
	if err != nil || info.Subject == "" || info.Subject == actor.UserID || info.Email != "root@example.com" || info.EmailVerified == nil || !*info.EmailVerified {
		t.Fatalf("userinfo = %#v, %v", info, err)
	}
	if _, err := f.manager.OAuthUserInfo(ctx, issuer.Issuer, "bad"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("malformed UserInfo token = %v", err)
	}
	if _, err := f.manager.AuthenticateOAuthAccessToken(ctx, resource.Resource, "bad"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("malformed access token = %v", err)
	}
	if err := f.manager.RevokeOAuthToken(ctx, credbound.RevokeOAuthTokenInput{
		Issuer: issuer.Issuer, ClientID: issuedClient.Client.ClientID,
		Token: "cbr_0123456789ab_" + strings.Repeat("A", 43),
	}); err != nil {
		t.Fatalf("unknown structured refresh revocation = %v", err)
	}
	if jwks, err := f.manager.OAuthJWKS(ctx, issuer.Issuer); err != nil || string(jwks) != `{"keys":[]}` {
		t.Fatalf("JWKS = %s, %v", jwks, err)
	}
	if metadata, err := f.manager.OAuthProtectedResourceMetadata(ctx, resource.Resource); err != nil || metadata.Resource != resource.Resource || len(metadata.ScopesSupported) != 1 {
		t.Fatalf("resource metadata = %#v, %v", metadata, err)
	}
	if err := f.manager.RevokeOAuthToken(ctx, credbound.RevokeOAuthTokenInput{Issuer: issuer.Issuer, ClientID: issuedClient.Client.ClientID, Token: refreshed.AccessToken}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.AuthenticateOAuthAccessToken(ctx, resource.Resource, refreshed.AccessToken); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("revoked access token = %v", err)
	}

	initial, err := f.manager.CreateOAuthInitialAccessToken(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.CreateOAuthInitialAccessTokenInput{
		ExpiresAt: f.now.Add(time.Hour), MaxRegistrations: 1,
	})
	if err != nil || initial.Token == "" {
		t.Fatalf("initial access token = %#v, %v", initial, err)
	}
	registration := credbound.OAuthClientRegistrationInput{
		Name: "Legacy MCP", ApplicationType: credbound.OAuthApplicationWeb,
		RedirectURIs: []string{"https://legacy.example.com/callback"}, Scopes: []string{"documents.read"}, TokenEndpointAuthMethod: credbound.OAuthAuthNone,
	}
	if _, err := f.manager.RegisterOAuthClient(ctx, issuer.Issuer, "invalid", registration); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("invalid initial access token = %v", err)
	}
	if _, err := f.manager.RegisterOAuthClient(ctx, issuer.Issuer, initial.Token, registration); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.RegisterOAuthClient(ctx, issuer.Issuer, initial.Token, registration); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("DCR quota error = %v", err)
	}
	if err := f.manager.RevokeOAuthInitialAccessToken(ctx, actor, credbound.TrustedRequest{Local: true}, initial.Credential.ID); err != nil {
		t.Fatal(err)
	}
	metadata, err := f.manager.OAuthAuthorizationServerMetadata(ctx, issuer.Issuer)
	if err != nil || metadata.RegistrationEndpoint == "" || metadata.ClientIDMetadataDocumentSupported {
		t.Fatalf("metadata = %#v, %v", metadata, err)
	}
	issuer, err = f.manager.UpdateOAuthIssuer(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.UpdateOAuthIssuerInput{
		OIDCEnabled: true, CIMDMode: credbound.OAuthCIMDPublicWeb, DCRMode: credbound.OAuthDCRDisabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if metadata, err := f.manager.OAuthAuthorizationServerMetadata(ctx, issuer.Issuer); err != nil || metadata.RegistrationEndpoint != "" || !metadata.ClientIDMetadataDocumentSupported {
		t.Fatalf("updated metadata = %#v, %v", metadata, err)
	}
	for _, clientID := range []string{
		"https://fetch-error.example.net/oauth/client.json",
		"https://invalid-metadata.example.net/oauth/client.json",
		"https://client.example.net/oauth/../client.json",
	} {
		if _, err := f.manager.BeginOAuthAuthorization(ctx, actor, credbound.BeginOAuthAuthorizationInput{
			Issuer: issuer.Issuer, ClientID: clientID, RedirectURI: "https://client.example.net/callback",
			Resource: resource.Resource, Scopes: []string{"documents.read"}, CodeChallenge: challenge, CodeChallengeMethod: "S256",
		}); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("rejected CIMD %q = %v", clientID, err)
		}
	}
	cimdID := "https://client.example.net/oauth/client.json"
	cimdConsent, err := f.manager.BeginOAuthAuthorization(ctx, actor, credbound.BeginOAuthAuthorizationInput{
		Issuer: issuer.Issuer, ClientID: cimdID, RedirectURI: "https://client.example.net/callback",
		Resource: resource.Resource, Scopes: []string{"documents.read"}, State: "cimd-state",
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	if err != nil || cimdConsent.ClientHost != "client.example.net" {
		t.Fatalf("CIMD consent = %#v, %v", cimdConsent, err)
	}
	if cached, err := f.manager.BeginOAuthAuthorization(ctx, actor, credbound.BeginOAuthAuthorizationInput{
		Issuer: issuer.Issuer, ClientID: cimdID, RedirectURI: "https://client.example.net/callback",
		Resource: resource.Resource, Scopes: []string{"documents.read"}, State: "cached",
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
	}); err != nil || cached.ClientID != cimdID {
		t.Fatalf("cached CIMD = %#v, %v", cached, err)
	}
	denied, err := f.manager.CompleteOAuthAuthorization(ctx, actor, cimdConsent.Continuation, false)
	if err != nil || denied.Error != "access_denied" {
		t.Fatalf("CIMD denial = %#v, %v", denied, err)
	}
	issuer, err = f.manager.UpdateOAuthIssuer(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.UpdateOAuthIssuerInput{
		OIDCEnabled: true, CIMDMode: credbound.OAuthCIMDPublicWeb, DCRMode: credbound.OAuthDCROpen,
	})
	if err != nil {
		t.Fatal(err)
	}
	openRegistration := credbound.OAuthClientRegistrationInput{
		Name: "Open DCR", ApplicationType: credbound.OAuthApplicationWeb,
		RedirectURIs: []string{"https://open.example.com/callback"}, Scopes: []string{"documents.read"},
	}
	if _, err := f.manager.RegisterOAuthClient(ctx, issuer.Issuer, "unexpected", openRegistration); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("open DCR accepted IAT = %v", err)
	}
	if registered, err := f.manager.RegisterOAuthClient(ctx, issuer.Issuer, "", openRegistration); err != nil || registered.Client.ClientID == "" {
		t.Fatalf("open DCR = %#v, %v", registered, err)
	}
}

// TestOAuthUserInfoRejectsDisabledUser guards USER-002 on the UserInfo path:
// disabling a user does not revoke their OAuth grants, so UserInfo must re-check
// account status exactly like the resource-server path, or a disabled user's
// subject and email keep leaking until the token expires.
func TestOAuthUserInfoRejectsDisabledUser(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := context.Background()
	root, workspace := f.bootstrap(t)
	rootAAL2 := aal2(root.UserID, f.now)

	issuer, err := f.manager.CreateOAuthIssuer(ctx, rootAAL2, credbound.TrustedRequest{Local: true}, credbound.CreateOAuthIssuerInput{
		Issuer: "https://auth.example.com", OIDCEnabled: true, CIMDMode: credbound.OAuthCIMDDisabled, DCRMode: credbound.OAuthDCRDisabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := f.manager.CreateOAuthProtectedResource(ctx, rootAAL2, workspace.ID, credbound.CreateOAuthProtectedResourceInput{
		IssuerID: issuer.ID, Resource: "https://mcp.example.com/workspaces/acme",
		Scopes: []credbound.OAuthScopeDefinition{{Name: "documents.read", Description: "Read", Permissions: []credbound.WorkspacePermission{credbound.PermissionWorkspaceAccess}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := f.manager.PreRegisterOAuthClient(ctx, rootAAL2, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.OAuthClientRegistrationInput{
		Name: "MCP", ApplicationType: credbound.OAuthApplicationWeb,
		RedirectURIs: []string{"https://client.example.com/callback"}, GrantTypes: []string{"authorization_code"},
		ResponseTypes: []string{"code"}, Scopes: []string{"documents.read", "openid", "email"}, TokenEndpointAuthMethod: credbound.OAuthAuthNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.manager.CreateUser(ctx, rootAAL2, workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	memberAAL2 := aal2(member.ID, f.now)

	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	consent, err := f.manager.BeginOAuthAuthorization(ctx, memberAAL2, credbound.BeginOAuthAuthorizationInput{
		Issuer: issuer.Issuer, ClientID: client.Client.ClientID, RedirectURI: "https://client.example.com/callback",
		Resource: resource.Resource, Scopes: []string{"documents.read", "openid", "email"}, State: "state",
		CodeChallenge: challenge, CodeChallengeMethod: "S256", Nonce: "nonce",
	})
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := f.manager.CompleteOAuthAuthorization(ctx, memberAAL2, consent.Continuation, true)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := f.manager.ExchangeOAuthAuthorizationCode(ctx, credbound.ExchangeOAuthAuthorizationCodeInput{
		Issuer: issuer.Issuer, ClientID: client.Client.ClientID, Code: authorized.Code,
		RedirectURI: "https://client.example.com/callback", CodeVerifier: verifier, Resource: resource.Resource,
	})
	if err != nil || tokens.AccessToken == "" {
		t.Fatalf("exchange = %#v, %v", tokens, err)
	}

	// While enabled, UserInfo answers.
	if info, err := f.manager.OAuthUserInfo(ctx, issuer.Issuer, tokens.AccessToken); err != nil || info.Subject == "" {
		t.Fatalf("userinfo before disable = %#v, %v", info, err)
	}
	// After disabling the member, the still-unexpired token must be refused by
	// both the resource-server path and UserInfo.
	if err := f.manager.DisableUser(ctx, rootAAL2, credbound.TrustedRequest{Local: true}, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.AuthenticateOAuthAccessToken(ctx, resource.Resource, tokens.AccessToken); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("resource-server path after disable = %v", err)
	}
	if _, err := f.manager.OAuthUserInfo(ctx, issuer.Issuer, tokens.AccessToken); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("userinfo after disable = %v", err)
	}
}

func TestOAuthAdministrationListsQuotaAndRevocation(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := context.Background()
	actor, workspace := f.bootstrap(t)
	actor.Level, actor.Method = credbound.AAL2, credbound.MethodTOTP
	issuer, err := f.manager.CreateOAuthIssuer(ctx, actor, credbound.TrustedRequest{Local: true}, credbound.CreateOAuthIssuerInput{
		Issuer: "https://auth.example.com/tenant", OIDCEnabled: true, DCRMode: credbound.OAuthDCROpen, DCROpenRegistrationLimit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := f.manager.CreateOAuthProtectedResource(ctx, actor, workspace.ID, credbound.CreateOAuthProtectedResourceInput{
		IssuerID: issuer.ID, Resource: "https://mcp.example.com/workspaces/acme",
		Scopes: []credbound.OAuthScopeDefinition{{Name: "documents.read", Description: "Read workspace documents", Permissions: []credbound.WorkspacePermission{credbound.PermissionWorkspaceAccess}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := f.manager.PreRegisterOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.OAuthClientRegistrationInput{
		Name: "Dashboard", ApplicationType: credbound.OAuthApplicationWeb,
		RedirectURIs: []string{"https://client.example.com/callback"}, Scopes: []string{"openid", "documents.read"},
	})
	if err != nil || client.Client.SectorIdentifier != "client.example.com" {
		t.Fatalf("client = %#v, %v", client, err)
	}
	if _, err := f.manager.PreRegisterOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.OAuthClientRegistrationInput{
		Name: "Invalid sectors", ApplicationType: credbound.OAuthApplicationWeb,
		RedirectURIs: []string{"https://one.example.com/callback", "https://two.example.com/callback"}, Scopes: []string{"openid"},
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("multiple OIDC sectors = %v", err)
	}
	if _, err := f.manager.PreRegisterOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.OAuthClientRegistrationInput{
		Name: "Unrestricted invalid sectors", ApplicationType: credbound.OAuthApplicationWeb,
		RedirectURIs: []string{"https://one.example.com/callback", "https://two.example.com/callback"},
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("multiple unrestricted OIDC sectors = %v", err)
	}
	register := credbound.OAuthClientRegistrationInput{
		Name: "Dynamic", ApplicationType: credbound.OAuthApplicationWeb,
		RedirectURIs: []string{"https://dynamic.example.com/callback"}, Scopes: []string{"documents.read"},
	}
	if _, err := f.manager.RegisterOAuthClient(ctx, issuer.Issuer, "", register); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.RegisterOAuthClient(ctx, issuer.Issuer, "", register); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("open DCR quota = %v", err)
	}
	if err := f.manager.ValidateOAuthAuthorizationRedirect(ctx, issuer.Issuer, client.Client.ClientID, "https://client.example.com/callback"); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.ValidateOAuthAuthorizationRedirect(ctx, issuer.Issuer, client.Client.ClientID, "https://evil.example.com/callback"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("unregistered redirect = %v", err)
	}
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	digest := sha256.Sum256([]byte(verifier))
	consent, err := f.manager.BeginOAuthAuthorization(ctx, actor, credbound.BeginOAuthAuthorizationInput{
		Issuer: issuer.Issuer, ClientID: client.Client.ClientID, RedirectURI: client.Client.RedirectURIs[0],
		Resource: resource.Resource, Scopes: []string{"openid", "documents.read"}, State: "state",
		CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:]), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.manager.CompleteOAuthAuthorization(ctx, actor, consent.Continuation, true)
	if err != nil || result.Code == "" {
		t.Fatalf("authorization = %#v, %v", result, err)
	}
	grants := collectLifecyclePage(t, f.manager.OAuthGrants(ctx, actor, "", credbound.PageRequest{}))
	if len(grants) != 1 {
		t.Fatalf("grants = %#v", grants)
	}
	if err := f.manager.RevokeOAuthGrant(ctx, actor, grants[0].ID); err != nil {
		t.Fatal(err)
	}
	if issuers := collectLifecyclePage(t, f.manager.OAuthIssuers(ctx, actor, credbound.PageRequest{})); len(issuers) != 1 {
		t.Fatalf("issuers = %#v", issuers)
	}
	if resources := collectLifecyclePage(t, f.manager.OAuthProtectedResources(ctx, actor, workspace.ID, credbound.PageRequest{})); len(resources) != 1 {
		t.Fatalf("resources = %#v", resources)
	}
	if clients := collectLifecyclePage(t, f.manager.OAuthClients(ctx, actor, issuer.ID, credbound.PageRequest{})); len(clients) != 2 {
		t.Fatalf("clients = %#v", clients)
	}
	metadata, err := f.manager.OAuthAuthorizationServerMetadata(ctx, issuer.Issuer)
	if err != nil || len(metadata.SubjectTypesSupported) != 1 || len(metadata.IDTokenSigningAlgValuesSupported) != 1 {
		t.Fatalf("metadata = %#v, %v", metadata, err)
	}
	if err := f.manager.DisableOAuthProtectedResource(ctx, actor, workspace.ID, resource.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.EnableOAuthProtectedResource(ctx, actor, workspace.ID, resource.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.DisableOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, client.Client.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.EnableOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, client.Client.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.DisableOAuthIssuer(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.EnableOAuthIssuer(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID); err != nil {
		t.Fatal(err)
	}
}

func TestOAuthAdministrationRejectsInvalidAndUnauthorizedRequests(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := context.Background()
	actor, workspace := f.bootstrap(t)
	actor.Level, actor.Method = credbound.AAL2, credbound.MethodTOTP
	issuer, err := f.manager.CreateOAuthIssuer(ctx, actor, credbound.TrustedRequest{Local: true}, credbound.CreateOAuthIssuerInput{Issuer: "https://auth.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := f.manager.CreateOAuthProtectedResource(ctx, actor, workspace.ID, credbound.CreateOAuthProtectedResourceInput{
		IssuerID: issuer.ID, Resource: "https://mcp.example.com",
		Scopes: []credbound.OAuthScopeDefinition{{Name: "documents.read", Description: "Read documents", Permissions: []credbound.WorkspacePermission{credbound.PermissionWorkspaceAccess}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := f.manager.PreRegisterOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.OAuthClientRegistrationInput{
		Name: "Client", ApplicationType: credbound.OAuthApplicationWeb, RedirectURIs: []string{"https://client.example.com/callback"}, Scopes: []string{"documents.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"issuer id": func() error {
			return f.manager.DisableOAuthIssuer(ctx, actor, credbound.TrustedRequest{Local: true}, "invalid")
		},
		"client id": func() error {
			return f.manager.DisableOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, "invalid")
		},
		"grant id": func() error { return f.manager.RevokeOAuthGrant(ctx, actor, "invalid") },
	} {
		if err := call(); !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("invalid %s = %v", name, err)
		}
	}
	if err := f.manager.DisableOAuthIssuer(ctx, credbound.Authentication{}, credbound.TrustedRequest{Local: true}, issuer.ID); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("unauthorized issuer disable = %v", err)
	}
	if err := f.manager.DisableOAuthClient(ctx, credbound.Authentication{}, credbound.TrustedRequest{Local: true}, client.Client.ID); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("unauthorized client disable = %v", err)
	}
	if err := f.manager.DisableOAuthProtectedResource(ctx, actor, "0198b463-0000-7000-8000-0000000000ff", resource.ID); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("cross-workspace resource disable = %v", err)
	}
	if err := f.manager.DisableOAuthIssuer(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.DisableOAuthIssuer(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID); err != nil {
		t.Fatalf("idempotent issuer disable = %v", err)
	}
	if err := f.manager.EnableOAuthIssuer(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.DisableOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, client.Client.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.DisableOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, client.Client.ID); err != nil {
		t.Fatalf("idempotent client disable = %v", err)
	}
	if err := f.manager.EnableOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, client.Client.ID); err != nil {
		t.Fatal(err)
	}
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	digest := sha256.Sum256([]byte(verifier))
	consent, err := f.manager.BeginOAuthAuthorization(ctx, actor, credbound.BeginOAuthAuthorizationInput{
		Issuer: issuer.Issuer, ClientID: client.Client.ClientID, RedirectURI: client.Client.RedirectURIs[0], Resource: resource.Resource,
		Scopes: []string{"documents.read"}, State: "state", CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:]), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := f.manager.CompleteOAuthAuthorization(ctx, actor, consent.Continuation, true)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := f.manager.ExchangeOAuthAuthorizationCode(ctx, credbound.ExchangeOAuthAuthorizationCodeInput{
		Issuer: issuer.Issuer, ClientID: client.Client.ClientID, Code: authorized.Code, RedirectURI: client.Client.RedirectURIs[0], CodeVerifier: verifier, Resource: resource.Resource,
	})
	if err != nil {
		t.Fatal(err)
	}
	grants := collectLifecyclePage(t, f.manager.OAuthGrants(ctx, actor, "", credbound.PageRequest{}))
	if len(grants) != 1 {
		t.Fatalf("grants = %#v", grants)
	}
	if err := f.manager.RevokeOAuthGrant(ctx, actor, grants[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.AuthenticateOAuthAccessToken(ctx, resource.Resource, tokens.AccessToken); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("revoked grant access token = %v", err)
	}
	assertLifecycleError(t, f.manager.OAuthIssuers(ctx, credbound.Authentication{}, credbound.PageRequest{}), credbound.ErrUnauthorized)
	assertLifecycleError(t, f.manager.OAuthIssuers(ctx, actor, credbound.PageRequest{Limit: 101}), credbound.ErrInvalidInput)
	assertLifecycleError(t, f.manager.OAuthProtectedResources(ctx, credbound.Authentication{}, workspace.ID, credbound.PageRequest{}), credbound.ErrUnauthorized)
	assertLifecycleError(t, f.manager.OAuthProtectedResources(ctx, actor, workspace.ID, credbound.PageRequest{Limit: 101}), credbound.ErrInvalidInput)
	assertLifecycleError(t, f.manager.OAuthClients(ctx, actor, "invalid", credbound.PageRequest{}), credbound.ErrInvalidInput)
	assertLifecycleError(t, f.manager.OAuthClients(ctx, actor, issuer.ID, credbound.PageRequest{Limit: 101}), credbound.ErrInvalidInput)
	assertLifecycleError(t, f.manager.OAuthGrants(ctx, credbound.Authentication{}, "", credbound.PageRequest{}), credbound.ErrUnauthorized)
	assertLifecycleError(t, f.manager.OAuthGrants(ctx, actor, "", credbound.PageRequest{Limit: 101}), credbound.ErrInvalidInput)
}

func TestOAuthRejectsInvalidRequests(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := context.Background()
	actor, workspace := f.bootstrap(t)
	actor.Level, actor.Method = credbound.AAL2, credbound.MethodTOTP
	for _, input := range []credbound.CreateOAuthIssuerInput{
		{Issuer: "http://auth.example.com"},
		{Issuer: "https://auth.example.com", CIMDMode: "invalid"},
		{Issuer: "https://auth.example.com", CIMDMode: credbound.OAuthCIMDAllowlist},
		{Issuer: "https://auth.example.com", DCRMode: credbound.OAuthDCROpen, DCRAllowClientSecrets: true},
		{Issuer: "https://auth.example.com", AccessTokenTTL: 2 * time.Hour},
	} {
		if _, err := f.manager.CreateOAuthIssuer(ctx, actor, credbound.TrustedRequest{Local: true}, input); !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("invalid issuer input %#v = %v", input, err)
		}
	}
	issuer, err := f.manager.CreateOAuthIssuer(ctx, actor, credbound.TrustedRequest{Local: true}, credbound.CreateOAuthIssuerInput{Issuer: "https://auth.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.CreateOAuthInitialAccessToken(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.CreateOAuthInitialAccessTokenInput{ExpiresAt: f.now.Add(time.Hour)}); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("IAT with disabled DCR = %v", err)
	}
	if _, err := f.manager.RegisterOAuthClient(ctx, issuer.Issuer, "", credbound.OAuthClientRegistrationInput{}); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("registration with disabled DCR = %v", err)
	}
	issuer, err = f.manager.UpdateOAuthIssuer(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.UpdateOAuthIssuerInput{DCRMode: credbound.OAuthDCRProtected})
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []credbound.CreateOAuthInitialAccessTokenInput{
		{ExpiresAt: f.now}, {ExpiresAt: f.now.Add(31 * 24 * time.Hour)},
		{ExpiresAt: f.now.Add(time.Hour), MaxRegistrations: -1}, {ExpiresAt: f.now.Add(time.Hour), MaxRegistrations: 101},
	} {
		if _, err := f.manager.CreateOAuthInitialAccessToken(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, input); !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("invalid IAT %#v = %v", input, err)
		}
	}
	if _, err := f.manager.UpdateOAuthIssuer(ctx, actor, credbound.TrustedRequest{Local: true}, "not-a-uuid", credbound.UpdateOAuthIssuerInput{}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid issuer id = %v", err)
	}
	for _, input := range []credbound.CreateOAuthProtectedResourceInput{
		{IssuerID: "bad", Resource: "https://mcp.example.com/acme", Scopes: []credbound.OAuthScopeDefinition{{Name: "read", Description: "Read", Permissions: []credbound.WorkspacePermission{credbound.PermissionWorkspaceAccess}}}},
		{IssuerID: issuer.ID, Resource: "http://mcp.example.com/acme", Scopes: []credbound.OAuthScopeDefinition{{Name: "read", Description: "Read", Permissions: []credbound.WorkspacePermission{credbound.PermissionWorkspaceAccess}}}},
		{IssuerID: issuer.ID, Resource: "https://mcp.example.com/acme"},
		{IssuerID: issuer.ID, Resource: "https://mcp.example.com/acme", Scopes: []credbound.OAuthScopeDefinition{{Name: "openid", Description: "Reserved", Permissions: []credbound.WorkspacePermission{credbound.PermissionWorkspaceAccess}}}},
		{IssuerID: issuer.ID, Resource: "https://mcp.example.com/acme", Scopes: []credbound.OAuthScopeDefinition{{Name: "read", Description: "Read", Permissions: []credbound.WorkspacePermission{"unknown.permission"}}}},
	} {
		if _, err := f.manager.CreateOAuthProtectedResource(ctx, actor, workspace.ID, input); err == nil {
			t.Fatalf("invalid resource input accepted: %#v", input)
		}
	}
	resource, err := f.manager.CreateOAuthProtectedResource(ctx, actor, workspace.ID, credbound.CreateOAuthProtectedResourceInput{
		IssuerID: issuer.ID, Resource: "https://mcp.example.com/acme",
		Scopes: []credbound.OAuthScopeDefinition{{Name: "documents.read", Description: "Read", Permissions: []credbound.WorkspacePermission{credbound.PermissionWorkspaceAccess}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []credbound.OAuthClientRegistrationInput{
		{ApplicationType: credbound.OAuthApplicationWeb, RedirectURIs: []string{"https://client.example.com/callback"}},
		{Name: "Client", ApplicationType: "desktop", RedirectURIs: []string{"https://client.example.com/callback"}},
		{Name: "Client", ApplicationType: credbound.OAuthApplicationWeb, RedirectURIs: []string{"http://client.example.com/callback"}},
		{Name: "Client", ApplicationType: credbound.OAuthApplicationWeb, RedirectURIs: []string{"https://client.example.com/callback"}, TokenEndpointAuthMethod: credbound.OAuthAuthPrivateKeyJWT},
	} {
		if _, err := f.manager.PreRegisterOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, input); !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("invalid client input %#v = %v", input, err)
		}
	}
	issued, err := f.manager.PreRegisterOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.OAuthClientRegistrationInput{
		Name: "Client", ApplicationType: credbound.OAuthApplicationWeb, RedirectURIs: []string{"https://client.example.com/callback"}, Scopes: []string{"documents.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	base := credbound.BeginOAuthAuthorizationInput{
		Issuer: issuer.Issuer, ClientID: issued.Client.ClientID, RedirectURI: "https://client.example.com/callback",
		Resource: resource.Resource, Scopes: []string{"documents.read"}, State: "state", CodeChallenge: challenge, CodeChallengeMethod: "S256",
	}
	invalidBegins := []credbound.BeginOAuthAuthorizationInput{
		func() credbound.BeginOAuthAuthorizationInput {
			v := base
			v.Issuer = "http://auth.example.com"
			return v
		}(),
		func() credbound.BeginOAuthAuthorizationInput { v := base; v.ClientID = "missing"; return v }(),
		func() credbound.BeginOAuthAuthorizationInput {
			v := base
			v.Resource = "http://mcp.example.com"
			return v
		}(),
		func() credbound.BeginOAuthAuthorizationInput {
			v := base
			v.RedirectURI = "https://evil.example.com"
			return v
		}(),
		func() credbound.BeginOAuthAuthorizationInput { v := base; v.CodeChallengeMethod = "plain"; return v }(),
		func() credbound.BeginOAuthAuthorizationInput { v := base; v.State = ""; return v }(),
		func() credbound.BeginOAuthAuthorizationInput {
			v := base
			v.Scopes = []string{"documents.write"}
			return v
		}(),
	}
	for _, input := range invalidBegins {
		if _, err := f.manager.BeginOAuthAuthorization(ctx, actor, input); err == nil {
			t.Fatalf("invalid authorization accepted: %#v", input)
		}
	}
	if _, err := f.manager.BeginOAuthAuthorization(ctx, credbound.Authentication{}, base); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous authorization = %v", err)
	}
	consent, err := f.manager.BeginOAuthAuthorization(ctx, actor, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.CompleteOAuthAuthorization(ctx, credbound.Authentication{}, consent.Continuation, true); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous consent = %v", err)
	}
	if _, err := f.manager.CompleteOAuthAuthorization(ctx, actor, consent.Continuation+"tampered", true); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("tampered consent = %v", err)
	}
	if _, err := f.manager.ExchangeOAuthAuthorizationCode(ctx, credbound.ExchangeOAuthAuthorizationCodeInput{Issuer: issuer.Issuer, ClientID: issued.Client.ClientID, Code: "bad", CodeVerifier: "short"}); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("invalid code = %v", err)
	}
	if _, err := f.manager.ExchangeOAuthAuthorizationCode(ctx, credbound.ExchangeOAuthAuthorizationCodeInput{Issuer: issuer.Issuer, ClientID: issued.Client.ClientID, ClientSecret: "unexpected", Code: "bad", CodeVerifier: "short"}); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("public client secret accepted = %v", err)
	}
	if _, err := f.manager.RefreshOAuthToken(ctx, credbound.RefreshOAuthTokenInput{Issuer: issuer.Issuer, ClientID: issued.Client.ClientID, RefreshToken: "bad"}); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("invalid refresh = %v", err)
	}
	if err := f.manager.RevokeOAuthToken(ctx, credbound.RevokeOAuthTokenInput{Issuer: issuer.Issuer, ClientID: issued.Client.ClientID, Token: "unknown"}); err != nil {
		t.Fatalf("unknown revocation = %v", err)
	}
	if err := f.manager.RevokeOAuthToken(ctx, credbound.RevokeOAuthTokenInput{Issuer: issuer.Issuer, ClientID: issued.Client.ClientID, Token: "cba_0123456789ab_" + strings.Repeat("A", 43)}); err != nil {
		t.Fatalf("unknown structured revocation = %v", err)
	}
	if _, err := f.manager.OAuthProtectedResourceMetadata(ctx, "https://missing.example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing resource metadata = %v", err)
	}
	if _, err := f.manager.OAuthProtectedResourceMetadata(ctx, "http://missing.example.com"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid resource metadata URL = %v", err)
	}
	if _, err := f.manager.OAuthAuthorizationServerMetadata(ctx, "http://auth.example.com"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid issuer metadata URL = %v", err)
	}
	if _, err := f.manager.OAuthAuthorizationServerMetadata(ctx, "https://missing.example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing issuer metadata = %v", err)
	}
	if _, err := f.manager.OAuthJWKS(ctx, "http://auth.example.com"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid JWKS issuer = %v", err)
	}
	if _, err := f.manager.OAuthJWKS(ctx, issuer.Issuer); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("disabled JWKS = %v", err)
	}
	if _, err := f.manager.OAuthUserInfo(ctx, "http://auth.example.com", "token"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid UserInfo issuer = %v", err)
	}
	confidential, err := f.manager.PreRegisterOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.OAuthClientRegistrationInput{
		Name: "Confidential", ApplicationType: credbound.OAuthApplicationWeb,
		RedirectURIs: []string{"https://confidential.example.com/callback"}, Scopes: []string{"documents.read"},
		TokenEndpointAuthMethod: credbound.OAuthAuthClientSecretBasic,
	})
	if err != nil || confidential.ClientSecret == "" {
		t.Fatalf("confidential client = %#v, %v", confidential, err)
	}
	confidentialRequest := base
	confidentialRequest.ClientID = confidential.Client.ClientID
	confidentialRequest.RedirectURI = "https://confidential.example.com/callback"
	confidentialConsent, err := f.manager.BeginOAuthAuthorization(ctx, actor, confidentialRequest)
	if err != nil {
		t.Fatal(err)
	}
	confidentialResult, err := f.manager.CompleteOAuthAuthorization(ctx, actor, confidentialConsent.Continuation, true)
	if err != nil {
		t.Fatal(err)
	}
	confidentialExchange := credbound.ExchangeOAuthAuthorizationCodeInput{
		Issuer: issuer.Issuer, ClientID: confidential.Client.ClientID, ClientSecret: "wrong",
		Code: confidentialResult.Code, RedirectURI: confidentialRequest.RedirectURI, CodeVerifier: verifier, Resource: resource.Resource,
	}
	if _, err := f.manager.ExchangeOAuthAuthorizationCode(ctx, confidentialExchange); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("wrong client secret = %v", err)
	}
	confidentialExchange.ClientSecret = confidential.ClientSecret
	confidentialTokens, err := f.manager.ExchangeOAuthAuthorizationCode(ctx, confidentialExchange)
	if err != nil || confidentialTokens.AccessToken == "" {
		t.Fatalf("confidential tokens = %#v, %v", confidentialTokens, err)
	}
	if _, err := f.manager.OAuthUserInfo(ctx, issuer.Issuer, confidentialTokens.AccessToken); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("userinfo without openid = %v", err)
	}
	if _, err := f.manager.AuthenticateOAuthAccessToken(ctx, "https://mcp.example.com/other", confidentialTokens.AccessToken); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("wrong token audience = %v", err)
	}
	if _, err := f.manager.CreateUser(ctx, actor, workspace.ID, credbound.CreateUserInput{
		Email: "backup-admin@example.com", DisplayName: "Backup admin", Password: "another secure password", Role: credbound.RoleAdmin,
	}); err != nil {
		t.Fatal(err)
	}
	membership, err := f.store.Membership(ctx, workspace.ID, actor.UserID)
	if err != nil {
		t.Fatal(err)
	}
	membership.Status = credbound.MembershipSuspended
	if err := f.store.UpsertMembership(ctx, membership, credbound.Commit{Audit: credbound.AuditEvent{
		ID: "0198b463-0000-7000-8000-00000000f001", OccurredAt: f.now, ActorID: actor.UserID,
		Action: "membership.suspend", ResourceType: "user", ResourceID: actor.UserID, WorkspaceID: workspace.ID, Outcome: credbound.AuditSucceeded,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.AuthenticateOAuthAccessToken(ctx, resource.Resource, confidentialTokens.AccessToken); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("suspended membership token = %v", err)
	}
	membership.Status = credbound.MembershipActive
	if err := f.store.UpsertMembership(ctx, membership, credbound.Commit{Audit: credbound.AuditEvent{
		ID: "0198b463-0000-7000-8000-00000000f002", OccurredAt: f.now, ActorID: actor.UserID,
		Action: "membership.restore", ResourceType: "user", ResourceID: actor.UserID, WorkspaceID: workspace.ID, Outcome: credbound.AuditSucceeded,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.RevokeOAuthToken(ctx, credbound.RevokeOAuthTokenInput{Issuer: issuer.Issuer, ClientID: confidential.Client.ClientID, ClientSecret: confidential.ClientSecret, Token: confidentialTokens.AccessToken}); err != nil {
		t.Fatal(err)
	}
	privateClient, err := f.manager.PreRegisterOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.OAuthClientRegistrationInput{
		Name: "Private key", ApplicationType: credbound.OAuthApplicationWeb,
		RedirectURIs: []string{"https://private.example.com/callback"}, Scopes: []string{"documents.read"},
		TokenEndpointAuthMethod: credbound.OAuthAuthPrivateKeyJWT, JWKS: json.RawMessage(`{"keys":[]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	privateRequest := base
	privateRequest.ClientID, privateRequest.RedirectURI = privateClient.Client.ClientID, "https://private.example.com/callback"
	privateConsent, err := f.manager.BeginOAuthAuthorization(ctx, actor, privateRequest)
	if err != nil {
		t.Fatal(err)
	}
	privateResult, err := f.manager.CompleteOAuthAuthorization(ctx, actor, privateConsent.Continuation, true)
	if err != nil {
		t.Fatal(err)
	}
	privateExchange := credbound.ExchangeOAuthAuthorizationCodeInput{
		Issuer: issuer.Issuer, ClientID: privateClient.Client.ClientID, ClientAssertion: "invalid",
		ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		Code:                privateResult.Code, RedirectURI: privateRequest.RedirectURI, CodeVerifier: verifier, Resource: resource.Resource,
	}
	if _, err := f.manager.ExchangeOAuthAuthorizationCode(ctx, privateExchange); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("invalid client assertion = %v", err)
	}
	privateExchange.ClientAssertion = "valid"
	if tokens, err := f.manager.ExchangeOAuthAuthorizationCode(ctx, privateExchange); err != nil || tokens.AccessToken == "" {
		t.Fatalf("private key tokens = %#v, %v", tokens, err)
	}
	sensitive, err := f.manager.CreateOAuthProtectedResource(ctx, actor, workspace.ID, credbound.CreateOAuthProtectedResourceInput{
		IssuerID: issuer.ID, Resource: "https://mcp.example.com/sensitive",
		Scopes: []credbound.OAuthScopeDefinition{{Name: "sensitive.read", Description: "Sensitive", Permissions: []credbound.WorkspacePermission{credbound.PermissionWorkspaceAccess}, MinimumAAL: credbound.AAL2}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sensitiveClient, err := f.manager.PreRegisterOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.OAuthClientRegistrationInput{
		Name: "Sensitive client", ApplicationType: credbound.OAuthApplicationWeb,
		RedirectURIs: []string{"https://sensitive.example.com/callback"}, Scopes: []string{"sensitive.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	lowerActor := actor
	lowerActor.Level, lowerActor.Method = credbound.AAL1, credbound.MethodPassword
	sensitiveConsent, err := f.manager.BeginOAuthAuthorization(ctx, lowerActor, credbound.BeginOAuthAuthorizationInput{
		Issuer: issuer.Issuer, ClientID: sensitiveClient.Client.ClientID, RedirectURI: "https://sensitive.example.com/callback",
		Resource: sensitive.Resource, Scopes: []string{"sensitive.read"}, State: "sensitive", CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	if err != nil || !sensitiveConsent.RequiresStepUp {
		t.Fatalf("sensitive consent = %#v, %v", sensitiveConsent, err)
	}
	if _, err := f.manager.CompleteOAuthAuthorization(ctx, lowerActor, sensitiveConsent.Continuation, true); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("missing OAuth step-up = %v", err)
	}

	subscription := f.manager.AddTransactionHook(rejectOAuthHook{})
	_, err = f.manager.PreRegisterOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.OAuthClientRegistrationInput{
		Name: "Rejected", ApplicationType: credbound.OAuthApplicationWeb, RedirectURIs: []string{"https://rejected.example.com/callback"},
	})
	subscription.Remove()
	if !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("OAuth transaction hook rejection = %v", err)
	}
}

type fakeOIDCSigner struct{}

func (fakeOIDCSigner) Algorithms() []string { return []string{"ES256"} }

func (fakeOIDCSigner) SignIDToken(context.Context, credbound.OIDCClaims) (string, error) {
	return "signed-id-token", nil
}

func (fakeOIDCSigner) JWKS(context.Context) (json.RawMessage, error) {
	return json.RawMessage(`{"keys":[]}`), nil
}

type fakeOAuthMetadataFetcher struct{ now func() time.Time }

func (f fakeOAuthMetadataFetcher) Fetch(_ context.Context, clientID string) (credbound.OAuthClientMetadataDocument, error) {
	if strings.Contains(clientID, "fetch-error") {
		return credbound.OAuthClientMetadataDocument{}, errors.New("metadata unavailable")
	}
	if strings.Contains(clientID, "invalid-metadata") {
		return credbound.OAuthClientMetadataDocument{ClientID: "https://other.example.net/oauth/client.json"}, nil
	}
	now := f.now()
	return credbound.OAuthClientMetadataDocument{
		ClientID: clientID, ClientName: "CIMD Client", ApplicationType: credbound.OAuthApplicationWeb,
		RedirectURIs: []string{"https://client.example.net/callback"}, GrantTypes: []string{"authorization_code"},
		ResponseTypes: []string{"code"}, Scope: "documents.read", TokenEndpointAuthMethod: credbound.OAuthAuthNone,
		FetchedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}, nil
}

type fakeOAuthAssertionVerifier struct{}

func (fakeOAuthAssertionVerifier) Verify(_ context.Context, _ credbound.OAuthClient, audience, assertion string, _ time.Time) error {
	if audience != "https://auth.example.com/token" || assertion != "valid" {
		return errors.New("invalid assertion")
	}
	return nil
}

type rejectOAuthHook struct {
	credbound.UnimplementedTransactionHook
}

func (rejectOAuthHook) ApplyOAuthChange(context.Context, credbound.Tx, credbound.OAuthChange) error {
	return credbound.ErrForbidden
}

// TestOAuthClientCredentials exercises the machine-to-machine grant: a
// confidential client obtains a userless access token bound to a resource, the
// token authenticates with no user subject, and the guard rails hold.
func TestOAuthClientCredentials(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := context.Background()
	actor, workspace := f.bootstrap(t)
	root := aal2(actor.UserID, f.now)

	issuer, err := f.manager.CreateOAuthIssuer(ctx, root, credbound.TrustedRequest{Local: true}, credbound.CreateOAuthIssuerInput{
		Issuer: "https://auth.example.com", OIDCEnabled: true, CIMDMode: credbound.OAuthCIMDDisabled, DCRMode: credbound.OAuthDCRDisabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := f.manager.CreateOAuthProtectedResource(ctx, root, workspace.ID, credbound.CreateOAuthProtectedResourceInput{
		IssuerID: issuer.ID, Resource: "https://mcp.example.com/workspaces/acme",
		Scopes: []credbound.OAuthScopeDefinition{{Name: "documents.read", Description: "Read", Permissions: []credbound.WorkspacePermission{credbound.PermissionWorkspaceAccess}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := f.manager.PreRegisterOAuthClient(ctx, root, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.OAuthClientRegistrationInput{
		Name: "Service", ApplicationType: credbound.OAuthApplicationWeb, RedirectURIs: []string{"https://svc.example.com/cb"},
		GrantTypes: []string{"client_credentials"}, Scopes: []string{"documents.read"}, TokenEndpointAuthMethod: credbound.OAuthAuthClientSecretBasic,
	})
	if err != nil || client.ClientSecret == "" {
		t.Fatalf("client = %#v, %v", client, err)
	}

	// A public client (or the wrong secret) cannot use the grant.
	if _, err := f.manager.IssueOAuthClientCredentials(ctx, credbound.OAuthClientCredentialsInput{
		Issuer: issuer.Issuer, ClientID: client.Client.ClientID, ClientSecret: "wrong", Resource: resource.Resource,
	}); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("wrong secret = %v", err)
	}
	// A scope the client is not registered for is refused.
	if _, err := f.manager.IssueOAuthClientCredentials(ctx, credbound.OAuthClientCredentialsInput{
		Issuer: issuer.Issuer, ClientID: client.Client.ClientID, ClientSecret: client.ClientSecret, Resource: resource.Resource, Scopes: []string{"documents.write"},
	}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("unregistered scope = %v", err)
	}

	// The happy path issues a Bearer token with no refresh token.
	tokens, err := f.manager.IssueOAuthClientCredentials(ctx, credbound.OAuthClientCredentialsInput{
		Issuer: issuer.Issuer, ClientID: client.Client.ClientID, ClientSecret: client.ClientSecret, Resource: resource.Resource, Scopes: []string{"documents.read"},
	})
	if err != nil || tokens.AccessToken == "" || tokens.RefreshToken != "" || tokens.TokenType != "Bearer" || tokens.Scope != "documents.read" {
		t.Fatalf("client-credentials tokens = %#v, %v", tokens, err)
	}
	// The token authenticates with a client subject and no user.
	principal, err := f.manager.AuthenticateOAuthAccessToken(ctx, resource.Resource, tokens.AccessToken)
	if err != nil || principal.UserID != "" || principal.ClientID != client.Client.ClientID || !principal.HasScope("documents.read") || principal.WorkspaceID != workspace.ID {
		t.Fatalf("principal = %#v, %v", principal, err)
	}
	// It is rejected for a different resource.
	if _, err := f.manager.AuthenticateOAuthAccessToken(ctx, "https://other.example.com/x", tokens.AccessToken); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("wrong-resource auth = %v", err)
	}
	// Disabling the client revokes its tokens implicitly.
	if err := f.manager.DisableOAuthClient(ctx, root, credbound.TrustedRequest{Local: true}, client.Client.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.AuthenticateOAuthAccessToken(ctx, resource.Resource, tokens.AccessToken); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("disabled-client auth = %v", err)
	}
}
