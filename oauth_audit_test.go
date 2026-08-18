package credbound_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/deepteams/credbound"
)

// TestOAuthAuditNeverRecordsSecrets pins OAUTH-010: registration, consent,
// issuance, rotation, denial and revocation all leave audit events, and none
// of those events carries a raw authorization code, access or refresh token,
// client secret or PKCE verifier.
func TestOAuthAuditNeverRecordsSecrets(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := context.Background()
	actor, workspace := f.bootstrap(t)
	actor.Level, actor.Method = credbound.AAL2, credbound.MethodTOTP

	issuer, err := f.manager.CreateOAuthIssuer(ctx, actor, credbound.TrustedRequest{Local: true}, credbound.CreateOAuthIssuerInput{
		Issuer: "https://auth.example.com", OIDCEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := f.manager.CreateOAuthProtectedResource(ctx, actor, workspace.ID, credbound.CreateOAuthProtectedResourceInput{
		IssuerID: issuer.ID, Resource: "https://mcp.example.com/workspaces/acme",
		Scopes: []credbound.OAuthScopeDefinition{{Name: "documents.read", Description: "Read documents", Permissions: []credbound.WorkspacePermission{credbound.PermissionWorkspaceAccess}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	webClient, err := f.manager.PreRegisterOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.OAuthClientRegistrationInput{
		Name: "Web client", ApplicationType: credbound.OAuthApplicationWeb,
		RedirectURIs: []string{"https://client.example.com/callback"}, GrantTypes: []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"}, Scopes: []string{"documents.read", "offline_access"},
		TokenEndpointAuthMethod: credbound.OAuthAuthClientSecretBasic,
	})
	if err != nil || webClient.ClientSecret == "" {
		t.Fatalf("web client = %#v, %v", webClient, err)
	}
	machineClient, err := f.manager.PreRegisterOAuthClient(ctx, actor, credbound.TrustedRequest{Local: true}, issuer.ID, credbound.OAuthClientRegistrationInput{
		Name: "Machine client", ApplicationType: credbound.OAuthApplicationWeb,
		RedirectURIs: []string{"https://svc.example.com/cb"}, GrantTypes: []string{"client_credentials"},
		Scopes: []string{"documents.read"}, ClientCredentialsResources: []string{resource.Resource},
		TokenEndpointAuthMethod: credbound.OAuthAuthClientSecretBasic,
	})
	if err != nil || machineClient.ClientSecret == "" {
		t.Fatalf("machine client = %#v, %v", machineClient, err)
	}

	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	begin := credbound.BeginOAuthAuthorizationInput{
		Issuer: issuer.Issuer, ClientID: webClient.Client.ClientID,
		RedirectURI: "https://client.example.com/callback", Resource: resource.Resource,
		Scopes: []string{"documents.read", "offline_access"}, State: "state",
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
	}
	consent, err := f.manager.BeginOAuthAuthorization(ctx, actor, begin)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := f.manager.CompleteOAuthAuthorization(ctx, actor, consent.Continuation, true)
	if err != nil || authorized.Code == "" {
		t.Fatalf("authorization = %#v, %v", authorized, err)
	}
	tokens, err := f.manager.ExchangeOAuthAuthorizationCode(ctx, credbound.ExchangeOAuthAuthorizationCodeInput{
		Issuer: issuer.Issuer, ClientID: webClient.Client.ClientID, ClientSecret: webClient.ClientSecret,
		Code: authorized.Code, RedirectURI: "https://client.example.com/callback", CodeVerifier: verifier, Resource: resource.Resource,
	})
	if err != nil || tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("tokens = %#v, %v", tokens, err)
	}
	refreshed, err := f.manager.RefreshOAuthToken(ctx, credbound.RefreshOAuthTokenInput{
		Issuer: issuer.Issuer, ClientID: webClient.Client.ClientID, ClientSecret: webClient.ClientSecret,
		RefreshToken: tokens.RefreshToken, Resource: resource.Resource,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.RevokeOAuthToken(ctx, credbound.RevokeOAuthTokenInput{
		Issuer: issuer.Issuer, ClientID: webClient.Client.ClientID, ClientSecret: webClient.ClientSecret,
		Token: refreshed.RefreshToken,
	}); err != nil {
		t.Fatal(err)
	}
	denied, err := f.manager.BeginOAuthAuthorization(ctx, actor, begin)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := f.manager.CompleteOAuthAuthorization(ctx, actor, denied.Continuation, false); err != nil || result.Error != "access_denied" {
		t.Fatalf("denial = %#v, %v", result, err)
	}
	machine, err := f.manager.IssueOAuthClientCredentials(ctx, credbound.OAuthClientCredentialsInput{
		Issuer: issuer.Issuer, ClientID: machineClient.Client.ClientID, ClientSecret: machineClient.ClientSecret,
		Resource: resource.Resource,
	})
	if err != nil || machine.AccessToken == "" {
		t.Fatalf("client credentials = %#v, %v", machine, err)
	}

	// Every audited step above must be visible in the instance audit trail,
	// and no event may embed any of the raw secret material the flow minted.
	secrets := []string{
		webClient.ClientSecret, machineClient.ClientSecret, authorized.Code, verifier,
		tokens.AccessToken, tokens.RefreshToken, refreshed.AccessToken, refreshed.RefreshToken,
		machine.AccessToken,
	}
	var trail strings.Builder
	oauthEvents := 0
	page := credbound.PageRequest{Limit: 100}
	for {
		var end credbound.PageEnd
		for event, err := range f.store.InstanceAuditEvents(ctx, page) {
			if err != nil {
				t.Fatal(err)
			}
			if event.Data != nil {
				encoded, marshalErr := json.Marshal(*event.Data)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				trail.Write(encoded)
				if strings.HasPrefix(event.Data.Action, "oauth.") {
					oauthEvents++
				}
			}
			if event.End != nil {
				end = *event.End
			}
		}
		if end.NextCursor == "" {
			break
		}
		page.Cursor = end.NextCursor
	}
	if oauthEvents < 8 {
		t.Fatalf("OAuth operations left only %d audit events", oauthEvents)
	}
	for _, secret := range secrets {
		if secret == "" {
			t.Fatal("flow produced an empty secret; the containment check would be vacuous")
		}
		if strings.Contains(trail.String(), secret) {
			t.Fatalf("audit trail leaks a raw credential: %q", secret)
		}
	}
}
