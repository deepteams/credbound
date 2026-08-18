package credbound

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ExchangeOAuthAuthorizationCode implements the token endpoint's
// authorization_code grant: it authenticates the client, verifies the
// single-use code, exact redirect URI and PKCE verifier, and consumes the
// code atomically with the issued tokens and audit. Opaque tokens are
// returned exactly once; a refresh token is added only for offline_access
// grants of refresh-capable clients and an ID Token only for openid grants
// of OIDC issuers. Every mismatch fails with ErrInvalidCredentials.
func (m *Manager) ExchangeOAuthAuthorizationCode(ctx context.Context, input ExchangeOAuthAuthorizationCodeInput) (_ OAuthTokenResponse, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.token.exchange", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	issuer, client, err := m.authenticateOAuthClient(ctx, input.Issuer, input.ClientID, input.ClientSecret, input.ClientAssertion, input.ClientAssertionType)
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	prefix, ok := parseOAuthBearer("cbc", input.Code)
	if !ok || !pkceVerifierPattern.MatchString(input.CodeVerifier) {
		return OAuthTokenResponse{}, ErrInvalidCredentials
	}
	code, err := store.OAuthAuthorizationCodeByPrefix(ctx, prefix)
	if err != nil || code.ClientRecordID != client.ID || code.RedirectURI != input.RedirectURI || code.UsedAt != nil || !m.now().Before(code.ExpiresAt) ||
		!hmac.Equal(code.Digest, m.oauthDigest("authorization-code", input.Code)) || !verifyPKCE(input.CodeVerifier, code.CodeChallenge) {
		return OAuthTokenResponse{}, ErrInvalidCredentials
	}
	grant, resource, err := m.activeOAuthGrant(ctx, code.GrantID, client, input.Resource)
	if err != nil || resource.ID != code.ResourceID || !slices.Equal(grant.Scopes, code.Scopes) {
		return OAuthTokenResponse{}, ErrInvalidCredentials
	}
	access, rawAccess, err := m.newOAuthAccessToken(grant, issuer.AccessTokenTTL)
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	var refresh *OAuthRefreshToken
	rawRefresh := ""
	if slices.Contains(grant.Scopes, "offline_access") && slices.Contains(client.GrantTypes, "refresh_token") {
		value, raw, createErr := m.newOAuthRefreshToken(grant, "", issuer.RefreshTokenTTL)
		if createErr != nil {
			return OAuthTokenResponse{}, createErr
		}
		refresh, rawRefresh = &value, raw
	}
	audit, err := m.newAudit(ctx, client.ID, "oauth.token.issued", "oauth_grant", grant.ID, grant.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	audit.ActorKind = ActorService
	change, commit, err := m.newOAuthChange(EventOAuthTokenIssued, "oauth.token.exchange", audit, client, grant.ID, access.ID, resource.ID, grant.WorkspaceID, grant.Scopes)
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	if err := store.ConsumeOAuthAuthorizationCode(ctx, code.ID, m.now(), access, refresh, commit); err != nil {
		return OAuthTokenResponse{}, m.mapOAuthCredentialStoreError(ctx, "oauth.token.exchange", err)
	}
	m.emitOAuthChange(ctx, change)
	idToken, err := m.oauthIDToken(ctx, issuer, client, grant, code.Nonce, access.ExpiresAt)
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	return OAuthTokenResponse{
		AccessToken: rawAccess, TokenType: "Bearer", ExpiresIn: int64(issuer.AccessTokenTTL / time.Second),
		RefreshToken: rawRefresh, Scope: strings.Join(grant.Scopes, " "), IDToken: idToken,
	}, nil
}

// IssueOAuthClientCredentials authenticates a confidential client and issues a
// machine-to-machine access token bound to a protected resource, with no user
// subject and no refresh token (RFC 6749 §4.4). The client must authenticate
// (client_secret or private_key_jwt, never a public client) and be registered
// for the client_credentials grant; the requested scopes must be non-reserved
// scopes the resource defines and the client is allowed. Revocation is implicit
// when the client, resource or issuer is disabled.
func (m *Manager) IssueOAuthClientCredentials(ctx context.Context, input OAuthClientCredentialsInput) (_ OAuthTokenResponse, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.token.client_credentials", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	issuer, client, err := m.authenticateOAuthClient(ctx, input.Issuer, input.ClientID, input.ClientSecret, input.ClientAssertion, input.ClientAssertionType)
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	if client.TokenEndpointAuthMethod == OAuthAuthNone || !slices.Contains(client.GrantTypes, "client_credentials") {
		return OAuthTokenResponse{}, ErrForbidden
	}
	resourceURL, err := validateResourceURL(input.Resource)
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	resource, err := store.OAuthProtectedResourceByURI(ctx, resourceURL)
	if err != nil || resource.IssuerID != issuer.ID || resource.DisabledAt != nil {
		return OAuthTokenResponse{}, ErrForbidden
	}
	scopes, err := clientCredentialsScopes(client, resource, input.Scopes)
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	id, err := m.newID()
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	prefix, raw, err := m.newOAuthBearer("cba")
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	now := m.now()
	token := OAuthClientAccessToken{
		ID: id, Prefix: prefix, Digest: m.oauthDigest("access-token", raw),
		ClientRecordID: client.ID, IssuerID: issuer.ID, ResourceID: resource.ID, WorkspaceID: resource.WorkspaceID,
		Scopes: scopes, CreatedAt: now, ExpiresAt: now.Add(issuer.AccessTokenTTL),
	}
	audit, err := m.newAudit(ctx, client.ID, "oauth.token.client_credentials", "oauth_client", client.ID, resource.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	audit.ActorKind = ActorService
	if err := store.CreateOAuthClientAccessToken(ctx, token, Commit{Audit: audit}); err != nil {
		return OAuthTokenResponse{}, m.mapOAuthCredentialStoreError(ctx, "oauth.token.client_credentials", err)
	}
	return OAuthTokenResponse{
		AccessToken: raw, TokenType: "Bearer", ExpiresIn: int64(issuer.AccessTokenTTL / time.Second),
		Scope: strings.Join(scopes, " "),
	}, nil
}

// clientCredentialsScopes resolves the scopes a client-credentials token may
// carry: non-reserved scopes the resource defines and the client is registered
// for. An empty request grants every eligible resource scope.
func clientCredentialsScopes(client OAuthClient, resource OAuthProtectedResource, requested []string) ([]string, error) {
	allowed := func(scope string) bool {
		if oauthReservedScope(scope) {
			return false
		}
		if _, ok := oauthScopeDefinition(resource.Scopes, scope); !ok {
			return false
		}
		return len(client.Scopes) == 0 || slices.Contains(client.Scopes, scope)
	}
	if len(requested) == 0 {
		granted := make([]string, 0, len(resource.Scopes))
		for _, definition := range resource.Scopes {
			if allowed(definition.Name) {
				granted = append(granted, definition.Name)
			}
		}
		return granted, nil
	}
	granted := make([]string, 0, len(requested))
	for _, scope := range requested {
		scope = strings.TrimSpace(scope)
		if !allowed(scope) {
			return nil, ErrForbidden
		}
		granted = append(granted, scope)
	}
	return granted, nil
}

// RefreshOAuthToken rotates a refresh token: it authenticates the client,
// re-validates the grant, and atomically retires the presented token while
// issuing a new access/refresh pair, optionally narrowed to a subset of the
// granted scopes. Reuse of an already rotated or revoked refresh token
// revokes its whole family and fails with ErrInvalidCredentials; an expired
// token fails with ErrExpired.
func (m *Manager) RefreshOAuthToken(ctx context.Context, input RefreshOAuthTokenInput) (_ OAuthTokenResponse, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.token.refresh", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	issuer, client, err := m.authenticateOAuthClient(ctx, input.Issuer, input.ClientID, input.ClientSecret, input.ClientAssertion, input.ClientAssertionType)
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	prefix, ok := parseOAuthBearer("cbr", input.RefreshToken)
	if !ok {
		return OAuthTokenResponse{}, ErrInvalidCredentials
	}
	previous, err := store.OAuthRefreshTokenByPrefix(ctx, prefix)
	if err != nil || previous.ClientRecordID != client.ID || !hmac.Equal(previous.Digest, m.oauthDigest("refresh-token", input.RefreshToken)) {
		return OAuthTokenResponse{}, ErrInvalidCredentials
	}
	if previous.UsedAt != nil || previous.RevokedAt != nil {
		_ = m.revokeOAuthRefreshFamily(ctx, previous, client, "reuse_detected")
		return OAuthTokenResponse{}, ErrInvalidCredentials
	}
	if !m.now().Before(previous.ExpiresAt) {
		return OAuthTokenResponse{}, ErrExpired
	}
	grant, resource, err := m.activeOAuthGrant(ctx, previous.GrantID, client, input.Resource)
	if err != nil || resource.ID != previous.ResourceID {
		return OAuthTokenResponse{}, ErrInvalidCredentials
	}
	scopes := slices.Clone(previous.Scopes)
	if len(input.Scopes) > 0 {
		scopes, err = normalizeOptionalOAuthScopes(input.Scopes)
		if err != nil || !scopesSubset(scopes, previous.Scopes) {
			return OAuthTokenResponse{}, fmt.Errorf("%w: refresh scopes must be a subset of the grant", ErrInvalidInput)
		}
	}
	grant.Scopes = scopes
	access, rawAccess, err := m.newOAuthAccessToken(grant, issuer.AccessTokenTTL)
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	replacement, rawRefresh, err := m.newOAuthRefreshToken(grant, previous.FamilyID, issuer.RefreshTokenTTL)
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	audit, err := m.newAudit(ctx, client.ID, "oauth.token.refreshed", "oauth_grant", grant.ID, grant.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	audit.ActorKind = ActorService
	change, commit, err := m.newOAuthChange(EventOAuthTokenRefreshed, "oauth.token.refresh", audit, client, grant.ID, access.ID, resource.ID, grant.WorkspaceID, scopes)
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	if err := store.RotateOAuthRefreshToken(ctx, previous.ID, m.now(), access, replacement, commit); err != nil {
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrInvalidCredentials) {
			_ = m.revokeOAuthRefreshFamily(ctx, previous, client, "reuse_detected")
			return OAuthTokenResponse{}, ErrInvalidCredentials
		}
		return OAuthTokenResponse{}, m.mapStoreError(ctx, "oauth.token.refresh", err)
	}
	m.emitOAuthChange(ctx, change)
	idToken, err := m.oauthIDToken(ctx, issuer, client, grant, "", access.ExpiresAt)
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	return OAuthTokenResponse{
		AccessToken: rawAccess, TokenType: "Bearer", ExpiresIn: int64(issuer.AccessTokenTTL / time.Second),
		RefreshToken: rawRefresh, Scope: strings.Join(scopes, " "), IDToken: idToken,
	}, nil
}

// RevokeOAuthToken implements RFC 7009 revocation for the authenticated
// client's own tokens: an access token is revoked individually, a refresh
// token revokes its whole family. As the RFC requires, unknown or foreign
// tokens are silently ignored; only a failed client authentication returns
// an error.
func (m *Manager) RevokeOAuthToken(ctx context.Context, input RevokeOAuthTokenInput) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.token.revoke", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return err
	}
	_, client, err := m.authenticateOAuthClient(ctx, input.Issuer, input.ClientID, input.ClientSecret, input.ClientAssertion, input.ClientAssertionType)
	if err != nil {
		return err
	}
	now := m.now()
	if prefix, ok := parseOAuthBearer("cba", input.Token); ok {
		token, lookupErr := store.OAuthAccessTokenByPrefix(ctx, prefix)
		if lookupErr != nil || token.ClientRecordID != client.ID || !hmac.Equal(token.Digest, m.oauthDigest("access-token", input.Token)) {
			return nil
		}
		audit, auditErr := m.newAudit(ctx, client.ID, "oauth.token.revoked", "oauth_access_token", token.ID, token.WorkspaceID, AuditSucceeded, "")
		if auditErr != nil {
			return auditErr
		}
		audit.ActorKind = ActorService
		change, commit, changeErr := m.newOAuthChange(EventOAuthTokenRevoked, "oauth.token.revoke", audit, client, token.GrantID, token.ID, token.ResourceID, token.WorkspaceID, token.Scopes)
		if changeErr != nil {
			return changeErr
		}
		if revokeErr := store.RevokeOAuthAccessToken(ctx, token.ID, now, commit); revokeErr != nil {
			return m.mapStoreError(ctx, "oauth.token.revoke", revokeErr)
		}
		m.emitOAuthChange(ctx, change)
		return nil
	}
	if prefix, ok := parseOAuthBearer("cbr", input.Token); ok {
		token, lookupErr := store.OAuthRefreshTokenByPrefix(ctx, prefix)
		if lookupErr != nil || token.ClientRecordID != client.ID || !hmac.Equal(token.Digest, m.oauthDigest("refresh-token", input.Token)) {
			return nil
		}
		return m.revokeOAuthRefreshFamily(ctx, token, client, "client_revocation")
	}
	return nil
}

// AuthenticateOAuthAccessToken validates a bearer access token for one
// resource URI — the MCP middleware check run on every request. It verifies
// the token digest, expiry and revocation, then re-validates the grant,
// client, issuer, resource binding, user, workspace and the workspace
// permissions behind every scope, so a suspended membership or revoked
// consent takes effect immediately. Returns the OAuthAuthentication
// capability, or ErrInvalidCredentials (ErrForbidden when only a scope
// permission is missing).
func (m *Manager) AuthenticateOAuthAccessToken(ctx context.Context, resourceURI, raw string) (_ OAuthAuthentication, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.access_token.authenticate", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return OAuthAuthentication{}, err
	}
	prefix, ok := parseOAuthBearer("cba", raw)
	if !ok {
		return OAuthAuthentication{}, ErrInvalidCredentials
	}
	token, err := store.OAuthAccessTokenByPrefix(ctx, prefix)
	if errors.Is(err, ErrNotFound) {
		// A "cba" bearer that is not a user access token may be a
		// client-credentials token, stored separately and with no user subject.
		return m.authenticateOAuthClientToken(ctx, store, prefix, raw, resourceURI)
	}
	if err != nil || token.RevokedAt != nil || !m.now().Before(token.ExpiresAt) || !hmac.Equal(token.Digest, m.oauthDigest("access-token", raw)) {
		return OAuthAuthentication{}, ErrInvalidCredentials
	}
	client, err := store.OAuthClientByID(ctx, token.ClientRecordID)
	if err != nil {
		return OAuthAuthentication{}, ErrInvalidCredentials
	}
	grant, resource, err := m.activeOAuthGrant(ctx, token.GrantID, client, resourceURI)
	if err != nil || token.ResourceID != resource.ID || token.UserID != grant.UserID || token.WorkspaceID != grant.WorkspaceID || !scopesSubset(token.Scopes, grant.Scopes) {
		return OAuthAuthentication{}, ErrInvalidCredentials
	}
	return OAuthAuthentication{
		TokenID: token.ID, GrantID: grant.ID, ClientRecordID: client.ID, ClientID: client.ClientID,
		UserID: token.UserID, WorkspaceID: token.WorkspaceID, Resource: resource.Resource,
		Scopes: slices.Clone(token.Scopes), AuthenticatedAt: m.now(),
	}, nil
}

// authenticateOAuthClientToken validates a client-credentials access token. It
// mirrors the resource-server checks of the user path — token freshness and
// digest, client/issuer/resource enabled, resource match — but carries no user
// subject, so the returned OAuthAuthentication has an empty UserID.
func (m *Manager) authenticateOAuthClientToken(ctx context.Context, store OAuthStore, prefix, raw, resourceURI string) (OAuthAuthentication, error) {
	token, err := store.OAuthClientAccessTokenByPrefix(ctx, prefix)
	if err != nil || !m.now().Before(token.ExpiresAt) || !hmac.Equal(token.Digest, m.oauthDigest("access-token", raw)) {
		return OAuthAuthentication{}, ErrInvalidCredentials
	}
	client, err := store.OAuthClientByID(ctx, token.ClientRecordID)
	if err != nil || client.DisabledAt != nil {
		return OAuthAuthentication{}, ErrInvalidCredentials
	}
	issuer, err := store.OAuthIssuerByID(ctx, token.IssuerID)
	if err != nil || issuer.DisabledAt != nil {
		return OAuthAuthentication{}, ErrInvalidCredentials
	}
	resource, err := store.OAuthProtectedResourceByID(ctx, token.ResourceID)
	if err != nil || resource.DisabledAt != nil || resource.IssuerID != issuer.ID || resource.WorkspaceID != token.WorkspaceID {
		return OAuthAuthentication{}, ErrInvalidCredentials
	}
	if resourceURI != "" {
		normalized, normalizeErr := validateResourceURL(resourceURI)
		if normalizeErr != nil || normalized != resource.Resource {
			return OAuthAuthentication{}, ErrInvalidCredentials
		}
	}
	workspace, err := m.store.WorkspaceByID(ctx, token.WorkspaceID)
	if err != nil || workspace.DisabledAt != nil {
		return OAuthAuthentication{}, ErrInvalidCredentials
	}
	return OAuthAuthentication{
		TokenID: token.ID, ClientRecordID: client.ID, ClientID: client.ClientID,
		WorkspaceID: token.WorkspaceID, Resource: resource.Resource,
		Scopes: slices.Clone(token.Scopes), AuthenticatedAt: m.now(),
	}, nil
}

// OAuthUserInfo implements the OIDC UserInfo endpoint for an issuer. The
// access token must carry the openid scope; the subject is pairwise and
// never exposes the user's global UUID, and email claims require the email
// scope. Returns ErrNotSupported when the issuer has OIDC disabled.
func (m *Manager) OAuthUserInfo(ctx context.Context, issuerURL, rawAccessToken string) (OIDCUserInfo, error) {
	store, _, err := m.requireOAuth()
	if err != nil {
		return OIDCUserInfo{}, err
	}
	issuerURL, err = validateIssuerURL(issuerURL)
	if err != nil {
		return OIDCUserInfo{}, err
	}
	issuer, err := store.OAuthIssuerByURL(ctx, issuerURL)
	if err != nil || !issuer.OIDCEnabled || issuer.DisabledAt != nil {
		return OIDCUserInfo{}, ErrNotSupported
	}
	prefix, ok := parseOAuthBearer("cba", rawAccessToken)
	if !ok {
		return OIDCUserInfo{}, ErrInvalidCredentials
	}
	token, err := store.OAuthAccessTokenByPrefix(ctx, prefix)
	if err != nil || token.RevokedAt != nil || !m.now().Before(token.ExpiresAt) || !hmac.Equal(token.Digest, m.oauthDigest("access-token", rawAccessToken)) || !slices.Contains(token.Scopes, "openid") {
		return OIDCUserInfo{}, ErrInvalidCredentials
	}
	grant, err := store.OAuthGrant(ctx, token.GrantID)
	if err != nil || grant.IssuerID != issuer.ID || grant.RevokedAt != nil {
		return OIDCUserInfo{}, ErrInvalidCredentials
	}
	client, err := store.OAuthClientByID(ctx, token.ClientRecordID)
	if err != nil {
		return OIDCUserInfo{}, ErrInvalidCredentials
	}
	// UserInfo must honor the same account/workspace status as the resource
	// server path (activeOAuthGrant): disabling a user does not revoke their
	// OAuth grants, so without this check a disabled user's subject and email
	// would keep leaking through UserInfo until the token expired (USER-002).
	user, err := m.store.UserByID(ctx, token.UserID)
	if err != nil || user.Disabled {
		return OIDCUserInfo{}, ErrInvalidCredentials
	}
	workspace, err := m.store.WorkspaceByID(ctx, grant.WorkspaceID)
	if err != nil || workspace.DisabledAt != nil {
		return OIDCUserInfo{}, ErrInvalidCredentials
	}
	info := OIDCUserInfo{Subject: m.oauthPairwiseSubject(issuer.ID, client.SectorIdentifier, token.UserID)}
	if slices.Contains(token.Scopes, "email") {
		info.Email, info.EmailVerified = m.oauthPrimaryEmail(ctx, token.UserID)
	}
	return info, nil
}

// OAuthAuthorizationServerMetadata returns the RFC 8414 discovery document
// of an enabled issuer, reflecting its actual DCR, CIMD and OIDC policy. No
// authentication is required; unknown or disabled issuers fail with
// ErrNotFound.
func (m *Manager) OAuthAuthorizationServerMetadata(ctx context.Context, issuerURL string) (OAuthAuthorizationServerMetadata, error) {
	store, _, err := m.requireOAuth()
	if err != nil {
		return OAuthAuthorizationServerMetadata{}, err
	}
	issuerURL, err = validateIssuerURL(issuerURL)
	if err != nil {
		return OAuthAuthorizationServerMetadata{}, err
	}
	issuer, err := store.OAuthIssuerByURL(ctx, issuerURL)
	if err != nil || issuer.DisabledAt != nil {
		return OAuthAuthorizationServerMetadata{}, ErrNotFound
	}
	result := OAuthAuthorizationServerMetadata{
		Issuer: issuer.Issuer, AuthorizationEndpoint: issuer.Issuer + "/authorize",
		TokenEndpoint: issuer.Issuer + "/token", RevocationEndpoint: issuer.Issuer + "/revoke",
		ResponseTypesSupported: []string{"code"}, GrantTypesSupported: []string{"authorization_code", "refresh_token", "client_credentials"},
		TokenEndpointAuthMethodsSupported: []string{string(OAuthAuthNone), string(OAuthAuthPrivateKeyJWT), string(OAuthAuthClientSecretBasic)},
		CodeChallengeMethodsSupported:     []string{"S256"}, AuthorizationResponseIssuerParameterSupport: true,
		ClientIDMetadataDocumentSupported: issuer.CIMDMode != OAuthCIMDDisabled,
	}
	if issuer.DCRMode != OAuthDCRDisabled {
		result.RegistrationEndpoint = issuer.Issuer + "/register"
	}
	if issuer.OIDCEnabled {
		result.JWKSURI, result.UserInfoEndpoint = issuer.Issuer+"/.well-known/jwks.json", issuer.Issuer+"/userinfo"
		result.SubjectTypesSupported = []string{"pairwise"}
		if m.oauth.OIDCSigner != nil {
			result.IDTokenSigningAlgValuesSupported = slices.Clone(m.oauth.OIDCSigner.Algorithms())
		}
	}
	return result, nil
}

// OAuthProtectedResourceMetadata returns the RFC 9728 metadata of an enabled
// protected resource. No authentication is required; unknown or disabled
// resources and issuers fail with ErrNotFound.
func (m *Manager) OAuthProtectedResourceMetadata(ctx context.Context, resourceURI string) (OAuthProtectedResourceMetadata, error) {
	store, _, err := m.requireOAuth()
	if err != nil {
		return OAuthProtectedResourceMetadata{}, err
	}
	resourceURI, err = validateResourceURL(resourceURI)
	if err != nil {
		return OAuthProtectedResourceMetadata{}, err
	}
	resource, err := store.OAuthProtectedResourceByURI(ctx, resourceURI)
	if err != nil || resource.DisabledAt != nil {
		return OAuthProtectedResourceMetadata{}, ErrNotFound
	}
	issuer, err := store.OAuthIssuerByID(ctx, resource.IssuerID)
	if err != nil || issuer.DisabledAt != nil {
		return OAuthProtectedResourceMetadata{}, ErrNotFound
	}
	scopes := make([]string, 0, len(resource.Scopes))
	for _, definition := range resource.Scopes {
		scopes = append(scopes, definition.Name)
	}
	return OAuthProtectedResourceMetadata{Resource: resource.Resource, AuthorizationServers: []string{issuer.Issuer}, ScopesSupported: scopes, BearerMethods: []string{"header"}}, nil
}

// OAuthJWKS returns the JSON Web Key Set of an OIDC-enabled issuer, as
// published by the configured OIDCSigner. No authentication is required;
// issuers without OIDC or a signer fail with ErrNotSupported.
func (m *Manager) OAuthJWKS(ctx context.Context, issuerURL string) ([]byte, error) {
	store, config, err := m.requireOAuth()
	if err != nil {
		return nil, err
	}
	issuerURL, err = validateIssuerURL(issuerURL)
	if err != nil {
		return nil, err
	}
	issuer, err := store.OAuthIssuerByURL(ctx, issuerURL)
	if err != nil || !issuer.OIDCEnabled || issuer.DisabledAt != nil || config.OIDCSigner == nil {
		return nil, ErrNotSupported
	}
	return config.OIDCSigner.JWKS(ctx)
}

func (m *Manager) authenticateOAuthClient(ctx context.Context, issuerURL, clientID, secret, assertion, assertionType string) (OAuthIssuer, OAuthClient, error) {
	const jwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	if assertion != "" && assertionType != jwtBearerAssertionType || assertion == "" && assertionType != "" {
		return OAuthIssuer{}, OAuthClient{}, ErrInvalidCredentials
	}
	issuerURL, err := validateIssuerURL(issuerURL)
	if err != nil {
		return OAuthIssuer{}, OAuthClient{}, ErrInvalidCredentials
	}
	issuer, err := m.oauthStore.OAuthIssuerByURL(ctx, issuerURL)
	if err != nil || issuer.DisabledAt != nil {
		return OAuthIssuer{}, OAuthClient{}, ErrInvalidCredentials
	}
	client, err := m.resolveOAuthClient(ctx, issuer, clientID)
	if err != nil || client.DisabledAt != nil {
		return OAuthIssuer{}, OAuthClient{}, ErrInvalidCredentials
	}
	switch client.TokenEndpointAuthMethod {
	case OAuthAuthNone:
		if secret != "" || assertion != "" {
			return OAuthIssuer{}, OAuthClient{}, ErrInvalidCredentials
		}
	case OAuthAuthClientSecretBasic:
		if assertion != "" || secret == "" || !hmac.Equal(client.SecretDigest, m.oauthDigest("client-secret", secret)) {
			return OAuthIssuer{}, OAuthClient{}, ErrInvalidCredentials
		}
	case OAuthAuthPrivateKeyJWT:
		if secret != "" || assertion == "" || m.oauth.ClientAssertions == nil || m.oauth.ClientAssertions.Verify(ctx, client, issuer.Issuer+"/token", assertion, m.now()) != nil {
			return OAuthIssuer{}, OAuthClient{}, ErrInvalidCredentials
		}
	default:
		return OAuthIssuer{}, OAuthClient{}, ErrInvalidCredentials
	}
	return issuer, client, nil
}

func (m *Manager) activeOAuthGrant(ctx context.Context, grantID string, client OAuthClient, resourceURI string) (OAuthGrant, OAuthProtectedResource, error) {
	grant, err := m.oauthStore.OAuthGrant(ctx, grantID)
	if err != nil || grant.RevokedAt != nil || grant.ClientRecordID != client.ID || !hmac.Equal(grant.MetadataHash, client.MetadataHash) {
		return OAuthGrant{}, OAuthProtectedResource{}, ErrInvalidCredentials
	}
	resource, err := m.oauthStore.OAuthProtectedResourceByID(ctx, grant.ResourceID)
	if err != nil || resource.DisabledAt != nil || resource.WorkspaceID != grant.WorkspaceID {
		return OAuthGrant{}, OAuthProtectedResource{}, ErrInvalidCredentials
	}
	if resourceURI != "" {
		normalized, normalizeErr := validateResourceURL(resourceURI)
		if normalizeErr != nil || normalized != resource.Resource {
			return OAuthGrant{}, OAuthProtectedResource{}, ErrInvalidCredentials
		}
	}
	issuer, err := m.oauthStore.OAuthIssuerByID(ctx, grant.IssuerID)
	if err != nil || issuer.DisabledAt != nil || issuer.ID != resource.IssuerID {
		return OAuthGrant{}, OAuthProtectedResource{}, ErrInvalidCredentials
	}
	user, err := m.store.UserByID(ctx, grant.UserID)
	if err != nil || user.Disabled {
		return OAuthGrant{}, OAuthProtectedResource{}, ErrInvalidCredentials
	}
	workspace, err := m.store.WorkspaceByID(ctx, grant.WorkspaceID)
	if err != nil || workspace.DisabledAt != nil {
		return OAuthGrant{}, OAuthProtectedResource{}, ErrInvalidCredentials
	}
	actor := Authentication{UserID: grant.UserID, WorkspaceID: grant.WorkspaceID}
	for _, scope := range grant.Scopes {
		definition, found := oauthScopeDefinition(resource.Scopes, scope)
		if oauthReservedScope(scope) {
			continue
		}
		if !found {
			return OAuthGrant{}, OAuthProtectedResource{}, ErrInvalidCredentials
		}
		for _, permission := range definition.Permissions {
			if err := m.AuthorizePermission(ctx, actor, resource.WorkspaceID, permission); err != nil {
				return OAuthGrant{}, OAuthProtectedResource{}, ErrForbidden
			}
		}
	}
	return grant, resource, nil
}

func (m *Manager) newOAuthAccessToken(grant OAuthGrant, ttl time.Duration) (OAuthAccessToken, string, error) {
	id, err := m.newID()
	if err != nil {
		return OAuthAccessToken{}, "", err
	}
	prefix, raw, err := m.newOAuthBearer("cba")
	if err != nil {
		return OAuthAccessToken{}, "", err
	}
	now := m.now()
	return OAuthAccessToken{
		ID: id, Prefix: prefix, Digest: m.oauthDigest("access-token", raw), GrantID: grant.ID,
		ClientRecordID: grant.ClientRecordID, UserID: grant.UserID, WorkspaceID: grant.WorkspaceID,
		ResourceID: grant.ResourceID, Scopes: slices.Clone(grant.Scopes), CreatedAt: now, ExpiresAt: now.Add(ttl),
	}, raw, nil
}

func (m *Manager) newOAuthRefreshToken(grant OAuthGrant, familyID string, ttl time.Duration) (OAuthRefreshToken, string, error) {
	id, err := m.newID()
	if err != nil {
		return OAuthRefreshToken{}, "", err
	}
	if familyID == "" {
		familyID, err = m.newID()
		if err != nil {
			return OAuthRefreshToken{}, "", err
		}
	}
	prefix, raw, err := m.newOAuthBearer("cbr")
	if err != nil {
		return OAuthRefreshToken{}, "", err
	}
	now := m.now()
	return OAuthRefreshToken{
		ID: id, FamilyID: familyID, Prefix: prefix, Digest: m.oauthDigest("refresh-token", raw), GrantID: grant.ID,
		ClientRecordID: grant.ClientRecordID, UserID: grant.UserID, WorkspaceID: grant.WorkspaceID,
		ResourceID: grant.ResourceID, Scopes: slices.Clone(grant.Scopes), CreatedAt: now, ExpiresAt: now.Add(ttl),
	}, raw, nil
}

func (m *Manager) revokeOAuthRefreshFamily(ctx context.Context, token OAuthRefreshToken, client OAuthClient, reason string) error {
	audit, err := m.newAudit(ctx, client.ID, "oauth.refresh_family.revoked", "oauth_refresh_family", token.FamilyID, token.WorkspaceID, AuditSucceeded, reason)
	if err != nil {
		return err
	}
	audit.ActorKind = ActorService
	name := EventOAuthTokenRevoked
	if reason == "reuse_detected" {
		name = EventOAuthRefreshReuseDetected
	}
	change, commit, err := m.newOAuthChange(name, "oauth.refresh_family.revoke", audit, client, token.GrantID, token.ID, token.ResourceID, token.WorkspaceID, token.Scopes)
	if err != nil {
		return err
	}
	if err := m.oauthStore.RevokeOAuthRefreshFamily(ctx, token.FamilyID, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, "oauth.refresh_family.revoke", err)
	}
	m.emitOAuthChange(ctx, change)
	return nil
}

func (m *Manager) oauthIDToken(ctx context.Context, issuer OAuthIssuer, client OAuthClient, grant OAuthGrant, nonce string, expiresAt time.Time) (string, error) {
	if !slices.Contains(grant.Scopes, "openid") {
		return "", nil
	}
	if !issuer.OIDCEnabled || m.oauth.OIDCSigner == nil {
		return "", ErrNotSupported
	}
	claims := OIDCClaims{
		Issuer: issuer.Issuer, Subject: m.oauthPairwiseSubject(issuer.ID, client.SectorIdentifier, grant.UserID),
		Audience: client.ClientID, ExpiresAt: expiresAt.Unix(), IssuedAt: m.now().Unix(),
		AuthTime: grant.AuthTime.Unix(), Nonce: nonce, ACR: fmt.Sprintf("urn:credbound:aal:%d", grant.AAL),
	}
	if grant.AuthMethod != "" {
		claims.AMR = []string{string(grant.AuthMethod)}
	}
	if slices.Contains(grant.Scopes, "email") {
		claims.Email, claims.EmailVerified = m.oauthPrimaryEmail(ctx, grant.UserID)
	}
	return m.oauth.OIDCSigner.SignIDToken(ctx, claims)
}

func (m *Manager) oauthPairwiseSubject(issuerID, sectorIdentifier, userID string) string {
	mac := hmac.New(sha256.New, m.oauth.Pepper)
	_, _ = mac.Write([]byte("oidc-subject\x00" + issuerID + "\x00" + sectorIdentifier + "\x00" + userID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *Manager) oauthPrimaryEmail(ctx context.Context, userID string) (string, *bool) {
	user, err := m.store.UserByID(ctx, userID)
	if err != nil || user.Email == "" {
		return "", nil
	}
	verified := false
	for event, eventErr := range m.store.Emails(ctx, userID, PageRequest{Limit: 100}) {
		if eventErr != nil {
			break
		}
		if event.Data != nil && event.Data.Primary && event.Data.Address == user.Email {
			verified = event.Data.VerifiedAt != nil
			break
		}
	}
	return user.Email, &verified
}

func verifyPKCE(verifier, expected string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return hmac.Equal([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(expected))
}

func scopesSubset(requested, available []string) bool {
	for _, scope := range requested {
		if !slices.Contains(available, scope) {
			return false
		}
	}
	return true
}

func (m *Manager) mapOAuthCredentialStoreError(ctx context.Context, operation string, err error) error {
	if errors.Is(err, ErrConflict) || errors.Is(err, ErrExpired) {
		return ErrInvalidCredentials
	}
	return m.mapStoreError(ctx, operation, err)
}
