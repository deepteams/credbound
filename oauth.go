package credbound

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	defaultOAuthCodeTTL        = 5 * time.Minute
	defaultOAuthAccessTokenTTL = 15 * time.Minute
	defaultOAuthRefreshTTL     = 30 * 24 * time.Hour
	maxOAuthCodeTTL            = 10 * time.Minute
	maxOAuthAccessTokenTTL     = time.Hour
	maxOAuthRefreshTTL         = 90 * 24 * time.Hour
)

var oauthScopePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~+:/-]{0,127}$`)
var pkceVerifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

type oauthAuthorizationContinuation struct {
	UserID         string         `json:"uid"`
	ClientRecordID string         `json:"cid"`
	ResourceID     string         `json:"rid"`
	RedirectURI    string         `json:"redirect_uri"`
	Scopes         []string       `json:"scopes"`
	State          string         `json:"state"`
	CodeChallenge  string         `json:"code_challenge"`
	Nonce          string         `json:"nonce,omitempty"`
	MetadataHash   []byte         `json:"metadata_hash,omitempty"`
	AuthTime       time.Time      `json:"auth_time"`
	AuthMethod     AuthMethod     `json:"auth_method"`
	AAL            AssuranceLevel `json:"aal"`
	ExpiresAt      time.Time      `json:"exp"`
}

// ValidateOAuthAuthorizationRedirect resolves the client and validates an
// exact redirect URI. HTTP adapters use it before deciding whether an OAuth
// authorization error may safely be redirected to the client.
func (m *Manager) ValidateOAuthAuthorizationRedirect(ctx context.Context, issuerURL, clientID, redirectURI string) error {
	store, _, err := m.requireOAuth()
	if err != nil {
		return err
	}
	issuerURL, err = validateIssuerURL(issuerURL)
	if err != nil {
		return err
	}
	issuer, err := store.OAuthIssuerByURL(ctx, issuerURL)
	if err != nil || issuer.DisabledAt != nil {
		return ErrInvalidCredentials
	}
	client, err := m.resolveOAuthClient(ctx, issuer, clientID)
	if err != nil || client.DisabledAt != nil {
		return ErrInvalidCredentials
	}
	if !slices.Contains(client.RedirectURIs, redirectURI) {
		return fmt.Errorf("%w: redirect URI is not registered", ErrInvalidInput)
	}
	return nil
}

func (m *Manager) CreateOAuthIssuer(ctx context.Context, actor Authentication, request TrustedRequest, input CreateOAuthIssuerInput) (_ OAuthIssuer, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.issuer.create", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return OAuthIssuer{}, err
	}
	if err := m.AuthorizeAdmin(ctx, actor, PermissionSettingsWrite); err != nil {
		return OAuthIssuer{}, err
	}
	if err := m.requireAdminMutation(ctx, actor, request, "oauth.issuer.create"); err != nil {
		return OAuthIssuer{}, err
	}
	issuerURL, err := validateIssuerURL(input.Issuer)
	if err != nil {
		return OAuthIssuer{}, err
	}
	policy, err := m.normalizeOAuthIssuerPolicy(UpdateOAuthIssuerInput{
		OIDCEnabled: input.OIDCEnabled, CIMDMode: input.CIMDMode,
		CIMDAllowedOrigins: input.CIMDAllowedOrigins, DCRMode: input.DCRMode,
		DCRAllowClientSecrets: input.DCRAllowClientSecrets, CodeTTL: input.CodeTTL,
		DCROpenRegistrationLimit: input.DCROpenRegistrationLimit,
		AccessTokenTTL:           input.AccessTokenTTL, RefreshTokenTTL: input.RefreshTokenTTL,
	})
	if err != nil {
		return OAuthIssuer{}, err
	}
	id, err := m.newID()
	if err != nil {
		return OAuthIssuer{}, err
	}
	now := m.now()
	issuer := OAuthIssuer{
		ID: id, Issuer: issuerURL, OIDCEnabled: policy.OIDCEnabled,
		CIMDMode: policy.CIMDMode, CIMDAllowedOrigins: policy.CIMDAllowedOrigins,
		DCRMode: policy.DCRMode, DCRAllowClientSecrets: policy.DCRAllowClientSecrets,
		DCROpenRegistrationLimit: policy.DCROpenRegistrationLimit,
		CodeTTL:                  policy.CodeTTL, AccessTokenTTL: policy.AccessTokenTTL,
		RefreshTokenTTL: policy.RefreshTokenTTL, CreatedAt: now, UpdatedAt: now,
	}
	audit, err := m.newAudit(ctx, actor.UserID, "oauth.issuer.create", "oauth_issuer", issuer.ID, "", AuditSucceeded, "")
	if err != nil {
		return OAuthIssuer{}, err
	}
	if err := store.CreateOAuthIssuer(ctx, issuer, Commit{Audit: audit}); err != nil {
		return OAuthIssuer{}, m.mapStoreError(ctx, "oauth.issuer.create", err)
	}
	return cloneOAuthIssuer(issuer), nil
}

func (m *Manager) UpdateOAuthIssuer(ctx context.Context, actor Authentication, request TrustedRequest, issuerID string, input UpdateOAuthIssuerInput) (_ OAuthIssuer, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.issuer.update", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return OAuthIssuer{}, err
	}
	if err := m.AuthorizeAdmin(ctx, actor, PermissionSettingsWrite); err != nil {
		return OAuthIssuer{}, err
	}
	if err := m.requireAdminMutation(ctx, actor, request, "oauth.issuer.update"); err != nil {
		return OAuthIssuer{}, err
	}
	if !validUUIDv7(issuerID) {
		return OAuthIssuer{}, fmt.Errorf("%w: invalid OAuth issuer id", ErrInvalidInput)
	}
	issuer, err := store.OAuthIssuerByID(ctx, issuerID)
	if err != nil {
		return OAuthIssuer{}, err
	}
	policy, err := m.normalizeOAuthIssuerPolicy(input)
	if err != nil {
		return OAuthIssuer{}, err
	}
	issuer.OIDCEnabled = policy.OIDCEnabled
	issuer.CIMDMode = policy.CIMDMode
	issuer.CIMDAllowedOrigins = policy.CIMDAllowedOrigins
	issuer.DCRMode = policy.DCRMode
	issuer.DCRAllowClientSecrets = policy.DCRAllowClientSecrets
	issuer.DCROpenRegistrationLimit = policy.DCROpenRegistrationLimit
	issuer.CodeTTL = policy.CodeTTL
	issuer.AccessTokenTTL = policy.AccessTokenTTL
	issuer.RefreshTokenTTL = policy.RefreshTokenTTL
	issuer.UpdatedAt = m.now()
	audit, err := m.newAudit(ctx, actor.UserID, "oauth.issuer.update", "oauth_issuer", issuer.ID, "", AuditSucceeded, "")
	if err != nil {
		return OAuthIssuer{}, err
	}
	if err := store.UpdateOAuthIssuer(ctx, issuer, Commit{Audit: audit}); err != nil {
		return OAuthIssuer{}, m.mapStoreError(ctx, "oauth.issuer.update", err)
	}
	return cloneOAuthIssuer(issuer), nil
}

func (m *Manager) CreateOAuthProtectedResource(ctx context.Context, actor Authentication, workspaceID string, input CreateOAuthProtectedResourceInput) (_ OAuthProtectedResource, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.resource.create", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return OAuthProtectedResource{}, err
	}
	if err := m.requireStepUp(ctx, actor, "oauth.resource.create"); err != nil {
		return OAuthProtectedResource{}, err
	}
	if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionOAuthResourceManage); err != nil {
		return OAuthProtectedResource{}, err
	}
	if !validUUIDv7(input.IssuerID) {
		return OAuthProtectedResource{}, fmt.Errorf("%w: invalid OAuth issuer id", ErrInvalidInput)
	}
	issuer, err := store.OAuthIssuerByID(ctx, input.IssuerID)
	if err != nil {
		return OAuthProtectedResource{}, err
	}
	if issuer.DisabledAt != nil {
		return OAuthProtectedResource{}, ErrForbidden
	}
	resourceURL, err := validateResourceURL(input.Resource)
	if err != nil {
		return OAuthProtectedResource{}, err
	}
	scopes, err := m.normalizeOAuthScopeDefinitions(input.Scopes)
	if err != nil {
		return OAuthProtectedResource{}, err
	}
	id, err := m.newID()
	if err != nil {
		return OAuthProtectedResource{}, err
	}
	now := m.now()
	resource := OAuthProtectedResource{
		ID: id, IssuerID: issuer.ID, WorkspaceID: workspaceID, Resource: resourceURL,
		Scopes: scopes, CreatedAt: now, UpdatedAt: now,
	}
	audit, err := m.newAudit(ctx, actor.UserID, "oauth.resource.create", "oauth_resource", id, workspaceID, AuditSucceeded, "")
	if err != nil {
		return OAuthProtectedResource{}, err
	}
	if err := store.CreateOAuthProtectedResource(ctx, resource, Commit{Audit: audit}); err != nil {
		return OAuthProtectedResource{}, m.mapStoreError(ctx, "oauth.resource.create", err)
	}
	return cloneOAuthResource(resource), nil
}

func (m *Manager) PreRegisterOAuthClient(ctx context.Context, actor Authentication, request TrustedRequest, issuerID string, input OAuthClientRegistrationInput) (_ IssuedOAuthClient, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.client.pre_register", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	if err := m.AuthorizeAdmin(ctx, actor, PermissionSettingsWrite); err != nil {
		return IssuedOAuthClient{}, err
	}
	if err := m.requireAdminMutation(ctx, actor, request, "oauth.client.pre_register"); err != nil {
		return IssuedOAuthClient{}, err
	}
	issuer, err := store.OAuthIssuerByID(ctx, issuerID)
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	client, rawSecret, err := m.newOAuthClient(issuer, OAuthClientPreRegistered, input, true)
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	audit, err := m.newAudit(ctx, actor.UserID, "oauth.client.pre_register", "oauth_client", client.ID, "", AuditSucceeded, "")
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	change, commit, err := m.newOAuthChange(EventOAuthClientRegistered, "oauth.client.pre_register", audit, client, "", "", "", "", client.Scopes)
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	if err := store.CreateOAuthClient(ctx, client, "", m.now(), commit); err != nil {
		return IssuedOAuthClient{}, m.mapStoreError(ctx, "oauth.client.pre_register", err)
	}
	m.emitOAuthChange(ctx, change)
	return IssuedOAuthClient{Client: publicOAuthClient(client), ClientSecret: rawSecret}, nil
}

func (m *Manager) CreateOAuthInitialAccessToken(ctx context.Context, actor Authentication, request TrustedRequest, issuerID string, input CreateOAuthInitialAccessTokenInput) (_ IssuedOAuthInitialAccessToken, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.initial_access_token.create", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return IssuedOAuthInitialAccessToken{}, err
	}
	if err := m.AuthorizeAdmin(ctx, actor, PermissionSettingsWrite); err != nil {
		return IssuedOAuthInitialAccessToken{}, err
	}
	if err := m.requireAdminMutation(ctx, actor, request, "oauth.initial_access_token.create"); err != nil {
		return IssuedOAuthInitialAccessToken{}, err
	}
	issuer, err := store.OAuthIssuerByID(ctx, issuerID)
	if err != nil {
		return IssuedOAuthInitialAccessToken{}, err
	}
	if issuer.DCRMode != OAuthDCRProtected || issuer.DisabledAt != nil {
		return IssuedOAuthInitialAccessToken{}, ErrNotSupported
	}
	if !input.ExpiresAt.After(m.now()) || input.ExpiresAt.After(m.now().Add(30*24*time.Hour)) {
		return IssuedOAuthInitialAccessToken{}, fmt.Errorf("%w: initial access token expiration must be within 30 days", ErrInvalidInput)
	}
	if input.MaxRegistrations == 0 {
		input.MaxRegistrations = 1
	}
	if input.MaxRegistrations < 1 || input.MaxRegistrations > 100 {
		return IssuedOAuthInitialAccessToken{}, fmt.Errorf("%w: registration limit must be between 1 and 100", ErrInvalidInput)
	}
	id, err := m.newID()
	if err != nil {
		return IssuedOAuthInitialAccessToken{}, err
	}
	prefix, raw, err := m.newOAuthBearer("cbi")
	if err != nil {
		return IssuedOAuthInitialAccessToken{}, err
	}
	credential := OAuthInitialAccessToken{
		ID: id, IssuerID: issuer.ID, Prefix: prefix,
		Digest: m.oauthDigest("initial-access-token", raw), MaxRegistrations: input.MaxRegistrations,
		CreatedAt: m.now(), ExpiresAt: input.ExpiresAt.UTC(),
	}
	audit, err := m.newAudit(ctx, actor.UserID, "oauth.initial_access_token.create", "oauth_initial_access_token", id, "", AuditSucceeded, "")
	if err != nil {
		return IssuedOAuthInitialAccessToken{}, err
	}
	if err := store.CreateOAuthInitialAccessToken(ctx, credential, Commit{Audit: audit}); err != nil {
		return IssuedOAuthInitialAccessToken{}, m.mapStoreError(ctx, "oauth.initial_access_token.create", err)
	}
	public := cloneOAuthInitialAccessToken(credential)
	public.Digest = nil
	return IssuedOAuthInitialAccessToken{Credential: public, Token: raw}, nil
}

func (m *Manager) RevokeOAuthInitialAccessToken(ctx context.Context, actor Authentication, request TrustedRequest, tokenID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.initial_access_token.revoke", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return err
	}
	if err := m.AuthorizeAdmin(ctx, actor, PermissionSettingsWrite); err != nil {
		return err
	}
	if err := m.requireAdminMutation(ctx, actor, request, "oauth.initial_access_token.revoke"); err != nil {
		return err
	}
	if !validUUIDv7(tokenID) {
		return fmt.Errorf("%w: invalid initial access token id", ErrInvalidInput)
	}
	audit, err := m.newAudit(ctx, actor.UserID, "oauth.initial_access_token.revoke", "oauth_initial_access_token", tokenID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	if err := store.RevokeOAuthInitialAccessToken(ctx, tokenID, m.now(), Commit{Audit: audit}); err != nil {
		return m.mapStoreError(ctx, "oauth.initial_access_token.revoke", err)
	}
	return nil
}

func (m *Manager) RegisterOAuthClient(ctx context.Context, issuerURL, initialAccessToken string, input OAuthClientRegistrationInput) (_ IssuedOAuthClient, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.client.dynamic_register", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	issuerURL, err = validateIssuerURL(issuerURL)
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	issuer, err := store.OAuthIssuerByURL(ctx, issuerURL)
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	if issuer.DisabledAt != nil || issuer.DCRMode == OAuthDCRDisabled {
		return IssuedOAuthClient{}, ErrNotSupported
	}
	input.Trusted = false
	allowSecret := issuer.DCRMode == OAuthDCRProtected && issuer.DCRAllowClientSecrets
	client, rawSecret, err := m.newOAuthClient(issuer, OAuthClientDCR, input, allowSecret)
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	initialID := ""
	actorKind := ActorSystem
	actorID := ""
	if issuer.DCRMode == OAuthDCRProtected {
		prefix, ok := parseOAuthBearer("cbi", initialAccessToken)
		if !ok {
			return IssuedOAuthClient{}, ErrInvalidCredentials
		}
		credential, lookupErr := store.OAuthInitialAccessTokenByPrefix(ctx, prefix)
		now := m.now()
		valid := lookupErr == nil && credential.IssuerID == issuer.ID && credential.RevokedAt == nil &&
			now.Before(credential.ExpiresAt) && credential.RegistrationCount < credential.MaxRegistrations &&
			hmac.Equal(credential.Digest, m.oauthDigest("initial-access-token", initialAccessToken))
		if !valid {
			return IssuedOAuthClient{}, ErrInvalidCredentials
		}
		initialID, actorID, actorKind = credential.ID, credential.ID, ActorService
	} else if initialAccessToken != "" {
		return IssuedOAuthClient{}, fmt.Errorf("%w: initial access token is not accepted by open DCR", ErrInvalidInput)
	}
	audit, err := m.newAudit(ctx, actorID, "oauth.client.dynamic_register", "oauth_client", client.ID, "", AuditSucceeded, "")
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	audit.ActorKind = actorKind
	change, commit, err := m.newOAuthChange(EventOAuthClientRegistered, "oauth.client.dynamic_register", audit, client, "", "", "", "", client.Scopes)
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	if err := store.CreateOAuthClient(ctx, client, initialID, m.now(), commit); err != nil {
		return IssuedOAuthClient{}, m.mapStoreError(ctx, "oauth.client.dynamic_register", err)
	}
	m.emitOAuthChange(ctx, change)
	return IssuedOAuthClient{Client: publicOAuthClient(client), ClientSecret: rawSecret}, nil
}

func (m *Manager) BeginOAuthAuthorization(ctx context.Context, actor Authentication, input BeginOAuthAuthorizationInput) (_ OAuthConsent, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.authorization.begin", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return OAuthConsent{}, err
	}
	if actor.UserID == "" || !actor.Interactive() {
		return OAuthConsent{}, ErrUnauthorized
	}
	issuerURL, err := validateIssuerURL(input.Issuer)
	if err != nil {
		return OAuthConsent{}, err
	}
	issuer, err := store.OAuthIssuerByURL(ctx, issuerURL)
	if err != nil || issuer.DisabledAt != nil {
		return OAuthConsent{}, ErrInvalidCredentials
	}
	client, err := m.resolveOAuthClient(ctx, issuer, input.ClientID)
	if err != nil {
		return OAuthConsent{}, err
	}
	for _, scope := range input.Scopes {
		if len(client.Scopes) > 0 && !slices.Contains(client.Scopes, strings.TrimSpace(scope)) {
			return OAuthConsent{}, ErrForbidden
		}
	}
	resourceURL, err := validateResourceURL(input.Resource)
	if err != nil {
		return OAuthConsent{}, err
	}
	resource, err := store.OAuthProtectedResourceByURI(ctx, resourceURL)
	if err != nil || resource.IssuerID != issuer.ID || resource.DisabledAt != nil {
		return OAuthConsent{}, ErrForbidden
	}
	if !slices.Contains(client.RedirectURIs, input.RedirectURI) {
		return OAuthConsent{}, fmt.Errorf("%w: redirect URI is not registered", ErrInvalidInput)
	}
	if input.CodeChallengeMethod != "S256" || !validPKCEChallenge(input.CodeChallenge) {
		return OAuthConsent{}, fmt.Errorf("%w: PKCE S256 is required", ErrInvalidInput)
	}
	if input.State == "" || len(input.State) > 1024 || len(input.Nonce) > 1024 {
		return OAuthConsent{}, fmt.Errorf("%w: state is required and request values are limited", ErrInvalidInput)
	}
	scopes, definitions, err := m.authorizedOAuthScopes(ctx, actor, issuer, resource, input.Scopes)
	if err != nil {
		return OAuthConsent{}, err
	}
	requiresStepUp := false
	for _, definition := range definitions {
		if definition.MinimumAAL > actor.Level || (definition.MaxAuthAge > 0 && !freshAuthentication(m.now(), actor.AuthenticatedAt, definition.MaxAuthAge)) {
			requiresStepUp = true
		}
	}
	continuation := oauthAuthorizationContinuation{
		UserID: actor.UserID, ClientRecordID: client.ID, ResourceID: resource.ID,
		RedirectURI: input.RedirectURI, Scopes: scopes, State: input.State,
		CodeChallenge: input.CodeChallenge, Nonce: input.Nonce,
		MetadataHash: slices.Clone(client.MetadataHash), AuthTime: actor.AuthenticatedAt,
		AuthMethod: actor.Method, AAL: actor.Level, ExpiresAt: m.now().Add(m.ceremonyTTL),
	}
	rawContinuation, err := m.encodeOAuthContinuation(continuation)
	if err != nil {
		return OAuthConsent{}, err
	}
	clientURL, _ := url.Parse(client.ClientID)
	redirectURL, _ := url.Parse(input.RedirectURI)
	consentScopes := make([]OAuthConsentScope, 0, len(scopes))
	for _, scope := range scopes {
		description := oauthReservedScopeDescription(scope)
		for _, definition := range definitions {
			if definition.Name == scope {
				description = definition.Description
				break
			}
		}
		consentScopes = append(consentScopes, OAuthConsentScope{Name: scope, Description: description})
	}
	return OAuthConsent{
		Continuation: rawContinuation, ClientID: client.ClientID, ClientName: client.Name,
		ClientHost: clientURL.Hostname(), RedirectURI: input.RedirectURI,
		RedirectHost: redirectURL.Hostname(), Resource: resource.Resource,
		WorkspaceID: resource.WorkspaceID, Scopes: consentScopes, RequiresStepUp: requiresStepUp,
		LocalhostRedirect: isLocalhostName(redirectURL.Hostname()),
	}, nil
}

func (m *Manager) CompleteOAuthAuthorization(ctx context.Context, actor Authentication, rawContinuation string, approved bool) (_ OAuthAuthorizationResult, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.authorization.complete", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return OAuthAuthorizationResult{}, err
	}
	continuation, err := m.decodeOAuthContinuation(rawContinuation)
	if err != nil {
		return OAuthAuthorizationResult{}, err
	}
	if actor.UserID == "" || actor.UserID != continuation.UserID || !actor.Interactive() {
		return OAuthAuthorizationResult{}, ErrUnauthorized
	}
	client, err := store.OAuthClientByID(ctx, continuation.ClientRecordID)
	if err != nil || client.DisabledAt != nil || !hmac.Equal(client.MetadataHash, continuation.MetadataHash) {
		return OAuthAuthorizationResult{}, ErrInvalidCredentials
	}
	resource, err := store.OAuthProtectedResourceByID(ctx, continuation.ResourceID)
	if err != nil || resource.DisabledAt != nil {
		return OAuthAuthorizationResult{}, ErrForbidden
	}
	issuer, err := store.OAuthIssuerByID(ctx, resource.IssuerID)
	if err != nil || issuer.DisabledAt != nil || client.IssuerID != issuer.ID {
		return OAuthAuthorizationResult{}, ErrForbidden
	}
	_, definitions, err := m.authorizedOAuthScopes(ctx, actor, issuer, resource, continuation.Scopes)
	if err != nil {
		return OAuthAuthorizationResult{}, err
	}
	for _, definition := range definitions {
		if definition.MinimumAAL > actor.Level || (definition.MaxAuthAge > 0 && !freshAuthentication(m.now(), actor.AuthenticatedAt, definition.MaxAuthAge)) {
			return OAuthAuthorizationResult{}, ErrStepUpRequired
		}
	}
	baseResult := OAuthAuthorizationResult{RedirectURI: continuation.RedirectURI, State: continuation.State, Issuer: issuer.Issuer}
	if !approved {
		audit, auditErr := m.newAudit(ctx, actor.UserID, "oauth.authorization.denied", "oauth_client", client.ID, resource.WorkspaceID, AuditFailed, "access_denied")
		if auditErr != nil {
			return OAuthAuthorizationResult{}, auditErr
		}
		change, commit, changeErr := m.newOAuthChange(EventOAuthAuthorizationDenied, "oauth.authorization.denied", audit, client, "", "", resource.ID, resource.WorkspaceID, continuation.Scopes)
		if changeErr != nil {
			return OAuthAuthorizationResult{}, changeErr
		}
		if auditErr = m.store.AppendAudit(ctx, commit); auditErr != nil {
			return OAuthAuthorizationResult{}, m.mapStoreError(ctx, "oauth.authorization.denied", auditErr)
		}
		m.emitOAuthChange(ctx, change)
		baseResult.Error = "access_denied"
		return baseResult, nil
	}
	grantID, err := m.newID()
	if err != nil {
		return OAuthAuthorizationResult{}, err
	}
	codeID, err := m.newID()
	if err != nil {
		return OAuthAuthorizationResult{}, err
	}
	prefix, rawCode, err := m.newOAuthBearer("cbc")
	if err != nil {
		return OAuthAuthorizationResult{}, err
	}
	now := m.now()
	grant := OAuthGrant{
		ID: grantID, IssuerID: issuer.ID, ClientRecordID: client.ID,
		UserID: actor.UserID, WorkspaceID: resource.WorkspaceID, ResourceID: resource.ID,
		Scopes: slices.Clone(continuation.Scopes), MetadataHash: slices.Clone(client.MetadataHash),
		AuthTime: actor.AuthenticatedAt, AuthMethod: actor.Method, AAL: actor.Level,
		CreatedAt: now, UpdatedAt: now,
	}
	code := OAuthAuthorizationCode{
		ID: codeID, Prefix: prefix, Digest: m.oauthDigest("authorization-code", rawCode),
		GrantID: grant.ID, ClientRecordID: client.ID, RedirectURI: continuation.RedirectURI,
		ResourceID: resource.ID, Scopes: slices.Clone(continuation.Scopes),
		CodeChallenge: continuation.CodeChallenge, Nonce: continuation.Nonce,
		CreatedAt: now, ExpiresAt: now.Add(issuer.CodeTTL),
	}
	audit, err := m.newAudit(ctx, actor.UserID, "oauth.authorization.granted", "oauth_grant", grant.ID, resource.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return OAuthAuthorizationResult{}, err
	}
	change, commit, err := m.newOAuthChange(EventOAuthAuthorizationGranted, "oauth.authorization.granted", audit, client, grant.ID, "", resource.ID, resource.WorkspaceID, grant.Scopes)
	if err != nil {
		return OAuthAuthorizationResult{}, err
	}
	if err := store.CreateOAuthGrantAndCode(ctx, grant, code, commit); err != nil {
		return OAuthAuthorizationResult{}, m.mapStoreError(ctx, "oauth.authorization.granted", err)
	}
	m.emitOAuthChange(ctx, change)
	baseResult.Code = rawCode
	return baseResult, nil
}

func (m *Manager) requireOAuth() (OAuthStore, *OAuthConfig, error) {
	if m.oauth == nil || m.oauthStore == nil {
		return nil, nil, ErrNotSupported
	}
	return m.oauthStore, m.oauth, nil
}

func (m *Manager) normalizeOAuthIssuerPolicy(input UpdateOAuthIssuerInput) (UpdateOAuthIssuerInput, error) {
	if input.CIMDMode == "" {
		input.CIMDMode = OAuthCIMDDisabled
	}
	if input.DCRMode == "" {
		input.DCRMode = OAuthDCRDisabled
	}
	if input.CIMDMode != OAuthCIMDDisabled && input.CIMDMode != OAuthCIMDAllowlist && input.CIMDMode != OAuthCIMDPublicWeb {
		return UpdateOAuthIssuerInput{}, fmt.Errorf("%w: invalid CIMD mode", ErrInvalidInput)
	}
	if input.DCRMode != OAuthDCRDisabled && input.DCRMode != OAuthDCRProtected && input.DCRMode != OAuthDCROpen {
		return UpdateOAuthIssuerInput{}, fmt.Errorf("%w: invalid DCR mode", ErrInvalidInput)
	}
	if input.DCRMode != OAuthDCRProtected && input.DCRAllowClientSecrets {
		return UpdateOAuthIssuerInput{}, fmt.Errorf("%w: client secrets require protected DCR", ErrInvalidInput)
	}
	if input.DCRMode == OAuthDCROpen {
		if input.DCROpenRegistrationLimit == 0 {
			input.DCROpenRegistrationLimit = 1000
		}
		if input.DCROpenRegistrationLimit < 1 || input.DCROpenRegistrationLimit > 100000 {
			return UpdateOAuthIssuerInput{}, fmt.Errorf("%w: open DCR registration limit must be between 1 and 100000", ErrInvalidInput)
		}
	} else if input.DCROpenRegistrationLimit != 0 {
		return UpdateOAuthIssuerInput{}, fmt.Errorf("%w: open DCR registration limit requires open mode", ErrInvalidInput)
	}
	if input.OIDCEnabled && m.oauth.OIDCSigner == nil {
		return UpdateOAuthIssuerInput{}, fmt.Errorf("%w: OIDC signer is required", ErrInvalidInput)
	}
	if input.OIDCEnabled {
		algorithms := m.oauth.OIDCSigner.Algorithms()
		if len(algorithms) == 0 {
			return UpdateOAuthIssuerInput{}, fmt.Errorf("%w: OIDC signer must advertise an algorithm", ErrInvalidInput)
		}
		for _, algorithm := range algorithms {
			if algorithm == "" || algorithm == "none" {
				return UpdateOAuthIssuerInput{}, fmt.Errorf("%w: invalid OIDC signing algorithm", ErrInvalidInput)
			}
		}
	}
	origins := make([]string, 0, len(input.CIMDAllowedOrigins))
	for _, raw := range input.CIMDAllowedOrigins {
		origin, err := normalizeHTTPSOrigin(raw)
		if err != nil {
			return UpdateOAuthIssuerInput{}, err
		}
		origins = append(origins, origin)
	}
	slices.Sort(origins)
	input.CIMDAllowedOrigins = slices.Compact(origins)
	if input.CIMDMode == OAuthCIMDAllowlist && len(input.CIMDAllowedOrigins) == 0 {
		return UpdateOAuthIssuerInput{}, fmt.Errorf("%w: CIMD allowlist cannot be empty", ErrInvalidInput)
	}
	if input.CodeTTL == 0 {
		input.CodeTTL = defaultOAuthCodeTTL
	}
	if input.AccessTokenTTL == 0 {
		input.AccessTokenTTL = defaultOAuthAccessTokenTTL
	}
	if input.RefreshTokenTTL == 0 {
		input.RefreshTokenTTL = defaultOAuthRefreshTTL
	}
	if input.CodeTTL <= 0 || input.CodeTTL > maxOAuthCodeTTL || input.AccessTokenTTL <= 0 || input.AccessTokenTTL > maxOAuthAccessTokenTTL || input.RefreshTokenTTL <= 0 || input.RefreshTokenTTL > maxOAuthRefreshTTL {
		return UpdateOAuthIssuerInput{}, fmt.Errorf("%w: invalid OAuth token lifetime", ErrInvalidInput)
	}
	return input, nil
}

func (m *Manager) normalizeOAuthScopeDefinitions(input []OAuthScopeDefinition) ([]OAuthScopeDefinition, error) {
	if len(input) == 0 || len(input) > 100 {
		return nil, fmt.Errorf("%w: at least one and at most 100 OAuth scopes are required", ErrInvalidInput)
	}
	result := make([]OAuthScopeDefinition, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for _, definition := range input {
		definition.Name = strings.TrimSpace(definition.Name)
		definition.Description = strings.TrimSpace(definition.Description)
		if !oauthScopePattern.MatchString(definition.Name) || oauthReservedScope(definition.Name) || definition.Description == "" || len(definition.Description) > 500 {
			return nil, fmt.Errorf("%w: invalid OAuth scope definition", ErrInvalidInput)
		}
		if _, duplicate := seen[definition.Name]; duplicate {
			return nil, fmt.Errorf("%w: duplicate OAuth scope", ErrInvalidInput)
		}
		seen[definition.Name] = struct{}{}
		if definition.MinimumAAL == 0 {
			definition.MinimumAAL = AAL1
		}
		if definition.MinimumAAL != AAL1 && definition.MinimumAAL != AAL2 || definition.MaxAuthAge < 0 {
			return nil, fmt.Errorf("%w: invalid OAuth scope assurance policy", ErrInvalidInput)
		}
		definition.Permissions = uniqueWorkspacePermissions(definition.Permissions)
		if len(definition.Permissions) == 0 {
			return nil, fmt.Errorf("%w: OAuth scopes require workspace permissions", ErrInvalidInput)
		}
		for _, permission := range definition.Permissions {
			if _, known := m.workspaceRoles.permissions[permission]; !known {
				return nil, fmt.Errorf("%w: OAuth scope references an unknown workspace permission", ErrInvalidInput)
			}
		}
		result = append(result, definition)
	}
	slices.SortFunc(result, func(left, right OAuthScopeDefinition) int { return strings.Compare(left.Name, right.Name) })
	return result, nil
}

func (m *Manager) newOAuthClient(issuer OAuthIssuer, source OAuthClientSource, input OAuthClientRegistrationInput, allowSecret bool) (OAuthClient, string, error) {
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || len(input.Name) > 200 {
		return OAuthClient{}, "", fmt.Errorf("%w: OAuth client name is required and limited to 200 characters", ErrInvalidInput)
	}
	if input.ApplicationType != OAuthApplicationWeb && input.ApplicationType != OAuthApplicationNative {
		return OAuthClient{}, "", fmt.Errorf("%w: OAuth application type must be web or native", ErrInvalidInput)
	}
	redirects, err := normalizeRedirectURIs(input.ApplicationType, input.RedirectURIs)
	if err != nil {
		return OAuthClient{}, "", err
	}
	grants, responses, err := normalizeOAuthFlowMetadata(input.GrantTypes, input.ResponseTypes)
	if err != nil {
		return OAuthClient{}, "", err
	}
	scopes, err := normalizeOptionalOAuthScopes(input.Scopes)
	if err != nil {
		return OAuthClient{}, "", err
	}
	// Without sector_identifier_uri support, an OIDC issuer can only provide a
	// stable pairwise subject when every redirect URI belongs to one host. This
	// must also cover clients with an empty (unrestricted) registered scope list
	// because they may request openid later.
	sectorIdentifier, err := oauthSectorIdentifier(redirects, issuer.OIDCEnabled)
	if err != nil {
		return OAuthClient{}, "", err
	}
	method := input.TokenEndpointAuthMethod
	if method == "" {
		method = OAuthAuthNone
	}
	if method != OAuthAuthNone && method != OAuthAuthPrivateKeyJWT && method != OAuthAuthClientSecretBasic {
		return OAuthClient{}, "", fmt.Errorf("%w: unsupported OAuth client authentication method", ErrInvalidInput)
	}
	if method == OAuthAuthPrivateKeyJWT && len(input.JWKS) == 0 && input.JWKSURI == "" {
		return OAuthClient{}, "", fmt.Errorf("%w: private_key_jwt requires jwks or jwks_uri", ErrInvalidInput)
	}
	if method == OAuthAuthClientSecretBasic && !allowSecret {
		return OAuthClient{}, "", fmt.Errorf("%w: client secrets are not allowed", ErrInvalidInput)
	}
	if input.JWKSURI != "" {
		if _, err := validatePublicHTTPSURL(input.JWKSURI, false); err != nil {
			return OAuthClient{}, "", fmt.Errorf("%w: invalid jwks_uri", ErrInvalidInput)
		}
	}
	if len(input.JWKS) > 32*1024 || (len(input.JWKS) > 0 && !json.Valid(input.JWKS)) {
		return OAuthClient{}, "", fmt.Errorf("%w: invalid jwks", ErrInvalidInput)
	}
	id, err := m.newID()
	if err != nil {
		return OAuthClient{}, "", err
	}
	now := m.now()
	client := OAuthClient{
		ID: id, IssuerID: issuer.ID, ClientID: id, Source: source, Name: input.Name,
		ApplicationType: input.ApplicationType, RedirectURIs: redirects,
		SectorIdentifier: sectorIdentifier,
		GrantTypes:       grants, ResponseTypes: responses, Scopes: scopes,
		TokenEndpointAuthMethod: method, JWKSURI: input.JWKSURI,
		JWKS: slices.Clone(input.JWKS), Trusted: input.Trusted && source == OAuthClientPreRegistered,
		CreatedAt: now, UpdatedAt: now,
	}
	client.MetadataHash = oauthClientMetadataHash(client)
	rawSecret := ""
	if method == OAuthAuthClientSecretBasic {
		secret, err := randomBytes(m.random, 32)
		if err != nil {
			return OAuthClient{}, "", err
		}
		rawSecret = "cbos_" + base64.RawURLEncoding.EncodeToString(secret)
		client.SecretDigest = m.oauthDigest("client-secret", rawSecret)
	}
	return client, rawSecret, nil
}

func (m *Manager) resolveOAuthClient(ctx context.Context, issuer OAuthIssuer, clientID string) (OAuthClient, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" || len(clientID) > 2048 {
		return OAuthClient{}, ErrInvalidCredentials
	}
	client, err := m.oauthStore.OAuthClientByClientID(ctx, issuer.ID, clientID)
	if err == nil {
		if client.Source != OAuthClientCIMD || client.MetadataExpiresAt == nil || m.now().Before(*client.MetadataExpiresAt) {
			return client, nil
		}
	} else if !errors.Is(err, ErrNotFound) {
		return OAuthClient{}, err
	}
	if issuer.CIMDMode == OAuthCIMDDisabled || m.oauth.MetadataFetcher == nil {
		return OAuthClient{}, ErrInvalidCredentials
	}
	clientURL, err := validateCIMDClientID(clientID)
	if err != nil || !issuerAllowsCIMD(issuer, clientURL) {
		m.emitOAuthCIMDRejected(ctx, issuer, clientID, "policy_rejected")
		return OAuthClient{}, ErrInvalidCredentials
	}
	document, err := m.oauth.MetadataFetcher.Fetch(ctx, clientID)
	if err != nil {
		m.emitOAuthCIMDRejected(ctx, issuer, clientID, "metadata_fetch_failed")
		return OAuthClient{}, ErrInvalidCredentials
	}
	resolved, err := m.oauthClientFromMetadata(issuer, document)
	if err != nil || resolved.ClientID != clientID {
		m.emitOAuthCIMDRejected(ctx, issuer, clientID, "metadata_invalid")
		return OAuthClient{}, ErrInvalidCredentials
	}
	name := EventOAuthCIMDResolved
	action := "oauth.cimd.resolve"
	if client.ID != "" && !hmac.Equal(client.MetadataHash, resolved.MetadataHash) {
		name, action = EventOAuthCIMDChanged, "oauth.cimd.change"
	}
	if client.ID != "" {
		resolved.ID, resolved.CreatedAt = client.ID, client.CreatedAt
	}
	audit, err := m.newAudit(ctx, "", action, "oauth_client", resolved.ID, "", AuditSucceeded, "")
	if err != nil {
		return OAuthClient{}, err
	}
	audit.ActorKind = ActorSystem
	change, commit, err := m.newOAuthChange(name, action, audit, resolved, "", "", "", "", resolved.Scopes)
	if err != nil {
		return OAuthClient{}, err
	}
	if err := m.oauthStore.UpsertOAuthCIMDClient(ctx, resolved, commit); err != nil {
		return OAuthClient{}, m.mapStoreError(ctx, "oauth.cimd.resolve", err)
	}
	m.emitOAuthChange(ctx, change)
	return resolved, nil
}

func (m *Manager) emitOAuthCIMDRejected(ctx context.Context, issuer OAuthIssuer, clientID, reason string) {
	audit, err := m.newAudit(ctx, "", "oauth.cimd.reject", "oauth_client", clientID, "", AuditFailed, reason)
	if err != nil {
		return
	}
	audit.ActorKind = ActorSystem
	client := OAuthClient{IssuerID: issuer.ID, ClientID: clientID, Source: OAuthClientCIMD}
	change, commit, err := m.newOAuthChange(EventOAuthCIMDRejected, "oauth.cimd.reject", audit, client, "", "", "", "", nil)
	if err != nil || m.store.AppendAudit(ctx, commit) != nil {
		return
	}
	m.emitOAuthChange(ctx, change)
}

func (m *Manager) oauthClientFromMetadata(issuer OAuthIssuer, document OAuthClientMetadataDocument) (OAuthClient, error) {
	clientURL, err := validateCIMDClientID(document.ClientID)
	if err != nil || !issuerAllowsCIMD(issuer, clientURL) {
		return OAuthClient{}, ErrInvalidCredentials
	}
	if document.FetchedAt.IsZero() || document.ExpiresAt.IsZero() || !document.ExpiresAt.After(document.FetchedAt) || !document.ExpiresAt.After(m.now()) {
		return OAuthClient{}, fmt.Errorf("%w: invalid CIMD cache lifetime", ErrInvalidInput)
	}
	input := OAuthClientRegistrationInput{
		Name: document.ClientName, ApplicationType: document.ApplicationType,
		RedirectURIs: document.RedirectURIs, GrantTypes: document.GrantTypes,
		ResponseTypes: document.ResponseTypes, Scopes: strings.Fields(document.Scope),
		TokenEndpointAuthMethod: document.TokenEndpointAuthMethod,
		JWKSURI:                 document.JWKSURI, JWKS: document.JWKS,
	}
	client, _, err := m.newOAuthClient(issuer, OAuthClientCIMD, input, false)
	if err != nil {
		return OAuthClient{}, err
	}
	client.ClientID = document.ClientID
	client.MetadataExpiresAt = cloneTime(&document.ExpiresAt)
	client.CreatedAt, client.UpdatedAt = document.FetchedAt.UTC(), m.now()
	client.MetadataHash = oauthClientMetadataHash(client)
	return client, nil
}

func (m *Manager) authorizedOAuthScopes(ctx context.Context, actor Authentication, issuer OAuthIssuer, resource OAuthProtectedResource, requested []string) ([]string, []OAuthScopeDefinition, error) {
	scopes, err := normalizeOptionalOAuthScopes(requested)
	if err != nil || len(scopes) == 0 {
		return nil, nil, fmt.Errorf("%w: at least one OAuth scope is required", ErrInvalidInput)
	}
	definitions := make([]OAuthScopeDefinition, 0, len(scopes))
	for _, scope := range scopes {
		if oauthReservedScope(scope) {
			if (scope == "openid" || scope == "profile" || scope == "email") && !issuer.OIDCEnabled {
				return nil, nil, ErrForbidden
			}
			if (scope == "profile" || scope == "email") && !slices.Contains(scopes, "openid") {
				return nil, nil, fmt.Errorf("%w: OIDC claim scopes require openid", ErrInvalidInput)
			}
			continue
		}
		definition, ok := oauthScopeDefinition(resource.Scopes, scope)
		if !ok {
			return nil, nil, ErrForbidden
		}
		for _, permission := range definition.Permissions {
			if err := m.AuthorizePermission(ctx, actor, resource.WorkspaceID, permission); err != nil {
				return nil, nil, ErrForbidden
			}
		}
		definitions = append(definitions, definition)
	}
	return scopes, definitions, nil
}

func (m *Manager) encodeOAuthContinuation(value oauthAuthorizationContinuation) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal OAuth continuation: %w", err)
	}
	sealed, err := m.seal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (m *Manager) decodeOAuthContinuation(raw string) (oauthAuthorizationContinuation, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return oauthAuthorizationContinuation{}, ErrInvalidCredentials
	}
	payload, err := m.open(sealed)
	if err != nil {
		return oauthAuthorizationContinuation{}, ErrInvalidCredentials
	}
	var value oauthAuthorizationContinuation
	if err := json.Unmarshal(payload, &value); err != nil || value.UserID == "" || value.ClientRecordID == "" || value.ResourceID == "" {
		return oauthAuthorizationContinuation{}, ErrInvalidCredentials
	}
	if !m.now().Before(value.ExpiresAt) {
		return oauthAuthorizationContinuation{}, ErrExpired
	}
	return value, nil
}

func (m *Manager) newOAuthBearer(marker string) (string, string, error) {
	prefixBytes, err := randomBytes(m.random, 6)
	if err != nil {
		return "", "", err
	}
	secret, err := randomBytes(m.random, 32)
	if err != nil {
		return "", "", err
	}
	prefix := hex.EncodeToString(prefixBytes)
	return prefix, marker + "_" + prefix + "_" + base64.RawURLEncoding.EncodeToString(secret), nil
}

func (m *Manager) oauthDigest(purpose, raw string) []byte {
	return digest(m.oauth.Pepper, purpose+"\x00"+raw)
}

func parseOAuthBearer(marker, raw string) (string, bool) {
	parts := strings.SplitN(raw, "_", 3)
	if len(parts) != 3 || parts[0] != marker || len(parts[1]) != 12 || len(parts[2]) != 43 {
		return "", false
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", false
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[2])
	return parts[1], err == nil && len(secret) == 32
}

func validateIssuerURL(raw string) (string, error) {
	value, err := validatePublicHTTPSURL(raw, false)
	if err != nil || value.RawQuery != "" {
		return "", fmt.Errorf("%w: issuer must be an HTTPS URL without query or fragment", ErrInvalidInput)
	}
	return strings.TrimSuffix(value.String(), "/"), nil
}

func validateResourceURL(raw string) (string, error) {
	value, err := validatePublicHTTPSURL(raw, false)
	if err != nil || value.RawQuery != "" {
		return "", fmt.Errorf("%w: resource must be an HTTPS URL without query or fragment", ErrInvalidInput)
	}
	return value.String(), nil
}

func validatePublicHTTPSURL(raw string, requirePath bool) (*url.URL, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || len(raw) > 2048 {
		return nil, fmt.Errorf("%w: invalid HTTPS URL", ErrInvalidInput)
	}
	value, err := url.Parse(raw)
	if err != nil || value.Scheme != "https" || value.Host == "" || value.User != nil || value.Fragment != "" {
		return nil, fmt.Errorf("%w: invalid HTTPS URL", ErrInvalidInput)
	}
	if requirePath && (value.EscapedPath() == "" || value.EscapedPath() == "/") {
		return nil, fmt.Errorf("%w: HTTPS URL requires a non-root path", ErrInvalidInput)
	}
	return value, nil
}

func validateCIMDClientID(raw string) (*url.URL, error) {
	value, err := validatePublicHTTPSURL(raw, true)
	if err != nil || value.RawQuery != "" {
		return nil, fmt.Errorf("%w: invalid Client Identifier URL", ErrInvalidInput)
	}
	for _, segment := range strings.Split(value.EscapedPath(), "/") {
		decoded, decodeErr := url.PathUnescape(segment)
		if decodeErr != nil || decoded == "." || decoded == ".." || strings.ContainsAny(decoded, `/\`) {
			return nil, fmt.Errorf("%w: invalid Client Identifier URL path", ErrInvalidInput)
		}
	}
	if path.Clean(value.EscapedPath()) != value.EscapedPath() {
		return nil, fmt.Errorf("%w: non-canonical Client Identifier URL path", ErrInvalidInput)
	}
	return value, nil
}

func normalizeHTTPSOrigin(raw string) (string, error) {
	value, err := validatePublicHTTPSURL(strings.TrimSuffix(strings.TrimSpace(raw), "/"), false)
	if err != nil || value.Path != "" || value.RawQuery != "" {
		return "", fmt.Errorf("%w: invalid CIMD allowlist origin", ErrInvalidInput)
	}
	return "https://" + strings.ToLower(value.Host), nil
}

func issuerAllowsCIMD(issuer OAuthIssuer, clientURL *url.URL) bool {
	if clientURL == nil || issuer.CIMDMode == OAuthCIMDDisabled {
		return false
	}
	if issuer.CIMDMode == OAuthCIMDPublicWeb {
		return true
	}
	origin := "https://" + strings.ToLower(clientURL.Host)
	return slices.Contains(issuer.CIMDAllowedOrigins, origin)
}

func normalizeRedirectURIs(applicationType OAuthApplicationType, input []string) ([]string, error) {
	if len(input) == 0 || len(input) > 20 {
		return nil, fmt.Errorf("%w: between one and 20 redirect URIs are required", ErrInvalidInput)
	}
	result := make([]string, 0, len(input))
	for _, raw := range input {
		if raw == "" || raw != strings.TrimSpace(raw) || len(raw) > 2048 {
			return nil, fmt.Errorf("%w: invalid redirect URI", ErrInvalidInput)
		}
		value, err := url.Parse(raw)
		if err != nil || value.Host == "" || value.User != nil || value.Fragment != "" {
			return nil, fmt.Errorf("%w: invalid redirect URI", ErrInvalidInput)
		}
		if applicationType == OAuthApplicationWeb {
			if value.Scheme != "https" {
				return nil, fmt.Errorf("%w: web redirect URIs require HTTPS", ErrInvalidInput)
			}
		} else if value.Scheme != "https" && !(value.Scheme == "http" && isLoopbackRedirectHost(value.Hostname())) {
			return nil, fmt.Errorf("%w: native HTTP redirects require a loopback host", ErrInvalidInput)
		}
		result = append(result, raw)
	}
	slices.Sort(result)
	result = slices.Compact(result)
	if len(result) != len(input) {
		return nil, fmt.Errorf("%w: duplicate redirect URI", ErrInvalidInput)
	}
	return result, nil
}

func isLoopbackRedirectHost(host string) bool {
	return isLocalhostName(host) || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

func isLocalhostName(host string) bool { return strings.EqualFold(host, "localhost") }

func normalizeOAuthFlowMetadata(grants, responses []string) ([]string, []string, error) {
	if len(grants) == 0 {
		grants = []string{"authorization_code"}
	}
	if len(responses) == 0 {
		responses = []string{"code"}
	}
	grants = slices.Clone(grants)
	responses = slices.Clone(responses)
	slices.Sort(grants)
	slices.Sort(responses)
	grants, responses = slices.Compact(grants), slices.Compact(responses)
	for _, grant := range grants {
		if grant != "authorization_code" && grant != "refresh_token" {
			return nil, nil, fmt.Errorf("%w: unsupported OAuth grant type", ErrInvalidInput)
		}
	}
	if !slices.Contains(grants, "authorization_code") || len(responses) != 1 || responses[0] != "code" {
		return nil, nil, fmt.Errorf("%w: authorization_code and response type code are required", ErrInvalidInput)
	}
	return grants, responses, nil
}

func normalizeOptionalOAuthScopes(scopes []string) ([]string, error) {
	if len(scopes) > 100 {
		return nil, fmt.Errorf("%w: too many OAuth scopes", ErrInvalidInput)
	}
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if !oauthScopePattern.MatchString(scope) {
			return nil, fmt.Errorf("%w: invalid OAuth scope", ErrInvalidInput)
		}
		result = append(result, scope)
	}
	slices.Sort(result)
	return slices.Compact(result), nil
}

func oauthReservedScope(scope string) bool {
	return scope == "openid" || scope == "profile" || scope == "email" || scope == "offline_access"
}

func oauthReservedScopeDescription(scope string) string {
	switch scope {
	case "openid":
		return "Identify the signed-in user"
	case "profile":
		return "Read the user's basic profile"
	case "email":
		return "Read the user's primary email address"
	case "offline_access":
		return "Keep access when the user is not present"
	default:
		return scope
	}
}

func oauthScopeDefinition(definitions []OAuthScopeDefinition, name string) (OAuthScopeDefinition, bool) {
	for _, definition := range definitions {
		if definition.Name == name {
			return definition, true
		}
	}
	return OAuthScopeDefinition{}, false
}

func oauthClientMetadataHash(client OAuthClient) []byte {
	value := struct {
		ClientID, Name, ApplicationType, AuthMethod, JWKSURI, SectorIdentifier string
		RedirectURIs, GrantTypes, ResponseTypes, Scopes                        []string
		JWKS                                                                   json.RawMessage
	}{
		ClientID: client.ClientID, Name: client.Name, ApplicationType: string(client.ApplicationType),
		AuthMethod: string(client.TokenEndpointAuthMethod), JWKSURI: client.JWKSURI,
		SectorIdentifier: client.SectorIdentifier,
		RedirectURIs:     client.RedirectURIs, GrantTypes: client.GrantTypes,
		ResponseTypes: client.ResponseTypes, Scopes: client.Scopes, JWKS: client.JWKS,
	}
	payload, _ := json.Marshal(value)
	sum := sha256.Sum256(payload)
	return sum[:]
}

func oauthSectorIdentifier(redirects []string, oidc bool) (string, error) {
	sectors := make(map[string]struct{})
	for _, raw := range redirects {
		parsed, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("%w: invalid redirect URI", ErrInvalidInput)
		}
		sector := strings.ToLower(parsed.Hostname())
		if sector == "" {
			if oidc {
				return "", fmt.Errorf("%w: OIDC redirect URIs require a host for pairwise subjects", ErrInvalidInput)
			}
			continue
		}
		sectors[sector] = struct{}{}
	}
	if oidc && len(sectors) != 1 {
		return "", fmt.Errorf("%w: OIDC clients require redirect URIs in one sector", ErrInvalidInput)
	}
	for sector := range sectors {
		return sector, nil
	}
	return "", nil
}

func validPKCEChallenge(challenge string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(decoded) == sha256.Size && len(challenge) == 43
}

func freshAuthentication(now, authenticatedAt time.Time, maxAge time.Duration) bool {
	age := now.Sub(authenticatedAt)
	return age >= 0 && age <= maxAge
}

func publicOAuthClient(client OAuthClient) OAuthClient {
	result := cloneOAuthClient(client)
	result.SecretDigest = nil
	return result
}

func cloneOAuthIssuer(value OAuthIssuer) OAuthIssuer {
	value.CIMDAllowedOrigins = slices.Clone(value.CIMDAllowedOrigins)
	value.DisabledAt = cloneTime(value.DisabledAt)
	return value
}

func cloneOAuthResource(value OAuthProtectedResource) OAuthProtectedResource {
	value.Scopes = make([]OAuthScopeDefinition, len(value.Scopes))
	for index, scope := range value.Scopes {
		value.Scopes[index] = scope
		value.Scopes[index].Permissions = slices.Clone(scope.Permissions)
	}
	value.DisabledAt = cloneTime(value.DisabledAt)
	return value
}

func cloneOAuthClient(value OAuthClient) OAuthClient {
	value.RedirectURIs = slices.Clone(value.RedirectURIs)
	value.GrantTypes = slices.Clone(value.GrantTypes)
	value.ResponseTypes = slices.Clone(value.ResponseTypes)
	value.Scopes = slices.Clone(value.Scopes)
	value.JWKS = slices.Clone(value.JWKS)
	value.SecretDigest = slices.Clone(value.SecretDigest)
	value.MetadataHash = slices.Clone(value.MetadataHash)
	value.MetadataExpiresAt = cloneTime(value.MetadataExpiresAt)
	value.DisabledAt = cloneTime(value.DisabledAt)
	return value
}

func cloneOAuthInitialAccessToken(value OAuthInitialAccessToken) OAuthInitialAccessToken {
	value.Digest = slices.Clone(value.Digest)
	value.RevokedAt = cloneTime(value.RevokedAt)
	return value
}

func cloneOAuthGrant(value OAuthGrant) OAuthGrant {
	value.Scopes = slices.Clone(value.Scopes)
	value.MetadataHash = slices.Clone(value.MetadataHash)
	value.RevokedAt = cloneTime(value.RevokedAt)
	return value
}

func cloneOAuthAuthorizationCode(value OAuthAuthorizationCode) OAuthAuthorizationCode {
	value.Digest = slices.Clone(value.Digest)
	value.Scopes = slices.Clone(value.Scopes)
	value.UsedAt = cloneTime(value.UsedAt)
	return value
}

func cloneOAuthAccessToken(value OAuthAccessToken) OAuthAccessToken {
	value.Digest = slices.Clone(value.Digest)
	value.Scopes = slices.Clone(value.Scopes)
	value.RevokedAt = cloneTime(value.RevokedAt)
	return value
}

func cloneOAuthRefreshToken(value OAuthRefreshToken) OAuthRefreshToken {
	value.Digest = slices.Clone(value.Digest)
	value.Scopes = slices.Clone(value.Scopes)
	value.UsedAt = cloneTime(value.UsedAt)
	value.RevokedAt = cloneTime(value.RevokedAt)
	return value
}
