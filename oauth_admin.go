package credbound

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"iter"
	"slices"
)

// DisableOAuthIssuer disables an issuer so all its discovery, authorization
// and token operations are refused, atomically with the audit event. The
// actor needs admin settings write and an admin mutation (fresh AAL2, or a
// trusted local request); disabling an already disabled issuer is a no-op.
// Returns ErrNotSupported without the OAuth capability.
func (m *Manager) DisableOAuthIssuer(ctx context.Context, actor Authentication, request TrustedRequest, issuerID UUID) error {
	return m.setOAuthIssuerDisabled(ctx, actor, request, issuerID, true)
}

// EnableOAuthIssuer re-enables a disabled issuer under the same
// authorization as DisableOAuthIssuer.
func (m *Manager) EnableOAuthIssuer(ctx context.Context, actor Authentication, request TrustedRequest, issuerID UUID) error {
	return m.setOAuthIssuerDisabled(ctx, actor, request, issuerID, false)
}

func (m *Manager) setOAuthIssuerDisabled(ctx context.Context, actor Authentication, request TrustedRequest, issuerID UUID, disabled bool) (err error) {
	operation, action, name := "oauth.issuer.enable", "oauth.issuer.enable", EventOAuthIssuerEnabled
	if disabled {
		operation, action, name = "oauth.issuer.disable", "oauth.issuer.disable", EventOAuthIssuerDisabled
	}
	started := m.now()
	defer func() { m.observe(ctx, operation, started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return err
	}
	if err := m.AuthorizeAdmin(ctx, actor, PermissionSettingsWrite); err != nil {
		return err
	}
	if err := m.requireAdminMutation(ctx, actor, request, operation); err != nil {
		return err
	}
	if !validUUIDv7(issuerID) {
		return fmt.Errorf("%w: invalid OAuth issuer id", ErrInvalidInput)
	}
	issuer, err := store.OAuthIssuerByID(ctx, issuerID)
	if err != nil {
		return err
	}
	if (issuer.DisabledAt != nil) == disabled {
		return nil
	}
	audit, err := m.newAudit(ctx, actor.UserID, action, "oauth_issuer", issuerID.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return err
	}
	change, commit, err := m.newOAuthChange(name, operation, audit, OAuthClient{IssuerID: issuerID}, UUID{}, UUID{}, UUID{}, UUID{}, nil)
	if err != nil {
		return err
	}
	if err := store.SetOAuthIssuerDisabled(ctx, issuerID, disabled, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, operation, err)
	}
	m.emitOAuthChange(ctx, change)
	return nil
}

// DisableOAuthProtectedResource disables an MCP resource of the workspace so
// its bearer validation and metadata are refused, atomically with the audit
// event. The actor needs a fresh AAL2 step-up and the oauth.resource.manage
// permission in that workspace; a resource of another workspace fails with
// ErrForbidden.
func (m *Manager) DisableOAuthProtectedResource(ctx context.Context, actor Authentication, workspaceID UUID, resourceID UUID) error {
	return m.setOAuthProtectedResourceDisabled(ctx, actor, workspaceID, resourceID, true)
}

// EnableOAuthProtectedResource re-enables a disabled resource under the same
// authorization as DisableOAuthProtectedResource.
func (m *Manager) EnableOAuthProtectedResource(ctx context.Context, actor Authentication, workspaceID UUID, resourceID UUID) error {
	return m.setOAuthProtectedResourceDisabled(ctx, actor, workspaceID, resourceID, false)
}

func (m *Manager) setOAuthProtectedResourceDisabled(ctx context.Context, actor Authentication, workspaceID UUID, resourceID UUID, disabled bool) (err error) {
	operation, action, name := "oauth.resource.enable", "oauth.resource.enable", EventOAuthResourceEnabled
	if disabled {
		operation, action, name = "oauth.resource.disable", "oauth.resource.disable", EventOAuthResourceDisabled
	}
	started := m.now()
	defer func() { m.observe(ctx, operation, started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return err
	}
	if err := m.authorizeWorkspaceMutation(ctx, actor, workspaceID, PermissionOAuthResourceManage, operation); err != nil {
		return err
	}
	resource, err := store.OAuthProtectedResourceByID(ctx, resourceID)
	if err != nil {
		return err
	}
	if resource.WorkspaceID != workspaceID {
		return ErrForbidden
	}
	if (resource.DisabledAt != nil) == disabled {
		return nil
	}
	audit, err := m.newAudit(ctx, actor.UserID, action, "oauth_resource", resourceID.String(), workspaceID, AuditSucceeded, "")
	if err != nil {
		return err
	}
	change, commit, err := m.newOAuthChange(name, operation, audit, OAuthClient{IssuerID: resource.IssuerID}, UUID{}, UUID{}, resourceID, workspaceID, nil)
	if err != nil {
		return err
	}
	if err := store.SetOAuthProtectedResourceDisabled(ctx, resourceID, disabled, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, operation, err)
	}
	m.emitOAuthChange(ctx, change)
	return nil
}

// DisableOAuthClient disables a client record so authorization, token, and
// bearer-validation operations refuse it — already-issued access tokens stop
// authenticating immediately — atomically with the audit event. The actor needs
// admin settings write and an admin mutation (fresh AAL2, or a trusted local
// request); disabling an already disabled client is a no-op.
func (m *Manager) DisableOAuthClient(ctx context.Context, actor Authentication, request TrustedRequest, clientRecordID UUID) error {
	return m.setOAuthClientDisabled(ctx, actor, request, clientRecordID, true)
}

// EnableOAuthClient re-enables a disabled client under the same
// authorization as DisableOAuthClient.
func (m *Manager) EnableOAuthClient(ctx context.Context, actor Authentication, request TrustedRequest, clientRecordID UUID) error {
	return m.setOAuthClientDisabled(ctx, actor, request, clientRecordID, false)
}

func (m *Manager) setOAuthClientDisabled(ctx context.Context, actor Authentication, request TrustedRequest, clientRecordID UUID, disabled bool) (err error) {
	operation, action := "oauth.client.enable", "oauth.client.enable"
	name := EventOAuthClientEnabled
	if disabled {
		operation, action = "oauth.client.disable", "oauth.client.disable"
		name = EventOAuthClientDisabled
	}
	started := m.now()
	defer func() { m.observe(ctx, operation, started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return err
	}
	if err := m.AuthorizeAdmin(ctx, actor, PermissionSettingsWrite); err != nil {
		return err
	}
	if err := m.requireAdminMutation(ctx, actor, request, operation); err != nil {
		return err
	}
	if !validUUIDv7(clientRecordID) {
		return fmt.Errorf("%w: invalid OAuth client id", ErrInvalidInput)
	}
	client, err := store.OAuthClientByID(ctx, clientRecordID)
	if err != nil {
		return err
	}
	if (client.DisabledAt != nil) == disabled {
		return nil
	}
	audit, err := m.newAudit(ctx, actor.UserID, action, "oauth_client", clientRecordID.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return err
	}
	change, commit, err := m.newOAuthChange(name, operation, audit, client, UUID{}, UUID{}, UUID{}, UUID{}, client.Scopes)
	if err != nil {
		return err
	}
	if err := store.SetOAuthClientDisabled(ctx, clientRecordID, disabled, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, operation, err)
	}
	m.emitOAuthChange(ctx, change)
	return nil
}

// RotateOAuthClientSecret replaces the secret of a pre-registered or DCR
// client that authenticates with client_secret_basic and returns the new
// secret exactly once; the previous secret stops authenticating immediately.
// The client keeps its client_id, so deployed configurations only change the
// secret, and rotation works on a disabled client, so the compromise runbook
// — disable, rotate, re-enable — has no window where the old secret is live.
// The actor needs admin settings write and an admin mutation (fresh AAL2, or
// a trusted local request). A CIMD client fails with ErrConflict (its
// credentials follow its published metadata) and a client without
// client_secret_basic with ErrInvalidInput. Returns ErrNotSupported without
// the OAuth capability.
func (m *Manager) RotateOAuthClientSecret(ctx context.Context, actor Authentication, request TrustedRequest, clientRecordID UUID) (_ IssuedOAuthClient, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.client.rotate_secret", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	if err := m.AuthorizeAdmin(ctx, actor, PermissionSettingsWrite); err != nil {
		return IssuedOAuthClient{}, err
	}
	if err := m.requireAdminMutation(ctx, actor, request, "oauth.client.rotate_secret"); err != nil {
		return IssuedOAuthClient{}, err
	}
	if !validUUIDv7(clientRecordID) {
		return IssuedOAuthClient{}, fmt.Errorf("%w: invalid OAuth client id", ErrInvalidInput)
	}
	client, err := store.OAuthClientByID(ctx, clientRecordID)
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	if client.Source == OAuthClientCIMD {
		return IssuedOAuthClient{}, fmt.Errorf("%w: a CIMD client's credentials follow its published metadata", ErrConflict)
	}
	if client.TokenEndpointAuthMethod != OAuthAuthClientSecretBasic {
		return IssuedOAuthClient{}, fmt.Errorf("%w: client does not authenticate with client_secret_basic", ErrInvalidInput)
	}
	secret, err := randomBytes(m.random, 32)
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	rawSecret := "cbos_" + base64.RawURLEncoding.EncodeToString(secret)
	secretDigest := m.oauthDigest("client-secret", rawSecret)
	audit, err := m.newAudit(ctx, actor.UserID, "oauth.client.rotate_secret", "oauth_client", clientRecordID.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	change, commit, err := m.newOAuthChange(EventOAuthClientSecretRotated, "oauth.client.rotate_secret", audit, client, UUID{}, UUID{}, UUID{}, UUID{}, client.Scopes)
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	now := m.now()
	if err := store.RotateOAuthClientCredentials(ctx, clientRecordID, secretDigest, nil, nil, now, commit); err != nil {
		return IssuedOAuthClient{}, m.mapStoreError(ctx, "oauth.client.rotate_secret", err)
	}
	m.emitOAuthChange(ctx, change)
	client.SecretDigest = secretDigest
	client.UpdatedAt = now
	return IssuedOAuthClient{Client: publicOAuthClient(client), ClientSecret: rawSecret}, nil
}

// ReplaceOAuthClientJWKS atomically replaces the inline JWKS of a
// pre-registered or DCR private_key_jwt client, so a compromised signing key
// rotates without re-registering the client. A client publishing a jwks_uri
// rotates by republishing its own document instead and fails here with
// ErrConflict, like a CIMD client, whose keys follow its published metadata.
// Same authorization and capability requirements as RotateOAuthClientSecret.
func (m *Manager) ReplaceOAuthClientJWKS(ctx context.Context, actor Authentication, request TrustedRequest, clientRecordID UUID, jwks []byte) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.client.replace_jwks", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return err
	}
	if err := m.AuthorizeAdmin(ctx, actor, PermissionSettingsWrite); err != nil {
		return err
	}
	if err := m.requireAdminMutation(ctx, actor, request, "oauth.client.replace_jwks"); err != nil {
		return err
	}
	if !validUUIDv7(clientRecordID) {
		return fmt.Errorf("%w: invalid OAuth client id", ErrInvalidInput)
	}
	if len(jwks) == 0 || len(jwks) > 32*1024 || !json.Valid(jwks) {
		return fmt.Errorf("%w: invalid jwks", ErrInvalidInput)
	}
	client, err := store.OAuthClientByID(ctx, clientRecordID)
	if err != nil {
		return err
	}
	if client.Source == OAuthClientCIMD {
		return fmt.Errorf("%w: a CIMD client's credentials follow its published metadata", ErrConflict)
	}
	if client.TokenEndpointAuthMethod != OAuthAuthPrivateKeyJWT {
		return fmt.Errorf("%w: client does not authenticate with private_key_jwt", ErrInvalidInput)
	}
	if len(client.JWKS) == 0 {
		return fmt.Errorf("%w: client publishes a jwks_uri and rotates keys there", ErrConflict)
	}
	updated := client
	updated.JWKS = slices.Clone(jwks)
	metadataHash := oauthClientMetadataHash(updated)
	audit, err := m.newAudit(ctx, actor.UserID, "oauth.client.replace_jwks", "oauth_client", clientRecordID.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return err
	}
	change, commit, err := m.newOAuthChange(EventOAuthClientJWKSReplaced, "oauth.client.replace_jwks", audit, client, UUID{}, UUID{}, UUID{}, UUID{}, client.Scopes)
	if err != nil {
		return err
	}
	if err := store.RotateOAuthClientCredentials(ctx, clientRecordID, nil, updated.JWKS, metadataHash, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, "oauth.client.replace_jwks", err)
	}
	m.emitOAuthChange(ctx, change)
	return nil
}

// RevokeOAuthGrant revokes a delegation and its tokens, atomically with the
// audit event. The grant's own user needs a fresh AAL2 step-up; revoking
// another user's grant requires the oauth.resource.manage permission in the
// grant's workspace with a fresh AAL2 step-up.
func (m *Manager) RevokeOAuthGrant(ctx context.Context, actor Authentication, grantID UUID) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "oauth.grant.revoke", started, err) }()
	store, _, err := m.requireOAuth()
	if err != nil {
		return err
	}
	if !validUUIDv7(grantID) {
		return fmt.Errorf("%w: invalid OAuth grant id", ErrInvalidInput)
	}
	grant, err := store.OAuthGrant(ctx, grantID)
	if err != nil {
		return err
	}
	if grant.UserID == actor.UserID {
		if err := m.requireStepUp(ctx, actor, "oauth.grant.revoke"); err != nil {
			return err
		}
	} else if err := m.authorizeWorkspaceMutation(ctx, actor, grant.WorkspaceID, PermissionOAuthResourceManage, "oauth.grant.revoke"); err != nil {
		return err
	}
	client, err := store.OAuthClientByID(ctx, grant.ClientRecordID)
	if err != nil {
		return err
	}
	audit, err := m.newAudit(ctx, actor.UserID, "oauth.consent.revoke", "oauth_grant", grantID.String(), grant.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return err
	}
	change, commit, err := m.newOAuthChange(EventOAuthConsentRevoked, "oauth.grant.revoke", audit, client, grantID, UUID{}, grant.ResourceID, grant.WorkspaceID, grant.Scopes)
	if err != nil {
		return err
	}
	if err := store.RevokeOAuthGrant(ctx, grantID, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, "oauth.grant.revoke", err)
	}
	m.emitOAuthChange(ctx, change)
	return nil
}

// OAuthIssuers streams every registered issuer. It requires admin settings
// read; ErrNotSupported without the OAuth capability.
func (m *Manager) OAuthIssuers(ctx context.Context, actor Authentication, page PageRequest) iter.Seq2[PageEvent[OAuthIssuer], error] {
	store, _, err := m.requireOAuth()
	if err != nil {
		return errorSeq[PageEvent[OAuthIssuer]](err)
	}
	if err := m.AuthorizeAdmin(ctx, actor, PermissionSettingsRead); err != nil {
		return errorSeq[PageEvent[OAuthIssuer]](err)
	}
	page, err = normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[OAuthIssuer]](err)
	}
	return store.OAuthIssuers(ctx, page)
}

// OAuthProtectedResources streams the MCP resources of a workspace. The
// actor needs the oauth.resource.manage permission in that workspace.
func (m *Manager) OAuthProtectedResources(ctx context.Context, actor Authentication, workspaceID UUID, page PageRequest) iter.Seq2[PageEvent[OAuthProtectedResource], error] {
	store, _, err := m.requireOAuth()
	if err != nil {
		return errorSeq[PageEvent[OAuthProtectedResource]](err)
	}
	if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionOAuthResourceManage); err != nil {
		return errorSeq[PageEvent[OAuthProtectedResource]](err)
	}
	page, err = normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[OAuthProtectedResource]](err)
	}
	return store.OAuthProtectedResources(ctx, workspaceID, page)
}

// OAuthClients streams the client records of an issuer. It requires admin
// settings read.
func (m *Manager) OAuthClients(ctx context.Context, actor Authentication, issuerID UUID, page PageRequest) iter.Seq2[PageEvent[OAuthClient], error] {
	store, _, err := m.requireOAuth()
	if err != nil {
		return errorSeq[PageEvent[OAuthClient]](err)
	}
	if err := m.AuthorizeAdmin(ctx, actor, PermissionSettingsRead); err != nil {
		return errorSeq[PageEvent[OAuthClient]](err)
	}
	if !validUUIDv7(issuerID) {
		return errorSeq[PageEvent[OAuthClient]](fmt.Errorf("%w: invalid OAuth issuer id", ErrInvalidInput))
	}
	page, err = normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[OAuthClient]](err)
	}
	return store.OAuthClients(ctx, issuerID, page)
}

// OAuthGrants streams delegations. With a workspaceID it lists the
// workspace's grants and requires the oauth.resource.manage permission
// there; with an empty workspaceID it lists the actor's own grants and
// requires a recent interactive authentication.
func (m *Manager) OAuthGrants(ctx context.Context, actor Authentication, workspaceID UUID, page PageRequest) iter.Seq2[PageEvent[OAuthGrant], error] {
	store, _, err := m.requireOAuth()
	if err != nil {
		return errorSeq[PageEvent[OAuthGrant]](err)
	}
	userID := actor.UserID
	if workspaceID != (UUID{}) {
		if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionOAuthResourceManage); err != nil {
			return errorSeq[PageEvent[OAuthGrant]](err)
		}
		userID = UUID{}
	} else if err := m.requireRecentInteractive(ctx, actor); err != nil {
		return errorSeq[PageEvent[OAuthGrant]](err)
	}
	page, err = normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[OAuthGrant]](err)
	}
	return store.OAuthGrants(ctx, userID, workspaceID, page)
}
