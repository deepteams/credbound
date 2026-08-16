package credbound

import (
	"context"
	"fmt"
	"iter"
)

func (m *Manager) DisableOAuthIssuer(ctx context.Context, actor Authentication, request TrustedRequest, issuerID string) error {
	return m.setOAuthIssuerDisabled(ctx, actor, request, issuerID, true)
}

func (m *Manager) EnableOAuthIssuer(ctx context.Context, actor Authentication, request TrustedRequest, issuerID string) error {
	return m.setOAuthIssuerDisabled(ctx, actor, request, issuerID, false)
}

func (m *Manager) setOAuthIssuerDisabled(ctx context.Context, actor Authentication, request TrustedRequest, issuerID string, disabled bool) (err error) {
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
	audit, err := m.newAudit(actor.UserID, action, "oauth_issuer", issuerID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	change, commit, err := m.newOAuthChange(name, operation, audit, OAuthClient{IssuerID: issuerID}, "", "", "", "", nil)
	if err != nil {
		return err
	}
	if err := store.SetOAuthIssuerDisabled(ctx, issuerID, disabled, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, operation, err)
	}
	m.emitOAuthChange(ctx, change)
	return nil
}

func (m *Manager) DisableOAuthProtectedResource(ctx context.Context, actor Authentication, workspaceID, resourceID string) error {
	return m.setOAuthProtectedResourceDisabled(ctx, actor, workspaceID, resourceID, true)
}

func (m *Manager) EnableOAuthProtectedResource(ctx context.Context, actor Authentication, workspaceID, resourceID string) error {
	return m.setOAuthProtectedResourceDisabled(ctx, actor, workspaceID, resourceID, false)
}

func (m *Manager) setOAuthProtectedResourceDisabled(ctx context.Context, actor Authentication, workspaceID, resourceID string, disabled bool) (err error) {
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
	audit, err := m.newAudit(actor.UserID, action, "oauth_resource", resourceID, workspaceID, AuditSucceeded, "")
	if err != nil {
		return err
	}
	change, commit, err := m.newOAuthChange(name, operation, audit, OAuthClient{IssuerID: resource.IssuerID}, "", "", resourceID, workspaceID, nil)
	if err != nil {
		return err
	}
	if err := store.SetOAuthProtectedResourceDisabled(ctx, resourceID, disabled, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, operation, err)
	}
	m.emitOAuthChange(ctx, change)
	return nil
}

func (m *Manager) DisableOAuthClient(ctx context.Context, actor Authentication, request TrustedRequest, clientID string) error {
	return m.setOAuthClientDisabled(ctx, actor, request, clientID, true)
}

func (m *Manager) EnableOAuthClient(ctx context.Context, actor Authentication, request TrustedRequest, clientID string) error {
	return m.setOAuthClientDisabled(ctx, actor, request, clientID, false)
}

func (m *Manager) setOAuthClientDisabled(ctx context.Context, actor Authentication, request TrustedRequest, clientID string, disabled bool) (err error) {
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
	if !validUUIDv7(clientID) {
		return fmt.Errorf("%w: invalid OAuth client id", ErrInvalidInput)
	}
	client, err := store.OAuthClientByID(ctx, clientID)
	if err != nil {
		return err
	}
	if (client.DisabledAt != nil) == disabled {
		return nil
	}
	audit, err := m.newAudit(actor.UserID, action, "oauth_client", clientID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	change, commit, err := m.newOAuthChange(name, operation, audit, client, "", "", "", "", client.Scopes)
	if err != nil {
		return err
	}
	if err := store.SetOAuthClientDisabled(ctx, clientID, disabled, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, operation, err)
	}
	m.emitOAuthChange(ctx, change)
	return nil
}

func (m *Manager) RevokeOAuthGrant(ctx context.Context, actor Authentication, grantID string) (err error) {
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
	audit, err := m.newAudit(actor.UserID, "oauth.consent.revoke", "oauth_grant", grantID, grant.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return err
	}
	change, commit, err := m.newOAuthChange(EventOAuthConsentRevoked, "oauth.grant.revoke", audit, client, grantID, "", grant.ResourceID, grant.WorkspaceID, grant.Scopes)
	if err != nil {
		return err
	}
	if err := store.RevokeOAuthGrant(ctx, grantID, m.now(), commit); err != nil {
		return m.mapStoreError(ctx, "oauth.grant.revoke", err)
	}
	m.emitOAuthChange(ctx, change)
	return nil
}

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

func (m *Manager) OAuthProtectedResources(ctx context.Context, actor Authentication, workspaceID string, page PageRequest) iter.Seq2[PageEvent[OAuthProtectedResource], error] {
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

func (m *Manager) OAuthClients(ctx context.Context, actor Authentication, issuerID string, page PageRequest) iter.Seq2[PageEvent[OAuthClient], error] {
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

func (m *Manager) OAuthGrants(ctx context.Context, actor Authentication, workspaceID string, page PageRequest) iter.Seq2[PageEvent[OAuthGrant], error] {
	store, _, err := m.requireOAuth()
	if err != nil {
		return errorSeq[PageEvent[OAuthGrant]](err)
	}
	userID := actor.UserID
	if workspaceID != "" {
		if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionOAuthResourceManage); err != nil {
			return errorSeq[PageEvent[OAuthGrant]](err)
		}
		userID = ""
	} else if err := m.requireRecentInteractive(ctx, actor); err != nil {
		return errorSeq[PageEvent[OAuthGrant]](err)
	}
	page, err = normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[OAuthGrant]](err)
	}
	return store.OAuthGrants(ctx, userID, workspaceID, page)
}
