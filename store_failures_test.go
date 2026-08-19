package credbound_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
)

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

type oauthFaultStore struct {
	*memory.Store
	fail string
	err  error
}

func (s *oauthFaultStore) failure(name string) error {
	if s.fail == name {
		return s.err
	}
	return nil
}

func (s *oauthFaultStore) UserByID(ctx context.Context, id credbound.UUID) (credbound.User, error) {
	if err := s.failure("user.lookup"); err != nil {
		return credbound.User{}, err
	}
	return s.Store.UserByID(ctx, id)
}

func (s *oauthFaultStore) CreateWorkspace(ctx context.Context, workspace credbound.Workspace, membership credbound.Membership, commit credbound.Commit) error {
	if err := s.failure("workspace.create"); err != nil {
		return err
	}
	return s.Store.CreateWorkspace(ctx, workspace, membership, commit)
}

func (s *oauthFaultStore) UpdateWorkspace(ctx context.Context, workspace credbound.Workspace, commit credbound.Commit) error {
	if err := s.failure("workspace.update"); err != nil {
		return err
	}
	return s.Store.UpdateWorkspace(ctx, workspace, commit)
}

func (s *oauthFaultStore) SetWorkspaceDisabled(ctx context.Context, id credbound.UUID, disabled bool, at time.Time, commit credbound.Commit) error {
	if err := s.failure("workspace.disable"); err != nil {
		return err
	}
	return s.Store.SetWorkspaceDisabled(ctx, id, disabled, at, commit)
}

func (s *oauthFaultStore) SetUserDisabled(ctx context.Context, id credbound.UUID, disabled bool, at time.Time, commit credbound.Commit) error {
	if err := s.failure("user.disable"); err != nil {
		return err
	}
	return s.Store.SetUserDisabled(ctx, id, disabled, at, commit)
}

func (s *oauthFaultStore) UpsertMembership(ctx context.Context, membership credbound.Membership, commit credbound.Commit) error {
	if err := s.failure("membership.upsert"); err != nil {
		return err
	}
	return s.Store.UpsertMembership(ctx, membership, commit)
}

func (s *oauthFaultStore) RemoveMembership(ctx context.Context, workspaceID, userID credbound.UUID, at time.Time, commit credbound.Commit) error {
	if err := s.failure("membership.remove"); err != nil {
		return err
	}
	return s.Store.RemoveMembership(ctx, workspaceID, userID, at, commit)
}

func (s *oauthFaultStore) CreateOAuthIssuer(ctx context.Context, issuer credbound.OAuthIssuer, commit credbound.Commit) error {
	if err := s.failure("issuer.create"); err != nil {
		return err
	}
	return s.Store.CreateOAuthIssuer(ctx, issuer, commit)
}

func (s *oauthFaultStore) UpdateOAuthIssuer(ctx context.Context, issuer credbound.OAuthIssuer, commit credbound.Commit) error {
	if err := s.failure("issuer.update"); err != nil {
		return err
	}
	return s.Store.UpdateOAuthIssuer(ctx, issuer, commit)
}

func (s *oauthFaultStore) OAuthIssuerByID(ctx context.Context, id credbound.UUID) (credbound.OAuthIssuer, error) {
	if err := s.failure("issuer.lookup"); err != nil {
		return credbound.OAuthIssuer{}, err
	}
	return s.Store.OAuthIssuerByID(ctx, id)
}

func (s *oauthFaultStore) OAuthIssuerByURL(ctx context.Context, issuer string) (credbound.OAuthIssuer, error) {
	if err := s.failure("issuer.url"); err != nil {
		return credbound.OAuthIssuer{}, err
	}
	return s.Store.OAuthIssuerByURL(ctx, issuer)
}

func (s *oauthFaultStore) SetOAuthIssuerDisabled(ctx context.Context, id credbound.UUID, disabled bool, at time.Time, commit credbound.Commit) error {
	if err := s.failure("issuer.disable"); err != nil {
		return err
	}
	return s.Store.SetOAuthIssuerDisabled(ctx, id, disabled, at, commit)
}

func (s *oauthFaultStore) CreateOAuthProtectedResource(ctx context.Context, resource credbound.OAuthProtectedResource, commit credbound.Commit) error {
	if err := s.failure("resource.create"); err != nil {
		return err
	}
	return s.Store.CreateOAuthProtectedResource(ctx, resource, commit)
}

func (s *oauthFaultStore) OAuthProtectedResourceByID(ctx context.Context, id credbound.UUID) (credbound.OAuthProtectedResource, error) {
	if err := s.failure("resource.lookup"); err != nil {
		return credbound.OAuthProtectedResource{}, err
	}
	return s.Store.OAuthProtectedResourceByID(ctx, id)
}

func (s *oauthFaultStore) OAuthProtectedResourceByURI(ctx context.Context, resource string) (credbound.OAuthProtectedResource, error) {
	if err := s.failure("resource.uri"); err != nil {
		return credbound.OAuthProtectedResource{}, err
	}
	return s.Store.OAuthProtectedResourceByURI(ctx, resource)
}

func (s *oauthFaultStore) SetOAuthProtectedResourceDisabled(ctx context.Context, id credbound.UUID, disabled bool, at time.Time, commit credbound.Commit) error {
	if err := s.failure("resource.disable"); err != nil {
		return err
	}
	return s.Store.SetOAuthProtectedResourceDisabled(ctx, id, disabled, at, commit)
}

func (s *oauthFaultStore) CreateOAuthClient(ctx context.Context, client credbound.OAuthClient, initialID credbound.UUID, at time.Time, commit credbound.Commit) error {
	if err := s.failure("client.create"); err != nil {
		return err
	}
	return s.Store.CreateOAuthClient(ctx, client, initialID, at, commit)
}

func (s *oauthFaultStore) OAuthClientByID(ctx context.Context, id credbound.UUID) (credbound.OAuthClient, error) {
	if err := s.failure("client.lookup"); err != nil {
		return credbound.OAuthClient{}, err
	}
	return s.Store.OAuthClientByID(ctx, id)
}

func (s *oauthFaultStore) OAuthClientByClientID(ctx context.Context, issuerID credbound.UUID, clientID string) (credbound.OAuthClient, error) {
	if err := s.failure("client.key"); err != nil {
		return credbound.OAuthClient{}, err
	}
	return s.Store.OAuthClientByClientID(ctx, issuerID, clientID)
}

func (s *oauthFaultStore) SetOAuthClientDisabled(ctx context.Context, id credbound.UUID, disabled bool, at time.Time, commit credbound.Commit) error {
	if err := s.failure("client.disable"); err != nil {
		return err
	}
	return s.Store.SetOAuthClientDisabled(ctx, id, disabled, at, commit)
}

func (s *oauthFaultStore) CreateOAuthInitialAccessToken(ctx context.Context, token credbound.OAuthInitialAccessToken, commit credbound.Commit) error {
	if err := s.failure("initial.create"); err != nil {
		return err
	}
	return s.Store.CreateOAuthInitialAccessToken(ctx, token, commit)
}

func (s *oauthFaultStore) RevokeOAuthInitialAccessToken(ctx context.Context, id credbound.UUID, at time.Time, commit credbound.Commit) error {
	if err := s.failure("initial.revoke"); err != nil {
		return err
	}
	return s.Store.RevokeOAuthInitialAccessToken(ctx, id, at, commit)
}

func (s *oauthFaultStore) CreateOAuthGrantAndCode(ctx context.Context, grant credbound.OAuthGrant, code credbound.OAuthAuthorizationCode, commit credbound.Commit) error {
	if err := s.failure("grant.create"); err != nil {
		return err
	}
	return s.Store.CreateOAuthGrantAndCode(ctx, grant, code, commit)
}

func (s *oauthFaultStore) OAuthGrant(ctx context.Context, id credbound.UUID) (credbound.OAuthGrant, error) {
	if err := s.failure("grant.lookup"); err != nil {
		return credbound.OAuthGrant{}, err
	}
	return s.Store.OAuthGrant(ctx, id)
}

func (s *oauthFaultStore) RevokeOAuthGrant(ctx context.Context, id credbound.UUID, at time.Time, commit credbound.Commit) error {
	if err := s.failure("grant.revoke"); err != nil {
		return err
	}
	return s.Store.RevokeOAuthGrant(ctx, id, at, commit)
}

func (s *oauthFaultStore) OAuthAuthorizationCodeByPrefix(ctx context.Context, prefix string) (credbound.OAuthAuthorizationCode, error) {
	if err := s.failure("code.lookup"); err != nil {
		return credbound.OAuthAuthorizationCode{}, err
	}
	return s.Store.OAuthAuthorizationCodeByPrefix(ctx, prefix)
}

func (s *oauthFaultStore) ConsumeOAuthAuthorizationCode(ctx context.Context, id credbound.UUID, at time.Time, access credbound.OAuthAccessToken, refresh *credbound.OAuthRefreshToken, commit credbound.Commit) error {
	if err := s.failure("code.consume"); err != nil {
		return err
	}
	return s.Store.ConsumeOAuthAuthorizationCode(ctx, id, at, access, refresh, commit)
}

func (s *oauthFaultStore) OAuthAccessTokenByPrefix(ctx context.Context, prefix string) (credbound.OAuthAccessToken, error) {
	if err := s.failure("access.lookup"); err != nil {
		return credbound.OAuthAccessToken{}, err
	}
	return s.Store.OAuthAccessTokenByPrefix(ctx, prefix)
}

func (s *oauthFaultStore) OAuthRefreshTokenByPrefix(ctx context.Context, prefix string) (credbound.OAuthRefreshToken, error) {
	if err := s.failure("refresh.lookup"); err != nil {
		return credbound.OAuthRefreshToken{}, err
	}
	return s.Store.OAuthRefreshTokenByPrefix(ctx, prefix)
}

func (s *oauthFaultStore) RotateOAuthRefreshToken(ctx context.Context, id credbound.UUID, at time.Time, access credbound.OAuthAccessToken, refresh credbound.OAuthRefreshToken, commit credbound.Commit) error {
	if err := s.failure("refresh.rotate"); err != nil {
		return err
	}
	return s.Store.RotateOAuthRefreshToken(ctx, id, at, access, refresh, commit)
}

func (s *oauthFaultStore) RevokeOAuthAccessToken(ctx context.Context, id credbound.UUID, at time.Time, commit credbound.Commit) error {
	if err := s.failure("access.revoke"); err != nil {
		return err
	}
	return s.Store.RevokeOAuthAccessToken(ctx, id, at, commit)
}

func (s *oauthFaultStore) RevokeOAuthRefreshFamily(ctx context.Context, id credbound.UUID, at time.Time, commit credbound.Commit) error {
	if err := s.failure("family.revoke"); err != nil {
		return err
	}
	return s.Store.RevokeOAuthRefreshFamily(ctx, id, at, commit)
}

func TestManagersPropagateStoreFailures(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("storage unavailable")
	store := &oauthFaultStore{Store: memory.New(), err: boom}
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	manager, err := credbound.New(credbound.Config{
		Store: store, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return now }, Random: &counterReader{next: 1},
		OAuth: &credbound.OAuthConfig{Pepper: bytesOf(4, 32), OIDCSigner: fakeOIDCSigner{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	actor, workspace, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	actor = aal2(actor.UserID, now)
	trusted := credbound.TrustedRequest{Local: true}
	issuer, err := manager.CreateOAuthIssuer(ctx, actor, trusted, credbound.CreateOAuthIssuerInput{
		Issuer: "https://auth.example.com", DCRMode: credbound.OAuthDCRProtected,
	})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := manager.CreateOAuthProtectedResource(ctx, actor, workspace.ID, credbound.CreateOAuthProtectedResourceInput{
		IssuerID: issuer.ID, Resource: "https://mcp.example.com",
		Scopes: []credbound.OAuthScopeDefinition{{Name: "read", Description: "Read", Permissions: []credbound.WorkspacePermission{credbound.PermissionWorkspaceAccess}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := manager.PreRegisterOAuthClient(ctx, actor, trusted, issuer.ID, credbound.OAuthClientRegistrationInput{
		Name: "Client", ApplicationType: credbound.OAuthApplicationWeb, RedirectURIs: []string{"https://client.example.com/callback"},
		GrantTypes: []string{"authorization_code", "refresh_token"}, Scopes: []string{"read", "offline_access"},
	})
	if err != nil {
		t.Fatal(err)
	}

	assertFailure := func(name string, call func() error) {
		t.Helper()
		store.fail = name
		if err := call(); !errors.Is(err, boom) {
			t.Fatalf("%s = %v", name, err)
		}
		store.fail = ""
	}
	assertMapped := func(name string, target error, call func() error) {
		t.Helper()
		store.fail = name
		if err := call(); !errors.Is(err, target) {
			t.Fatalf("%s = %v, want %v", name, err, target)
		}
		store.fail = ""
	}
	store.fail = "user.lookup"
	if _, err := manager.CreateWorkspace(ctx, actor, credbound.CreateWorkspaceInput{Name: "Other"}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("user.lookup = %v", err)
	}
	store.fail = ""
	assertFailure("workspace.create", func() error {
		_, err := manager.CreateWorkspace(ctx, actor, credbound.CreateWorkspaceInput{Name: "Other"})
		return err
	})
	assertFailure("workspace.update", func() error {
		_, err := manager.UpdateWorkspace(ctx, actor, workspace.ID, credbound.UpdateWorkspaceInput{Name: "Renamed"})
		return err
	})
	assertFailure("workspace.disable", func() error { return manager.DisableWorkspace(ctx, actor, workspace.ID) })
	assertFailure("user.disable", func() error { return manager.DisableUser(ctx, actor, trusted, actor.UserID) })
	assertFailure("membership.upsert", func() error {
		_, err := manager.SetMembershipStatus(ctx, actor, workspace.ID, actor.UserID, credbound.MembershipSuspended)
		return err
	})

	assertFailure("issuer.create", func() error {
		_, err := manager.CreateOAuthIssuer(ctx, actor, trusted, credbound.CreateOAuthIssuerInput{Issuer: "https://other-auth.example.com"})
		return err
	})
	assertFailure("issuer.lookup", func() error {
		_, err := manager.UpdateOAuthIssuer(ctx, actor, trusted, issuer.ID, credbound.UpdateOAuthIssuerInput{})
		return err
	})
	assertFailure("issuer.update", func() error {
		_, err := manager.UpdateOAuthIssuer(ctx, actor, trusted, issuer.ID, credbound.UpdateOAuthIssuerInput{})
		return err
	})
	assertFailure("issuer.disable", func() error { return manager.DisableOAuthIssuer(ctx, actor, trusted, issuer.ID) })
	assertFailure("resource.create", func() error {
		_, err := manager.CreateOAuthProtectedResource(ctx, actor, workspace.ID, credbound.CreateOAuthProtectedResourceInput{
			IssuerID: issuer.ID, Resource: "https://other-mcp.example.com",
			Scopes: []credbound.OAuthScopeDefinition{{Name: "read", Description: "Read", Permissions: []credbound.WorkspacePermission{credbound.PermissionWorkspaceAccess}}},
		})
		return err
	})
	assertFailure("resource.lookup", func() error { return manager.DisableOAuthProtectedResource(ctx, actor, workspace.ID, resource.ID) })
	assertFailure("resource.disable", func() error { return manager.DisableOAuthProtectedResource(ctx, actor, workspace.ID, resource.ID) })
	assertFailure("client.create", func() error {
		_, err := manager.PreRegisterOAuthClient(ctx, actor, trusted, issuer.ID, credbound.OAuthClientRegistrationInput{
			Name: "Other", ApplicationType: credbound.OAuthApplicationWeb, RedirectURIs: []string{"https://other.example.com/callback"}, Scopes: []string{"read"},
		})
		return err
	})
	assertFailure("client.lookup", func() error { return manager.DisableOAuthClient(ctx, actor, trusted, client.Client.ID) })
	assertFailure("client.disable", func() error { return manager.DisableOAuthClient(ctx, actor, trusted, client.Client.ID) })
	assertMapped("issuer.url", credbound.ErrNotFound, func() error {
		_, err := manager.OAuthAuthorizationServerMetadata(ctx, issuer.Issuer)
		return err
	})
	assertMapped("resource.uri", credbound.ErrNotFound, func() error {
		_, err := manager.OAuthProtectedResourceMetadata(ctx, resource.Resource)
		return err
	})
	assertMapped("issuer.lookup", credbound.ErrNotFound, func() error {
		_, err := manager.OAuthProtectedResourceMetadata(ctx, resource.Resource)
		return err
	})
	assertMapped("issuer.url", credbound.ErrNotSupported, func() error {
		_, err := manager.OAuthJWKS(ctx, issuer.Issuer)
		return err
	})
	assertMapped("issuer.url", credbound.ErrNotSupported, func() error {
		_, err := manager.OAuthUserInfo(ctx, issuer.Issuer, "00000000-0000-4000-8000-000000000000")
		return err
	})
	assertFailure("initial.create", func() error {
		_, err := manager.CreateOAuthInitialAccessToken(ctx, actor, trusted, issuer.ID, credbound.CreateOAuthInitialAccessTokenInput{ExpiresAt: now.Add(time.Hour)})
		return err
	})
	assertFailure("initial.revoke", func() error { return manager.RevokeOAuthInitialAccessToken(ctx, actor, trusted, client.Client.ID) })

	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	consent, err := manager.BeginOAuthAuthorization(ctx, actor, credbound.BeginOAuthAuthorizationInput{
		Issuer: issuer.Issuer, ClientID: client.Client.ClientID, RedirectURI: client.Client.RedirectURIs[0], Resource: resource.Resource,
		Scopes: []string{"read", "offline_access"}, State: "state", CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertFailure("grant.create", func() error {
		_, err := manager.CompleteOAuthAuthorization(ctx, actor, consent.Continuation, true)
		return err
	})
	result, err := manager.CompleteOAuthAuthorization(ctx, actor, consent.Continuation, true)
	if err != nil {
		t.Fatal(err)
	}
	grants := collectLifecyclePage(t, manager.OAuthGrants(ctx, actor, credbound.UUID{}, credbound.PageRequest{}))
	if len(grants) != 1 || result.Code == "" {
		t.Fatalf("grant setup = %#v, %#v", grants, result)
	}
	assertFailure("grant.lookup", func() error { return manager.RevokeOAuthGrant(ctx, actor, grants[0].ID) })
	assertFailure("client.lookup", func() error { return manager.RevokeOAuthGrant(ctx, actor, grants[0].ID) })
	assertFailure("grant.revoke", func() error { return manager.RevokeOAuthGrant(ctx, actor, grants[0].ID) })

	exchange := credbound.ExchangeOAuthAuthorizationCodeInput{
		Issuer: issuer.Issuer, ClientID: client.Client.ClientID, Code: result.Code,
		RedirectURI: client.Client.RedirectURIs[0], CodeVerifier: verifier, Resource: resource.Resource,
	}
	assertMapped("issuer.url", credbound.ErrInvalidCredentials, func() error { _, err := manager.ExchangeOAuthAuthorizationCode(ctx, exchange); return err })
	assertMapped("client.key", credbound.ErrInvalidCredentials, func() error { _, err := manager.ExchangeOAuthAuthorizationCode(ctx, exchange); return err })
	assertMapped("code.lookup", credbound.ErrInvalidCredentials, func() error { _, err := manager.ExchangeOAuthAuthorizationCode(ctx, exchange); return err })
	assertFailure("code.consume", func() error { _, err := manager.ExchangeOAuthAuthorizationCode(ctx, exchange); return err })
	tokens, err := manager.ExchangeOAuthAuthorizationCode(ctx, exchange)
	if err != nil || tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("token setup = %#v, %v", tokens, err)
	}
	assertMapped("access.lookup", credbound.ErrInvalidCredentials, func() error {
		_, err := manager.AuthenticateOAuthAccessToken(ctx, resource.Resource, tokens.AccessToken)
		return err
	})
	assertMapped("client.lookup", credbound.ErrInvalidCredentials, func() error {
		_, err := manager.AuthenticateOAuthAccessToken(ctx, resource.Resource, tokens.AccessToken)
		return err
	})
	assertMapped("grant.lookup", credbound.ErrInvalidCredentials, func() error {
		_, err := manager.AuthenticateOAuthAccessToken(ctx, resource.Resource, tokens.AccessToken)
		return err
	})
	assertMapped("resource.lookup", credbound.ErrInvalidCredentials, func() error {
		_, err := manager.AuthenticateOAuthAccessToken(ctx, resource.Resource, tokens.AccessToken)
		return err
	})
	refresh := credbound.RefreshOAuthTokenInput{Issuer: issuer.Issuer, ClientID: client.Client.ClientID, RefreshToken: tokens.RefreshToken, Resource: resource.Resource}
	assertMapped("refresh.lookup", credbound.ErrInvalidCredentials, func() error { _, err := manager.RefreshOAuthToken(ctx, refresh); return err })
	assertFailure("refresh.rotate", func() error { _, err := manager.RefreshOAuthToken(ctx, refresh); return err })
	assertMapped("access.lookup", nil, func() error {
		return manager.RevokeOAuthToken(ctx, credbound.RevokeOAuthTokenInput{Issuer: issuer.Issuer, ClientID: client.Client.ClientID, Token: tokens.AccessToken})
	})
	assertFailure("access.revoke", func() error {
		return manager.RevokeOAuthToken(ctx, credbound.RevokeOAuthTokenInput{Issuer: issuer.Issuer, ClientID: client.Client.ClientID, Token: tokens.AccessToken})
	})
	assertFailure("family.revoke", func() error {
		return manager.RevokeOAuthToken(ctx, credbound.RevokeOAuthTokenInput{Issuer: issuer.Issuer, ClientID: client.Client.ClientID, Token: tokens.RefreshToken})
	})
}
