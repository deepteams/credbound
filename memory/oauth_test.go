package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

func TestOAuthStoreHonorsCanceledContext(t *testing.T) {
	store := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	commit := credbound.Commit{}
	issuer := credbound.OAuthIssuer{}
	resource := credbound.OAuthProtectedResource{}
	client := credbound.OAuthClient{}
	initial := credbound.OAuthInitialAccessToken{}
	grant := credbound.OAuthGrant{}
	code := credbound.OAuthAuthorizationCode{}
	access := credbound.OAuthAccessToken{}
	refresh := credbound.OAuthRefreshToken{}
	calls := []func() error{
		func() error { return store.CreateOAuthIssuer(ctx, issuer, commit) },
		func() error { return store.UpdateOAuthIssuer(ctx, issuer, commit) },
		func() error { return store.SetOAuthIssuerDisabled(ctx, "", true, time.Time{}, commit) },
		func() error { _, err := store.OAuthIssuerByID(ctx, ""); return err },
		func() error { _, err := store.OAuthIssuerByURL(ctx, ""); return err },
		func() error { return store.CreateOAuthProtectedResource(ctx, resource, commit) },
		func() error { return store.SetOAuthProtectedResourceDisabled(ctx, "", true, time.Time{}, commit) },
		func() error { _, err := store.OAuthProtectedResourceByID(ctx, ""); return err },
		func() error { _, err := store.OAuthProtectedResourceByURI(ctx, ""); return err },
		func() error { return store.CreateOAuthClient(ctx, client, "", time.Time{}, commit) },
		func() error { return store.UpsertOAuthCIMDClient(ctx, client, commit) },
		func() error { return store.SetOAuthClientDisabled(ctx, "", true, time.Time{}, commit) },
		func() error { _, err := store.OAuthClientByID(ctx, ""); return err },
		func() error { _, err := store.OAuthClientByClientID(ctx, "", ""); return err },
		func() error { return store.CreateOAuthInitialAccessToken(ctx, initial, commit) },
		func() error { _, err := store.OAuthInitialAccessTokenByPrefix(ctx, ""); return err },
		func() error { return store.RevokeOAuthInitialAccessToken(ctx, "", time.Time{}, commit) },
		func() error { return store.CreateOAuthGrantAndCode(ctx, grant, code, commit) },
		func() error { _, err := store.OAuthGrant(ctx, ""); return err },
		func() error { return store.RevokeOAuthGrant(ctx, "", time.Time{}, commit) },
		func() error { _, err := store.OAuthAuthorizationCodeByPrefix(ctx, ""); return err },
		func() error {
			return store.ConsumeOAuthAuthorizationCode(ctx, "", time.Time{}, access, &refresh, commit)
		},
		func() error { _, err := store.OAuthAccessTokenByPrefix(ctx, ""); return err },
		func() error { _, err := store.OAuthRefreshTokenByPrefix(ctx, ""); return err },
		func() error { return store.RotateOAuthRefreshToken(ctx, "", time.Time{}, access, refresh, commit) },
		func() error { return store.RevokeOAuthAccessToken(ctx, "", time.Time{}, commit) },
		func() error { return store.RevokeOAuthRefreshFamily(ctx, "", time.Time{}, commit) },
	}
	for index, call := range calls {
		if err := call(); !errors.Is(err, context.Canceled) {
			t.Fatalf("call %d = %v", index, err)
		}
	}
	assertSequenceError(t, store.OAuthIssuers(ctx, credbound.PageRequest{Limit: 50}), context.Canceled)
	assertSequenceError(t, store.OAuthProtectedResources(ctx, "", credbound.PageRequest{Limit: 50}), context.Canceled)
	assertSequenceError(t, store.OAuthClients(ctx, "", credbound.PageRequest{Limit: 50}), context.Canceled)
	assertSequenceError(t, store.OAuthGrants(ctx, "", "", credbound.PageRequest{Limit: 50}), context.Canceled)
}

func TestOAuthStoreRejectsBrokenReferencesAndReplay(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	commit := credbound.Commit{}
	badPage := credbound.PageRequest{Cursor: "%%%", Limit: 50}
	assertSequenceError(t, store.OAuthIssuers(ctx, badPage), credbound.ErrInvalidInput)
	assertSequenceError(t, store.OAuthProtectedResources(ctx, "", badPage), credbound.ErrInvalidInput)
	assertSequenceError(t, store.OAuthClients(ctx, "", badPage), credbound.ErrInvalidInput)
	assertSequenceError(t, store.OAuthGrants(ctx, "", "", badPage), credbound.ErrInvalidInput)
	want := func(name string, err, target error) {
		t.Helper()
		if !errors.Is(err, target) {
			t.Fatalf("%s = %v, want %v", name, err, target)
		}
	}
	_, err := store.OAuthIssuerByID(ctx, "missing")
	want("missing issuer id", err, credbound.ErrNotFound)
	_, err = store.OAuthIssuerByURL(ctx, "missing")
	want("missing issuer URL", err, credbound.ErrNotFound)
	_, err = store.OAuthProtectedResourceByID(ctx, "missing")
	want("missing resource id", err, credbound.ErrNotFound)
	_, err = store.OAuthProtectedResourceByURI(ctx, "missing")
	want("missing resource URI", err, credbound.ErrNotFound)
	_, err = store.OAuthClientByID(ctx, "missing")
	want("missing client id", err, credbound.ErrNotFound)
	_, err = store.OAuthClientByClientID(ctx, "missing", "missing")
	want("missing client key", err, credbound.ErrNotFound)
	_, err = store.OAuthInitialAccessTokenByPrefix(ctx, "missing")
	want("missing initial prefix", err, credbound.ErrNotFound)
	_, err = store.OAuthGrant(ctx, "missing")
	want("missing grant", err, credbound.ErrNotFound)
	_, err = store.OAuthAuthorizationCodeByPrefix(ctx, "missing")
	want("missing code", err, credbound.ErrNotFound)
	_, err = store.OAuthAccessTokenByPrefix(ctx, "missing")
	want("missing access", err, credbound.ErrNotFound)
	_, err = store.OAuthRefreshTokenByPrefix(ctx, "missing")
	want("missing refresh", err, credbound.ErrNotFound)
	issuer := credbound.OAuthIssuer{ID: "issuer", Issuer: "https://auth.example.com"}
	store.oauthIssuers[issuer.ID] = issuer
	store.oauthIssuerURLs[issuer.Issuer] = issuer.ID
	want("duplicate issuer id", store.CreateOAuthIssuer(ctx, issuer, commit), credbound.ErrConflict)
	want("duplicate issuer URL", store.CreateOAuthIssuer(ctx, credbound.OAuthIssuer{ID: "other", Issuer: issuer.Issuer}, commit), credbound.ErrConflict)
	want("missing issuer update", store.UpdateOAuthIssuer(ctx, credbound.OAuthIssuer{ID: "missing"}, commit), credbound.ErrNotFound)

	resource := credbound.OAuthProtectedResource{ID: "resource", IssuerID: issuer.ID, WorkspaceID: "workspace", Resource: "https://mcp.example.com"}
	want("missing resource issuer", store.CreateOAuthProtectedResource(ctx, credbound.OAuthProtectedResource{IssuerID: "missing"}, commit), credbound.ErrNotFound)
	want("missing resource workspace", store.CreateOAuthProtectedResource(ctx, resource, commit), credbound.ErrNotFound)
	store.workspaces[resource.WorkspaceID] = credbound.Workspace{ID: resource.WorkspaceID}
	store.oauthResources[resource.ID] = resource
	store.oauthResourceURIs[resource.Resource] = resource.ID
	want("duplicate resource id", store.CreateOAuthProtectedResource(ctx, resource, commit), credbound.ErrConflict)
	want("duplicate resource URI", store.CreateOAuthProtectedResource(ctx, credbound.OAuthProtectedResource{ID: "other", IssuerID: issuer.ID, WorkspaceID: resource.WorkspaceID, Resource: resource.Resource}, commit), credbound.ErrConflict)

	client := credbound.OAuthClient{ID: "client", IssuerID: issuer.ID, ClientID: "client-id"}
	want("missing client issuer", store.CreateOAuthClient(ctx, credbound.OAuthClient{IssuerID: "missing"}, "", now, commit), credbound.ErrNotFound)
	store.oauthClients[client.ID] = client
	store.oauthClientKeys[oauthClientKey(client.IssuerID, client.ClientID)] = client.ID
	want("duplicate client id", store.CreateOAuthClient(ctx, client, "", now, commit), credbound.ErrConflict)
	want("duplicate client key", store.CreateOAuthClient(ctx, credbound.OAuthClient{ID: "other", IssuerID: issuer.ID, ClientID: client.ClientID}, "", now, commit), credbound.ErrConflict)
	want("missing CIMD issuer", store.UpsertOAuthCIMDClient(ctx, credbound.OAuthClient{IssuerID: "missing"}, commit), credbound.ErrNotFound)
	want("conflicting CIMD", store.UpsertOAuthCIMDClient(ctx, credbound.OAuthClient{ID: "other", IssuerID: issuer.ID, ClientID: client.ClientID}, commit), credbound.ErrConflict)

	initial := credbound.OAuthInitialAccessToken{ID: "initial", IssuerID: issuer.ID, Prefix: "prefix", MaxRegistrations: 1, ExpiresAt: now.Add(time.Hour)}
	want("missing initial issuer", store.CreateOAuthInitialAccessToken(ctx, credbound.OAuthInitialAccessToken{IssuerID: "missing"}, commit), credbound.ErrNotFound)
	store.oauthInitialTokens[initial.ID] = initial
	store.oauthInitialKeys[initial.Prefix] = initial.ID
	want("duplicate initial id", store.CreateOAuthInitialAccessToken(ctx, initial, commit), credbound.ErrConflict)
	want("duplicate initial prefix", store.CreateOAuthInitialAccessToken(ctx, credbound.OAuthInitialAccessToken{ID: "other", IssuerID: issuer.ID, Prefix: initial.Prefix}, commit), credbound.ErrConflict)
	want("missing initial reference", store.CreateOAuthClient(ctx, credbound.OAuthClient{ID: "other", IssuerID: issuer.ID, ClientID: "other"}, "missing", now, commit), credbound.ErrNotFound)
	initial.RegistrationCount = 1
	store.oauthInitialTokens[initial.ID] = initial
	want("exhausted initial", store.CreateOAuthClient(ctx, credbound.OAuthClient{ID: "other", IssuerID: issuer.ID, ClientID: "other"}, initial.ID, now, commit), credbound.ErrConflict)
	want("missing initial revoke", store.RevokeOAuthInitialAccessToken(ctx, "missing", now, commit), credbound.ErrNotFound)

	grant := credbound.OAuthGrant{ID: "grant", ClientRecordID: client.ID, ResourceID: resource.ID}
	code := credbound.OAuthAuthorizationCode{ID: "code", Prefix: "code-prefix", GrantID: grant.ID, ExpiresAt: now.Add(time.Hour)}
	want("missing grant client", store.CreateOAuthGrantAndCode(ctx, credbound.OAuthGrant{ClientRecordID: "missing"}, code, commit), credbound.ErrNotFound)
	want("missing grant resource", store.CreateOAuthGrantAndCode(ctx, credbound.OAuthGrant{ClientRecordID: client.ID, ResourceID: "missing"}, code, commit), credbound.ErrNotFound)
	store.oauthGrants[grant.ID] = grant
	store.oauthCodes[code.ID] = code
	store.oauthCodeKeys[code.Prefix] = code.ID
	want("duplicate grant", store.CreateOAuthGrantAndCode(ctx, grant, credbound.OAuthAuthorizationCode{ID: "other"}, commit), credbound.ErrConflict)
	want("duplicate code", store.CreateOAuthGrantAndCode(ctx, credbound.OAuthGrant{ID: "other", ClientRecordID: client.ID, ResourceID: resource.ID}, code, commit), credbound.ErrConflict)
	want("duplicate code prefix", store.CreateOAuthGrantAndCode(ctx, credbound.OAuthGrant{ID: "other", ClientRecordID: client.ID, ResourceID: resource.ID}, credbound.OAuthAuthorizationCode{ID: "other", Prefix: code.Prefix}, commit), credbound.ErrConflict)
	want("missing code consume", store.ConsumeOAuthAuthorizationCode(ctx, "missing", now, credbound.OAuthAccessToken{}, nil, commit), credbound.ErrNotFound)
	used := now
	code.UsedAt = &used
	store.oauthCodes[code.ID] = code
	want("code replay", store.ConsumeOAuthAuthorizationCode(ctx, code.ID, now, credbound.OAuthAccessToken{}, nil, commit), credbound.ErrConflict)
	code.UsedAt = nil
	store.oauthCodes[code.ID] = code
	store.oauthAccessKeys["duplicate-access"] = "access"
	want("duplicate access prefix", store.ConsumeOAuthAuthorizationCode(ctx, code.ID, now, credbound.OAuthAccessToken{Prefix: "duplicate-access"}, nil, commit), credbound.ErrConflict)
	delete(store.oauthAccessKeys, "duplicate-access")
	store.oauthRefreshKeys["duplicate-refresh"] = "refresh"
	want("duplicate refresh prefix", store.ConsumeOAuthAuthorizationCode(ctx, code.ID, now, credbound.OAuthAccessToken{}, &credbound.OAuthRefreshToken{Prefix: "duplicate-refresh"}, commit), credbound.ErrConflict)

	refresh := credbound.OAuthRefreshToken{ID: "refresh", FamilyID: "family", Prefix: "refresh-prefix", GrantID: grant.ID, ExpiresAt: now.Add(time.Hour)}
	store.oauthRefreshTokens[refresh.ID] = refresh
	store.oauthRefreshKeys[refresh.Prefix] = refresh.ID
	want("missing refresh rotate", store.RotateOAuthRefreshToken(ctx, "missing", now, credbound.OAuthAccessToken{}, credbound.OAuthRefreshToken{}, commit), credbound.ErrNotFound)
	refresh.UsedAt = &used
	store.oauthRefreshTokens[refresh.ID] = refresh
	want("refresh replay", store.RotateOAuthRefreshToken(ctx, refresh.ID, now, credbound.OAuthAccessToken{}, credbound.OAuthRefreshToken{}, commit), credbound.ErrConflict)
	refresh.UsedAt = nil
	store.oauthRefreshTokens[refresh.ID] = refresh
	want("refresh family mismatch", store.RotateOAuthRefreshToken(ctx, refresh.ID, now, credbound.OAuthAccessToken{}, credbound.OAuthRefreshToken{FamilyID: "other"}, commit), credbound.ErrConflict)
	want("missing access revoke", store.RevokeOAuthAccessToken(ctx, "missing", now, commit), credbound.ErrNotFound)
	want("missing family revoke", store.RevokeOAuthRefreshFamily(ctx, "missing", now, commit), credbound.ErrNotFound)
}
