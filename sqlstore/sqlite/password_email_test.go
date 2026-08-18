package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

func TestChangePasswordAndEmailReissue(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	workspace := credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleAdmin, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.Bootstrap(ctx, user, f.email(user), credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}, workspace, membership, credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}, f.event(user.ID, "bootstrap", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}

	replaced := credbound.PasswordCredential{UserID: user.ID, Hash: "new-hash", UpdatedAt: f.now.Add(time.Minute)}
	if err := f.store.ChangePassword(ctx, replaced, f.now.Add(time.Minute), f.event(user.ID, "password.change", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.PasswordByUserID(ctx, user.ID); err != nil || got.Hash != "new-hash" {
		t.Fatalf("replaced password = %#v, %v", got, err)
	}
	missing := credbound.PasswordCredential{UserID: f.id(), Hash: "x", UpdatedAt: f.now}
	if err := f.store.ChangePassword(ctx, missing, f.now, f.event(user.ID, "password.change", missing.UserID, "")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing-user change = %v", err)
	}

	if got, err := f.store.EmailByAddress(ctx, "root@example.com"); err != nil || got.UserID != user.ID {
		t.Fatalf("email by address = %#v, %v", got, err)
	}
	if _, err := f.store.EmailByAddress(ctx, "ghost@example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown address = %v", err)
	}

	pending := credbound.EmailAddress{ID: f.id(), UserID: user.ID, Address: "second@example.com", CreatedAt: f.now, UpdatedAt: f.now}
	verification := credbound.EmailVerificationCredential{EmailID: pending.ID, Digest: []byte("digest-1"), ExpiresAt: f.now.Add(time.Hour)}
	if err := f.store.SaveEmail(ctx, pending, verification, f.event(user.ID, "email.add", pending.ID, "")); err != nil {
		t.Fatal(err)
	}
	reissued := credbound.EmailVerificationCredential{EmailID: pending.ID, Digest: []byte("digest-2"), ExpiresAt: f.now.Add(2 * time.Hour)}
	if err := f.store.ReissueEmailVerification(ctx, pending.ID, reissued, f.event(user.ID, "email.reissue", pending.ID, "")); err != nil {
		t.Fatal(err)
	}
	if _, credential, err := f.store.EmailVerificationByID(ctx, pending.ID); err != nil || string(credential.Digest) != "digest-2" {
		t.Fatalf("reissued credential = %#v, %v", credential, err)
	}
	if err := f.store.ReissueEmailVerification(ctx, f.id(), reissued, f.event(user.ID, "email.reissue", pending.ID, "")); err == nil {
		t.Fatal("missing address reissue succeeded")
	}
}

func TestPasskeyByCredentialID(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	workspace := credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleAdmin, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.Bootstrap(ctx, user, f.email(user), credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}, workspace, membership, credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}, f.event(user.ID, "bootstrap", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	passkey := credbound.Passkey{ID: f.id(), UserID: user.ID, Name: "MacBook", CredentialID: []byte("credential"), CredentialJSON: []byte("sealed"), CreatedAt: f.now}
	if err := f.store.SavePasskey(ctx, passkey, f.event(user.ID, "passkey.create", passkey.ID, "")); err != nil {
		t.Fatal(err)
	}
	got, err := f.store.PasskeyByCredentialID(ctx, []byte("credential"))
	if err != nil || got.ID != passkey.ID || got.UserID != user.ID || string(got.CredentialJSON) != "sealed" {
		t.Fatalf("passkey by credential = %#v, %v", got, err)
	}
	if _, err := f.store.PasskeyByCredentialID(ctx, []byte("missing")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing credential = %v", err)
	}
}

func TestOAuthClientAccessTokenLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	workspace := credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleAdmin, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.Bootstrap(ctx, user, f.email(user), credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}, workspace, membership, credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}, f.event(user.ID, "bootstrap", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	issuer := credbound.OAuthIssuer{ID: f.id(), Issuer: "https://auth.example.com", CodeTTL: 5 * time.Minute, AccessTokenTTL: 15 * time.Minute, RefreshTokenTTL: 24 * time.Hour, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateOAuthIssuer(ctx, issuer, f.event(user.ID, "oauth.issuer.create", issuer.ID, "")); err != nil {
		t.Fatal(err)
	}
	client := credbound.OAuthClient{ID: f.id(), IssuerID: issuer.ID, ClientID: "client", Source: credbound.OAuthClientPreRegistered, Name: "Client", CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateOAuthClient(ctx, client, "", f.now, f.event(user.ID, "oauth.client.create", client.ID, "")); err != nil {
		t.Fatal(err)
	}

	token := credbound.OAuthClientAccessToken{
		ID: f.id(), Prefix: "ccpfx", Digest: []byte("digest"), ClientRecordID: client.ID,
		IssuerID: issuer.ID, WorkspaceID: workspace.ID, Scopes: []string{"mcp.read"},
		CreatedAt: f.now, ExpiresAt: f.now.Add(15 * time.Minute),
	}
	if err := f.store.CreateOAuthClientAccessToken(ctx, token, f.event(user.ID, "oauth.cc.issue", token.ID, "")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.OAuthClientAccessTokenByPrefix(ctx, "ccpfx"); err != nil || got.ID != token.ID || got.RevokedAt != nil {
		t.Fatalf("token by prefix = %#v, %v", got, err)
	}
	if _, err := f.store.OAuthClientAccessTokenByPrefix(ctx, "missing"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing prefix = %v", err)
	}
	revokedAt := f.now.Add(time.Minute)
	if err := f.store.RevokeOAuthClientAccessToken(ctx, token.ID, revokedAt, f.event(user.ID, "oauth.cc.revoke", token.ID, "")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.OAuthClientAccessTokenByPrefix(ctx, "ccpfx"); err != nil || got.RevokedAt == nil || !got.RevokedAt.Equal(revokedAt) {
		t.Fatalf("revoked token = %#v, %v", got, err)
	}
	if err := f.store.RevokeOAuthClientAccessToken(ctx, f.id(), revokedAt, f.event(user.ID, "oauth.cc.revoke", token.ID, "")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("missing revoke = %v", err)
	}
}
