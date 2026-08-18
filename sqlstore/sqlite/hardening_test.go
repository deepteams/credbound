package sqlite_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

func TestHardeningStoreContract(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	workspace := credbound.Workspace{ID: f.id(), Name: "Main", RequireMFA: true, CreatedAt: f.now, UpdatedAt: f.now}
	password := credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleAdmin, CreatedAt: f.now, UpdatedAt: f.now}
	admin := credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.Bootstrap(ctx, user, f.email(user), password, workspace, membership, admin, f.event(user.ID, "bootstrap", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}

	// The workspace MFA policy round-trips through every read path.
	if got, err := f.store.WorkspaceByID(ctx, workspace.ID); err != nil || !got.RequireMFA {
		t.Fatalf("workspace = %#v, %v", got, err)
	}
	workspace.RequireMFA = false
	workspace.UpdatedAt = f.now.Add(time.Minute)
	if err := f.store.UpdateWorkspace(ctx, workspace, f.event(user.ID, "workspace.update", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.store.WorkspaceByID(ctx, workspace.ID); got.RequireMFA {
		t.Fatalf("MFA policy was not cleared: %#v", got)
	}
	for event, err := range f.store.Workspaces(ctx, credbound.PageRequest{Limit: 10}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil && event.Data.RequireMFA {
			t.Fatalf("listed workspace policy = %#v", event.Data)
		}
	}

	// Login throttle: increment, lock at the threshold, restart after
	// expiry, and clear on successful authentication.
	if _, err := f.store.LoginThrottleByUserID(ctx, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("initial throttle = %v", err)
	}
	lockUntil := f.now.Add(15 * time.Minute)
	first, err := f.store.RecordLoginFailure(ctx, user.ID, f.now, 2, lockUntil, f.event(user.ID, "auth.fail", user.ID, ""))
	if err != nil || first.FailedAttempts != 1 || first.LockedUntil != nil {
		t.Fatalf("first failure = %#v, %v", first, err)
	}
	second, err := f.store.RecordLoginFailure(ctx, user.ID, f.now, 2, lockUntil, f.event(user.ID, "auth.fail", user.ID, ""))
	if err != nil || second.FailedAttempts != 2 || second.LockedUntil == nil {
		t.Fatalf("locking failure = %#v, %v", second, err)
	}
	if got, err := f.store.LoginThrottleByUserID(ctx, user.ID); err != nil || got.LockedUntil == nil {
		t.Fatalf("stored throttle = %#v, %v", got, err)
	}
	afterExpiry, err := f.store.RecordLoginFailure(ctx, user.ID, lockUntil.Add(time.Minute), 2, lockUntil.Add(16*time.Minute), f.event(user.ID, "auth.fail", user.ID, ""))
	if err != nil || afterExpiry.FailedAttempts != 1 || afterExpiry.LockedUntil != nil {
		t.Fatalf("post-expiry failure = %#v, %v", afterExpiry, err)
	}
	if err := f.store.RecordAuthentication(ctx, user.ID, f.now, f.event(user.ID, "auth.ok", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.LoginThrottleByUserID(ctx, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("throttle after success = %v", err)
	}
	if _, err := f.store.RecordLoginFailure(ctx, f.id(), f.now, 2, lockUntil, f.event(user.ID, "auth.fail", user.ID, "")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown user failure = %v", err)
	}

	// Recovery-code counting.
	if count, err := f.store.CountUnusedRecoveryCodes(ctx, user.ID); err != nil || count != 0 {
		t.Fatalf("initial recovery count = %d, %v", count, err)
	}
	factor := credbound.TOTPFactor{UserID: user.ID, EncryptedSecret: []byte("sealed"), CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.SaveTOTPEnrollment(ctx, factor, f.event(user.ID, "totp.save", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	codes := []credbound.RecoveryCode{{UserID: user.ID, Digest: []byte("a")}, {UserID: user.ID, Digest: []byte("b")}}
	if err := f.store.ActivateTOTP(ctx, factor, codes, f.event(user.ID, "totp.activate", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	if count, _ := f.store.CountUnusedRecoveryCodes(ctx, user.ID); count != 2 {
		t.Fatalf("recovery count = %d", count)
	}
	if used, err := f.store.ConsumeRecoveryCode(ctx, user.ID, []byte("a"), f.now, f.event(user.ID, "recovery", user.ID, "")); err != nil || !used {
		t.Fatalf("consume recovery = %v, %v", used, err)
	}
	if count, _ := f.store.CountUnusedRecoveryCodes(ctx, user.ID); count != 1 {
		t.Fatalf("recovery count after use = %d", count)
	}

	// Password reset: single use, sibling cleanup, credential revocation.
	pat := credbound.PAT{ID: f.id(), UserID: user.ID, Name: "n", Prefix: "aabbccddeeff", Digest: []byte("d"), Scopes: []string{"read"}, CreatedAt: f.now}
	if err := f.store.CreatePAT(ctx, pat, f.event(user.ID, "pat.create", pat.ID, "")); err != nil {
		t.Fatal(err)
	}
	reset := credbound.PasswordResetCredential{ID: f.id(), UserID: user.ID, Digest: []byte("r1"), CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	sibling := credbound.PasswordResetCredential{ID: f.id(), UserID: user.ID, Digest: []byte("r2"), CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	if err := f.store.CreatePasswordReset(ctx, reset, f.event(user.ID, "reset.create", reset.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreatePasswordReset(ctx, sibling, f.event(user.ID, "reset.create", sibling.ID, "")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.PasswordResetByID(ctx, reset.ID); err != nil || got.UserID != user.ID || got.UsedAt != nil {
		t.Fatalf("reset lookup = %#v, %v", got, err)
	}
	newPassword := credbound.PasswordCredential{UserID: user.ID, Hash: "reset-hash", UpdatedAt: f.now}
	if err := f.store.CompletePasswordReset(ctx, reset.ID, newPassword, f.now, f.event(user.ID, "reset.complete", reset.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CompletePasswordReset(ctx, reset.ID, newPassword, f.now, f.event(user.ID, "reset.complete", reset.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("reused reset = %v", err)
	}
	if _, err := f.store.PasswordResetByID(ctx, sibling.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("sibling reset survived: %v", err)
	}
	if got, _ := f.store.PasswordByUserID(ctx, user.ID); got.Hash != "reset-hash" {
		t.Fatalf("password after reset = %#v", got)
	}
	if got, err := f.store.PATByPrefix(ctx, pat.Prefix); err != nil || got.RevokedAt == nil {
		t.Fatalf("PAT after reset = %#v, %v", got, err)
	}

	// Magic-link tokens are single use and touch last_seen_at.
	emails := collectEmailIDs(t, f.store.Emails(ctx, user.ID, credbound.PageRequest{Limit: 10}))
	link := credbound.EmailAuthenticationCredential{ID: f.id(), UserID: user.ID, EmailID: emails[0], Digest: []byte("m"), CreatedAt: f.now, ExpiresAt: f.now.Add(15 * time.Minute)}
	if err := f.store.CreateEmailAuthentication(ctx, link, f.event(user.ID, "link.create", link.ID, "")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.EmailAuthenticationByID(ctx, link.ID); err != nil || got.EmailID != emails[0] {
		t.Fatalf("link lookup = %#v, %v", got, err)
	}
	if err := f.store.ConsumeEmailAuthentication(ctx, link.ID, user.ID, f.now, true, f.event(user.ID, "link.use", link.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ConsumeEmailAuthentication(ctx, link.ID, user.ID, f.now, true, f.event(user.ID, "link.use", link.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("reused link = %v", err)
	}

	// A consumption that leaves a second factor pending spends the token
	// without clearing the login throttle.
	pendingLink := credbound.EmailAuthenticationCredential{ID: f.id(), UserID: user.ID, EmailID: emails[0], Digest: []byte("m2"), CreatedAt: f.now, ExpiresAt: f.now.Add(15 * time.Minute)}
	if err := f.store.CreateEmailAuthentication(ctx, pendingLink, f.event(user.ID, "link.create", pendingLink.ID, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RecordLoginFailure(ctx, user.ID, f.now, 3, f.now.Add(15*time.Minute), f.event(user.ID, "auth.fail", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ConsumeEmailAuthentication(ctx, pendingLink.ID, user.ID, f.now, false, f.event(user.ID, "link.use", pendingLink.ID, "")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.LoginThrottleByUserID(ctx, user.ID); err != nil || got.FailedAttempts != 1 {
		t.Fatalf("throttle after pending consumption = %#v, %v", got, err)
	}

	// AUTH-009: the possession-based sign-ins clear the throttle too.
	passkey := credbound.Passkey{ID: f.id(), UserID: user.ID, Name: "key", CredentialID: []byte("cred-unlock"), CredentialJSON: []byte("{}"), CreatedAt: f.now}
	if err := f.store.SavePasskey(ctx, passkey, f.event(user.ID, "passkey.create", passkey.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.TouchPasskey(ctx, user.ID, passkey.CredentialID, []byte("{}"), f.now, f.event(user.ID, "auth.passkey", passkey.ID, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.LoginThrottleByUserID(ctx, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("throttle after passkey sign-in = %v", err)
	}

	identity := credbound.SSOIdentity{
		ID: f.id(), UserID: user.ID, ProviderConfigurationID: f.id(), ProviderKind: credbound.SSOProviderOIDC,
		Issuer: "https://idp.example.com", Subject: "unlock-subject", Email: "root@example.com", CreatedAt: f.now, LastUsedAt: &f.now,
	}
	if _, err := f.store.RecordLoginFailure(ctx, user.ID, f.now, 3, f.now.Add(15*time.Minute), f.event(user.ID, "auth.fail", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.LinkSSO(ctx, identity, f.event(user.ID, "sso.link", identity.ID, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.LoginThrottleByUserID(ctx, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("throttle after SSO link sign-in = %v", err)
	}
	if _, err := f.store.RecordLoginFailure(ctx, user.ID, f.now, 3, f.now.Add(15*time.Minute), f.event(user.ID, "auth.fail", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.TouchSSO(ctx, user.ID, identity.ID, f.now, f.event(user.ID, "auth.sso", identity.ID, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.LoginThrottleByUserID(ctx, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("throttle after SSO sign-in = %v", err)
	}

	// RevokeUserCredentials revokes the user's PATs.
	pat2 := credbound.PAT{ID: f.id(), UserID: user.ID, Name: "n2", Prefix: "aabbccddee00", Digest: []byte("d2"), Scopes: []string{"read"}, CreatedAt: f.now}
	if err := f.store.CreatePAT(ctx, pat2, f.event(user.ID, "pat.create", pat2.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RevokeUserCredentials(ctx, user.ID, f.now, f.event(user.ID, "creds.revoke", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.store.PATByPrefix(ctx, pat2.Prefix); got.RevokedAt == nil {
		t.Fatalf("PAT after revocation = %#v", got)
	}
	if err := f.store.RevokeUserCredentials(ctx, f.id(), f.now, f.event(user.ID, "creds.revoke", user.ID, "")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown user revocation = %v", err)
	}
}

func TestInvitationStoreContract(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	workspace := credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
	password := credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleAdmin, CreatedAt: f.now, UpdatedAt: f.now}
	admin := credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.Bootstrap(ctx, user, f.email(user), password, workspace, membership, admin, f.event(user.ID, "bootstrap", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}

	invitation := credbound.WorkspaceInvitation{
		ID: f.id(), WorkspaceID: workspace.ID, Email: "invitee@example.com", Role: credbound.RoleMember,
		InvitedBy: user.ID, Digest: []byte("digest"), CreatedAt: f.now, ExpiresAt: f.now.Add(24 * time.Hour),
	}
	if err := f.store.CreateWorkspaceInvitation(ctx, invitation, f.event(user.ID, "invite", invitation.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.WorkspaceInvitationByID(ctx, invitation.ID); err != nil || got.Email != invitation.Email || !bytes.Equal(got.Digest, invitation.Digest) {
		t.Fatalf("invitation lookup = %#v, %v", got, err)
	}
	if got, err := f.store.PendingWorkspaceInvitation(ctx, workspace.ID, invitation.Email); err != nil || got.ID != invitation.ID {
		t.Fatalf("pending lookup = %#v, %v", got, err)
	}
	duplicate := invitation
	duplicate.ID = f.id()
	if err := f.store.CreateWorkspaceInvitation(ctx, duplicate, f.event(user.ID, "invite", duplicate.ID, workspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate pending invitation = %v", err)
	}

	// Registration consumes the invitation and creates the account.
	invited := credbound.User{ID: f.id(), Email: invitation.Email, DisplayName: "Invitee", CreatedAt: f.now, UpdatedAt: f.now}
	invitedMembership := credbound.Membership{WorkspaceID: workspace.ID, UserID: invited.ID, Role: credbound.RoleMember, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.RegisterInvitedUser(ctx, invitation.ID, invited, f.email(invited), credbound.PasswordCredential{UserID: invited.ID, Hash: "h", UpdatedAt: f.now}, invitedMembership, f.now, f.event(invited.ID, "invite.register", invitation.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RegisterInvitedUser(ctx, invitation.ID, invited, f.email(invited), credbound.PasswordCredential{UserID: invited.ID, Hash: "h", UpdatedAt: f.now}, invitedMembership, f.now, f.event(invited.ID, "invite.register", invitation.ID, workspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("reused registration = %v", err)
	}
	if got, err := f.store.Membership(ctx, workspace.ID, invited.ID); err != nil || got.Role != credbound.RoleMember {
		t.Fatalf("invited membership = %#v, %v", got, err)
	}
	if _, err := f.store.PendingWorkspaceInvitation(ctx, workspace.ID, invitation.Email); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("consumed invitation still pending = %v", err)
	}

	// Acceptance by an existing user and revocation of a pending invitation.
	acceptable := credbound.WorkspaceInvitation{
		ID: f.id(), WorkspaceID: workspace.ID, Email: "root@example.com", Role: credbound.RoleMember,
		InvitedBy: user.ID, Digest: []byte("digest2"), CreatedAt: f.now, ExpiresAt: f.now.Add(24 * time.Hour),
	}
	if err := f.store.CreateWorkspaceInvitation(ctx, acceptable, f.event(user.ID, "invite", acceptable.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.AcceptWorkspaceInvitation(ctx, acceptable.ID, user.ID, f.now, membership, f.event(user.ID, "invite.accept", acceptable.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.AcceptWorkspaceInvitation(ctx, acceptable.ID, user.ID, f.now, membership, f.event(user.ID, "invite.accept", acceptable.ID, workspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("reused acceptance = %v", err)
	}

	revocable := credbound.WorkspaceInvitation{
		ID: f.id(), WorkspaceID: workspace.ID, Email: "revoked@example.com", Role: credbound.RoleMember,
		InvitedBy: user.ID, Digest: []byte("digest3"), CreatedAt: f.now, ExpiresAt: f.now.Add(24 * time.Hour),
	}
	if err := f.store.CreateWorkspaceInvitation(ctx, revocable, f.event(user.ID, "invite", revocable.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RevokeWorkspaceInvitation(ctx, workspace.ID, revocable.ID, f.now, f.event(user.ID, "invite.revoke", revocable.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RevokeWorkspaceInvitation(ctx, workspace.ID, revocable.ID, f.now, f.event(user.ID, "invite.revoke", revocable.ID, workspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("double revocation = %v", err)
	}

	// Paginated listing in reverse chronological order.
	items := 0
	seenRevoked := false
	for event, err := range f.store.WorkspaceInvitations(ctx, workspace.ID, credbound.PageRequest{Limit: 2}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			items++
			if event.Data.ID == revocable.ID && event.Data.RevokedAt != nil {
				seenRevoked = true
			}
		}
		if event.End != nil && event.End.HasMore {
			for next, err := range f.store.WorkspaceInvitations(ctx, workspace.ID, credbound.PageRequest{Limit: 2, Cursor: event.End.NextCursor}) {
				if err != nil {
					t.Fatal(err)
				}
				if next.Data != nil {
					items++
					if next.Data.ID == revocable.ID && next.Data.RevokedAt != nil {
						seenRevoked = true
					}
				}
			}
		}
	}
	if items != 3 || !seenRevoked {
		t.Fatalf("listed invitations = %d, revoked seen = %v", items, seenRevoked)
	}
}

// TestHardeningStreamEarlyBreak pins the streamed-list contract (DATA-002):
// lists are traversed lazily through iter.Seq2, so a consumer can stop
// mid-stream after one element instead of receiving a materialized slice.
func TestHardeningStreamEarlyBreak(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for range 3 {
		if err := f.store.AppendAudit(ctx, f.event("", "test.append", "resource", "")); err != nil {
			t.Fatal(err)
		}
	}
	seen := 0
	for _, err := range f.store.ChainedAuditEvents(ctx, 0) {
		if err != nil {
			t.Fatal(err)
		}
		seen++
		break
	}
	if seen != 1 {
		t.Fatalf("early break yielded %d events", seen)
	}
	user := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	workspace := credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleAdmin, CreatedAt: f.now, UpdatedAt: f.now}
	admin := credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.Bootstrap(ctx, user, f.email(user), credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}, workspace, membership, admin, f.event(user.ID, "bootstrap", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	for index := range 2 {
		invitation := credbound.WorkspaceInvitation{
			ID: f.id(), WorkspaceID: workspace.ID, Email: []string{"a", "b"}[index] + "@example.com", Role: credbound.RoleMember,
			InvitedBy: user.ID, Digest: []byte{byte(index)}, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour),
		}
		if err := f.store.CreateWorkspaceInvitation(ctx, invitation, f.event(user.ID, "invite", invitation.ID, workspace.ID)); err != nil {
			t.Fatal(err)
		}
	}
	seen = 0
	for event, err := range f.store.WorkspaceInvitations(ctx, workspace.ID, credbound.PageRequest{Limit: 10}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			seen++
			break
		}
	}
	if seen != 1 {
		t.Fatalf("early break yielded %d invitations", seen)
	}
	if _, err := f.store.WorkspaceInvitationByID(ctx, f.id()); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown invitation lookup = %v", err)
	}
	if _, err := f.store.EmailAuthenticationByID(ctx, f.id()); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown link lookup = %v", err)
	}
	if _, err := f.store.PasswordResetByID(ctx, f.id()); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown reset lookup = %v", err)
	}
	if _, err := f.store.CountUnusedRecoveryCodes(ctx, user.ID); err != nil {
		t.Fatalf("recovery count = %v", err)
	}
	for _, err := range f.store.WorkspaceInvitations(ctx, workspace.ID, credbound.PageRequest{Limit: 10, Cursor: "!!!"}) {
		if !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("bad cursor error = %v", err)
		}
	}
	// Referential errors surface as store failures.
	if err := f.store.CreatePasswordReset(ctx, credbound.PasswordResetCredential{ID: f.id(), UserID: f.id(), Digest: []byte("x"), CreatedAt: f.now, ExpiresAt: f.now}, f.event(user.ID, "reset", "r", "")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("reset for unknown user = %v", err)
	}
	if err := f.store.CreateEmailAuthentication(ctx, credbound.EmailAuthenticationCredential{ID: f.id(), UserID: f.id(), EmailID: f.id(), Digest: []byte("x"), CreatedAt: f.now, ExpiresAt: f.now}, f.event(user.ID, "link", "l", "")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("link for unknown user = %v", err)
	}
	// Registration re-using an existing account fails inside the transaction.
	third := credbound.WorkspaceInvitation{
		ID: f.id(), WorkspaceID: workspace.ID, Email: "root@example.com", Role: credbound.RoleMember,
		InvitedBy: user.ID, Digest: []byte("z"), CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour),
	}
	if err := f.store.CreateWorkspaceInvitation(ctx, third, f.event(user.ID, "invite", third.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RegisterInvitedUser(ctx, third.ID, user, f.email(user), credbound.PasswordCredential{UserID: user.ID, Hash: "h", UpdatedAt: f.now}, credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, CreatedAt: f.now, UpdatedAt: f.now}, f.now, f.event(user.ID, "register", third.ID, workspace.ID)); err == nil {
		t.Fatal("registration with existing account succeeded")
	}
}

func TestRevokeUserCredentialsCascadesOAuthGrants(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	workspace := credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleAdmin, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.Bootstrap(ctx, user, f.email(user), credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}, workspace, membership, credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}, f.event(user.ID, "bootstrap", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	issuer := credbound.OAuthIssuer{ID: f.id(), Issuer: "https://auth.example.com", CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateOAuthIssuer(ctx, issuer, f.event(user.ID, "oauth.issuer.create", issuer.ID, "")); err != nil {
		t.Fatal(err)
	}
	resource := credbound.OAuthProtectedResource{ID: f.id(), IssuerID: issuer.ID, WorkspaceID: workspace.ID, Resource: "https://mcp.example.com/acme", CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateOAuthProtectedResource(ctx, resource, f.event(user.ID, "oauth.resource.create", resource.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	client := credbound.OAuthClient{ID: f.id(), IssuerID: issuer.ID, ClientID: "client", Source: credbound.OAuthClientPreRegistered, Name: "Client", CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateOAuthClient(ctx, client, "", f.now, f.event(user.ID, "oauth.client.create", client.ID, "")); err != nil {
		t.Fatal(err)
	}
	grant := credbound.OAuthGrant{ID: f.id(), IssuerID: issuer.ID, ClientRecordID: client.ID, UserID: user.ID, WorkspaceID: workspace.ID, ResourceID: resource.ID, Scopes: []string{"documents.read"}, CreatedAt: f.now, UpdatedAt: f.now}
	code := credbound.OAuthAuthorizationCode{ID: f.id(), Prefix: "code", GrantID: grant.ID, ClientRecordID: client.ID, ResourceID: resource.ID, ExpiresAt: f.now.Add(time.Minute), CreatedAt: f.now}
	if err := f.store.CreateOAuthGrantAndCode(ctx, grant, code, f.event(user.ID, "oauth.authorization", grant.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RevokeUserCredentials(ctx, user.ID, f.now, f.event(user.ID, "creds.revoke", user.ID, "")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.OAuthGrant(ctx, grant.ID); err != nil || got.RevokedAt == nil {
		t.Fatalf("grant after revocation = %#v, %v", got, err)
	}
}

func collectEmailIDs(t *testing.T, sequence func(func(credbound.PageEvent[credbound.EmailAddress], error) bool)) []string {
	t.Helper()
	var ids []string
	for event, err := range sequence {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			ids = append(ids, event.Data.ID)
		}
	}
	return ids
}

func TestAuditChainPersistence(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for range 3 {
		if err := f.store.AppendAudit(ctx, f.event("", "test.append", "resource", "")); err != nil {
			t.Fatal(err)
		}
	}
	sequence, head, err := f.store.AuditChainHead(ctx)
	if err != nil || sequence != 3 || len(head) != 32 {
		t.Fatalf("chain head = %d, %x, %v", sequence, head, err)
	}
	previous := make([]byte, 32)
	expected := int64(0)
	for event, err := range f.store.ChainedAuditEvents(ctx, 0) {
		if err != nil {
			t.Fatal(err)
		}
		expected++
		if event.Sequence != expected {
			t.Fatalf("sequence = %d, expected %d", event.Sequence, expected)
		}
		if !bytes.Equal(event.PreviousHash, previous) || !bytes.Equal(event.Hash, credbound.ComputeAuditHash(previous, event)) {
			t.Fatalf("event %s does not chain", event.ID)
		}
		previous = event.Hash
	}
	if expected != 3 || !bytes.Equal(previous, head) {
		t.Fatalf("chained events = %d, head match = %v", expected, bytes.Equal(previous, head))
	}

	// Simulate out-of-band tampering (the immutability trigger blocks plain
	// SQL, so drop it the way a database-file attacker effectively would).
	if _, err := f.db.Exec(`DROP TRIGGER credbound_audit_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE credbound_audit_events SET reason = 'rewritten' WHERE sequence = 2`); err != nil {
		t.Fatal(err)
	}
	previous = make([]byte, 32)
	broken := false
	for event, err := range f.store.ChainedAuditEvents(ctx, 0) {
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(event.Hash, credbound.ComputeAuditHash(previous, event)) {
			broken = true
			break
		}
		previous = event.Hash
	}
	if !broken {
		t.Fatal("tampered audit row was not detected")
	}
}

func TestAuditMetadataRoundTrip(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	commit := f.event("", "test.metadata", "resource", "")
	commit.Audit.IPAddress = "198.51.100.4"
	commit.Audit.UserAgent = "agent/1.0"
	if err := f.store.AppendAudit(ctx, commit); err != nil {
		t.Fatal(err)
	}
	for event, err := range f.store.ChainedAuditEvents(ctx, 0) {
		if err != nil {
			t.Fatal(err)
		}
		if event.IPAddress != "198.51.100.4" || event.UserAgent != "agent/1.0" {
			t.Fatalf("metadata round trip = %#v", event)
		}
	}
}
