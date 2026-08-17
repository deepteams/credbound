package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

func (f *storeFixture) signupRecords(verified bool) (credbound.User, credbound.EmailAddress, *credbound.EmailVerificationCredential, credbound.PasswordCredential, credbound.Workspace, credbound.Membership) {
	user := credbound.User{ID: f.id(), Email: "visitor@example.com", DisplayName: "Visitor", CreatedAt: f.now, UpdatedAt: f.now}
	email := credbound.EmailAddress{ID: f.id(), UserID: user.ID, Address: user.Email, Primary: true, CreatedAt: f.now, UpdatedAt: f.now}
	var verification *credbound.EmailVerificationCredential
	if verified {
		verifiedAt := f.now
		email.VerifiedAt = &verifiedAt
	} else {
		verification = &credbound.EmailVerificationCredential{EmailID: email.ID, Digest: []byte("digest"), ExpiresAt: f.now.Add(time.Hour)}
	}
	password := credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}
	workspace := credbound.Workspace{ID: f.id(), Name: "Startup", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleAdmin, Status: credbound.MembershipActive, ProvisioningSource: credbound.ProvisioningSourceLocal, CreatedAt: f.now, UpdatedAt: f.now}
	return user, email, verification, password, workspace, membership
}

func TestCreateSignupPendingVerification(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	user, email, verification, password, workspace, membership := f.signupRecords(false)
	if err := f.store.CreateSignup(ctx, user, email, verification, password, workspace, membership, f.event("signup")); err != nil {
		t.Fatal(err)
	}
	// The unverified primary address must not resolve for authentication.
	if _, err := f.store.UserByEmail(ctx, email.Address); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unverified address resolved: %v", err)
	}
	storedEmail, storedVerification, err := f.store.EmailVerificationByID(ctx, email.ID)
	if err != nil || storedEmail.VerifiedAt != nil || string(storedVerification.Digest) != "digest" {
		t.Fatalf("verification = %#v, %#v, %v", storedEmail, storedVerification, err)
	}
	if _, err := f.store.PasswordByUserID(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.Membership(ctx, workspace.ID, user.ID); err != nil || got.Role != credbound.RoleAdmin {
		t.Fatalf("membership = %#v, %v", got, err)
	}
	if got, err := f.store.WorkspaceByID(ctx, workspace.ID); err != nil || got.Name != "Startup" {
		t.Fatalf("workspace = %#v, %v", got, err)
	}
	if _, err := f.store.InstanceAdministrator(ctx, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("signup granted instance role: %v", err)
	}
	if err := f.store.VerifyEmail(ctx, email.ID, f.now, f.event("verify")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.UserByEmail(ctx, email.Address); err != nil || got.ID != user.ID {
		t.Fatalf("verified lookup = %#v, %v", got, err)
	}
}

func TestCreateSignupVerified(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	user, email, _, password, workspace, membership := f.signupRecords(true)
	if err := f.store.CreateSignup(ctx, user, email, nil, password, workspace, membership, f.event("signup")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.UserByEmail(ctx, email.Address); err != nil || got.ID != user.ID {
		t.Fatalf("verified lookup = %#v, %v", got, err)
	}
	if _, storedVerification, err := f.store.EmailVerificationByID(ctx, email.ID); err != nil || storedVerification.Digest != nil {
		t.Fatalf("verified signup persisted a verification: %#v, %v", storedVerification, err)
	}
}

func TestCreateSignupConflicts(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	user, email, verification, password, workspace, membership := f.signupRecords(false)
	if err := f.store.CreateSignup(ctx, user, email, verification, password, workspace, membership, f.event("signup")); err != nil {
		t.Fatal(err)
	}
	// The unconfirmed address already reserves its uniqueness.
	other, otherEmail, otherVerification, otherPassword, otherWorkspace, otherMembership := f.signupRecords(false)
	otherEmail.Address = email.Address
	other.Email = email.Address
	if err := f.store.CreateSignup(ctx, other, otherEmail, otherVerification, otherPassword, otherWorkspace, otherMembership, f.event("signup.email.conflict")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate address = %v", err)
	}
	// Duplicate user and workspace identifiers also fail closed.
	duplicateUser, duplicateEmail, duplicateVerification, duplicatePassword, duplicateWorkspace, duplicateMembership := f.signupRecords(false)
	duplicateUser.ID = user.ID
	duplicateMembership.UserID = user.ID
	duplicateEmail.UserID = user.ID
	duplicateEmail.Address = "second@example.com"
	if err := f.store.CreateSignup(ctx, duplicateUser, duplicateEmail, duplicateVerification, duplicatePassword, duplicateWorkspace, duplicateMembership, f.event("signup.user.conflict")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate user id = %v", err)
	}
	conflictUser, conflictEmail, conflictVerification, conflictPassword, conflictWorkspace, conflictMembership := f.signupRecords(false)
	conflictEmail.Address = "third@example.com"
	conflictWorkspace.ID = workspace.ID
	conflictMembership.WorkspaceID = workspace.ID
	if err := f.store.CreateSignup(ctx, conflictUser, conflictEmail, conflictVerification, conflictPassword, conflictWorkspace, conflictMembership, f.event("signup.workspace.conflict")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate workspace id = %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := f.store.CreateSignup(canceled, conflictUser, conflictEmail, conflictVerification, conflictPassword, conflictWorkspace, conflictMembership, f.event("signup.canceled")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled signup = %v", err)
	}
}

func TestCreateSignupAtomicity(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	user, email, verification, password, workspace, membership := f.signupRecords(false)
	commit := f.event("signup.rollback")
	boom := errors.New("host write rejected")
	commit.Transactional = func(context.Context, credbound.Tx) error { return boom }
	if err := f.store.CreateSignup(ctx, user, email, verification, password, workspace, membership, commit); !errors.Is(err, boom) {
		t.Fatalf("rejected signup = %v", err)
	}
	if _, err := f.store.UserByID(ctx, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("user survived rollback: %v", err)
	}
	if _, err := f.store.WorkspaceByID(ctx, workspace.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("workspace survived rollback: %v", err)
	}
	if _, err := f.store.PasswordByUserID(ctx, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("password survived rollback: %v", err)
	}
	if _, err := f.store.Membership(ctx, workspace.ID, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("membership survived rollback: %v", err)
	}
	if _, _, err := f.store.EmailVerificationByID(ctx, email.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("email survived rollback: %v", err)
	}
	// The identifiers stay reusable after the rollback.
	if err := f.store.CreateSignup(ctx, user, email, verification, password, workspace, membership, f.event("signup.retry")); err != nil {
		t.Fatal(err)
	}
	f.store.SetAuditFailure(errors.New("disk full"))
	other, otherEmail, otherVerification, otherPassword, otherWorkspace, otherMembership := f.signupRecords(false)
	otherEmail.Address = "second@example.com"
	if err := f.store.CreateSignup(ctx, other, otherEmail, otherVerification, otherPassword, otherWorkspace, otherMembership, f.event("signup.audit")); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("audit failure = %v", err)
	}
	f.store.SetAuditFailure(nil)
	if _, err := f.store.UserByID(ctx, other.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("audit-failed signup persisted its user: %v", err)
	}
}
