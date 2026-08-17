package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

func (f *fixture) signupRecords(verified bool) (credbound.User, credbound.EmailAddress, *credbound.EmailVerificationCredential, credbound.PasswordCredential, credbound.Workspace, credbound.Membership) {
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
	f := newFixture(t)
	ctx := context.Background()
	user, email, verification, password, workspace, membership := f.signupRecords(false)
	if err := f.store.CreateSignup(ctx, user, email, verification, password, workspace, membership, f.event(user.ID, "signup", workspace.ID, workspace.ID)); err != nil {
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
	if got, err := f.store.PasswordByUserID(ctx, user.ID); err != nil || got.Hash != "hash" {
		t.Fatalf("password = %#v, %v", got, err)
	}
	if got, err := f.store.Membership(ctx, workspace.ID, user.ID); err != nil || got.Role != credbound.RoleAdmin || got.Status != credbound.MembershipActive {
		t.Fatalf("membership = %#v, %v", got, err)
	}
	if got, err := f.store.WorkspaceByID(ctx, workspace.ID); err != nil || got.Name != "Startup" {
		t.Fatalf("workspace = %#v, %v", got, err)
	}
	if _, err := f.store.InstanceAdministrator(ctx, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("signup granted instance role: %v", err)
	}
	if err := f.store.VerifyEmail(ctx, email.ID, f.now, f.event(user.ID, "email.verify", email.ID, "")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.UserByEmail(ctx, email.Address); err != nil || got.ID != user.ID {
		t.Fatalf("verified lookup = %#v, %v", got, err)
	}
}

func TestCreateSignupVerifiedAndConflicts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user, email, _, password, workspace, membership := f.signupRecords(true)
	if err := f.store.CreateSignup(ctx, user, email, nil, password, workspace, membership, f.event(user.ID, "signup", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.UserByEmail(ctx, email.Address); err != nil || got.ID != user.ID {
		t.Fatalf("verified lookup = %#v, %v", got, err)
	}
	// A second registration for the same address hits the uniqueness
	// constraint and fails with ErrConflict.
	other, otherEmail, otherVerification, otherPassword, otherWorkspace, otherMembership := f.signupRecords(false)
	otherEmail.Address = email.Address
	if err := f.store.CreateSignup(ctx, other, otherEmail, otherVerification, otherPassword, otherWorkspace, otherMembership, f.event(other.ID, "signup.conflict", otherWorkspace.ID, otherWorkspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate address = %v", err)
	}
	if _, err := f.store.UserByID(ctx, other.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("conflicting signup persisted its user: %v", err)
	}
}

func TestCreateSignupAtomicity(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user, email, verification, password, workspace, membership := f.signupRecords(false)
	commit := f.event(user.ID, "signup.rollback", workspace.ID, workspace.ID)
	boom := errors.New("host write rejected")
	commit.Transactional = func(context.Context, credbound.Tx) error { return boom }
	if err := f.store.CreateSignup(ctx, user, email, verification, password, workspace, membership, commit); !errors.Is(err, boom) {
		t.Fatalf("rejected signup = %v", err)
	}
	for name, check := range map[string]error{
		"user":      firstError(f.store.UserByID(ctx, user.ID)),
		"workspace": firstError(f.store.WorkspaceByID(ctx, workspace.ID)),
		"password":  firstError(f.store.PasswordByUserID(ctx, user.ID)),
	} {
		if !errors.Is(check, credbound.ErrNotFound) {
			t.Fatalf("%s survived rollback: %v", name, check)
		}
	}
	// The rolled-back identifiers stay reusable.
	if err := f.store.CreateSignup(ctx, user, email, verification, password, workspace, membership, f.event(user.ID, "signup.retry", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
}

func firstError[T any](_ T, err error) error { return err }
