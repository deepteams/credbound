package credbound_test

import (
	"context"
	"errors"
	"testing"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
)

func TestOptionalSecondFactorProviders(t *testing.T) {
	manager, err := credbound.New(credbound.Config{
		Store: memory.New(), Passwords: &fakePasswords{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Random: &counterReader{next: 0x42},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	authn, _, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.BeginTOTPEnrollment(ctx, authn); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("TOTP enrollment without provider = %v", err)
	}
	if _, err := manager.ConfirmTOTPEnrollment(ctx, authn, "123456"); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("TOTP confirmation without provider = %v", err)
	}
	if _, err := manager.VerifyTOTP(ctx, authn, "123456"); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("TOTP verification without provider = %v", err)
	}
	if err := manager.DisableTOTP(ctx, authn, "123456"); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("TOTP disable without provider = %v", err)
	}
	if _, err := manager.BeginPasskeyRegistration(ctx, authn, "laptop"); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("passkey registration without provider = %v", err)
	}
	if _, err := manager.FinishPasskeyRegistration(ctx, authn, "state", nil); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("passkey finish registration without provider = %v", err)
	}
	if _, err := manager.BeginPasskeyAuthentication(ctx, "root@example.com"); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("passkey authentication without provider = %v", err)
	}
	if _, err := manager.FinishPasskeyAuthentication(ctx, "state", nil); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("passkey finish authentication without provider = %v", err)
	}
	// Everything else keeps working without the optional providers.
	if _, err := manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err != nil {
		t.Fatalf("password login without optional providers = %v", err)
	}
	if status, err := manager.TOTPStatus(ctx, authn, credbound.UUID{}); err != nil || status.Enrolled {
		t.Fatalf("TOTP status without provider = %#v, %v", status, err)
	}
}

func TestCollectPageAndValidationError(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	stepUp := aal2(authn.UserID, f.now)
	for _, name := range []string{"laptop", "phone"} {
		if _, err := f.manager.CreatePAT(ctx, stepUp, credbound.CreatePATInput{
			Name: name, WorkspaceID: workspace.ID, Scopes: []string{"read"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	pats, page, err := credbound.CollectPage(f.manager.PATs(ctx, authn, credbound.UUID{}, credbound.PageRequest{Limit: 1}))
	if err != nil || len(pats) != 1 || !page.HasMore || page.NextCursor == "" {
		t.Fatalf("first page = %d items, %#v, %v", len(pats), page, err)
	}
	rest, last, err := credbound.CollectPage(f.manager.PATs(ctx, authn, credbound.UUID{}, credbound.PageRequest{Cursor: page.NextCursor, Limit: 10}))
	if err != nil || len(rest) != 1 || last.HasMore {
		t.Fatalf("second page = %d items, %#v, %v", len(rest), last, err)
	}
	if _, _, err := credbound.CollectPage(f.manager.PATs(ctx, credbound.Authentication{}, credbound.UUID{}, credbound.PageRequest{})); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("collect error passthrough = %v", err)
	}

	_, err = f.manager.CreateUser(ctx, stepUp, workspace.ID, credbound.CreateUserInput{
		Email: "not-an-email", DisplayName: "X", Password: "another strong password", Role: credbound.RoleMember,
	})
	var validation *credbound.ValidationError
	if !errors.As(err, &validation) || validation.Field != "email" || validation.Rule != "format" {
		t.Fatalf("email validation = %#v, %v", validation, err)
	}
	if !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("validation sentinel = %v", err)
	}
	_, err = f.manager.CreateUser(ctx, stepUp, workspace.ID, credbound.CreateUserInput{
		Email: "short@example.com", DisplayName: "X", Password: "tiny", Role: credbound.RoleMember,
	})
	if !errors.As(err, &validation) || validation.Field != "password" || validation.Rule != "too_short" {
		t.Fatalf("password validation = %#v, %v", validation, err)
	}
}

// TestTrustedRequestFromAddr pins ADMIN-006: the server adapter sets Local
// only from the actually observed loopback peer address — never from a value
// a remote client could supply.
func TestTrustedRequestFromAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:52441":   true,
		"[::1]:8080":        true,
		"::1":               true,
		"203.0.113.9:443":   false,
		"[2001:db8::1]:443": false,
		"not-an-address":    false,
		"":                  false,
	}
	for addr, local := range cases {
		if got := credbound.TrustedRequestFromAddr(addr); got.Local != local {
			t.Fatalf("TrustedRequestFromAddr(%q).Local = %v, want %v", addr, got.Local, local)
		}
	}
}
