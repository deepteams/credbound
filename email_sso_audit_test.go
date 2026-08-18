package credbound_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
)

func TestMultipleEmailLifecycleAndLastSeen(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	authn, _ := f.bootstrap(t)
	initial, err := f.store.UserByID(ctx, authn.UserID)
	if err != nil || initial.LastSeenAt == nil || !initial.LastSeenAt.Equal(f.now) {
		t.Fatalf("bootstrap last seen = %#v, %v", initial.LastSeenAt, err)
	}

	issued, err := f.manager.BeginEmailAddition(ctx, authn, " Alias@Example.com ")
	if err != nil || !uuidV7.MatchString(issued.Email.ID) || issued.Email.VerifiedAt != nil || issued.Token == "" {
		t.Fatalf("issued secondary email = %#v, %v", issued, err)
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "alias@example.com", "correct horse battery"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("unverified alias login = %v", err)
	}
	if _, err := f.manager.ConfirmEmail(ctx, issued.Token+"x"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("tampered email token = %v", err)
	}
	verified, err := f.manager.ConfirmEmail(ctx, issued.Token)
	if err != nil || verified.VerifiedAt == nil {
		t.Fatalf("verified email = %#v, %v", verified, err)
	}
	if _, err := f.manager.ConfirmEmail(ctx, issued.Token); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("reused email token = %v", err)
	}

	f.now = f.now.Add(time.Minute)
	aliasAuth, err := f.manager.AuthenticatePassword(ctx, "alias@example.com", "correct horse battery")
	if err != nil || aliasAuth.UserID != authn.UserID {
		t.Fatalf("verified alias login = %#v, %v", aliasAuth, err)
	}
	user, err := f.store.UserByID(ctx, authn.UserID)
	if err != nil || user.Email != "root@example.com" || user.LastSeenAt == nil || !user.LastSeenAt.Equal(f.now) {
		t.Fatalf("primary projection or last seen = %#v, %v", user, err)
	}
	if err := f.manager.SetPrimaryEmail(ctx, aliasAuth, issued.Email.ID); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("primary change without step-up = %v", err)
	}
	stepUp := aal2(authn.UserID, f.now)
	if err := f.manager.SetPrimaryEmail(ctx, stepUp, issued.Email.ID); err != nil {
		t.Fatal(err)
	}
	emails := collectEmails(t, f.manager.Emails(ctx, stepUp, authn.UserID, credbound.PageRequest{}))
	if len(emails) != 2 || countPrimary(emails) != 1 {
		t.Fatalf("email list = %#v", emails)
	}
	var oldPrimaryID string
	for _, email := range emails {
		if email.Address == "root@example.com" {
			oldPrimaryID = email.ID
		}
	}
	if err := f.manager.RemoveEmail(ctx, stepUp, oldPrimaryID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.RemoveEmail(ctx, stepUp, issued.Email.ID); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("primary email removal = %v", err)
	}
	if _, err := f.manager.BeginEmailAddition(ctx, stepUp, "alias@example.com"); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate email = %v", err)
	}
	user, err = f.store.UserByID(ctx, authn.UserID)
	if err != nil || user.Email != "alias@example.com" {
		t.Fatalf("new primary projection = %#v, %v", user, err)
	}
}

func TestClientAuditAPIControlsEnvelope(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	authn, workspace := f.bootstrap(t)
	if err := f.manager.RecordAudit(ctx, authn, credbound.AuditInput{
		Action: "billing.invoice.sent", ResourceType: "invoice", ResourceID: "inv_123",
		WorkspaceID: workspace.ID, Outcome: credbound.AuditSucceeded,
	}); err != nil {
		t.Fatal(err)
	}
	page := collectAuditPage(t, f.manager.AuditEvents(ctx, aal2(authn.UserID, f.now), workspace.ID, credbound.PageRequest{}))
	var recorded *credbound.AuditEvent
	for index := range page.items {
		if page.items[index].Action == "billing.invoice.sent" {
			recorded = &page.items[index]
		}
	}
	if recorded == nil || recorded.ActorID != authn.UserID || !uuidV7.MatchString(recorded.ID) || !recorded.OccurredAt.Equal(f.now) {
		t.Fatalf("manager-controlled audit envelope = %#v", recorded)
	}
	if err := f.manager.RecordAudit(ctx, authn, credbound.AuditInput{
		Action: "Bad Action", ResourceType: "invoice", ResourceID: "inv_123", WorkspaceID: workspace.ID, Outcome: credbound.AuditSucceeded,
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid client audit = %v", err)
	}
	if err := f.manager.RecordAudit(ctx, credbound.Authentication{}, credbound.AuditInput{
		Action: "billing.invoice.sent", ResourceType: "invoice", ResourceID: "inv_123", WorkspaceID: workspace.ID, Outcome: credbound.AuditSucceeded,
	}); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous client audit = %v", err)
	}
	if err := f.manager.RecordAudit(ctx, authn, credbound.AuditInput{
		Action: "billing.invoice.sent", ResourceType: "invoice", ResourceID: "inv_123", WorkspaceID: workspace.ID,
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid audit outcome = %v", err)
	}
	if err := f.manager.RecordAudit(ctx, authn, credbound.AuditInput{
		Action: "billing.invoice.sent", ResourceType: "invoice", ResourceID: "inv_123",
		WorkspaceID: "0198b463-0000-7000-8000-0000000000ee", Outcome: credbound.AuditFailed,
	}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("foreign workspace audit = %v", err)
	}
	if err := f.manager.RecordAudit(ctx, authn, credbound.AuditInput{
		Action: "billing.job.failed", ResourceType: "job", ResourceID: "job_123", Outcome: credbound.AuditFailed, Reason: "provider_error",
	}); err != nil {
		t.Fatalf("global admin audit = %v", err)
	}
	if err := f.manager.RecordAudit(ctx, authn, credbound.AuditInput{
		ResourceType: "job", ResourceID: "job_123", WorkspaceID: workspace.ID, Outcome: credbound.AuditFailed,
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("empty audit action = %v", err)
	}
	member, err := f.manager.CreateUser(ctx, aal2(authn.UserID, f.now), workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another secure password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.RecordAudit(ctx, aal2(member.ID, f.now), credbound.AuditInput{
		Action: "billing.job.failed", ResourceType: "job", ResourceID: "job_123", Outcome: credbound.AuditFailed,
	}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("global non-admin audit = %v", err)
	}
}

func TestSSOLinkLoginStepUpAndUnlink(t *testing.T) {
	provider := &fakeSSOProvider{
		configurationID: "0198b463-0000-7000-8000-0000000000aa", kind: credbound.SSOProviderOIDC,
		claims: credbound.SSOClaims{Issuer: "https://idp.example.com", Subject: "subject-1", Email: "root@example.com", EmailVerified: true},
	}
	f := newFixture(t, provider)
	ctx := context.Background()
	authn, _ := f.bootstrap(t)

	unknown, err := f.manager.BeginSSO(ctx, provider.configurationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.FinishSSO(ctx, unknown.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("SSO email auto-link occurred: %v", err)
	}

	link, err := f.manager.BeginSSOLink(ctx, authn, provider.configurationID)
	if err != nil || provider.lastRequest.ForceReauthentication {
		t.Fatalf("SSO link begin = %#v, %v", provider.lastRequest, err)
	}
	linked, err := f.manager.FinishSSO(ctx, link.Continuation, []byte("valid"))
	if err != nil || linked.Method != credbound.MethodSSO || linked.Level != credbound.AAL2 || linked.UserID != authn.UserID {
		t.Fatalf("SSO link = %#v, %v", linked, err)
	}
	duplicateLink, err := f.manager.BeginSSOLink(ctx, linked, provider.configurationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.FinishSSO(ctx, duplicateLink.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate SSO link = %v", err)
	}
	identities := collectSSOIdentities(t, f.manager.SSOIdentities(ctx, linked, credbound.PageRequest{}))
	if len(identities) != 1 || !uuidV7.MatchString(identities[0].ID) || identities[0].ProviderKind != credbound.SSOProviderOIDC {
		t.Fatalf("SSO identities = %#v", identities)
	}

	f.now = f.now.Add(time.Minute)
	login, err := f.manager.BeginSSO(ctx, provider.configurationID)
	if err != nil {
		t.Fatal(err)
	}
	ssoAuth, err := f.manager.FinishSSO(ctx, login.Continuation, []byte("valid"))
	if err != nil || ssoAuth.Level != credbound.AAL2 || ssoAuth.UserID != authn.UserID {
		t.Fatalf("SSO login = %#v, %v", ssoAuth, err)
	}
	// The ceremony is single use: replaying the same continuation and
	// captured response can never authenticate again within the TTL.
	if _, err := f.manager.FinishSSO(ctx, login.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("replayed SSO ceremony = %v", err)
	}
	user, err := f.store.UserByID(ctx, authn.UserID)
	if err != nil || user.LastSeenAt == nil || !user.LastSeenAt.Equal(f.now) {
		t.Fatalf("SSO last seen = %#v, %v", user.LastSeenAt, err)
	}
	stepUp, err := f.manager.BeginSSOStepUp(ctx, ssoAuth, provider.configurationID)
	if err != nil || !provider.lastRequest.ForceReauthentication {
		t.Fatalf("SSO step-up did not force IdP reauthentication: %#v, %v", provider.lastRequest, err)
	}
	if _, err := f.manager.FinishSSO(ctx, stepUp.Continuation, []byte("valid")); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.UnlinkSSO(ctx, ssoAuth, identities[0].ID); err != nil {
		t.Fatal(err)
	}
	login, err = f.manager.BeginSSO(ctx, provider.configurationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.FinishSSO(ctx, login.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("unlinked SSO login = %v", err)
	}
}

func TestEmailAndSSOFailureBoundaries(t *testing.T) {
	ctx := context.Background()
	emailFixture := newFixture(t)
	authn, _ := emailFixture.bootstrap(t)
	if _, err := emailFixture.manager.BeginEmailAddition(ctx, credbound.Authentication{}, "alias@example.com"); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous email addition = %v", err)
	}
	if _, err := emailFixture.manager.BeginEmailAddition(ctx, authn, "invalid"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid secondary email = %v", err)
	}
	if err := emailFixture.manager.SetPrimaryEmail(ctx, aal2(authn.UserID, emailFixture.now), "invalid"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid primary email id = %v", err)
	}
	if err := emailFixture.manager.RemoveEmail(ctx, authn, "invalid"); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("email removal without step-up = %v", err)
	}
	if err := emailFixture.manager.RemoveEmail(ctx, aal2(authn.UserID, emailFixture.now), "invalid"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid removed email id = %v", err)
	}
	missingToken := "cbe_0198b463-0000-7000-8000-0000000000ff_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := emailFixture.manager.ConfirmEmail(ctx, missingToken); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("unknown email proof = %v", err)
	}
	issued, err := emailFixture.manager.BeginEmailAddition(ctx, authn, "alias@example.com")
	if err != nil {
		t.Fatal(err)
	}
	mutated := issued.Token[:len(issued.Token)-1] + "A"
	if mutated == issued.Token {
		mutated = issued.Token[:len(issued.Token)-1] + "B"
	}
	if _, err := emailFixture.manager.ConfirmEmail(ctx, mutated); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("wrong email proof = %v", err)
	}
	emailFixture.now = emailFixture.now.Add(24 * time.Hour)
	if _, err := emailFixture.manager.ConfirmEmail(ctx, issued.Token); !errors.Is(err, credbound.ErrExpired) {
		t.Fatalf("expired email proof = %v", err)
	}
	assertEmailSequenceError(t, emailFixture.manager.Emails(ctx, credbound.Authentication{}, "", credbound.PageRequest{}), credbound.ErrUnauthorized)
	assertEmailSequenceError(t, emailFixture.manager.Emails(ctx, authn, "", credbound.PageRequest{Limit: 101}), credbound.ErrStepUpRequired)
	freshAuth := authn
	freshAuth.AuthenticatedAt = emailFixture.now
	assertEmailSequenceError(t, emailFixture.manager.Emails(ctx, freshAuth, "", credbound.PageRequest{Limit: 101}), credbound.ErrInvalidInput)
	if values := collectEmails(t, emailFixture.manager.Emails(ctx, freshAuth, "", credbound.PageRequest{})); len(values) != 2 {
		t.Fatalf("default self email list = %#v", values)
	}
	admin := aal2(authn.UserID, emailFixture.now)
	if values := collectEmails(t, emailFixture.manager.Emails(ctx, admin, "0198b463-0000-7000-8000-0000000000ee", credbound.PageRequest{})); len(values) != 0 {
		t.Fatalf("missing user's emails = %#v", values)
	}

	provider := &fakeSSOProvider{
		configurationID: "0198b463-0000-7000-8000-0000000000bb", kind: credbound.SSOProviderGitHub,
		claims: credbound.SSOClaims{Issuer: "https://github.com", Subject: "42"},
	}
	ssoFixture := newFixture(t, provider)
	authn, _ = ssoFixture.bootstrap(t)
	if _, err := ssoFixture.manager.BeginSSOLink(ctx, credbound.Authentication{}, provider.configurationID); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous SSO link = %v", err)
	}
	if _, err := ssoFixture.manager.BeginSSOStepUp(ctx, credbound.Authentication{}, provider.configurationID); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous SSO step-up = %v", err)
	}
	if _, err := ssoFixture.manager.BeginSSO(ctx, "0198b463-0000-7000-8000-0000000000ff"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown SSO provider = %v", err)
	}
	provider.beginErr = errors.New("provider offline")
	if _, err := ssoFixture.manager.BeginSSO(ctx, provider.configurationID); err == nil {
		t.Fatal("SSO provider begin failure ignored")
	}
	provider.beginErr = nil
	provider.incomplete = true
	if _, err := ssoFixture.manager.BeginSSO(ctx, provider.configurationID); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("incomplete SSO challenge = %v", err)
	}
	provider.incomplete = false
	if _, err := ssoFixture.manager.FinishSSO(ctx, "%%%", nil); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("malformed SSO continuation = %v", err)
	}
	link, err := ssoFixture.manager.BeginSSOLink(ctx, authn, provider.configurationID)
	if err != nil {
		t.Fatal(err)
	}
	provider.finishErr = errors.New("invalid callback")
	if _, err := ssoFixture.manager.FinishSSO(ctx, link.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("SSO callback failure = %v", err)
	}
	provider.finishErr = nil
	provider.claims = credbound.SSOClaims{}
	if _, err := ssoFixture.manager.FinishSSO(ctx, link.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("empty SSO claims = %v", err)
	}
	provider.claims = credbound.SSOClaims{Issuer: "https://github.com", Subject: "42", Email: "not-an-email"}
	if _, err := ssoFixture.manager.FinishSSO(ctx, link.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("invalid SSO email claim = %v", err)
	}
	provider.claims = credbound.SSOClaims{Issuer: "https://github.com", Subject: "42"}
	expiring, err := ssoFixture.manager.BeginSSO(ctx, provider.configurationID)
	if err != nil {
		t.Fatal(err)
	}
	ssoFixture.now = ssoFixture.now.Add(6 * time.Minute)
	if _, err := ssoFixture.manager.FinishSSO(ctx, expiring.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrExpired) {
		t.Fatalf("expired SSO continuation = %v", err)
	}
	if err := ssoFixture.manager.UnlinkSSO(ctx, authn, "invalid"); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("SSO unlink without step-up = %v", err)
	}
	if err := ssoFixture.manager.UnlinkSSO(ctx, aal2(authn.UserID, ssoFixture.now), "invalid"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid SSO identity id = %v", err)
	}
	assertSSOSequenceError(t, ssoFixture.manager.SSOIdentities(ctx, credbound.Authentication{}, credbound.PageRequest{}), credbound.ErrUnauthorized)
	assertSSOSequenceError(t, ssoFixture.manager.SSOIdentities(ctx, aal2(authn.UserID, ssoFixture.now), credbound.PageRequest{Limit: 101}), credbound.ErrInvalidInput)
}

func collectEmails(t *testing.T, sequence func(func(credbound.PageEvent[credbound.EmailAddress], error) bool)) []credbound.EmailAddress {
	t.Helper()
	var values []credbound.EmailAddress
	for event, err := range sequence {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			values = append(values, *event.Data)
		}
	}
	return values
}

func countPrimary(emails []credbound.EmailAddress) int {
	count := 0
	for _, email := range emails {
		if email.Primary {
			count++
		}
	}
	return count
}

func collectSSOIdentities(t *testing.T, sequence func(func(credbound.PageEvent[credbound.SSOIdentity], error) bool)) []credbound.SSOIdentity {
	t.Helper()
	var values []credbound.SSOIdentity
	for event, err := range sequence {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			values = append(values, *event.Data)
		}
	}
	return values
}

func assertEmailSequenceError(t *testing.T, sequence func(func(credbound.PageEvent[credbound.EmailAddress], error) bool), target error) {
	t.Helper()
	for _, err := range sequence {
		if !errors.Is(err, target) {
			t.Fatalf("email sequence error = %v, want %v", err, target)
		}
		return
	}
	t.Fatal("email sequence yielded no error")
}

func assertSSOSequenceError(t *testing.T, sequence func(func(credbound.PageEvent[credbound.SSOIdentity], error) bool), target error) {
	t.Helper()
	for _, err := range sequence {
		if !errors.Is(err, target) {
			t.Fatalf("SSO sequence error = %v, want %v", err, target)
		}
		return
	}
	t.Fatal("SSO sequence yielded no error")
}

type fakeSSOProvider struct {
	configurationID string
	kind            credbound.SSOProviderKind
	claims          credbound.SSOClaims
	lastRequest     credbound.SSORequest
	beginErr        error
	finishErr       error
	incomplete      bool
}

func (f *fakeSSOProvider) ConfigurationID() string         { return f.configurationID }
func (f *fakeSSOProvider) Kind() credbound.SSOProviderKind { return f.kind }
func (f *fakeSSOProvider) Begin(_ context.Context, request credbound.SSORequest) (credbound.SSOProviderChallenge, error) {
	f.lastRequest = request
	if f.beginErr != nil {
		return credbound.SSOProviderChallenge{}, f.beginErr
	}
	if f.incomplete {
		return credbound.SSOProviderChallenge{}, nil
	}
	return credbound.SSOProviderChallenge{RedirectURL: "https://idp.example.com/authorize", Session: []byte("session")}, nil
}
func (f *fakeSSOProvider) Finish(_ context.Context, session, response []byte) (credbound.SSOClaims, error) {
	if f.finishErr != nil {
		return credbound.SSOClaims{}, f.finishErr
	}
	if string(session) != "session" || string(response) != "valid" {
		return credbound.SSOClaims{}, errors.New("invalid SSO response")
	}
	return f.claims, nil
}

func TestSSOAssurancePolicy(t *testing.T) {
	provider := &fakeSSOProvider{
		configurationID: "0198b463-0000-7000-8000-0000000000bb", kind: credbound.SSOProviderOIDC,
		claims: credbound.SSOClaims{Issuer: "https://idp.example.com", Subject: "subject-2"},
	}
	store := memory.New()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	manager, err := credbound.New(credbound.Config{
		Store: store, Passwords: &fakePasswords{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return now }, Random: &counterReader{next: 0x51},
		SSOProviders: []credbound.SSOProvider{provider},
		SSOAssurance: map[string]credbound.SSOAssurancePolicy{
			provider.configurationID: {AcceptedACR: []string{"urn:example:mfa"}, RequiredAMR: []string{"mfa"}},
		},
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

	// Without the required assurance the ceremony fails before any link.
	link, err := manager.BeginSSOLink(ctx, authn, provider.configurationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.FinishSSO(ctx, link.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("unasserted MFA error = %v", err)
	}

	// The full assurance satisfies the policy: link, then sign in.
	provider.claims.ACR, provider.claims.AMR = "urn:example:mfa", []string{"pwd", "mfa"}
	link, err = manager.BeginSSOLink(ctx, authn, provider.configurationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.FinishSSO(ctx, link.Continuation, []byte("valid")); err != nil {
		t.Fatalf("asserted MFA link = %v", err)
	}
	login, err := manager.BeginSSO(ctx, provider.configurationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.FinishSSO(ctx, login.Continuation, []byte("valid")); err != nil {
		t.Fatalf("asserted MFA login = %v", err)
	}

	// Losing a required AMR method fails again, and never at AAL2.
	provider.claims.AMR = []string{"pwd"}
	login, err = manager.BeginSSO(ctx, provider.configurationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.FinishSSO(ctx, login.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("downgraded AMR error = %v", err)
	}

	// Config validation: unknown configuration and empty policy are rejected.
	if _, err := credbound.New(credbound.Config{
		Store: store, Passwords: &fakePasswords{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		SSOProviders: []credbound.SSOProvider{provider},
		SSOAssurance: map[string]credbound.SSOAssurancePolicy{"0198b463-0000-7000-8000-0000000000cc": {AcceptedACR: []string{"x"}}},
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("unregistered policy error = %v", err)
	}
	if _, err := credbound.New(credbound.Config{
		Store: store, Passwords: &fakePasswords{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		SSOProviders: []credbound.SSOProvider{provider},
		SSOAssurance: map[string]credbound.SSOAssurancePolicy{provider.configurationID: {}},
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("empty policy error = %v", err)
	}
}

// TestSSOAAL1WithoutAssurance locks the fail-safe default: a provider with no
// assurance policy authenticates at AAL1, never AAL2, so an unverified IdP
// cannot satisfy a RequireMFA workspace or a step-up on its own word.
func TestSSOAAL1WithoutAssurance(t *testing.T) {
	provider := &fakeSSOProvider{
		configurationID: "0198b463-0000-7000-8000-0000000000dd", kind: credbound.SSOProviderOIDC,
		claims: credbound.SSOClaims{Issuer: "https://idp.example.com", Subject: "subject-3", Email: "root@example.com", EmailVerified: true},
	}
	store := memory.New()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	manager, err := credbound.New(credbound.Config{
		Store: store, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return now }, Random: &counterReader{next: 0x62},
		StepUpMaxAge: 10 * time.Minute, CeremonyTTL: 5 * time.Minute,
		SSOProviders: []credbound.SSOProvider{provider},
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

	link, err := manager.BeginSSOLink(ctx, authn, provider.configurationID)
	if err != nil {
		t.Fatal(err)
	}
	linked, err := manager.FinishSSO(ctx, link.Continuation, []byte("valid"))
	if err != nil || linked.Level != credbound.AAL1 {
		t.Fatalf("unverified SSO link level = %#v, %v", linked, err)
	}

	login, err := manager.BeginSSO(ctx, provider.configurationID)
	if err != nil {
		t.Fatal(err)
	}
	signedIn, err := manager.FinishSSO(ctx, login.Continuation, []byte("valid"))
	if err != nil || signedIn.Level != credbound.AAL1 {
		t.Fatalf("unverified SSO sign-in level = %#v, %v", signedIn, err)
	}
}
