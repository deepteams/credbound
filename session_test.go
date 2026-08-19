package credbound_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
)

type sessionRecorder struct {
	credbound.UnimplementedEventListener
	created     []credbound.SessionCreatedEvent
	revoked     []credbound.SessionRevokedEvent
	userRevoked []credbound.UserSessionsRevokedEvent
}

func (r *sessionRecorder) OnSessionCreated(_ context.Context, event credbound.SessionCreatedEvent) error {
	r.created = append(r.created, event)
	return nil
}

func (r *sessionRecorder) OnSessionRevoked(_ context.Context, event credbound.SessionRevokedEvent) error {
	r.revoked = append(r.revoked, event)
	return nil
}

func (r *sessionRecorder) OnUserSessionsRevoked(_ context.Context, event credbound.UserSessionsRevokedEvent) error {
	r.userRevoked = append(r.userRevoked, event)
	return nil
}

func deviceContext() context.Context {
	return credbound.WithRequestMetadata(context.Background(), credbound.RequestMetadata{
		IPAddress: "203.0.113.7", UserAgent: "Mozilla/5.0 (Macintosh)",
	})
}

func collectSessions(t *testing.T, sequence func(func(credbound.PageEvent[credbound.Session], error) bool)) ([]credbound.Session, *credbound.PageEnd) {
	t.Helper()
	var items []credbound.Session
	var end *credbound.PageEnd
	for event, err := range sequence {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			items = append(items, *event.Data)
		}
		if event.End != nil {
			end = event.End
		}
	}
	return items, end
}

func sessionsError(sequence func(func(credbound.PageEvent[credbound.Session], error) bool)) error {
	for _, err := range sequence {
		return err
	}
	return nil
}

// TestSessionLifecycle pins SESS-001: a session persists an Authentication
// snapshot behind an opaque single-display cbs_ token, authenticates requests
// from that token, and lists every active session with its device metadata.
func TestSessionLifecycle(t *testing.T) {
	f := newFixture(t)
	recorder := &sessionRecorder{}
	f.manager.AddEventListener(recorder)
	authn, _ := f.bootstrap(t)
	ctx := deviceContext()

	issued, err := f.manager.CreateSession(ctx, authn, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(issued.Token, "_", 3)
	if len(parts) != 3 || parts[0] != "cbs" || !uuidV7.MatchString(parts[1]) || len(parts[2]) != 43 {
		t.Fatalf("token shape = %q", issued.Token)
	}
	session := issued.Session
	if parts[1] != session.ID.String() || session.Digest != nil {
		t.Fatalf("issued session leaked or mismatched: %#v", session)
	}
	if session.UserID != authn.UserID || session.Method != credbound.MethodPassword || session.Level != credbound.AAL1 ||
		!session.AuthenticatedAt.Equal(authn.AuthenticatedAt) || session.SecondFactorRequired {
		t.Fatalf("snapshot = %#v", session)
	}
	if session.UserAgent != "Mozilla/5.0 (Macintosh)" || session.IPAddress != "203.0.113.7" {
		t.Fatalf("device metadata = %#v", session)
	}
	if !session.ExpiresAt.Equal(session.CreatedAt.Add(30 * 24 * time.Hour)) {
		t.Fatalf("default TTL = %v .. %v", session.CreatedAt, session.ExpiresAt)
	}
	if len(recorder.created) != 1 || recorder.created[0].Session.ID != session.ID ||
		recorder.created[0].Session.Digest != nil || recorder.created[0].Request.IPAddress != "203.0.113.7" {
		t.Fatalf("session.created event = %#v", recorder.created)
	}

	// SESS-002: authentication restores the snapshot verbatim — the assurance
	// level never changes in place — and touches last-seen.
	f.now = f.now.Add(time.Minute)
	restored, live, err := f.manager.AuthenticateSession(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	if restored.UserID != authn.UserID || restored.Method != credbound.MethodPassword || restored.Level != credbound.AAL1 ||
		!restored.AuthenticatedAt.Equal(authn.AuthenticatedAt) || restored.SecondFactorRequired {
		t.Fatalf("restored authentication = %#v", restored)
	}
	if live.ID != session.ID || live.Digest != nil || !live.LastSeenAt.Equal(f.now) {
		t.Fatalf("live session = %#v", live)
	}
	user, err := f.store.UserByID(context.Background(), authn.UserID)
	if err != nil || user.LastSeenAt == nil || !user.LastSeenAt.Equal(f.now) {
		t.Fatalf("user last seen = %#v, %v", user, err)
	}

	listActor := authn
	listActor.AuthenticatedAt = f.now
	listed, end := collectSessions(t, f.manager.Sessions(context.Background(), listActor, credbound.UUID{}, credbound.PageRequest{}))
	if len(listed) != 1 || end == nil || end.HasMore {
		t.Fatalf("sessions page = %#v %#v", listed, end)
	}
	if listed[0].Digest != nil || listed[0].UserAgent != "Mozilla/5.0 (Macintosh)" || listed[0].IPAddress != "203.0.113.7" || !listed[0].LastSeenAt.Equal(f.now) {
		t.Fatalf("listed session = %#v", listed[0])
	}

	if err := f.manager.RevokeSession(context.Background(), aal2(authn.UserID, f.now), session.ID); err != nil {
		t.Fatal(err)
	}
	if len(recorder.revoked) != 1 || recorder.revoked[0].SessionID != session.ID || recorder.revoked[0].UserID != authn.UserID {
		t.Fatalf("session.revoked event = %#v", recorder.revoked)
	}
	if _, _, err := f.manager.AuthenticateSession(ctx, issued.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("revoked session error = %v", err)
	}
	listed, _ = collectSessions(t, f.manager.Sessions(context.Background(), listActor, authn.UserID, credbound.PageRequest{}))
	if len(listed) != 1 || listed[0].RevokedAt == nil {
		t.Fatalf("revoked listing = %#v", listed)
	}
	// Revoking the same session again stays idempotent.
	if err := f.manager.RevokeSession(context.Background(), aal2(authn.UserID, f.now), session.ID); err != nil {
		t.Fatal(err)
	}
}

func TestSessionTokenForgery(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()
	issued, err := f.manager.CreateSession(ctx, authn, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	// A forged secret with a valid identifier is rejected.
	if _, _, err := f.manager.AuthenticateSession(ctx, forgeSecret(issued.Token)); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("forged secret error = %v", err)
	}
	// A well-formed token with an unknown identifier is rejected too.
	ghost := "cbs_" + authn.UserID.String() + "_" + strings.Repeat("A", 43)
	if _, _, err := f.manager.AuthenticateSession(ctx, ghost); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("unknown session error = %v", err)
	}
	for _, malformed := range []string{"", "cbs_bogus", "cbp_" + authn.UserID.String() + "_" + strings.Repeat("A", 43), issued.Token + "x"} {
		if _, _, err := f.manager.AuthenticateSession(ctx, malformed); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("malformed token %q error = %v", malformed, err)
		}
	}
	// The intact token still works after all the rejections.
	if _, _, err := f.manager.AuthenticateSession(ctx, issued.Token); err != nil {
		t.Fatal(err)
	}
}

// TestSessionExpiryIsAbsolute proves the expiry clause of SESS-002: session
// authentication re-checks expiry on every call, and activity never extends
// the absolute deadline.
func TestSessionExpiryIsAbsolute(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()
	issued, err := f.manager.CreateSession(ctx, authn, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	// Activity one day before the deadline succeeds but never extends it.
	f.now = f.now.Add(29 * 24 * time.Hour)
	if _, _, err := f.manager.AuthenticateSession(ctx, issued.Token); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(24 * time.Hour)
	if _, _, err := f.manager.AuthenticateSession(ctx, issued.Token); !errors.Is(err, credbound.ErrExpired) {
		t.Fatalf("expired session error = %v", err)
	}

	// Config.SessionTTL overrides the 30-day default.
	custom, err := credbound.New(credbound.Config{
		Store: f.store, Passwords: f.passwords, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return f.now }, Random: &counterReader{next: 0x24},
		SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	short, err := custom.CreateSession(ctx, credbound.Authentication{UserID: authn.UserID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: f.now}, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	if !short.Session.ExpiresAt.Equal(short.Session.CreatedAt.Add(time.Hour)) {
		t.Fatalf("custom TTL = %v .. %v", short.Session.CreatedAt, short.Session.ExpiresAt)
	}
	f.now = f.now.Add(2 * time.Hour)
	if _, _, err := custom.AuthenticateSession(ctx, short.Token); !errors.Is(err, credbound.ErrExpired) {
		t.Fatalf("custom TTL expiry error = %v", err)
	}
}

func TestSessionIdleTimeout(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()
	manager, err := credbound.New(credbound.Config{
		Store: f.store, Passwords: f.passwords, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return f.now }, Random: &counterReader{next: 0x51},
		SessionTTL: 30 * 24 * time.Hour, SessionIdleTimeout: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := manager.CreateSession(ctx, credbound.Authentication{UserID: authn.UserID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: f.now}, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	// Activity within the window refreshes last-seen and slides the window.
	f.now = f.now.Add(10 * time.Minute)
	if _, _, err := manager.AuthenticateSession(ctx, issued.Token); err != nil {
		t.Fatalf("active session rejected = %v", err)
	}
	f.now = f.now.Add(10 * time.Minute)
	if _, _, err := manager.AuthenticateSession(ctx, issued.Token); err != nil {
		t.Fatalf("session within slid window rejected = %v", err)
	}
	// Idle beyond the timeout expires it, well before the absolute TTL.
	f.now = f.now.Add(16 * time.Minute)
	if _, _, err := manager.AuthenticateSession(ctx, issued.Token); !errors.Is(err, credbound.ErrExpired) {
		t.Fatalf("idle session error = %v", err)
	}
}

// TestSessionTouchInterval pins the coarsened write contract of
// Config.SessionTouchInterval: within the interval a successful validation
// performs no write — last-seen stays as persisted — while a revocation
// still takes effect on the very next request; past the interval the touch
// resumes; and a configuration that could defeat the idle timeout, or a
// negative interval, is refused at construction.
func TestSessionTouchInterval(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()
	manager, err := credbound.New(credbound.Config{
		Store: f.store, Passwords: f.passwords, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return f.now }, Random: &counterReader{next: 0x71},
		SessionTouchInterval: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := manager.CreateSession(ctx, credbound.Authentication{UserID: authn.UserID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: f.now}, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	created := issued.Session.LastSeenAt
	f.now = f.now.Add(2 * time.Minute)
	if _, session, err := manager.AuthenticateSession(ctx, issued.Token); err != nil || !session.LastSeenAt.Equal(created) {
		t.Fatalf("validation within the interval must stay read-only: %#v, %v", session, err)
	}
	f.now = f.now.Add(4 * time.Minute)
	if _, session, err := manager.AuthenticateSession(ctx, issued.Token); err != nil || !session.LastSeenAt.Equal(f.now) {
		t.Fatalf("validation past the interval must touch last-seen: %#v, %v", session, err)
	}
	// Revocation is checked against the store on every call, so it bites on
	// the next request even inside the interval window.
	if err := manager.SignOut(ctx, issued.Token); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Minute)
	if _, _, err := manager.AuthenticateSession(ctx, issued.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("revoked session within the interval = %v", err)
	}

	for name, mutate := range map[string]func(*credbound.Config){
		"negative interval": func(c *credbound.Config) { c.SessionTouchInterval = -time.Second },
		"interval not below idle window": func(c *credbound.Config) {
			c.SessionIdleTimeout = 15 * time.Minute
			c.SessionTouchInterval = 15 * time.Minute
		},
	} {
		config := credbound.Config{
			Store: f.store, Passwords: f.passwords, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
			SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		}
		mutate(&config)
		if _, err := credbound.New(config); !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("%s: New = %v", name, err)
		}
	}
}

func TestCreateSessionAuthorization(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	if _, err := f.manager.CreateSession(ctx, credbound.Authentication{}, credbound.CreateSessionInput{}); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous create error = %v", err)
	}
	// A PAT-backed Authentication is non-interactive and cannot mint a session.
	issued, err := f.manager.CreatePAT(ctx, aal2(authn.UserID, f.now), credbound.CreatePATInput{Name: "cli", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	patAuth, err := f.manager.AuthenticatePAT(ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.CreateSession(ctx, patAuth, credbound.CreateSessionInput{}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("PAT-backed create error = %v", err)
	}
	// A disabled user's Authentication no longer creates sessions.
	member, err := f.manager.CreateUser(ctx, aal2(authn.UserID, f.now), workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	memberAuthn := credbound.Authentication{UserID: member.ID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: f.now}
	if err := f.manager.DisableUser(ctx, authn, credbound.TrustedRequest{Local: true}, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.CreateSession(ctx, memberAuthn, credbound.CreateSessionInput{}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("disabled user create error = %v", err)
	}
}

func TestSessionsOnBehalfAuthorization(t *testing.T) {
	f := newFixture(t)
	root, workspace := f.bootstrap(t)
	ctx := context.Background()
	member, err := f.manager.CreateUser(ctx, aal2(root.UserID, f.now), workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	memberAuthn := credbound.Authentication{UserID: member.ID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: f.now}
	if _, err := f.manager.CreateSession(ctx, memberAuthn, credbound.CreateSessionInput{}); err != nil {
		t.Fatal(err)
	}

	if err := sessionsError(f.manager.Sessions(ctx, credbound.Authentication{}, credbound.UUID{}, credbound.PageRequest{})); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous listing error = %v", err)
	}
	// Self listing needs only a recent interactive authentication.
	if items, _ := collectSessions(t, f.manager.Sessions(ctx, memberAuthn, member.ID, credbound.PageRequest{})); len(items) != 1 {
		t.Fatalf("self listing = %#v", items)
	}
	// A stale interactive context cannot list, even for itself.
	stale := memberAuthn
	stale.AuthenticatedAt = f.now.Add(-time.Hour)
	if err := sessionsError(f.manager.Sessions(ctx, stale, credbound.UUID{}, credbound.PageRequest{})); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("stale self listing error = %v", err)
	}
	// Another user requires a fresh AAL2 step-up and admin users read.
	if err := sessionsError(f.manager.Sessions(ctx, root, member.ID, credbound.PageRequest{})); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 admin listing error = %v", err)
	}
	if items, _ := collectSessions(t, f.manager.Sessions(ctx, aal2(root.UserID, f.now), member.ID, credbound.PageRequest{})); len(items) != 1 {
		t.Fatalf("admin listing = %#v", items)
	}
	if err := sessionsError(f.manager.Sessions(ctx, aal2(member.ID, f.now), root.UserID, credbound.PageRequest{})); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("non-admin on-behalf listing error = %v", err)
	}
	// The invalid page limit is rejected after authorization.
	if err := sessionsError(f.manager.Sessions(ctx, memberAuthn, credbound.UUID{}, credbound.PageRequest{Limit: 500})); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("page limit error = %v", err)
	}
}

func TestRevokeSessionAuthorization(t *testing.T) {
	f := newFixture(t)
	root, workspace := f.bootstrap(t)
	ctx := context.Background()
	member, err := f.manager.CreateUser(ctx, aal2(root.UserID, f.now), workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	memberAuthn := credbound.Authentication{UserID: member.ID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: f.now}
	issued, err := f.manager.CreateSession(ctx, memberAuthn, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.RevokeSession(ctx, memberAuthn, issued.Session.ID); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 revoke error = %v", err)
	}
	if err := f.manager.RevokeSession(ctx, aal2(member.ID, f.now), credbound.UUID{}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("empty id error = %v", err)
	}
	if err := f.manager.RevokeSession(ctx, aal2(member.ID, f.now), member.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown session error = %v", err)
	}
	// Another user's session — even for the root administrator — reads as absent.
	if err := f.manager.RevokeSession(ctx, aal2(root.UserID, f.now), issued.Session.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("foreign session revoke error = %v", err)
	}
	if err := f.manager.RevokeSession(ctx, aal2(member.ID, f.now), issued.Session.ID); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeUserSessions(t *testing.T) {
	f := newFixture(t)
	recorder := &sessionRecorder{}
	f.manager.AddEventListener(recorder)
	root, workspace := f.bootstrap(t)
	ctx := context.Background()
	member, err := f.manager.CreateUser(ctx, aal2(root.UserID, f.now), workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	memberAuthn := credbound.Authentication{UserID: member.ID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: f.now}
	first, err := f.manager.CreateSession(ctx, memberAuthn, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.manager.CreateSession(ctx, memberAuthn, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.RevokeUserSessions(ctx, memberAuthn, credbound.TrustedRequest{}, credbound.UUID{}); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 self bulk revoke error = %v", err)
	}
	if err := f.manager.RevokeUserSessions(ctx, aal2(member.ID, f.now), credbound.TrustedRequest{}, credbound.MustParseUUID("00000000-0000-4000-8000-000000000000")); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid user id error = %v", err)
	}
	// A non-administrator cannot log out another user.
	if err := f.manager.RevokeUserSessions(ctx, aal2(member.ID, f.now), credbound.TrustedRequest{Local: true}, root.UserID); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("non-admin bulk revoke error = %v", err)
	}
	// Self "log out everywhere" with a fresh step-up.
	if err := f.manager.RevokeUserSessions(ctx, aal2(member.ID, f.now), credbound.TrustedRequest{}, credbound.UUID{}); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{first.Token, second.Token} {
		if _, _, err := f.manager.AuthenticateSession(ctx, token); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("session survived bulk revocation: %v", err)
		}
	}
	if len(recorder.userRevoked) != 1 || recorder.userRevoked[0].UserID != member.ID {
		t.Fatalf("session.user_revoked event = %#v", recorder.userRevoked)
	}
	// An administrator revokes through a trusted local request without AAL2.
	third, err := f.manager.CreateSession(ctx, memberAuthn, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.RevokeUserSessions(ctx, root, credbound.TrustedRequest{Local: true}, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.manager.AuthenticateSession(ctx, third.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("session survived administrative revocation: %v", err)
	}
}

// TestSessionRevocationCascades pins SESS-003: completing a password reset,
// disabling a user, and revoking a user's credentials all revoke that user's
// sessions.
func TestSessionRevocationCascades(t *testing.T) {
	f := newFixture(t)
	root, workspace := f.bootstrap(t)
	ctx := context.Background()
	newMember := func(email string) (credbound.User, credbound.IssuedSession) {
		t.Helper()
		member, err := f.manager.CreateUser(ctx, aal2(root.UserID, f.now), workspace.ID, credbound.CreateUserInput{
			Email: email, DisplayName: "Member", Password: "another strong password", Role: credbound.RoleMember,
		})
		if err != nil {
			t.Fatal(err)
		}
		authn := credbound.Authentication{UserID: member.ID, Method: credbound.MethodPassword, Level: credbound.AAL1, AuthenticatedAt: f.now}
		issued, err := f.manager.CreateSession(ctx, authn, credbound.CreateSessionInput{})
		if err != nil {
			t.Fatal(err)
		}
		return member, issued
	}

	// Completing a password reset revokes the user's sessions atomically.
	_, resetSession := newMember("reset@example.com")
	reset, err := f.manager.BeginPasswordReset(ctx, "reset@example.com")
	if err != nil || reset.Token == "" {
		t.Fatalf("reset = %#v, %v", reset, err)
	}
	if _, err := f.manager.CompletePasswordReset(ctx, reset.Token, "a brand new password"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.manager.AuthenticateSession(ctx, resetSession.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("session survived password reset: %v", err)
	}

	// Disabling the user revokes sessions; re-enabling does not restore them.
	disabled, disabledSession := newMember("disabled@example.com")
	if err := f.manager.DisableUser(ctx, root, credbound.TrustedRequest{Local: true}, disabled.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.EnableUser(ctx, root, credbound.TrustedRequest{Local: true}, disabled.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.manager.AuthenticateSession(ctx, disabledSession.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("session survived user disable: %v", err)
	}

	// Revoking a user's credentials includes their sessions.
	revoked, revokedSession := newMember("revoked@example.com")
	if err := f.manager.RevokeUserCredentials(ctx, root, credbound.TrustedRequest{Local: true}, revoked.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.manager.AuthenticateSession(ctx, revokedSession.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("session survived credential revocation: %v", err)
	}
}

func TestSessionNotSupported(t *testing.T) {
	limited, err := credbound.New(credbound.Config{
		Store: coreStore{Store: memory.New()}, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	actor := aal2(credbound.MustParseUUID("0198b463-0000-7000-8000-0000000000aa"), time.Now())
	if _, err := limited.CreateSession(ctx, actor, credbound.CreateSessionInput{}); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("create error = %v", err)
	}
	if _, _, err := limited.AuthenticateSession(ctx, "cbs_x_y"); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("authenticate error = %v", err)
	}
	if err := sessionsError(limited.Sessions(ctx, actor, credbound.UUID{}, credbound.PageRequest{})); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("list error = %v", err)
	}
	if err := limited.RevokeSession(ctx, actor, credbound.MustParseUUID("0198b463-0000-7000-8000-0000000000ab")); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("revoke error = %v", err)
	}
	if err := limited.RevokeUserSessions(ctx, actor, credbound.TrustedRequest{}, credbound.UUID{}); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("bulk revoke error = %v", err)
	}
}

// sessionFaultStore injects lookup failures around the embedded memory
// store's session capability.
type sessionFaultStore struct {
	*memory.Store
	sessionByIDErr error
	userByIDErr    error
}

func (s *sessionFaultStore) SessionByID(ctx context.Context, id credbound.UUID) (credbound.Session, error) {
	if s.sessionByIDErr != nil {
		return credbound.Session{}, s.sessionByIDErr
	}
	return s.Store.SessionByID(ctx, id)
}

func (s *sessionFaultStore) UserByID(ctx context.Context, id credbound.UUID) (credbound.User, error) {
	if s.userByIDErr != nil {
		return credbound.User{}, s.userByIDErr
	}
	return s.Store.UserByID(ctx, id)
}

func TestSessionAuditUnavailableAndFaults(t *testing.T) {
	f := newFixture(t)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()

	f.store.SetAuditFailure(errors.New("disk full"))
	if _, err := f.manager.CreateSession(ctx, authn, credbound.CreateSessionInput{}); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("audit-unavailable create = %v", err)
	}
	f.store.SetAuditFailure(nil)
	issued, err := f.manager.CreateSession(ctx, authn, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	f.store.SetAuditFailure(errors.New("disk full"))
	if _, _, err := f.manager.AuthenticateSession(ctx, issued.Token); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("audit-unavailable authenticate = %v", err)
	}
	if err := f.manager.RevokeSession(ctx, aal2(authn.UserID, f.now), issued.Session.ID); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("audit-unavailable revoke = %v", err)
	}
	if err := f.manager.RevokeUserSessions(ctx, aal2(authn.UserID, f.now), credbound.TrustedRequest{}, credbound.UUID{}); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("audit-unavailable bulk revoke = %v", err)
	}
	f.store.SetAuditFailure(nil)
	if _, _, err := f.manager.AuthenticateSession(ctx, issued.Token); err != nil {
		t.Fatalf("session mutated despite audit failure: %v", err)
	}

	// The failure audits fail closed too: a rejection that cannot be audited
	// surfaces as ErrAuditUnavailable rather than a credential error.
	forged, err := f.manager.CreateSession(ctx, authn, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	f.store.SetAuditFailure(errors.New("disk full"))
	if _, _, err := f.manager.AuthenticateSession(ctx, forgeSecret(forged.Token)); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("unauditable forgery = %v", err)
	}
	f.store.SetAuditFailure(nil)
	if err := f.manager.RevokeSession(ctx, aal2(authn.UserID, f.now), forged.Session.ID); err != nil {
		t.Fatal(err)
	}
	f.store.SetAuditFailure(errors.New("disk full"))
	if _, _, err := f.manager.AuthenticateSession(ctx, forged.Token); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("unauditable revoked rejection = %v", err)
	}
	f.store.SetAuditFailure(nil)
	expiring, err := f.manager.CreateSession(ctx, authn, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(31 * 24 * time.Hour)
	f.store.SetAuditFailure(errors.New("disk full"))
	if _, _, err := f.manager.AuthenticateSession(ctx, expiring.Token); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("unauditable expiry = %v", err)
	}
	f.store.SetAuditFailure(nil)

	// Infrastructure failures propagate instead of masquerading as bad tokens.
	infrastructure := errors.New("database offline")
	fault := &sessionFaultStore{Store: memory.New()}
	manager, err := credbound.New(credbound.Config{
		Store: fault, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return f.now }, Random: &counterReader{next: 0x24},
	})
	if err != nil {
		t.Fatal(err)
	}
	rootAuthn, _, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	faultIssued, err := manager.CreateSession(ctx, rootAuthn, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	fault.sessionByIDErr = infrastructure
	if _, _, err := manager.AuthenticateSession(ctx, faultIssued.Token); !errors.Is(err, infrastructure) {
		t.Fatalf("session lookup fault = %v", err)
	}
	fault.sessionByIDErr = nil
	fault.userByIDErr = infrastructure
	if _, _, err := manager.AuthenticateSession(ctx, faultIssued.Token); !errors.Is(err, infrastructure) {
		t.Fatalf("user lookup fault = %v", err)
	}
	// A vanished user reads as invalid credentials, not as an infrastructure
	// failure.
	fault.userByIDErr = credbound.ErrNotFound
	if _, _, err := manager.AuthenticateSession(ctx, faultIssued.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("vanished user error = %v", err)
	}
	fault.userByIDErr = nil

	// Entropy failures abort before any store write.
	entropy, err := credbound.New(credbound.Config{
		Store: fault.Store, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Random: errorReader{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entropy.CreateSession(ctx, rootAuthn, credbound.CreateSessionInput{}); err == nil {
		t.Fatal("entropy failure ignored")
	}
}

// TestSessionSignOut proves the sign-out clause of SESS-003: possession of
// the session token revokes it without any step-up.
func TestSessionSignOut(t *testing.T) {
	f := newFixture(t)
	recorder := &sessionRecorder{}
	f.manager.AddEventListener(recorder)
	authn, _ := f.bootstrap(t)
	ctx := context.Background()

	issued, err := f.manager.CreateSession(ctx, authn, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	// Logout works by possession alone: an AAL1 password session needs no
	// step-up to sign itself out.
	if _, _, err := f.manager.AuthenticateSession(ctx, issued.Token); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.SignOut(ctx, issued.Token); err != nil {
		t.Fatalf("sign out = %v", err)
	}
	if _, _, err := f.manager.AuthenticateSession(ctx, issued.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("signed-out session error = %v", err)
	}
	if len(recorder.revoked) != 1 || recorder.revoked[0].SessionID != issued.Session.ID {
		t.Fatalf("session.revoked event = %#v", recorder.revoked)
	}
	// Logout is idempotent; forged and malformed tokens still fail.
	if err := f.manager.SignOut(ctx, issued.Token); err != nil {
		t.Fatalf("repeated sign out = %v", err)
	}
	if len(recorder.revoked) != 1 {
		t.Fatalf("idempotent sign out emitted extra events: %#v", recorder.revoked)
	}
	if err := f.manager.SignOut(ctx, forgeSecret(issued.Token)); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("forged sign out = %v", err)
	}
	if err := f.manager.SignOut(ctx, "not-a-token"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("malformed sign out = %v", err)
	}
	unknown := "cbs_" + issued.Session.UserID.String() + "_" + strings.Repeat("A", 43)
	if err := f.manager.SignOut(ctx, unknown); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("unknown sign out = %v", err)
	}

	// An expired session still signs out, and a capability-less store refuses.
	expired, err := f.manager.CreateSession(ctx, authn, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(31 * 24 * time.Hour)
	if err := f.manager.SignOut(ctx, expired.Token); err != nil {
		t.Fatalf("expired sign out = %v", err)
	}
}
