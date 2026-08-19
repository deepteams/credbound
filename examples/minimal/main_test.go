package main

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/credboundtest"
)

// The example is the first thing an integration copies, and it is where the
// sessions contract of the README is demonstrated. These tests drive its
// routes end to end so a regression in the flow hosts imitate — the cookie
// attributes, the pending second factor, the revocation on sign-out — fails
// here rather than in someone's production service.

func newJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return jar
}

func newTestServer(t *testing.T, options ...credboundtest.Option) (*httptest.Server, *credbound.Manager) {
	t.Helper()
	manager := credboundtest.NewManager(t, options...)
	credboundtest.Bootstrap(t, manager)
	server := httptest.NewServer(newHandler(manager))
	t.Cleanup(server.Close)
	return server, manager
}

func signIn(t *testing.T, server *httptest.Server, client *http.Client, email, password string) *http.Response {
	t.Helper()
	response, err := client.PostForm(server.URL+"/signin", url.Values{
		"email": {email}, "password": {password},
	})
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	t.Cleanup(func() { response.Body.Close() })
	return response
}

func TestExampleSignInReadSignOut(t *testing.T) {
	server, _ := newTestServer(t)
	jar := newJar(t)
	client := &http.Client{Jar: jar}

	// An unauthenticated read is refused before anything else.
	response, err := client.Get(server.URL + "/me")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous /me = %d, want 401", response.StatusCode)
	}

	// A wrong password answers exactly like an unknown address.
	wrong := signIn(t, server, client, credboundtest.BootstrapEmail, "wrong password here")
	unknown := signIn(t, server, client, "missing@example.com", "wrong password here")
	if wrong.StatusCode != http.StatusUnauthorized || unknown.StatusCode != http.StatusUnauthorized {
		t.Fatalf("failed sign-ins = %d and %d, want 401", wrong.StatusCode, unknown.StatusCode)
	}

	accepted := signIn(t, server, client, credboundtest.BootstrapEmail, credboundtest.BootstrapPassword)
	if accepted.StatusCode != http.StatusNoContent {
		t.Fatalf("sign in = %d, want 204", accepted.StatusCode)
	}
	cookie := sessionCookie(t, accepted)
	if !cookie.HttpOnly || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie = %#v", cookie)
	}
	if !strings.HasPrefix(cookie.Value, "cbs_") {
		t.Fatalf("session cookie carries %q, want the cbs_ session token", cookie.Value)
	}

	response, err = client.Get(server.URL + "/me")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authenticated /me = %d, want 200", response.StatusCode)
	}
	var identity map[string]any
	if err := json.NewDecoder(response.Body).Decode(&identity); err != nil {
		t.Fatalf("decode identity: %v", err)
	}
	if identity["user_id"] == "" || identity["method"] != string(credbound.MethodPassword) {
		t.Fatalf("identity = %#v", identity)
	}
	if identity["level"] != float64(credbound.AAL1) {
		t.Fatalf("identity level = %#v, want AAL1", identity["level"])
	}

	// Sign-out revokes the session server-side, not just the cookie: the
	// captured token stops working even when replayed.
	captured := cookie.Value
	out, err := client.Post(server.URL+"/signout", "", nil)
	if err != nil {
		t.Fatalf("sign out: %v", err)
	}
	out.Body.Close()
	if out.StatusCode != http.StatusNoContent {
		t.Fatalf("sign out = %d, want 204", out.StatusCode)
	}
	replay := httptest.NewRequest(http.MethodGet, "/me", nil)
	replay.AddCookie(&http.Cookie{Name: "credbound_session", Value: captured})
	recorder := httptest.NewRecorder()
	server.Config.Handler.ServeHTTP(recorder, replay)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("replayed session = %d, want 401", recorder.Code)
	}
}

func TestExampleRejectsTamperedAndPendingSessions(t *testing.T) {
	server, manager := newTestServer(t)
	client := &http.Client{Jar: newJar(t)}
	accepted := signIn(t, server, client, credboundtest.BootstrapEmail, credboundtest.BootstrapPassword)
	if accepted.StatusCode != http.StatusNoContent {
		t.Fatalf("sign in = %d, want 204", accepted.StatusCode)
	}
	token := sessionCookie(t, accepted).Value

	for name, value := range map[string]string{
		"tampered":  token + "0",
		"truncated": token[:len(token)-1],
		"foreign":   "cbs_0198b463-0000-7000-8000-000000000001_" + strings.Repeat("A", 43),
		"empty":     "",
	} {
		request := httptest.NewRequest(http.MethodGet, "/me", nil)
		request.AddCookie(&http.Cookie{Name: "credbound_session", Value: value})
		recorder := httptest.NewRecorder()
		server.Config.Handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s session = %d, want 401", name, recorder.Code)
		}
	}

	// With a second factor enrolled, the first factor alone must not mint a
	// session: the example answers 403 instead of setting a cookie.
	root, err := manager.AuthenticatePassword(t.Context(), credboundtest.BootstrapEmail, credboundtest.BootstrapPassword)
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	actor := credboundtest.AAL2(root.UserID, credboundtest.DefaultStartTime)
	if _, err := manager.BeginTOTPEnrollment(t.Context(), actor); err != nil {
		t.Fatalf("begin totp: %v", err)
	}
	if _, err := manager.ConfirmTOTPEnrollment(t.Context(), actor, credboundtest.ValidTOTPCode); err != nil {
		t.Fatalf("confirm totp: %v", err)
	}
	pending := signIn(t, server, client, credboundtest.BootstrapEmail, credboundtest.BootstrapPassword)
	if pending.StatusCode != http.StatusForbidden {
		t.Fatalf("pending second factor = %d, want 403", pending.StatusCode)
	}
	if hasSessionCookie(pending) {
		t.Fatal("a session cookie was issued for a pending second factor")
	}
}

func sessionCookie(t *testing.T, response *http.Response) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Cookies() {
		if cookie.Name == "credbound_session" {
			return cookie
		}
	}
	t.Fatal("no session cookie was set")
	return nil
}

func hasSessionCookie(response *http.Response) bool {
	for _, cookie := range response.Cookies() {
		if cookie.Name == "credbound_session" && cookie.Value != "" {
			return true
		}
	}
	return false
}
