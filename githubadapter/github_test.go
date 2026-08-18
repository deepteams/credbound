package githubadapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

// testGitHub fakes the two GitHub surfaces the adapter talks to: the OAuth
// token endpoint and the REST API (GET /user, GET /user/emails). The
// authorization endpoint is never fetched by the adapter, so it is not
// served.
type testGitHub struct {
	server *httptest.Server

	mu            sync.Mutex
	tokenStatus   int
	tokenBody     string
	userStatus    int
	userBody      string
	emailsStatus  int
	emailsBody    string
	lastTokenForm url.Values
	lastUserReq   *http.Request
}

func newTestGitHub(t *testing.T) *testGitHub {
	t.Helper()
	github := &testGitHub{
		tokenBody:  `{"access_token":"gho_test-token","token_type":"bearer","scope":"read:user,user:email"}`,
		userBody:   `{"id":581348,"login":"octocat","email":"public@example.com"}`,
		emailsBody: `[{"email":"secondary@example.com","primary":false,"verified":true},{"email":"primary@example.com","primary":true,"verified":true}]`,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse token form: %v", err)
		}
		github.mu.Lock()
		github.lastTokenForm = r.PostForm
		status, body := github.tokenStatus, github.tokenBody
		github.mu.Unlock()
		respond(w, status, body)
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		github.mu.Lock()
		github.lastUserReq = r.Clone(r.Context())
		status, body := github.userStatus, github.userBody
		github.mu.Unlock()
		respond(w, status, body)
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		github.mu.Lock()
		status, body := github.emailsStatus, github.emailsBody
		github.mu.Unlock()
		respond(w, status, body)
	})
	github.server = httptest.NewServer(mux)
	t.Cleanup(github.server.Close)
	return github
}

func respond(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	if status != 0 {
		w.WriteHeader(status)
	}
	_, _ = w.Write([]byte(body))
}

func (g *testGitHub) url() string { return g.server.URL }

func (g *testGitHub) set(field *string, value string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	*field = value
}

func (g *testGitHub) setStatus(field *int, status int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	*field = status
}

// setEmails installs a GET /user/emails answer built from triples.
func (g *testGitHub) setEmails(t *testing.T, emails ...map[string]any) {
	t.Helper()
	body, err := json.Marshal(emails)
	if err != nil {
		t.Fatalf("marshal emails: %v", err)
	}
	g.set(&g.emailsBody, string(body))
}

func (g *testGitHub) tokenRequest() url.Values {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lastTokenForm
}

func (g *testGitHub) userRequest() *http.Request {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lastUserReq
}
