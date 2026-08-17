package ssoadapter

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// testIssuer is a minimal in-process OIDC issuer: discovery, JWKS, and a
// token endpoint that signs RS256 ID tokens with a throwaway RSA key.
type testIssuer struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey

	mu sync.Mutex
	// claims overrides merged into the next ID token.
	claims map[string]any
	// nonce used in the next ID token; when empty the nonce sent to the
	// authorization endpoint is unknown to the issuer, so tests set it from
	// the parsed Begin URL.
	nonce string
	// expiry of the next ID token relative to now.
	tokenTTL time.Duration
	// lastTokenRequest records the form the client posted to /token.
	lastTokenRequest url.Values
	// tokenStatus, when non-zero, forces an error response from /token.
	tokenStatus int
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	issuer := &testIssuer{t: t, key: key, tokenTTL: time.Hour, claims: map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", issuer.discovery)
	mux.HandleFunc("/keys", issuer.jwks)
	mux.HandleFunc("/token", issuer.token)
	issuer.server = httptest.NewServer(mux)
	t.Cleanup(issuer.server.Close)
	return issuer
}

func (i *testIssuer) url() string { return i.server.URL }

func (i *testIssuer) setNonce(nonce string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.nonce = nonce
}

func (i *testIssuer) setClaim(name string, value any) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.claims[name] = value
}

func (i *testIssuer) setTokenTTL(ttl time.Duration) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.tokenTTL = ttl
}

func (i *testIssuer) tokenRequest() url.Values {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.lastTokenRequest
}

func (i *testIssuer) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(i.t, w, map[string]any{
		"issuer":                                i.server.URL,
		"authorization_endpoint":                i.server.URL + "/authorize",
		"token_endpoint":                        i.server.URL + "/token",
		"jwks_uri":                              i.server.URL + "/keys",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	})
}

func (i *testIssuer) jwks(w http.ResponseWriter, _ *http.Request) {
	public := &i.key.PublicKey
	writeJSON(i.t, w, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test-key",
			"n": base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
		}},
	})
}

func (i *testIssuer) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		i.t.Errorf("parse token request: %v", err)
	}
	i.mu.Lock()
	i.lastTokenRequest = r.Form
	status := i.tokenStatus
	i.mu.Unlock()
	if status != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, `{"error":"invalid_grant"}`)
		return
	}
	writeJSON(i.t, w, map[string]any{
		"access_token": "test-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     i.signIDToken(),
	})
}

func (i *testIssuer) signIDToken() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := time.Now()
	payload := map[string]any{
		"iss": i.server.URL,
		"aud": "test-client",
		"sub": "user-123",
		"iat": now.Unix(),
		"exp": now.Add(i.tokenTTL).Unix(),
	}
	if i.nonce != "" {
		payload["nonce"] = i.nonce
	}
	for name, value := range i.claims {
		payload[name] = value
	}
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "test-key"}
	signingInput := encodeSegment(i.t, header) + "." + encodeSegment(i.t, payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, digest[:])
	if err != nil {
		i.t.Fatalf("sign id token: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func encodeSegment(t *testing.T, value any) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode jwt segment: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("write json response: %v", err)
	}
}

// verifierFor recomputes the S256 challenge for assertions.
func challengeFor(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// mustParseURL fails the test on malformed URLs.
func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	if !strings.HasPrefix(raw, "http") {
		t.Fatalf("unexpected redirect url %q", raw)
	}
	return parsed
}
