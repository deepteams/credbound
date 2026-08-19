package oauthclientadapter

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

// TestJWTAssertionVerifierES256AndReplay pins OAUTH-011: a well-formed ES256
// client assertion verifies once, and presenting the same jti again is
// refused by the replay store.
func TestJWTAssertionVerifierES256AndReplay(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	jwk, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "kid": "client-key", "use": "sig", "alg": "ES256", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(raw[1:33]), "y": base64.RawURLEncoding.EncodeToString(raw[33:65]),
	}}})
	verifier, err := NewJWTAssertionVerifier(VerifierConfig{
		ReplayStore: NewMemoryReplayStore(func() time.Time { return now }), Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	client := credbound.OAuthClient{ClientID: "client", JWKS: jwk}
	assertion := signES256(t, key, map[string]any{
		"iss": "client", "sub": "client", "aud": "https://auth.example.com/token",
		"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "jti": "one",
	})
	if err := verifier.Verify(context.Background(), client, "https://auth.example.com/token", assertion, now); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), client, "https://auth.example.com/token", assertion, now); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("replayed assertion = %v", err)
	}
}

func TestJWTAssertionVerifierRequiresReplayStore(t *testing.T) {
	if _, err := NewJWTAssertionVerifier(VerifierConfig{}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("missing replay store = %v", err)
	}
}

func TestJWTAssertionVerifierRS256ValidationAndFailures(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "rsa-key", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}}})
	verifier, err := NewJWTAssertionVerifier(VerifierConfig{
		ReplayStore: NewMemoryReplayStore(func() time.Time { return now }), Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	client := credbound.OAuthClient{ClientID: "client", JWKS: jwk}
	claims := map[string]any{
		"iss": "client", "sub": "client", "aud": []string{"other", "https://auth.example.com/token"},
		"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "jti": "rsa-one",
	}
	assertion := signRS256(t, key, claims)
	if err := verifier.Verify(t.Context(), client, "https://auth.example.com/token", assertion, time.Time{}); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]string{
		"shape": "broken", "audience": signRS256(t, key, map[string]any{"iss": "client", "sub": "client", "aud": 42, "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "jti": "bad-aud"}),
		"claims": signRS256(t, key, map[string]any{"iss": "other", "sub": "client", "aud": "https://auth.example.com/token", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "jti": "bad-claims"}),
	} {
		if err := verifier.Verify(t.Context(), client, "https://auth.example.com/token", invalid, now); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("%s assertion = %v", name, err)
		}
	}
	badClient := client
	badClient.JWKS = json.RawMessage(`{"keys":[{"kty":"RSA","kid":"rsa-key","n":credbound.MustParseUUID("00000000-0000-4000-8000-000000000000"),"e":"AQAB"}]}`)
	if err := verifier.Verify(t.Context(), badClient, "https://auth.example.com/token", signRS256(t, key, map[string]any{
		"iss": "client", "sub": "client", "aud": "https://auth.example.com/token", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "jti": "bad-key",
	}), now); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("bad key = %v", err)
	}
}

// TestJWTAssertionVerifierFetchPolicy pins the public-address-pinned JWKS
// loading of OAUTH-011: HTTP URLs and hosts resolving to private, loopback,
// or otherwise non-public addresses never serve client keys.
func TestJWTAssertionVerifierFetchPolicy(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	for _, config := range []VerifierConfig{
		{ReplayStore: NewMemoryReplayStore(nil), FetchTimeout: -time.Second},
		{ReplayStore: NewMemoryReplayStore(nil), CacheTTL: 2 * time.Hour},
	} {
		if _, err := NewJWTAssertionVerifier(config); !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("invalid policy = %v", err)
		}
	}
	resolver := resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	})
	verifier, err := NewJWTAssertionVerifier(VerifierConfig{
		ReplayStore: NewMemoryReplayStore(func() time.Time { return now }), Resolver: resolver, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	client := credbound.OAuthClient{ClientID: "client", JWKSURI: "http://example.com/jwks"}
	assertion := unsignedAssertion(map[string]any{
		"iss": "client", "sub": "client", "aud": "audience", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "jti": "fetch",
	})
	if err := verifier.Verify(t.Context(), client, "audience", assertion, now); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("HTTP JWKS = %v", err)
	}
	client.JWKSURI = "https://example.com/jwks"
	if err := verifier.Verify(t.Context(), client, "audience", assertion, now); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("private JWKS address = %v", err)
	}
	for _, raw := range []string{
		"", "0.0.0.0", "127.0.0.1", "10.0.0.1", "169.254.1.1", "224.0.0.1", "::1",
		// Ranges net.IP.IsPrivate does not cover but SSRF must still block.
		"100.64.0.1", "100.127.255.255", "192.0.0.1", "192.0.2.5", "198.18.0.1",
		"198.51.100.7", "203.0.113.9", "240.0.0.1", "255.255.255.255", "2001:db8::1", "fe80::1",
	} {
		if publicIP(net.ParseIP(raw)) {
			t.Fatalf("non-public address accepted: %q", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !publicIP(net.ParseIP(raw)) {
			t.Fatalf("public address rejected: %q", raw)
		}
	}
}

func TestJWTAssertionVerifierParsingKeyAndJWKSFailures(t *testing.T) {
	invalidAssertions := []string{
		"", "one.two", strings.Repeat("x", 64<<10+1),
		"%%%.e30.AA", "e30.%%%.AA", "e30.e30.%%%",
		base64.RawURLEncoding.EncodeToString([]byte(`{"extra":true}`)) + ".e30.AA",
		"e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"extra":true}`)) + ".AA",
		base64.RawURLEncoding.EncodeToString([]byte(`{} {}`)) + ".e30.AA",
		"e30." + base64.RawURLEncoding.EncodeToString([]byte(`{} {}`)) + ".AA",
	}
	for _, assertion := range invalidAssertions {
		if _, _, _, _, err := parseAssertion(assertion); err == nil {
			t.Fatalf("invalid assertion parsed: %.32q", assertion)
		}
	}
	if (assertionClaims{Audience: json.RawMessage(`42`)}).hasAudience("audience") {
		t.Fatal("numeric audience accepted")
	}
	if (assertionClaims{Audience: json.RawMessage(`["other"]`)}).hasAudience("audience") {
		t.Fatal("missing array audience accepted")
	}

	for name, test := range map[string]struct {
		header assertionHeader
		jwks   string
		sig    []byte
	}{
		"missing kid": {header: assertionHeader{Algorithm: "ES256"}, jwks: `{"keys":[{}]}`},
		"bad alg":     {header: assertionHeader{Algorithm: "none", KeyID: "key"}, jwks: `{"keys":[{}]}`},
		"bad json":    {header: assertionHeader{Algorithm: "ES256", KeyID: "key"}, jwks: `{`},
		"empty":       {header: assertionHeader{Algorithm: "ES256", KeyID: "key"}, jwks: `{"keys":[]}`},
		"unknown":     {header: assertionHeader{Algorithm: "ES256", KeyID: "key"}, jwks: `{"keys":[],"extra":true}`},
		"skipped":     {header: assertionHeader{Algorithm: "ES256", KeyID: "key"}, jwks: `{"keys":[{"kid":"other"},{"kid":"key","use":"enc"},{"kid":"key","alg":"RS256"}]}`},
		"short sig":   {header: assertionHeader{Algorithm: "ES256", KeyID: "key"}, jwks: `{"keys":[{"kty":"EC","kid":"key","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`, sig: []byte{1}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifySignature(test.header, []byte(test.jwks), "header.claims", test.sig); !errors.Is(err, credbound.ErrInvalidCredentials) {
				t.Fatalf("verifySignature = %v", err)
			}
		})
	}
	one := make([]byte, 32)
	one[31] = 1
	keys := []jwk{
		{KeyType: "EC", Curve: "P-384"},
		{KeyType: "EC", Curve: "P-256", X: "%%%", Y: "%%%"},
		{KeyType: "EC", Curve: "P-256", X: base64.RawURLEncoding.EncodeToString(make([]byte, 31)), Y: base64.RawURLEncoding.EncodeToString(make([]byte, 32))},
		// (1, 1) is not on P-256: the parse must reject an off-curve point.
		{KeyType: "EC", Curve: "P-256", X: base64.RawURLEncoding.EncodeToString(one), Y: base64.RawURLEncoding.EncodeToString(one)},
	}
	for _, key := range keys {
		if _, err := ecKey(key); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("ecKey(%#v) = %v", key, err)
		}
	}
	for _, key := range []jwk{
		{KeyType: "EC"},
		{KeyType: "RSA", Modulus: "%%%", Exponent: "AQAB"},
		{KeyType: "RSA", Modulus: base64.RawURLEncoding.EncodeToString(make([]byte, 256)), Exponent: "%%%"},
		{KeyType: "RSA", Modulus: base64.RawURLEncoding.EncodeToString(make([]byte, 256)), Exponent: base64.RawURLEncoding.EncodeToString([]byte{2})},
	} {
		if _, err := rsaKey(key); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("rsaKey(%#v) = %v", key, err)
		}
	}
}

func TestJWTAssertionVerifierJWKSCacheAndResolverFailures(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	verifier, err := NewJWTAssertionVerifier(VerifierConfig{
		ReplayStore: NewMemoryReplayStore(func() time.Time { return now }),
		Resolver: resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
			return nil, errors.New("DNS unavailable")
		}),
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	url := "https://keys.example.com/jwks.json"
	verifier.cache[url] = cachedJWKS{raw: []byte(`{"keys":[]}`), expiresAt: now.Add(time.Minute)}
	raw, err := verifier.fetchJWKS(t.Context(), url)
	if err != nil || string(raw) != `{"keys":[]}` {
		t.Fatalf("cache = %s, %v", raw, err)
	}
	raw[0] = 'x'
	if verifier.cache[url].raw[0] != '{' {
		t.Fatal("cached JWKS was returned without cloning")
	}
	verifier.cache[url] = cachedJWKS{raw: []byte(`{}`), expiresAt: now.Add(-time.Second)}
	for _, invalid := range []string{"http://keys.example.com", "https://", "https://user@keys.example.com", "https://keys.example.com/#fragment"} {
		if _, err := verifier.fetchJWKS(t.Context(), invalid); !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("fetchJWKS(%q) = %v", invalid, err)
		}
	}
	if _, err := verifier.fetchJWKS(t.Context(), url); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("resolver error = %v", err)
	}
	verifier.resolver = resolverFunc(func(context.Context, string) ([]net.IPAddr, error) { return nil, nil })
	if _, err := verifier.fetchJWKS(t.Context(), url); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("empty resolver = %v", err)
	}
	verifier.resolver = resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	})
	if _, err := verifier.fetchJWKS(t.Context(), url); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("mixed resolver = %v", err)
	}
	verifier.resolver = resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	})
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := verifier.fetchJWKS(canceled, "https://keys.example.com:443/jwks.json"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled fetch = %v", err)
	}
}

type resolverFunc func(context.Context, string) ([]net.IPAddr, error)

func (f resolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

func signRS256(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "rsa-key", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func unsignedAssertion(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "key"})
	payload, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".AA"
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "client-key", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}
