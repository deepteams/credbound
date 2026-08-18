// Package oauthclientadapter provides hardened OAuth client authentication
// adapters without coupling Credbound to an HTTP server: JWTAssertionVerifier
// validates private_key_jwt client assertions (RFC 7523) against a client's
// registered JWKS with single-use JWT ID enforcement, and MemoryReplayStore
// supplies the replay protection for single-process hosts.
//
// Wire the verifier into credbound.Config.OAuth.ClientAssertions:
//
//	verifier, err := oauthclientadapter.NewJWTAssertionVerifier(
//		oauthclientadapter.VerifierConfig{
//			ReplayStore: oauthclientadapter.NewMemoryReplayStore(nil),
//		})
//
// Multi-process hosts must replace MemoryReplayStore with a shared
// AssertionReplayStore, or a captured assertion could be replayed against a
// sibling process.
package oauthclientadapter

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deepteams/credbound"
)

const (
	defaultFetchTimeout = 5 * time.Second
	defaultCacheTTL     = 5 * time.Minute
	maxJWKSBody         = 64 << 10
)

// AssertionReplayStore atomically consumes a JWT ID until its expiration.
// Use a shared implementation when the host runs more than one process.
type AssertionReplayStore interface {
	Use(context.Context, string, string, time.Time) (bool, error)
}

// Resolver resolves host names for the SSRF guard on JWKS fetches;
// net.DefaultResolver satisfies it.
type Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// VerifierConfig configures a JWTAssertionVerifier. Only ReplayStore is
// required; every other field has a safe default.
type VerifierConfig struct {
	// ReplayStore enforces single use of each assertion's JWT ID.
	// Required; it must be shared across processes in multi-process hosts.
	ReplayStore AssertionReplayStore
	// Resolver is used to vet JWKS hosts before dialing. Defaults to
	// net.DefaultResolver.
	Resolver Resolver
	// Clock supplies the verification time and defaults to time.Now.
	// Override it only in tests.
	Clock func() time.Time
	// FetchTimeout bounds one JWKS fetch. Zero defaults to 5s; values
	// above 30s are rejected.
	FetchTimeout time.Duration
	// CacheTTL is how long a fetched JWKS is reused. Zero defaults to 5
	// minutes; values above an hour are rejected because a stale cache
	// delays key revocation.
	CacheTTL time.Duration
}

// JWTAssertionVerifier validates private_key_jwt client assertions against
// the client's registered JWKS or SSRF-guarded HTTPS jwks_uri, enforcing
// issuer/subject, audience, expiry and single-use JWT IDs. It is safe for
// concurrent use and implements credbound.OAuthClientAssertionVerifier for
// credbound.OAuthConfig.ClientAssertions.
type JWTAssertionVerifier struct {
	replay       AssertionReplayStore
	resolver     Resolver
	now          func() time.Time
	fetchTimeout time.Duration
	cacheTTL     time.Duration
	mu           sync.Mutex
	cache        map[string]cachedJWKS
}

type cachedJWKS struct {
	raw       []byte
	expiresAt time.Time
}

// NewJWTAssertionVerifier validates config and returns a verifier. A
// missing replay store or an out-of-bounds fetch/cache policy is rejected.
func NewJWTAssertionVerifier(config VerifierConfig) (*JWTAssertionVerifier, error) {
	if config.ReplayStore == nil {
		return nil, fmt.Errorf("%w: assertion replay store is required", credbound.ErrInvalidInput)
	}
	if config.Resolver == nil {
		config.Resolver = net.DefaultResolver
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.FetchTimeout == 0 {
		config.FetchTimeout = defaultFetchTimeout
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = defaultCacheTTL
	}
	if config.FetchTimeout <= 0 || config.FetchTimeout > 30*time.Second || config.CacheTTL <= 0 || config.CacheTTL > time.Hour {
		return nil, fmt.Errorf("%w: invalid JWKS fetch policy", credbound.ErrInvalidInput)
	}
	return &JWTAssertionVerifier{
		replay: config.ReplayStore, resolver: config.Resolver, now: func() time.Time { return config.Clock().UTC() },
		fetchTimeout: config.FetchTimeout, cacheTTL: config.CacheTTL, cache: make(map[string]cachedJWKS),
	}, nil
}

// Verify checks assertion for client against the expected audience at the
// given time (zero means the verifier's clock), then consumes its JWT ID in
// the replay store. Any validation failure — malformed token, wrong
// signature, expired, replayed — reports credbound.ErrInvalidCredentials
// without detail, so callers cannot oracle the cause.
func (v *JWTAssertionVerifier) Verify(ctx context.Context, client credbound.OAuthClient, audience, assertion string, now time.Time) error {
	header, claims, signingInput, signature, err := parseAssertion(assertion)
	if err != nil {
		return credbound.ErrInvalidCredentials
	}
	if now.IsZero() {
		now = v.now()
	} else {
		now = now.UTC()
	}
	if claims.Issuer != client.ClientID || claims.Subject != client.ClientID || !claims.hasAudience(audience) ||
		claims.JWTID == "" || claims.ExpiresAt <= now.Unix() || claims.ExpiresAt > now.Add(5*time.Minute).Unix() ||
		claims.IssuedAt == 0 || claims.IssuedAt > now.Add(time.Minute).Unix() {
		return credbound.ErrInvalidCredentials
	}
	rawJWKS := client.JWKS
	if len(rawJWKS) == 0 {
		if client.JWKSURI == "" {
			return credbound.ErrInvalidCredentials
		}
		rawJWKS, err = v.fetchJWKS(ctx, client.JWKSURI)
		if err != nil {
			return credbound.ErrInvalidCredentials
		}
	}
	if err := verifySignature(header, rawJWKS, signingInput, signature); err != nil {
		return credbound.ErrInvalidCredentials
	}
	used, err := v.replay.Use(ctx, client.ClientID, claims.JWTID, time.Unix(claims.ExpiresAt, 0).UTC())
	if err != nil {
		return err
	}
	if !used {
		return credbound.ErrInvalidCredentials
	}
	return nil
}

type assertionHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ,omitempty"`
}

type assertionClaims struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  json.RawMessage `json:"aud"`
	ExpiresAt int64           `json:"exp"`
	IssuedAt  int64           `json:"iat"`
	JWTID     string          `json:"jti"`
}

func (c assertionClaims) hasAudience(expected string) bool {
	var one string
	if json.Unmarshal(c.Audience, &one) == nil {
		return subtle.ConstantTimeCompare([]byte(one), []byte(expected)) == 1
	}
	var many []string
	if json.Unmarshal(c.Audience, &many) != nil {
		return false
	}
	for _, candidate := range many {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1 {
			return true
		}
	}
	return false
}

func parseAssertion(raw string) (assertionHeader, assertionClaims, string, []byte, error) {
	// Bound the input before splitting so a multi-megabyte assertion made of
	// dots cannot force a huge allocation for a caller that has not already
	// capped the request body.
	if len(raw) > 64<<10 {
		return assertionHeader{}, assertionClaims{}, "", nil, credbound.ErrInvalidCredentials
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return assertionHeader{}, assertionClaims{}, "", nil, credbound.ErrInvalidCredentials
	}
	decode := func(value string, destination any) error {
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			return err
		}
		decoder := json.NewDecoder(strings.NewReader(string(decoded)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(destination); err != nil {
			return err
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			return credbound.ErrInvalidCredentials
		}
		return nil
	}
	var header assertionHeader
	var claims assertionClaims
	if err := decode(parts[0], &header); err != nil {
		return header, claims, "", nil, err
	}
	if err := decode(parts[1], &claims); err != nil {
		return header, claims, "", nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	return header, claims, parts[0] + "." + parts[1], signature, err
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

func verifySignature(header assertionHeader, rawJWKS []byte, signingInput string, signature []byte) error {
	if header.KeyID == "" || header.Algorithm != "RS256" && header.Algorithm != "ES256" {
		return credbound.ErrInvalidCredentials
	}
	var document jwksDocument
	decoder := json.NewDecoder(strings.NewReader(string(rawJWKS)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || len(document.Keys) == 0 || len(document.Keys) > 100 {
		return credbound.ErrInvalidCredentials
	}
	digest := sha256.Sum256([]byte(signingInput))
	for _, key := range document.Keys {
		if key.KeyID != header.KeyID || key.Use != "" && key.Use != "sig" || key.Algorithm != "" && key.Algorithm != header.Algorithm {
			continue
		}
		switch header.Algorithm {
		case "RS256":
			public, err := rsaKey(key)
			if err == nil && rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature) == nil {
				return nil
			}
		case "ES256":
			public, err := ecKey(key)
			if err == nil && len(signature) == 64 && ecdsa.Verify(public, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
				return nil
			}
		}
	}
	return credbound.ErrInvalidCredentials
}

func rsaKey(key jwk) (*rsa.PublicKey, error) {
	if key.KeyType != "RSA" {
		return nil, credbound.ErrInvalidCredentials
	}
	modulus, err := base64.RawURLEncoding.DecodeString(key.Modulus)
	if err != nil || len(modulus) < 256 {
		return nil, credbound.ErrInvalidCredentials
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(key.Exponent)
	if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
		return nil, credbound.ErrInvalidCredentials
	}
	exponent := 0
	for _, value := range exponentBytes {
		exponent = exponent<<8 | int(value)
	}
	if exponent < 3 || exponent%2 == 0 {
		return nil, credbound.ErrInvalidCredentials
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}, nil
}

func ecKey(key jwk) (*ecdsa.PublicKey, error) {
	if key.KeyType != "EC" || key.Curve != "P-256" {
		return nil, credbound.ErrInvalidCredentials
	}
	x, errX := base64.RawURLEncoding.DecodeString(key.X)
	y, errY := base64.RawURLEncoding.DecodeString(key.Y)
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return nil, credbound.ErrInvalidCredentials
	}
	public := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !public.Curve.IsOnCurve(public.X, public.Y) {
		return nil, credbound.ErrInvalidCredentials
	}
	return public, nil
}

func (v *JWTAssertionVerifier) fetchJWKS(ctx context.Context, rawURL string) ([]byte, error) {
	now := v.now()
	v.mu.Lock()
	if cached, ok := v.cache[rawURL]; ok && now.Before(cached.expiresAt) {
		raw := append([]byte(nil), cached.raw...)
		v.mu.Unlock()
		return raw, nil
	}
	v.mu.Unlock()
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, credbound.ErrInvalidInput
	}
	fetchCtx, cancel := context.WithTimeout(ctx, v.fetchTimeout)
	defer cancel()
	addresses, err := v.resolver.LookupIPAddr(fetchCtx, parsed.Hostname())
	if err != nil || len(addresses) == 0 {
		return nil, credbound.ErrInvalidCredentials
	}
	for _, address := range addresses {
		if !publicIP(address.IP) {
			return nil, credbound.ErrInvalidCredentials
		}
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	dialAddress := net.JoinHostPort(addresses[0].IP.String(), port)
	dialer := &net.Dialer{Timeout: v.fetchTimeout}
	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parsed.Hostname()},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", dialAddress)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: v.fetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, credbound.ErrInvalidCredentials
	}
	length := response.Header.Get("Content-Length")
	if length != "" {
		value, err := strconv.ParseInt(length, 10, 64)
		if err != nil || value < 0 || value > maxJWKSBody {
			return nil, credbound.ErrInvalidCredentials
		}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBody+1))
	if err != nil || len(raw) == 0 || len(raw) > maxJWKSBody || !json.Valid(raw) {
		return nil, credbound.ErrInvalidCredentials
	}
	v.mu.Lock()
	v.cache[rawURL] = cachedJWKS{raw: append([]byte(nil), raw...), expiresAt: now.Add(v.cacheTTL)}
	v.mu.Unlock()
	return raw, nil
}

// publicIP reports whether a resolved address may be dialed for a jwks_uri
// fetch. It applies the same block list as oauthhttp's SSRF-hardened metadata
// fetcher: net.IP's IsPrivate covers only the RFC 1918 / ULA ranges, so CGNAT
// (100.64.0.0/10), the reserved and TEST-NET blocks, and 240.0.0.0/4 must be
// rejected explicitly or a jwks_uri resolving into them could reach internal
// services (cloud metadata behind CGNAT, carrier-internal hosts).
func publicIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, raw := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"2001:db8::/32", "2001::/23", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		if netip.MustParsePrefix(raw).Contains(address) {
			return false
		}
	}
	return true
}

var _ credbound.OAuthClientAssertionVerifier = (*JWTAssertionVerifier)(nil)
