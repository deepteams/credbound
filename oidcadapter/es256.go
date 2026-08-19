// Package oidcadapter provides standard-library OIDC signing adapters.
package oidcadapter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/deepteams/credbound"
)

// ES256Signer implements credbound.OIDCSigner over one active ECDSA P-256
// signing key and any retiring verification-only keys, published together in
// the issuer's JWKS so rotation never invalidates tokens signed under the
// previous key. Build one with NewES256KeyRing.
type ES256Signer struct {
	kid          string
	key          *ecdsa.PrivateKey
	verification []ES256VerificationKey
}

// ES256VerificationKey is a retiring public key that remains discoverable
// during the maximum ID-token lifetime. It is never used for new signatures.
type ES256VerificationKey struct {
	KID       string
	PublicKey *ecdsa.PublicKey
}

// NewES256Signer creates a signer with a single active key and no retiring
// verification keys; it is NewES256KeyRing without a ring.
func NewES256Signer(kid string, key *ecdsa.PrivateKey) (*ES256Signer, error) {
	return NewES256KeyRing(kid, key)
}

// NewES256KeyRing creates a signer with one active key and optional retiring
// verification keys. KIDs must be unique across the ring.
func NewES256KeyRing(kid string, key *ecdsa.PrivateKey, retiring ...ES256VerificationKey) (*ES256Signer, error) {
	if kid == "" || len(kid) > 128 || key == nil || !validP256(&key.PublicKey) {
		return nil, fmt.Errorf("%w: valid P-256 key and kid are required", credbound.ErrInvalidInput)
	}
	seen := map[string]struct{}{kid: {}}
	verification := make([]ES256VerificationKey, len(retiring))
	for index, candidate := range retiring {
		if candidate.KID == "" || len(candidate.KID) > 128 || !validP256(candidate.PublicKey) {
			return nil, fmt.Errorf("%w: invalid retiring P-256 key", credbound.ErrInvalidInput)
		}
		if _, duplicate := seen[candidate.KID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate OIDC key id", credbound.ErrInvalidInput)
		}
		seen[candidate.KID] = struct{}{}
		verification[index] = candidate
	}
	return &ES256Signer{kid: kid, key: key, verification: verification}, nil
}

// validP256 reports whether the key is a well-formed point on P-256, using
// the encode/parse round-trip of the modern crypto/ecdsa API — the parse
// performs the on-curve check — instead of the deprecated raw-coordinate
// accessors.
func validP256(public *ecdsa.PublicKey) bool {
	if public == nil || public.Curve != elliptic.P256() {
		return false
	}
	//nolint:staticcheck // Read-only nil guard: Bytes panics on a zero-value key.
	if public.X == nil || public.Y == nil {
		return false
	}
	raw, err := public.Bytes()
	if err != nil {
		return false
	}
	_, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	return err == nil
}

func (*ES256Signer) Algorithms() []string { return []string{"ES256"} }

func (s *ES256Signer) SignIDToken(ctx context.Context, claims credbound.OIDCClaims) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	header, err := json.Marshal(map[string]string{"alg": "ES256", "kid": s.kid, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign OIDC ID token: %w", err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	ss.FillBytes(signature[32:])
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (s *ES256Signer) JWKS(ctx context.Context) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keys := make([]map[string]string, 0, 1+len(s.verification))
	appendKey := func(kid string, key *ecdsa.PublicKey) error {
		// Bytes yields the SEC 1 uncompressed encoding, 0x04 || X || Y with
		// 32 bytes per coordinate on P-256.
		raw, err := key.Bytes()
		if err != nil {
			return fmt.Errorf("encode OIDC JWKS key %q: %w", kid, err)
		}
		keys = append(keys, map[string]string{
			"kty": "EC", "use": "sig", "alg": "ES256", "kid": kid,
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(raw[1:33]),
			"y":   base64.RawURLEncoding.EncodeToString(raw[33:65]),
		})
		return nil
	}
	if err := appendKey(s.kid, &s.key.PublicKey); err != nil {
		return nil, err
	}
	for _, retiring := range s.verification {
		if err := appendKey(retiring.KID, retiring.PublicKey); err != nil {
			return nil, err
		}
	}
	return json.Marshal(map[string]any{"keys": keys})
}

var _ credbound.OIDCSigner = (*ES256Signer)(nil)
