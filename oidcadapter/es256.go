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
	if kid == "" || len(kid) > 128 || key == nil || key.Curve != elliptic.P256() || key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, fmt.Errorf("%w: valid P-256 key and kid are required", credbound.ErrInvalidInput)
	}
	seen := map[string]struct{}{kid: {}}
	verification := make([]ES256VerificationKey, len(retiring))
	for index, candidate := range retiring {
		public := candidate.PublicKey
		if candidate.KID == "" || len(candidate.KID) > 128 || public == nil || public.Curve != elliptic.P256() || public.X == nil || public.Y == nil || !public.Curve.IsOnCurve(public.X, public.Y) {
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
	coordinate := func(value []byte) string {
		padded := make([]byte, 32)
		copy(padded[32-len(value):], value)
		return base64.RawURLEncoding.EncodeToString(padded)
	}
	keys := make([]map[string]string, 0, 1+len(s.verification))
	appendKey := func(kid string, key *ecdsa.PublicKey) {
		keys = append(keys, map[string]string{
			"kty": "EC", "use": "sig", "alg": "ES256", "kid": kid,
			"crv": "P-256", "x": coordinate(key.X.Bytes()), "y": coordinate(key.Y.Bytes()),
		})
	}
	appendKey(s.kid, &s.key.PublicKey)
	for _, retiring := range s.verification {
		appendKey(retiring.KID, retiring.PublicKey)
	}
	return json.Marshal(map[string]any{"keys": keys})
}

var _ credbound.OIDCSigner = (*ES256Signer)(nil)
