package oidcadapter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/deepteams/credbound"
)

func TestES256Signer(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewES256Signer("current", key)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer.SignIDToken(context.Background(), credbound.OIDCClaims{Issuer: "https://auth.example.com", Subject: "subject", Audience: "client", ExpiresAt: 2, IssuedAt: 1})
	if err != nil || len(strings.Split(token, ".")) != 3 {
		t.Fatalf("token = %q, %v", token, err)
	}
	parts := strings.Split(token, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		t.Fatalf("signature = %x, %v", signature, err)
	}
	jwks, err := signer.JWKS(context.Background())
	var document map[string]any
	if err != nil || json.Unmarshal(jwks, &document) != nil || len(document["keys"].([]any)) != 1 {
		t.Fatalf("JWKS = %s, %v", jwks, err)
	}
	if algorithms := signer.Algorithms(); len(algorithms) != 1 || algorithms[0] != "ES256" {
		t.Fatalf("algorithms = %#v", algorithms)
	}
}

// TestES256KeyRingValidationAndRetirement pins OAUTH-012: the key ring
// publishes the single active signing key alongside verification-only
// retiring keys in the JWKS, and malformed rings are rejected outright.
func TestES256KeyRingValidationAndRetirement(t *testing.T) {
	active, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	retiring, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, err := NewES256KeyRing("active", active, ES256VerificationKey{KID: "retiring", PublicKey: &retiring.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := signer.JWKS(t.Context())
	var document map[string]any
	if err != nil || json.Unmarshal(jwks, &document) != nil || len(document["keys"].([]any)) != 2 {
		t.Fatalf("key ring = %s, %v", jwks, err)
	}
	for name, build := range map[string]func() (*ES256Signer, error){
		"empty kid": func() (*ES256Signer, error) { return NewES256KeyRing("", active) },
		"nil key":   func() (*ES256Signer, error) { return NewES256KeyRing("active", nil) },
		"duplicate": func() (*ES256Signer, error) {
			return NewES256KeyRing("active", active, ES256VerificationKey{KID: "active", PublicKey: &retiring.PublicKey})
		},
		"invalid retiring": func() (*ES256Signer, error) {
			return NewES256KeyRing("active", active, ES256VerificationKey{KID: "retiring"})
		},
		"zero-value retiring": func() (*ES256Signer, error) {
			return NewES256KeyRing("active", active, ES256VerificationKey{KID: "retiring", PublicKey: &ecdsa.PublicKey{Curve: elliptic.P256()}})
		},
		"wrong-curve retiring": func() (*ES256Signer, error) {
			p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				return nil, nil
			}
			return NewES256KeyRing("active", active, ES256VerificationKey{KID: "retiring", PublicKey: &p384.PublicKey})
		},
	} {
		if _, err := build(); err == nil {
			t.Fatalf("%s key ring accepted", name)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := signer.SignIDToken(canceled, credbound.OIDCClaims{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled sign = %v", err)
	}
	if _, err := signer.JWKS(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled JWKS = %v", err)
	}
}
