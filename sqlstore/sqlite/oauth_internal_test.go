package sqlite

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/deepteams/credbound"
)

func TestOAuthJSONHelpersRejectUnsupportedAndInvalidData(t *testing.T) {
	if issuer, err := oauthDecode[credbound.OAuthIssuer](json.RawMessage(`{"id":"issuer"}`)); err != nil || issuer.ID != "issuer" {
		t.Fatalf("RawMessage OAuth JSON = %#v, %v", issuer, err)
	}
	if _, err := oauthDecode[credbound.OAuthIssuer](42); err == nil {
		t.Fatal("unsupported OAuth JSON type accepted")
	}
	if _, err := oauthDecode[credbound.OAuthIssuer]("{"); err == nil {
		t.Fatal("invalid OAuth JSON accepted")
	}
	if _, err := oauthDecodeQuery[credbound.OAuthIssuer]("{}", credbound.ErrNotFound); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("query error = %v", err)
	}
}
