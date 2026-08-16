package totpadapter

import (
	"strings"
	"testing"
	"time"

	upstream "github.com/pquerna/otp/totp"
)

func TestGenerateAndValidate(t *testing.T) {
	provider, err := New(Config{Issuer: " Credbound "})
	if err != nil {
		t.Fatal(err)
	}
	secret, uri, err := provider.Generate("user@example.com")
	if err != nil || secret == "" || !strings.HasPrefix(uri, "otpauth://totp/Credbound:") {
		t.Fatalf("generated = %q, %q, %v", secret, uri, err)
	}
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	code, err := upstream.GenerateCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	step, valid := provider.Validate(code, secret, now)
	if !valid || step != now.Unix()/30 {
		t.Fatalf("validation = %d, %v", step, valid)
	}
	if _, valid := provider.Validate("000000", secret, now); valid {
		t.Fatal("invalid code accepted")
	}
}

func TestConfigurationValidation(t *testing.T) {
	invalid := []Config{
		{},
		{Issuer: "x", Period: 10},
		{Issuer: "x", Period: 30, Skew: 3},
	}
	for _, config := range invalid {
		if _, err := New(config); err == nil {
			t.Fatalf("accepted config %#v", config)
		}
	}
	provider, err := New(Config{Issuer: "x", Period: 60, Skew: 1})
	if err != nil || provider.period != 60 || provider.skew != 1 {
		t.Fatalf("custom provider = %#v, %v", provider, err)
	}
}
