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

// TestValidateReturnsMatchedStep guards against replay across the skew window.
// A code generated for one step, when presented while an adjacent step is the
// wall-clock step, must report the step it was generated for — not the
// wall-clock step — so the store's last_used_step guard cannot be bypassed by
// replaying the same code as the clock advances through the window.
func TestValidateReturnsMatchedStep(t *testing.T) {
	provider, err := New(Config{Issuer: "Credbound", Skew: 1})
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := provider.Generate("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	// Code minted for the previous step, still accepted at the current step
	// because Skew is 1.
	prev := base.Add(-30 * time.Second)
	prevStep := prev.Unix() / 30
	code, err := upstream.GenerateCode(secret, prev)
	if err != nil {
		t.Fatal(err)
	}
	step, valid := provider.Validate(code, secret, base)
	if !valid {
		t.Fatal("code within skew window was rejected")
	}
	if step != prevStep {
		t.Fatalf("matched step = %d, want %d (the step the code was minted for)", step, prevStep)
	}
	// Because the reported step is the mint step, a store that recorded
	// last_used_step = prevStep would reject this same code at every later
	// wall-clock step: Validate never reports a step greater than prevStep for it.
	next := base.Add(30 * time.Second)
	if step, valid := provider.Validate(code, secret, next); valid && step > prevStep {
		t.Fatalf("replay at later step reported advancing step %d > %d", step, prevStep)
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
