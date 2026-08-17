// Package totpadapter implements the credbound.TOTPProvider port with
// RFC 6238 six-digit SHA-1 codes (the interoperable authenticator-app
// profile) on top of github.com/pquerna/otp.
//
// Wire it into credbound.Config.TOTP:
//
//	totp, err := totpadapter.New(totpadapter.Config{Issuer: "Example"})
//
// Credbound owns everything around the algorithm: secret storage, replay
// rejection by time step, recovery codes and step-up semantics.
package totpadapter

import (
	"errors"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Config parameterizes the TOTP algorithm. Only Issuer is required.
type Config struct {
	// Issuer is the display name embedded in otpauth:// URIs so
	// authenticator apps can label the account. Required.
	Issuer string
	// Period is the time-step length in seconds. Zero defaults to 30;
	// values outside 15 through 120 are rejected.
	Period uint
	// Skew is how many adjacent time steps are accepted around the current
	// one to absorb clock drift. At most 2; larger windows widen the
	// brute-force and replay surface.
	Skew uint
}

// Provider generates and validates TOTP codes. It is stateless and safe for
// concurrent use. It implements credbound.TOTPProvider.
type Provider struct {
	issuer string
	period uint
	skew   uint
}

// New validates config and returns a Provider. A missing issuer or an
// unsafe period/skew combination is rejected.
func New(config Config) (*Provider, error) {
	config.Issuer = strings.TrimSpace(config.Issuer)
	if config.Issuer == "" {
		return nil, errors.New("totp: issuer is required")
	}
	if config.Period == 0 {
		config.Period = 30
	}
	if config.Period < 15 || config.Period > 120 || config.Skew > 2 {
		return nil, errors.New("totp: unsafe period or skew")
	}
	return &Provider{issuer: config.Issuer, period: config.Period, skew: config.Skew}, nil
}

// Generate creates a fresh 160-bit shared secret for accountName and
// returns the base32 secret together with its otpauth:// provisioning URI.
// The secret must be treated as a credential; Credbound stores it
// encrypted and the URI should only ever be shown to the enrolling user.
func (p *Provider) Generate(accountName string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: p.issuer, AccountName: accountName,
		Period: p.period, SecretSize: 20,
		Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// Validate checks code against secret at the given time, accepting the
// configured skew. It always returns the current time step so the store can
// reject replays of an already-used step, and reports whether the code was
// valid.
func (p *Provider) Validate(code, secret string, at time.Time) (int64, bool) {
	valid, err := totp.ValidateCustom(code, secret, at, totp.ValidateOpts{
		Period: p.period, Skew: p.skew, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	return at.Unix() / int64(p.period), err == nil && valid
}
