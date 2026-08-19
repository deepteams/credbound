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
	"crypto/subtle"
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
// configured skew. It returns the time step of the code that actually matched
// — not the wall-clock step — so the store's monotonic replay guard
// (last_used_step) rejects reuse of a code across every step in the skew
// window. Returning the wall-clock step would let a code accepted at an earlier
// step be replayed at each later step still inside the window. The reported
// step is meaningful only when the boolean is true; otherwise it is the current
// wall-clock step.
func (p *Provider) Validate(code, secret string, at time.Time) (int64, bool) {
	period := int64(p.period)
	current := at.Unix() / period
	skew := int64(p.skew)
	opts := totp.ValidateOpts{Period: p.period, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	matched := false
	step := current
	// Scan the whole window without early exit so timing does not reveal which
	// step matched.
	for offset := -skew; offset <= skew; offset++ {
		counter := current + offset
		expected, err := totp.GenerateCodeCustom(secret, time.Unix(counter*period, 0), opts)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			matched = true
			step = counter
		}
	}
	return step, matched
}
