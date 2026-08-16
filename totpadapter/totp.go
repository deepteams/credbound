package totpadapter

import (
	"errors"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type Config struct {
	Issuer string
	Period uint
	Skew   uint
}

type Provider struct {
	issuer string
	period uint
	skew   uint
}

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

func (p *Provider) Validate(code, secret string, at time.Time) (int64, bool) {
	valid, err := totp.ValidateCustom(code, secret, at, totp.ValidateOpts{
		Period: p.period, Skew: p.skew, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	return at.Unix() / int64(p.period), err == nil && valid
}
