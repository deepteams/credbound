package webauthnadapter

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/deepteams/credbound"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type Config struct {
	RPID           string
	RPDisplayName  string
	RPOrigins      []string
	UserHandleKey  []byte
	MaxCredentials int
}

type Provider struct {
	webAuthn       engine
	userHandleKey  []byte
	maxCredentials int
	parseCreation  func([]byte) (*protocol.ParsedCredentialCreationData, error)
	parseAssertion func([]byte) (*protocol.ParsedCredentialAssertionData, error)
}

type engine interface {
	BeginRegistration(webauthn.User, ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	CreateCredential(webauthn.User, webauthn.SessionData, *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error)
	BeginLogin(webauthn.User, ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	ValidateLogin(webauthn.User, webauthn.SessionData, *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error)
}

func New(config Config) (*Provider, error) {
	if len(config.UserHandleKey) < 32 {
		return nil, errors.New("webauthn: user handle key must contain at least 32 bytes")
	}
	if config.MaxCredentials == 0 {
		config.MaxCredentials = 20
	}
	if config.MaxCredentials < 1 || config.MaxCredentials > 100 {
		return nil, errors.New("webauthn: max credentials must be between 1 and 100")
	}
	instance, err := webauthn.New(&webauthn.Config{
		RPID: config.RPID, RPDisplayName: config.RPDisplayName, RPOrigins: slices.Clone(config.RPOrigins),
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, err
	}
	return &Provider{
		webAuthn: instance, userHandleKey: slices.Clone(config.UserHandleKey), maxCredentials: config.MaxCredentials,
		parseCreation:  protocol.ParseCredentialCreationResponseBytes,
		parseAssertion: protocol.ParseCredentialRequestResponseBytes,
	}, nil
}

func (p *Provider) BeginRegistration(ctx context.Context, input credbound.PasskeyUser) (json.RawMessage, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	user, err := p.convertUser(input)
	if err != nil {
		return nil, nil, err
	}
	creation, session, err := p.webAuthn.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		}),
	)
	if err != nil {
		return nil, nil, err
	}
	return marshalCeremony(creation, session)
}

func (p *Provider) FinishRegistration(ctx context.Context, input credbound.PasskeyUser, rawSession, response []byte) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	user, err := p.convertUser(input)
	if err != nil {
		return nil, nil, err
	}
	session, err := unmarshalSession(rawSession)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := p.parseCreation(response)
	if err != nil {
		return nil, nil, err
	}
	credential, err := p.webAuthn.CreateCredential(user, session, parsed)
	if err != nil {
		return nil, nil, err
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		return nil, nil, err
	}
	return slices.Clone(credential.ID), encoded, nil
}

func (p *Provider) BeginAuthentication(ctx context.Context, input credbound.PasskeyUser) (json.RawMessage, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	user, err := p.convertUser(input)
	if err != nil {
		return nil, nil, err
	}
	if len(user.credentials) == 0 {
		return nil, nil, errors.New("webauthn: user has no passkey")
	}
	assertion, session, err := p.webAuthn.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, nil, err
	}
	return marshalCeremony(assertion, session)
}

func (p *Provider) FinishAuthentication(ctx context.Context, input credbound.PasskeyUser, rawSession, response []byte) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	user, err := p.convertUser(input)
	if err != nil {
		return nil, nil, err
	}
	session, err := unmarshalSession(rawSession)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := p.parseAssertion(response)
	if err != nil {
		return nil, nil, err
	}
	credential, err := p.webAuthn.ValidateLogin(user, session, parsed)
	if err != nil {
		return nil, nil, err
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		return nil, nil, err
	}
	return slices.Clone(credential.ID), encoded, nil
}

type user struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u user) WebAuthnID() []byte                         { return slices.Clone(u.id) }
func (u user) WebAuthnName() string                       { return u.name }
func (u user) WebAuthnDisplayName() string                { return u.displayName }
func (u user) WebAuthnCredentials() []webauthn.Credential { return slices.Clone(u.credentials) }

func (p *Provider) convertUser(input credbound.PasskeyUser) (user, error) {
	handle := hmac.New(sha256.New, p.userHandleKey)
	_, _ = handle.Write([]byte(input.User.ID))
	result := user{id: handle.Sum(nil), name: input.User.Email, displayName: input.User.DisplayName}
	for passkey, err := range input.Credentials {
		if err != nil {
			return user{}, err
		}
		if len(result.credentials) >= p.maxCredentials {
			return user{}, fmt.Errorf("webauthn: user exceeds the limit of %d credentials", p.maxCredentials)
		}
		var credential webauthn.Credential
		if err := json.Unmarshal(passkey.CredentialJSON, &credential); err != nil {
			return user{}, fmt.Errorf("webauthn: decode credential: %w", err)
		}
		if !hmac.Equal(credential.ID, passkey.CredentialID) {
			return user{}, errors.New("webauthn: credential id mismatch")
		}
		result.credentials = append(result.credentials, credential)
	}
	return result, nil
}

func marshalCeremony(value any, session *webauthn.SessionData) (json.RawMessage, []byte, error) {
	options, err := json.Marshal(value)
	if err != nil {
		return nil, nil, err
	}
	encodedSession, err := json.Marshal(session)
	if err != nil {
		return nil, nil, err
	}
	return options, encodedSession, nil
}

func unmarshalSession(raw []byte) (webauthn.SessionData, error) {
	var session webauthn.SessionData
	if err := json.Unmarshal(raw, &session); err != nil {
		return webauthn.SessionData{}, err
	}
	return session, nil
}

var _ credbound.PasskeyProvider = (*Provider)(nil)
