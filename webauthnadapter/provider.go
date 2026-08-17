// Package webauthnadapter implements the credbound.PasskeyProvider port on
// top of github.com/go-webauthn/webauthn. Every ceremony requires user
// verification, so passkey authentication yields AAL2 directly, and user
// handles are HMAC-derived from the account ID so authenticators never
// learn stable Credbound identifiers.
//
// Wire it into credbound.Config.Passkeys:
//
//	passkeys, err := webauthnadapter.New(webauthnadapter.Config{
//		RPID:          "example.com",
//		RPDisplayName: "Example",
//		RPOrigins:     []string{"https://app.example.com"},
//		UserHandleKey: key, // at least 32 secret bytes
//	})
//
// Credbound seals the ceremony session into its continuation; the host only
// shuttles the JSON options and browser responses.
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

// Config identifies the WebAuthn relying party and the key material used to
// derive user handles.
type Config struct {
	// RPID is the relying-party identifier, normally the registrable
	// domain (e.g. "example.com"). Changing it invalidates every
	// registered passkey.
	RPID string
	// RPDisplayName is the human-readable relying-party name shown by
	// authenticators during ceremonies.
	RPDisplayName string
	// RPOrigins lists the exact web origins allowed to complete
	// ceremonies (e.g. "https://app.example.com"). Responses from any
	// other origin are rejected.
	RPOrigins []string
	// UserHandleKey is a secret of at least 32 bytes used to HMAC user IDs
	// into WebAuthn user handles. Keep it stable — rotating it orphans
	// discoverable credentials — and never reuse another Credbound key.
	UserHandleKey []byte
	// MaxCredentials caps how many stored passkeys one user may present in
	// a ceremony, 1 through 100. Zero defaults to 20.
	MaxCredentials int
}

// Provider runs WebAuthn registration and authentication ceremonies with
// mandatory user verification. It is safe for concurrent use and implements
// credbound.PasskeyProvider.
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

// New validates config and returns a Provider. A user handle key shorter
// than 32 bytes, an out-of-range credential cap or an invalid relying-party
// configuration is rejected.
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

// BeginRegistration starts a passkey registration ceremony and returns the
// browser creation options plus the opaque session Credbound seals into the
// continuation.
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

// FinishRegistration validates the browser's attestation response against
// the sealed session and returns the new credential ID and its JSON
// encoding for storage.
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

// BeginAuthentication starts an assertion ceremony over the user's stored
// passkeys and returns the browser request options plus the opaque session.
// It fails when the user has no passkey.
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

// FinishAuthentication validates the browser's assertion response against
// the sealed session and returns the matched credential ID and its updated
// JSON encoding (sign counter, flags) for persistence via TouchPasskey.
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
