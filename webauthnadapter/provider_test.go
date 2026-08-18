package webauthnadapter

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/deepteams/credbound"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestBeginDecoyAuthentication(t *testing.T) {
	provider := newProvider(t, 2)
	ctx := context.Background()
	parse := func(seed string) protocol.CredentialAssertion {
		t.Helper()
		options, session, err := provider.BeginDecoyAuthentication(ctx, []byte(seed))
		if err != nil || len(options) == 0 || len(session) == 0 {
			t.Fatalf("decoy(%q) = %s, %x, %v", seed, options, session, err)
		}
		var assertion protocol.CredentialAssertion
		if err := json.Unmarshal(options, &assertion); err != nil {
			t.Fatal(err)
		}
		return assertion
	}
	// Structurally a real assertion challenge: user verification required and
	// exactly one allowed credential.
	first := parse("seed-a")
	if first.Response.UserVerification != protocol.VerificationRequired {
		t.Fatalf("user verification = %q", first.Response.UserVerification)
	}
	if len(first.Response.AllowedCredentials) != 1 {
		t.Fatalf("allowed credentials = %d, want 1", len(first.Response.AllowedCredentials))
	}
	// Stable for the same address, distinct across addresses, so probes cannot
	// tell a decoy from a real challenge by its variation.
	firstID := string(first.Response.AllowedCredentials[0].CredentialID)
	if firstID != string(parse("seed-a").Response.AllowedCredentials[0].CredentialID) {
		t.Fatal("decoy credential id not stable for the same seed")
	}
	if firstID == string(parse("seed-b").Response.AllowedCredentials[0].CredentialID) {
		t.Fatal("decoy credential id must differ across seeds")
	}
}

func TestRegistrationOptionsRequireUserVerification(t *testing.T) {
	provider := newProvider(t, 2)
	input := emptyUser()
	options, session, err := provider.BeginRegistration(context.Background(), input)
	if err != nil || len(session) == 0 {
		t.Fatalf("begin registration = %s, %x, %v", options, session, err)
	}
	var creation protocol.CredentialCreation
	if err := json.Unmarshal(options, &creation); err != nil {
		t.Fatal(err)
	}
	if creation.Response.AuthenticatorSelection.UserVerification != protocol.VerificationRequired {
		t.Fatalf("user verification = %q", creation.Response.AuthenticatorSelection.UserVerification)
	}
	if creation.Response.AuthenticatorSelection.ResidentKey != protocol.ResidentKeyRequirementPreferred {
		t.Fatalf("resident key = %q", creation.Response.AuthenticatorSelection.ResidentKey)
	}
	var state webauthn.SessionData
	if err := json.Unmarshal(session, &state); err != nil || len(state.UserID) != sha256Size {
		t.Fatalf("session = %#v, %v", state, err)
	}
	if _, _, err := provider.BeginAuthentication(context.Background(), input); err == nil {
		t.Fatal("authentication without credential succeeded")
	}
}

func TestCredentialConversionAndErrors(t *testing.T) {
	provider := newProvider(t, 1)
	credential := webauthn.Credential{ID: []byte("credential"), PublicKey: []byte("public-key")}
	encoded, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	input := userWith(credbound.Passkey{CredentialID: []byte("credential"), CredentialJSON: encoded})
	converted, err := provider.convertUser(input)
	if err != nil || len(converted.credentials) != 1 || len(converted.id) != sha256Size {
		t.Fatalf("converted = %#v, %v", converted, err)
	}
	if converted.WebAuthnName() != "user@example.com" || converted.WebAuthnDisplayName() != "User" || len(converted.WebAuthnCredentials()) != 1 {
		t.Fatalf("WebAuthn user = %#v", converted)
	}
	copyID := converted.WebAuthnID()
	copyID[0] ^= 0xff
	if copyID[0] == converted.WebAuthnID()[0] {
		t.Fatal("WebAuthn ID was not cloned")
	}
	if _, err := provider.convertUser(userWith(credbound.Passkey{CredentialID: []byte("credential"), CredentialJSON: []byte("bad")})); err == nil {
		t.Fatal("invalid credential JSON accepted")
	}
	if _, err := provider.convertUser(userWith(credbound.Passkey{CredentialID: []byte("other"), CredentialJSON: encoded})); err == nil {
		t.Fatal("credential ID mismatch accepted")
	}
	two := func(yield func(credbound.Passkey, error) bool) {
		yield(credbound.Passkey{CredentialID: []byte("credential"), CredentialJSON: encoded}, nil)
		yield(credbound.Passkey{CredentialID: []byte("credential"), CredentialJSON: encoded}, nil)
	}
	overLimit := emptyUser()
	overLimit.Credentials = two
	if _, err := provider.convertUser(overLimit); err == nil {
		t.Fatal("credential limit was not enforced")
	}
	withError := emptyUser()
	withError.Credentials = func(yield func(credbound.Passkey, error) bool) { yield(credbound.Passkey{}, errors.New("store")) }
	if _, err := provider.convertUser(withError); err == nil {
		t.Fatal("store error was ignored")
	}
}

func TestProviderValidationAndMalformedFinishes(t *testing.T) {
	if _, err := New(Config{RPID: "example.com", RPDisplayName: "App", RPOrigins: []string{"https://example.com"}, UserHandleKey: []byte("short")}); err == nil {
		t.Fatal("short user handle key accepted")
	}
	if _, err := New(Config{RPID: "example.com", RPDisplayName: "App", RPOrigins: []string{"https://example.com"}, UserHandleKey: bytes(32), MaxCredentials: 101}); err == nil {
		t.Fatal("invalid credential limit accepted")
	}
	if _, err := New(Config{RPID: "bad host", RPDisplayName: "App", RPOrigins: []string{"https://example.com"}, UserHandleKey: bytes(32)}); err == nil {
		t.Fatal("invalid RPID accepted")
	}
	provider := newProvider(t, 2)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := provider.BeginRegistration(ctx, emptyUser()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled begin = %v", err)
	}
	if _, _, err := provider.FinishRegistration(ctx, emptyUser(), nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled registration finish = %v", err)
	}
	if _, _, err := provider.FinishAuthentication(ctx, emptyUser(), nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled authentication finish = %v", err)
	}
	if _, _, err := provider.FinishRegistration(context.Background(), emptyUser(), []byte("bad"), []byte("bad")); err == nil {
		t.Fatal("malformed registration session accepted")
	}
	if _, err := unmarshalSession([]byte("bad")); err == nil {
		t.Fatal("malformed session accepted")
	}
}

func TestCeremonyDelegationAndCredentialPersistence(t *testing.T) {
	credential := webauthn.Credential{ID: []byte("credential"), PublicKey: []byte("public-key")}
	encoded, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	backend := &fakeEngine{credential: &credential}
	provider := &Provider{
		webAuthn: backend, userHandleKey: bytes(32), maxCredentials: 2,
		parseCreation: func([]byte) (*protocol.ParsedCredentialCreationData, error) {
			return &protocol.ParsedCredentialCreationData{}, nil
		},
		parseAssertion: func([]byte) (*protocol.ParsedCredentialAssertionData, error) {
			return &protocol.ParsedCredentialAssertionData{}, nil
		},
	}
	input := userWith(credbound.Passkey{CredentialID: credential.ID, CredentialJSON: encoded})
	if options, session, err := provider.BeginAuthentication(context.Background(), input); err != nil || len(options) == 0 || len(session) == 0 {
		t.Fatalf("begin authentication = %s, %s, %v", options, session, err)
	}
	credentialID, updated, err := provider.FinishRegistration(context.Background(), input, []byte(`{}`), []byte(`{}`))
	if err != nil || string(credentialID) != "credential" || len(updated) == 0 {
		t.Fatalf("finish registration = %q, %s, %v", credentialID, updated, err)
	}
	credentialID, updated, err = provider.FinishAuthentication(context.Background(), input, []byte(`{}`), []byte(`{}`))
	if err != nil || string(credentialID) != "credential" || len(updated) == 0 {
		t.Fatalf("finish authentication = %q, %s, %v", credentialID, updated, err)
	}

	backend.err = errors.New("backend")
	if _, _, err := provider.BeginRegistration(context.Background(), input); err == nil {
		t.Fatal("backend registration begin error ignored")
	}
	if _, _, err := provider.BeginAuthentication(context.Background(), input); err == nil {
		t.Fatal("backend begin error ignored")
	}
	if _, _, err := provider.FinishRegistration(context.Background(), input, []byte(`{}`), []byte(`{}`)); err == nil {
		t.Fatal("backend registration error ignored")
	}
	if _, _, err := provider.FinishAuthentication(context.Background(), input, []byte(`{}`), []byte(`{}`)); err == nil {
		t.Fatal("backend authentication error ignored")
	}
	provider.parseCreation = func([]byte) (*protocol.ParsedCredentialCreationData, error) { return nil, errors.New("parse") }
	if _, _, err := provider.FinishRegistration(context.Background(), input, []byte(`{}`), nil); err == nil {
		t.Fatal("registration parse error ignored")
	}
	provider.parseAssertion = func([]byte) (*protocol.ParsedCredentialAssertionData, error) { return nil, errors.New("parse") }
	if _, _, err := provider.FinishAuthentication(context.Background(), input, []byte(`{}`), nil); err == nil {
		t.Fatal("authentication parse error ignored")
	}
}

func TestConversionAndSessionFailuresAcrossCeremonies(t *testing.T) {
	provider := newProvider(t, 2)
	badUser := emptyUser()
	badUser.Credentials = func(yield func(credbound.Passkey, error) bool) {
		yield(credbound.Passkey{}, errors.New("credential store offline"))
	}
	if _, _, err := provider.BeginRegistration(context.Background(), badUser); err == nil {
		t.Fatal("registration conversion error ignored")
	}
	if _, _, err := provider.FinishRegistration(context.Background(), badUser, []byte(`{}`), nil); err == nil {
		t.Fatal("registration finish conversion error ignored")
	}
	if _, _, err := provider.BeginAuthentication(context.Background(), badUser); err == nil {
		t.Fatal("authentication conversion error ignored")
	}
	if _, _, err := provider.FinishAuthentication(context.Background(), badUser, []byte(`{}`), nil); err == nil {
		t.Fatal("authentication finish conversion error ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := provider.BeginAuthentication(ctx, emptyUser()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled authentication begin = %v", err)
	}
	if _, _, err := provider.FinishAuthentication(context.Background(), emptyUser(), []byte("bad"), nil); err == nil {
		t.Fatal("malformed authentication session accepted")
	}
	if _, _, err := marshalCeremony(make(chan int), &webauthn.SessionData{}); err == nil {
		t.Fatal("unmarshalable ceremony options accepted")
	}
}

// TestFinishAuthenticationRejectsCloneWarning ensures a regressed signature
// counter (which go-webauthn signals via CloneWarning rather than an error) is
// rejected instead of silently authenticating a possibly cloned authenticator.
func TestFinishAuthenticationRejectsCloneWarning(t *testing.T) {
	credential := webauthn.Credential{ID: []byte("credential"), PublicKey: []byte("public-key")}
	credential.Authenticator.CloneWarning = true
	encoded, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	provider := &Provider{
		webAuthn: &fakeEngine{credential: &credential}, userHandleKey: bytes(32), maxCredentials: 2,
		parseAssertion: func([]byte) (*protocol.ParsedCredentialAssertionData, error) {
			return &protocol.ParsedCredentialAssertionData{}, nil
		},
	}
	input := userWith(credbound.Passkey{CredentialID: credential.ID, CredentialJSON: encoded})
	if _, _, err := provider.FinishAuthentication(context.Background(), input, []byte(`{}`), []byte(`{}`)); !errors.Is(err, credbound.ErrPasskeyCloneDetected) {
		t.Fatalf("clone warning not rejected: %v", err)
	}
}

const sha256Size = 32

func newProvider(t *testing.T, max int) *Provider {
	t.Helper()
	provider, err := New(Config{
		RPID: "example.com", RPDisplayName: "Credbound", RPOrigins: []string{"https://example.com"},
		UserHandleKey: bytes(32), MaxCredentials: max,
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func emptyUser() credbound.PasskeyUser {
	return credbound.PasskeyUser{
		User:        credbound.User{ID: "0198b463-0000-7000-8000-000000000001", Email: "user@example.com", DisplayName: "User"},
		Credentials: func(func(credbound.Passkey, error) bool) {},
	}
}

func userWith(passkey credbound.Passkey) credbound.PasskeyUser {
	value := emptyUser()
	value.Credentials = func(yield func(credbound.Passkey, error) bool) { yield(passkey, nil) }
	return value
}

func bytes(size int) []byte { return []byte(strings.Repeat("k", size)) }

type fakeEngine struct {
	credential *webauthn.Credential
	err        error
}

func (f *fakeEngine) BeginRegistration(webauthn.User, ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	if f.err != nil {
		return nil, nil, f.err
	}
	return &protocol.CredentialCreation{}, &webauthn.SessionData{}, nil
}
func (f *fakeEngine) CreateCredential(webauthn.User, webauthn.SessionData, *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
	return f.credential, f.err
}
func (f *fakeEngine) BeginLogin(webauthn.User, ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	if f.err != nil {
		return nil, nil, f.err
	}
	return &protocol.CredentialAssertion{}, &webauthn.SessionData{}, nil
}
func (f *fakeEngine) ValidateLogin(webauthn.User, webauthn.SessionData, *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
	return f.credential, f.err
}
