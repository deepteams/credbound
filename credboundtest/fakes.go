package credboundtest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/deepteams/credbound"
)

// ValidTOTPCode is the only code the TOTP fake accepts. Any other input is
// rejected, so tests can exercise both success and failure paths.
const ValidTOTPCode = "123456"

// ValidPasskeyResponse is the only client response the Passkeys fake accepts;
// pass []byte(ValidPasskeyResponse) to FinishPasskeyRegistration and
// FinishPasskeyAuthentication. Any other response fails the ceremony.
const ValidPasskeyResponse = "valid"

// Passwords is a fast fake credbound.PasswordHasher for tests. Hash returns a
// recoverable marker ("credboundtest$" plus the password) instead of a real
// key derivation, so building a manager and authenticating cost nothing.
//
// It must never be used in production: it performs no salting, no stretching,
// and stores the password in clear inside the "hash".
type Passwords struct{}

var _ credbound.PasswordHasher = Passwords{}

// Hash returns a deterministic marker embedding the password.
func (Passwords) Hash(password string) (string, error) {
	return "credboundtest$" + password, nil
}

// Verify reports whether encoded is the marker produced by Hash for password.
// It never requests a rehash.
func (Passwords) Verify(password, encoded string) (match bool, rehash bool, err error) {
	return encoded == "credboundtest$"+password, false, nil
}

// TOTP is a fake credbound.TOTPProvider for tests. Generate returns a fixed
// secret and otpauth URI, and Validate accepts exactly ValidTOTPCode
// ("123456" is always valid; everything else never is).
//
// Validate reports the real 30-second step for the given instant, so the
// manager's replay protection behaves as in production: verifying
// ValidTOTPCode twice without advancing the Clock by at least 30 seconds
// fails the second attempt with credbound.ErrInvalidCredentials.
type TOTP struct{}

var _ credbound.TOTPProvider = TOTP{}

// Generate returns a fixed secret and a syntactically valid otpauth URI for
// the account.
func (TOTP) Generate(accountName string) (secret string, uri string, err error) {
	return "CREDBOUNDTESTSECRET", "otpauth://totp/credboundtest:" + accountName, nil
}

// Validate accepts exactly ValidTOTPCode and reports the 30-second step of at.
func (TOTP) Validate(code, _ string, at time.Time) (step int64, valid bool) {
	return at.Unix() / 30, code == ValidTOTPCode
}

// Passkeys is a fake credbound.PasskeyProvider for tests. Both ceremonies
// return fixed JSON options and an opaque session, and both Finish methods
// accept exactly []byte(ValidPasskeyResponse) as the client response. The
// registered credential is a fixed JSON document whose authenticator counter
// increments on authentication, mirroring a real WebAuthn provider closely
// enough for the manager's encrypt-at-rest and ceremony plumbing to be
// exercised end to end.
type Passkeys struct{}

var _ credbound.PasskeyProvider = Passkeys{}

// BeginRegistration returns fixed creation options and the registration
// session that FinishRegistration expects back.
func (Passkeys) BeginRegistration(context.Context, credbound.PasskeyUser) (json.RawMessage, []byte, error) {
	return json.RawMessage(`{"publicKey":{}}`), []byte("registration-session"), nil
}

// FinishRegistration validates the session issued by BeginRegistration and
// accepts exactly []byte(ValidPasskeyResponse), returning a fixed credential.
func (Passkeys) FinishRegistration(_ context.Context, _ credbound.PasskeyUser, session, response []byte) (credentialID, credentialJSON []byte, err error) {
	if string(session) != "registration-session" || string(response) != ValidPasskeyResponse {
		return nil, nil, errors.New("credboundtest: invalid registration ceremony")
	}
	return []byte("credential"), []byte(`{"id":"credential","counter":0}`), nil
}

// BeginAuthentication drains the user's stored credentials — surfacing any
// decryption error the manager reports — and returns fixed request options
// with the session that FinishAuthentication expects back.
func (Passkeys) BeginAuthentication(_ context.Context, user credbound.PasskeyUser) (json.RawMessage, []byte, error) {
	for _, err := range user.Credentials {
		if err != nil {
			return nil, nil, err
		}
	}
	return json.RawMessage(`{"publicKey":{}}`), []byte("authentication-session"), nil
}

// FinishAuthentication validates the session issued by BeginAuthentication
// and accepts exactly []byte(ValidPasskeyResponse), returning the fixed
// credential with its counter advanced.
func (Passkeys) FinishAuthentication(_ context.Context, _ credbound.PasskeyUser, session, response []byte) (credentialID, credentialJSON []byte, err error) {
	if string(session) != "authentication-session" || string(response) != ValidPasskeyResponse {
		return nil, nil, errors.New("credboundtest: invalid authentication ceremony")
	}
	return []byte("credential"), []byte(`{"id":"credential","counter":1}`), nil
}

// NewDeterministicRandom returns an io.Reader emitting a fixed byte sequence,
// so identifiers and tokens are reproducible across runs. It is the default
// random source of NewManager and is, by design, not cryptographically
// secure; never use it outside tests.
func NewDeterministicRandom() io.Reader {
	return &deterministicReader{next: 0x42}
}

type deterministicReader struct {
	next byte
}

func (r *deterministicReader) Read(value []byte) (int, error) {
	for index := range value {
		value[index] = r.next
		r.next++
	}
	return len(value), nil
}
