// Package password implements the credbound.PasswordHasher port with
// Argon2id (RFC 9106). Hashes are self-describing PHC strings
// ($argon2id$v=19$...), so parameters can be raised later and existing
// hashes transparently renew on the next successful login.
//
// Wire it into credbound.Config.Passwords:
//
//	hasher, err := password.New(password.DefaultParams())
//
// New rejects parameters below the OWASP-recommended floor; there is no
// weak fallback.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params are the Argon2id cost and encoding parameters used for new hashes.
// New validates every bound; use DefaultParams unless a security review
// calls for different costs.
type Params struct {
	// Memory is the Argon2id memory cost in KiB. New requires 19 MiB
	// (19*1024) through 1 GiB.
	Memory uint32
	// Iterations is the time cost (passes over memory), 2 through 20.
	Iterations uint32
	// Parallelism is the number of lanes, 1 through 16.
	Parallelism uint8
	// SaltLength is the random salt size in bytes, 16 through 64.
	SaltLength uint32
	// KeyLength is the derived key size in bytes, 16 through 64.
	KeyLength uint32
	// Random supplies salt entropy and defaults to crypto/rand.Reader.
	// Override it only in tests.
	Random io.Reader
}

// Hasher hashes and verifies passwords with Argon2id. It is stateless and
// safe for concurrent use. It implements credbound.PasswordHasher.
type Hasher struct {
	params Params
}

// DefaultParams returns the recommended production parameters: 64 MiB of
// memory, 3 iterations, 2 lanes, a 16 byte salt and a 32 byte key.
func DefaultParams() Params {
	return Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32, Random: rand.Reader}
}

// New validates params and returns a Hasher. Parameters outside the safe
// bounds documented on Params are rejected outright — there is no silent
// weakening. A nil Random falls back to crypto/rand.Reader.
func New(params Params) (*Hasher, error) {
	if params.Random == nil {
		params.Random = rand.Reader
	}
	if params.Memory < 19*1024 || params.Memory > 1024*1024 || params.Iterations < 2 || params.Iterations > 20 ||
		params.Parallelism == 0 || params.Parallelism > 16 || params.SaltLength < 16 || params.SaltLength > 64 ||
		params.KeyLength < 16 || params.KeyLength > 64 {
		return nil, errors.New("password: unsafe argon2id parameters")
	}
	return &Hasher{params: params}, nil
}

// Hash derives an Argon2id hash of password under the configured parameters
// with a fresh random salt and returns it as a PHC-formatted string.
func (h *Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.params.SaltLength)
	if _, err := io.ReadFull(h.params.Random, salt); err != nil {
		return "", fmt.Errorf("password: read salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, h.params.Iterations, h.params.Memory, h.params.Parallelism, h.params.KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.params.Memory, h.params.Iterations, h.params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

// Verify recomputes the hash under the parameters embedded in encoded and
// compares it in constant time. It reports match, plus rehash when the match
// succeeded but the stored parameters differ from the Hasher's current
// policy, so the caller can renew the hash. Encodings outside the safety
// bounds (below 8 MiB of memory) are rejected as malformed, not verified.
func (h *Hasher) Verify(password, encoded string) (bool, bool, error) {
	params, salt, expected, err := parse(encoded)
	if err != nil {
		return false, false, err
	}
	actual := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(expected)))
	match := subtle.ConstantTimeCompare(actual, expected) == 1
	rehash := match && (params.Memory != h.params.Memory || params.Iterations != h.params.Iterations ||
		params.Parallelism != h.params.Parallelism || uint32(len(salt)) != h.params.SaltLength || uint32(len(expected)) != h.params.KeyLength)
	return match, rehash, nil
}

func parse(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return Params{}, nil, nil, errors.New("password: malformed argon2id hash")
	}
	var params Params
	values := strings.Split(parts[3], ",")
	if len(values) != 3 {
		return Params{}, nil, nil, errors.New("password: malformed argon2id parameters")
	}
	memory, err := parseUint(values[0], "m=", 32)
	if err != nil {
		return Params{}, nil, nil, err
	}
	iterations, err := parseUint(values[1], "t=", 32)
	if err != nil {
		return Params{}, nil, nil, err
	}
	parallelism, err := parseUint(values[2], "p=", 8)
	if err != nil {
		return Params{}, nil, nil, err
	}
	params.Memory, params.Iterations, params.Parallelism = uint32(memory), uint32(iterations), uint8(parallelism)
	// Verification accepts a wider floor than New so hashes imported from a
	// previous system can still authenticate once (they are rehashed under the
	// current policy on the first successful login), but never below 8 MiB of
	// memory: weaker stored parameters indicate tampering, not legacy data.
	if params.Memory < 8*1024 || params.Memory > 1024*1024 || params.Iterations == 0 || params.Iterations > 20 || params.Parallelism == 0 || params.Parallelism > 16 {
		return Params{}, nil, nil, errors.New("password: argon2id parameters outside safety bounds")
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return Params{}, nil, nil, errors.New("password: malformed argon2id salt")
	}
	hash, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(hash) < 16 || len(hash) > 64 {
		return Params{}, nil, nil, errors.New("password: malformed argon2id digest")
	}
	return params, salt, hash, nil
}

func parseUint(value, prefix string, bits int) (uint64, error) {
	if !strings.HasPrefix(value, prefix) {
		return 0, errors.New("password: malformed argon2id parameter")
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, bits)
	if err != nil {
		return 0, errors.New("password: malformed argon2id parameter")
	}
	return parsed, nil
}
