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

type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
	Random      io.Reader
}

type Hasher struct {
	params Params
}

func DefaultParams() Params {
	return Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32, Random: rand.Reader}
}

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
	if params.Memory < 8 || params.Memory > 1024*1024 || params.Iterations == 0 || params.Iterations > 20 || params.Parallelism == 0 || params.Parallelism > 16 {
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
