package password

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestHashVerifyAndRehash(t *testing.T) {
	params := Params{Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 16, Random: strings.NewReader(strings.Repeat("s", 64))}
	hasher, err := New(params)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := hasher.Hash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	match, rehash, err := hasher.Verify("correct horse battery", encoded)
	if err != nil || !match || rehash {
		t.Fatalf("verify = %v, %v, %v", match, rehash, err)
	}
	match, rehash, err = hasher.Verify("wrong", encoded)
	if err != nil || match || rehash {
		t.Fatalf("wrong verify = %v, %v, %v", match, rehash, err)
	}
	stronger, err := New(Params{Memory: 19 * 1024, Iterations: 3, Parallelism: 1, SaltLength: 16, KeyLength: 16, Random: strings.NewReader(strings.Repeat("x", 64))})
	if err != nil {
		t.Fatal(err)
	}
	match, rehash, err = stronger.Verify("correct horse battery", encoded)
	if err != nil || !match || !rehash {
		t.Fatalf("rehash verify = %v, %v, %v", match, rehash, err)
	}
}

func TestParameterAndEncodingValidation(t *testing.T) {
	defaults := DefaultParams()
	if defaults.Memory == 0 || defaults.Random == nil {
		t.Fatalf("invalid defaults: %#v", defaults)
	}
	invalid := []Params{
		{},
		{Memory: 18 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 16},
		{Memory: 19 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16},
		{Memory: 19 * 1024, Iterations: 2, Parallelism: 17, SaltLength: 16, KeyLength: 16},
		{Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 8, KeyLength: 16},
		{Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 8},
	}
	for _, params := range invalid {
		if _, err := New(params); err == nil {
			t.Fatalf("accepted unsafe params: %#v", params)
		}
	}
	malformed := []string{
		"", "$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$MTIzNDU2Nzg5MDEyMzQ1Ng",
		"$argon2id$v=18$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$MTIzNDU2Nzg5MDEyMzQ1Ng",
		"$argon2id$v=19$m=19456,t=2$c2FsdHNhbHRzYWx0c2FsdA$MTIzNDU2Nzg5MDEyMzQ1Ng",
		"$argon2id$v=19$x=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$MTIzNDU2Nzg5MDEyMzQ1Ng",
		"$argon2id$v=19$m=19456,x=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$MTIzNDU2Nzg5MDEyMzQ1Ng",
		"$argon2id$v=19$m=19456,t=2,x=1$c2FsdHNhbHRzYWx0c2FsdA$MTIzNDU2Nzg5MDEyMzQ1Ng",
		"$argon2id$v=19$m=99999999,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$MTIzNDU2Nzg5MDEyMzQ1Ng",
		"$argon2id$v=19$m=19456,t=2,p=1$bad!$MTIzNDU2Nzg5MDEyMzQ1Ng",
		"$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$bad!",
	}
	hasher, _ := New(Params{Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 16})
	for _, encoded := range malformed {
		if _, _, err := hasher.Verify("password", encoded); err == nil {
			t.Fatalf("accepted malformed hash: %q", encoded)
		}
	}
	if _, err := parseUint("m=nope", "m=", 32); err == nil {
		t.Fatal("accepted non numeric parameter")
	}
}

func TestEntropyFailure(t *testing.T) {
	hasher, err := New(Params{Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 16, Random: errorReader{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hasher.Hash("password"); err == nil {
		t.Fatal("expected entropy error")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

var _ io.Reader = errorReader{}
