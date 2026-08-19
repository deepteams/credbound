package password

import (
	"strings"
	"testing"
)

// FuzzParse pins the stored-hash parser, which reads whatever the database
// holds: a malformed or tampered encoding must be refused rather than
// silently accepted with weak parameters, and an accepted one always carries
// parameters inside the safety bounds together with a usable salt and digest.
func FuzzParse(f *testing.F) {
	hasher, err := New(Params{Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	if err != nil {
		f.Fatal(err)
	}
	encoded, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add("")
	f.Add("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGE")
	f.Add("$argon2id$v=19$m=1,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGE")
	f.Add("$argon2i$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA")
	f.Add("$argon2id$v=19$m=19456,t=2,p=1$$")
	f.Add(strings.Repeat("$", 6))

	f.Fuzz(func(t *testing.T, raw string) {
		params, salt, hash, err := parse(raw)
		if err != nil {
			if params != (Params{}) || salt != nil || hash != nil {
				t.Fatalf("rejected encoding returned %#v, %v, %v", params, salt, hash)
			}
			return
		}
		if params.Memory < 8*1024 || params.Memory > 1024*1024 {
			t.Fatalf("accepted memory cost %d KiB", params.Memory)
		}
		if params.Iterations == 0 || params.Iterations > 20 || params.Parallelism == 0 || params.Parallelism > 16 {
			t.Fatalf("accepted cost parameters %#v", params)
		}
		if len(salt) < 8 || len(salt) > 64 || len(hash) < 16 || len(hash) > 64 {
			t.Fatalf("accepted a %d-byte salt and a %d-byte digest", len(salt), len(hash))
		}
		// Verification over the same encoding must stay total: it may
		// refuse, but it must never panic nor report a match with an error.
		match, _, verifyErr := hasher.Verify("correct horse battery staple", raw)
		if match && verifyErr != nil {
			t.Fatalf("match reported alongside %v", verifyErr)
		}
	})
}

// FuzzVerify pins the hasher's outer entry point: any stored string at all,
// including one an attacker managed to write, is answered without panicking.
func FuzzVerify(f *testing.F) {
	hasher, err := New(DefaultParams())
	if err != nil {
		f.Fatal(err)
	}
	f.Add("correct horse battery staple", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGE")
	f.Add("", "")
	f.Add("password", "credboundtest$password")

	f.Fuzz(func(t *testing.T, secret, encoded string) {
		match, rehash, err := hasher.Verify(secret, encoded)
		if err != nil && (match || rehash) {
			t.Fatalf("failed verification reported match=%v rehash=%v", match, rehash)
		}
	})
}
