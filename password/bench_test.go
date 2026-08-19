package password_test

import (
	"testing"

	"github.com/deepteams/credbound/password"
)

// Argon2id cost is a security parameter with a latency budget attached: the
// defaults are chosen to make a sign-in expensive for an attacker and
// tolerable for a user. These benchmarks make a change to DefaultParams
// measurable — `go test ./password -bench . -benchtime 10x` — instead of
// something a reviewer has to guess at.

func BenchmarkHashDefaultParams(b *testing.B) {
	hasher, err := password.New(password.DefaultParams())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := hasher.Hash("correct horse battery staple"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyDefaultParams(b *testing.B) {
	hasher, err := password.New(password.DefaultParams())
	if err != nil {
		b.Fatal(err)
	}
	encoded, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		match, _, err := hasher.Verify("correct horse battery staple", encoded)
		if err != nil || !match {
			b.Fatalf("verify = %v, %v", match, err)
		}
	}
}

// BenchmarkVerifyWrongPassword measures the failure path, which must cost the
// same derivation as the success path: a cheap rejection would leak account
// state through timing.
func BenchmarkVerifyWrongPassword(b *testing.B) {
	hasher, err := password.New(password.DefaultParams())
	if err != nil {
		b.Fatal(err)
	}
	encoded, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if match, _, err := hasher.Verify("wrong horse battery staple", encoded); err != nil || match {
			b.Fatalf("verify = %v, %v", match, err)
		}
	}
}
