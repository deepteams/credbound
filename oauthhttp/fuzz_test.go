package oauthhttp

import (
	"testing"
	"time"
)

// FuzzParseMaxAge pins the OIDC max_age parameter, which arrives straight from
// a query string: an accepted value is never negative, and max_age=0 must map
// to a positive duration so it forces re-authentication instead of meaning
// "no constraint".
func FuzzParseMaxAge(f *testing.F) {
	f.Add("")
	f.Add("0")
	f.Add("3600")
	f.Add("-1")
	f.Add("+42")
	f.Add("99999999999999999999")
	f.Add("1e3")
	f.Add(" 60")

	f.Fuzz(func(t *testing.T, raw string) {
		age, ok := parseMaxAge(raw)
		if !ok {
			if age != 0 {
				t.Fatalf("rejected max_age %q returned %v", raw, age)
			}
			return
		}
		if age < 0 {
			t.Fatalf("accepted max_age %q as %v", raw, age)
		}
		if raw == "" {
			if age != 0 {
				t.Fatalf("absent max_age produced %v", age)
			}
			return
		}
		if age <= 0 {
			t.Fatalf("present max_age %q produced the no-constraint value %v", raw, age)
		}
		if raw == "0" && age != time.Nanosecond {
			t.Fatalf("max_age=0 produced %v, want the smallest positive duration", age)
		}
	})
}
