package credbound

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"unicode"
)

// The token parsers below are the first code an unauthenticated request
// reaches: whatever a client sends, they must decide without panicking and
// without ever accepting a shape the issuing side cannot produce. Fuzzing them
// is cheap — they are pure functions over a string — and it is the only way to
// cover the input space a hand-written table never will.

// FuzzParseSecretToken pins the shared `<prefix>_<uuidv7>_<43 chars>` shape of
// every emailed proof: an accepted token always carries a canonical UUIDv7 and
// a 32-byte secret, and a token built from those parts always parses back.
func FuzzParseSecretToken(f *testing.F) {
	f.Add("cbe", "cbe_0198b463-0000-7000-8000-000000000001_"+base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	f.Add("cbe", "")
	f.Add("cbe", "cbe_0198b463-0000-7000-8000-000000000001_short")
	f.Add("cbe", "cbe__")
	f.Add("cbr", "cbr_0198b463-0000-7000-8000-000000000001_"+strings.Repeat("A", 43))
	f.Add("cbe", "cbe_0198b463-0000-7000-8000-000000000001_"+strings.Repeat("=", 43))
	f.Add("", "_0198b463-0000-7000-8000-000000000001_"+strings.Repeat("A", 43))

	f.Fuzz(func(t *testing.T, prefix, raw string) {
		id, ok := parseSecretToken(prefix, raw)
		if !ok {
			if id != "" {
				t.Fatalf("rejected token returned the identifier %q", id)
			}
			return
		}
		if !validUUIDv7(id) {
			t.Fatalf("accepted token carries the non-UUIDv7 identifier %q", id)
		}
		if !strings.HasPrefix(raw, prefix+"_"+id+"_") {
			t.Fatalf("accepted token %q does not have the shape %q", raw, prefix+"_"+id+"_…")
		}
		secret := raw[len(prefix)+len(id)+2:]
		decoded, err := base64.RawURLEncoding.DecodeString(secret)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("accepted token carries a %d-byte secret (%v)", len(decoded), err)
		}
		// Re-parsing the same token is stable: no hidden state, no
		// normalization that would make a second lookup differ.
		if again, okAgain := parseSecretToken(prefix, raw); !okAgain || again != id {
			t.Fatalf("second parse = %q, %v", again, okAgain)
		}
	})
}

// FuzzParsePAT pins the PAT shape: an accepted token always yields the
// 12-hex-character prefix the store indexes, so a lookup can never be driven
// by an arbitrary string.
func FuzzParsePAT(f *testing.F) {
	f.Add("cbp_0123456789ab_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	f.Add("cbp_0123456789ab_short")
	f.Add("cbp__")
	f.Add("cbs_0123456789ab_" + strings.Repeat("A", 43))
	f.Add("cbp_0123456789AB_" + strings.Repeat("A", 43))

	f.Fuzz(func(t *testing.T, raw string) {
		prefix, ok := parsePAT(raw)
		if !ok {
			if prefix != "" {
				t.Fatalf("rejected PAT returned the prefix %q", prefix)
			}
			return
		}
		if len(prefix) != 12 {
			t.Fatalf("accepted PAT yields a %d-character prefix", len(prefix))
		}
		if _, err := hex.DecodeString(prefix); err != nil {
			t.Fatalf("accepted PAT prefix %q is not hexadecimal", prefix)
		}
		if !strings.HasPrefix(raw, "cbp_"+prefix+"_") {
			t.Fatalf("accepted PAT %q does not have the cbp shape", raw)
		}
	})
}

// FuzzParseServiceTokens pins the SCIM credential and OAuth bearer parsers,
// which sit on unauthenticated HTTP handlers. Both index the store by a
// 12-hexadecimal-character prefix, and both must yield nothing at all when
// they reject: a caller reading the identifier before the boolean would
// otherwise be handed attacker-controlled input.
func FuzzParseServiceTokens(f *testing.F) {
	f.Add("cbs_0123456789ab_"+strings.Repeat("A", 43), "cbat", "cbat_0123456789ab_"+strings.Repeat("A", 43))
	f.Add("", "", "")
	f.Add("cbs_x_y", "cbat", "cbat__")
	f.Add("cbs_0123456789ab_"+strings.Repeat("=", 43), "cbat", "cbat_0123456789ab_"+strings.Repeat("=", 43))

	f.Fuzz(func(t *testing.T, scim, marker, bearer string) {
		scimPrefix, scimOK := parseSCIMToken(scim)
		assertPrefixToken(t, "SCIM credential", scim, "cbs", scimPrefix, scimOK)
		bearerPrefix, bearerOK := parseOAuthBearer(marker, bearer)
		assertPrefixToken(t, "OAuth bearer", bearer, marker, bearerPrefix, bearerOK)
	})
}

// assertPrefixToken checks the shared contract of the prefix-indexed token
// parsers.
func assertPrefixToken(t *testing.T, label, raw, marker, prefix string, ok bool) {
	t.Helper()
	if !ok {
		if prefix != "" {
			t.Fatalf("rejected %s returned the prefix %q", label, prefix)
		}
		return
	}
	if len(prefix) != 12 {
		t.Fatalf("accepted %s yields a %d-character prefix", label, len(prefix))
	}
	if _, err := hex.DecodeString(prefix); err != nil {
		t.Fatalf("accepted %s prefix %q is not hexadecimal", label, prefix)
	}
	if !strings.HasPrefix(raw, marker+"_"+prefix+"_") {
		t.Fatalf("accepted %s %q does not carry the marker %q", label, raw, marker)
	}
	secret := raw[len(marker)+len(prefix)+2:]
	if decoded, err := base64.RawURLEncoding.DecodeString(secret); err != nil || len(decoded) != 32 {
		t.Fatalf("accepted %s carries a %d-byte secret (%v)", label, len(decoded), err)
	}
}

// FuzzNormalizeEmail pins the normalization every address lookup depends on:
// it is idempotent, it never leaves surrounding space, and a validated address
// is already in its normal form — otherwise two accounts could exist for what
// the store considers one address.
func FuzzNormalizeEmail(f *testing.F) {
	f.Add(" ROOT@Example.com ")
	f.Add("root@example.com")
	f.Add("")
	f.Add("\t\nroot@example.com\r\n")
	f.Add("ROOT+tag@EXAMPLE.COM")
	f.Add("root@exämple.com")
	f.Add("root@@example.com")

	f.Fuzz(func(t *testing.T, raw string) {
		normalized := normalizeEmail(raw)
		if again := normalizeEmail(normalized); again != normalized {
			t.Fatalf("normalization is not idempotent: %q then %q", normalized, again)
		}
		if strings.TrimFunc(normalized, unicode.IsSpace) != normalized {
			t.Fatalf("normalized address %q keeps surrounding space", normalized)
		}
		valid, err := validEmail(raw)
		if err != nil {
			return
		}
		if valid != normalized {
			t.Fatalf("validated address %q differs from the normalized %q", valid, normalized)
		}
		if !strings.Contains(valid, "@") || strings.ContainsFunc(valid, unicode.IsSpace) {
			t.Fatalf("validated address %q is not a plausible address", valid)
		}
	})
}

// FuzzValidUUIDv7 pins the identifier guard that keeps arbitrary strings out
// of store lookups: an accepted value is always the canonical 36-character
// lowercase form with version 7 and an RFC 4122 variant.
func FuzzValidUUIDv7(f *testing.F) {
	f.Add("0198b463-0000-7000-8000-000000000001")
	f.Add("0198B463-0000-7000-8000-000000000001")
	f.Add("0198b463-0000-4000-8000-000000000001")
	f.Add("0198b463-0000-7000-c000-000000000001")
	f.Add("")
	f.Add("0198b463000070008000000000000001")

	f.Fuzz(func(t *testing.T, raw string) {
		if !validUUIDv7(raw) {
			return
		}
		if len(raw) != 36 || raw != strings.ToLower(raw) {
			t.Fatalf("accepted identifier %q is not the canonical form", raw)
		}
		if raw[14] != '7' {
			t.Fatalf("accepted identifier %q is not version 7", raw)
		}
		if !strings.ContainsRune("89ab", rune(raw[19])) {
			t.Fatalf("accepted identifier %q has the variant nibble %q", raw, raw[19])
		}
		for index, char := range raw {
			if index == 8 || index == 13 || index == 18 || index == 23 {
				if char != '-' {
					t.Fatalf("accepted identifier %q is misgrouped", raw)
				}
				continue
			}
			if !strings.ContainsRune("0123456789abcdef", char) {
				t.Fatalf("accepted identifier %q holds the non-hex rune %q", raw, char)
			}
		}
	})
}
