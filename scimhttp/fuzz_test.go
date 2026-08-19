package scimhttp

import (
	"errors"
	"strings"
	"testing"

	"github.com/deepteams/credbound"
)

// FuzzParseFilter pins the SCIM filter parser, which reads an unauthenticated
// query string and feeds the attribute and value into a store lookup. An
// accepted filter must always name the attribute the directory actually sent —
// the store allowlists it before building any query — and the parser must
// stay total over arbitrary whitespace, quoting and Unicode.
func FuzzParseFilter(f *testing.F) {
	f.Add(`userName eq "alice@example.com"`)
	f.Add("")
	f.Add("   ")
	f.Add(`userName eq`)
	f.Add(`active eq true`)
	f.Add(`userName EQ "alice"`)
	f.Add("userName\teq\t\"alice\"")
	f.Add(`emails.value eq "alice@example.com"]`)
	f.Add(`userName eq "alice" and active eq true`)
	f.Add(`userName co "alice"`)
	f.Add("userName eq \"\\u0000\"")

	f.Fuzz(func(t *testing.T, raw string) {
		filter, err := parseFilter(raw)
		if err != nil {
			if !errors.Is(err, credbound.ErrInvalidInput) {
				t.Fatalf("rejected filter %q with %v, want ErrInvalidInput", raw, err)
			}
			if filter != (credbound.SCIMFilter{}) {
				t.Fatalf("rejected filter %q returned %#v", raw, filter)
			}
			return
		}
		if strings.TrimSpace(raw) == "" {
			if filter != (credbound.SCIMFilter{}) {
				t.Fatalf("the empty filter parsed to %#v", filter)
			}
			return
		}
		fields := strings.Fields(raw)
		if len(fields) < 3 || filter.Attribute != fields[0] {
			t.Fatalf("filter %q parsed to the attribute %q", raw, filter.Attribute)
		}
		if !strings.EqualFold(fields[1], "eq") {
			t.Fatalf("filter %q was accepted with the operator %q", raw, fields[1])
		}
	})
}

// FuzzListParameters pins the paging parameters of the same handler: a count
// outside 1..100 is refused rather than clamped, so a directory cannot widen
// a page by asking for one.
func FuzzListParameters(f *testing.F) {
	f.Add(`userName eq "alice"`, "cursor", "50")
	f.Add("", "", "")
	f.Add("", "", "0")
	f.Add("", "", "101")
	f.Add("", "", "-1")
	f.Add("", "", "abc")

	f.Fuzz(func(t *testing.T, filter, cursor, count string) {
		_, page, err := listParameters(filter, cursor, count)
		if err != nil {
			if !errors.Is(err, credbound.ErrInvalidInput) {
				t.Fatalf("rejected parameters with %v, want ErrInvalidInput", err)
			}
			return
		}
		if page.Limit < 1 || page.Limit > 100 {
			t.Fatalf("accepted count %q as the limit %d", count, page.Limit)
		}
		if page.Cursor != cursor {
			t.Fatalf("cursor %q was rewritten to %q", cursor, page.Cursor)
		}
	})
}
