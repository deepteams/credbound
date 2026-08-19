package postgresql

import (
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

// FuzzDecodeCursor pins the opaque pagination cursor of the postgresql store: an
// arbitrary string is either rejected with ErrInvalidInput or decoded into a
// position that survives a re-encode unchanged. The three stores share this
// contract, so a divergence here would make a host's paged export behave
// differently depending on the engine underneath it.
func FuzzDecodeCursor(f *testing.F) {
	f.Add("")
	f.Add("not base64 $$$")
	f.Add(encodeCursor(time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC), credbound.MustParseUUID("0198b463-0000-7000-8000-000000000001")))
	f.Add("e30")
	f.Add("eyJ0IjoiMDAwMS0wMS0wMVQwMDowMDowMFoiLCJpZCI6IiJ9")

	f.Fuzz(func(t *testing.T, raw string) {
		decoded, err := decodeCursor(raw)
		if err != nil {
			if !errors.Is(err, credbound.ErrInvalidInput) {
				t.Fatalf("rejected cursor %q with %v, want ErrInvalidInput", raw, err)
			}
			if !decoded.Time.IsZero() || decoded.ID != (credbound.UUID{}) {
				t.Fatalf("rejected cursor %q returned %#v", raw, decoded)
			}
			return
		}
		if raw == "" {
			if !decoded.Time.IsZero() || decoded.ID != (credbound.UUID{}) {
				t.Fatalf("the empty cursor decoded to %#v", decoded)
			}
			return
		}
		again, err := decodeCursor(encodeCursor(decoded.Time, decoded.ID))
		if err != nil || !again.Time.Equal(decoded.Time) || again.ID != decoded.ID {
			t.Fatalf("re-encoded cursor decoded to %#v, %v, want %#v", again, err, decoded)
		}
	})
}
