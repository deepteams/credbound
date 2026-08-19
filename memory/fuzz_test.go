package memory

import (
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

// FuzzDecodeCursor pins the opaque pagination cursor: an arbitrary string is
// either rejected with ErrInvalidInput or decoded into a value that re-encodes
// to a cursor decoding to exactly the same position. Without that canonicity a
// crafted cursor could shift a listing's window — a paged export would then
// skip or repeat rows silently.
func FuzzDecodeCursor(f *testing.F) {
	f.Add("")
	f.Add("not base64 $$$")
	f.Add(encodeCursor(time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC), credbound.MustParseUUID("0198b463-0000-7000-8000-000000000001")))
	f.Add("e30")
	f.Add("eyJ0IjowLCJpZCI6IiJ9")
	f.Add("eyJ0IjotMSwiaWQiOiJ4In0")

	f.Fuzz(func(t *testing.T, raw string) {
		decoded, err := decodeCursor(raw)
		if err != nil {
			if !errors.Is(err, credbound.ErrInvalidInput) {
				t.Fatalf("rejected cursor %q with %v, want ErrInvalidInput", raw, err)
			}
			if decoded != (pageCursor{}) {
				t.Fatalf("rejected cursor %q returned %#v", raw, decoded)
			}
			return
		}
		if raw == "" {
			if decoded != (pageCursor{}) {
				t.Fatalf("the empty cursor decoded to %#v", decoded)
			}
			return
		}
		again, err := decodeCursor(encodeCursor(time.Unix(0, decoded.UnixNano), decoded.ID))
		if err != nil || again != decoded {
			t.Fatalf("re-encoded cursor decoded to %#v, %v, want %#v", again, err, decoded)
		}
	})
}
