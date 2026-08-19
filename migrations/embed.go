// Package migrations embeds Credbound's Goose-compatible PostgreSQL
// migrations. Filenames are timestamps, so lexical order is application order
// and they interleave safely with a host's own Goose migrations. Hosts either
// hand PostgreSQL() to goose or call ApplyPostgreSQL for a dependency-free
// application path.
package migrations

import (
	"embed"
	"io/fs"
)

//go:embed postgresql/*.sql
var postgresql embed.FS

// PostgreSQL returns the embedded PostgreSQL migrations as a Goose-compatible
// fs.FS. Every Credbound object they create lives in the dedicated credbound
// schema.
func PostgreSQL() fs.FS {
	result, err := fs.Sub(postgresql, "postgresql")
	if err != nil {
		panic(err)
	}
	return result
}
