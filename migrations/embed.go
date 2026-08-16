package migrations

import (
	"embed"
	"io/fs"
)

//go:embed postgresql/*.sql
var postgresql embed.FS

//go:embed sqlite/*.sql
var sqlite embed.FS

func PostgreSQL() fs.FS {
	result, err := fs.Sub(postgresql, "postgresql")
	if err != nil {
		panic(err)
	}
	return result
}

func SQLite() fs.FS {
	result, err := fs.Sub(sqlite, "sqlite")
	if err != nil {
		panic(err)
	}
	return result
}
