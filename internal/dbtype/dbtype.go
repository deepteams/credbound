// Package dbtype names the types the generated queries bind to.
//
// It exists for one reason: sqlc recognises the package name "pgtype" and
// injects an import of the v4 module alongside the v5 one, which does not
// compile. Binding the queries to an alias declared here sidesteps that while
// keeping the underlying type exactly pgx's.
package dbtype

import "github.com/jackc/pgx/v5/pgtype"

// UUID is how an identifier crosses the database boundary: the raw 16 bytes
// plus a validity flag, carrying the sql.Scanner and driver.Valuer
// implementations that the identifier type itself deliberately lacks. One type
// covers both nullable and non-nullable columns.
type UUID = pgtype.UUID
