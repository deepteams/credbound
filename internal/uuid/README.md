# Vendored `uuid`

`uuid.go` is the package accepted for the Go standard library in
[golang/go#62026](https://github.com/golang/go/issues/62026), copied here
**verbatim**. Do not edit it, and do not add files beside it.

When the package ships with Go, this directory is deleted and the alias in the
root package — `type UUID = uuid.UUID` — is repointed at the standard library.
That is the whole migration.

Nothing in Credbound depends on methods the standard library does not provide.
The accepted package treats UUIDs as opaque identifiers and ships no database
interfaces; the PostgreSQL store therefore binds `pgtype.UUID`, which brings its
own, and converts at the row boundary where it already turns rows into domain
values (`dbID` / `domainID` in `sqlstore/postgresql/dialect.go`).

To refresh the copy, replace `uuid.go` with the upstream file as-is.
