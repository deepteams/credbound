# ADR-013 — Dedicated PostgreSQL schema and timestamp migration versions

## Status

Accepted.

## Context

Credbound is embedded inside a host service that owns the database. Two
frictions appeared:

- On PostgreSQL, Credbound tables landed in whatever schema the connection's
  `search_path` selected (usually `public`), mixed with the host's tables and
  namespaced only by a `credbound_` prefix.
- Migration versions were sequential (`00001`…), which collides with the host
  service's own Goose migrations when both sets share one version table.

## Decision

### `credbound` schema on PostgreSQL

The first migration creates the `credbound` schema and every Credbound object
lives in it with schema qualification and without the redundant prefix:
`credbound.users`, `credbound.audit_events`, `credbound.prevent_audit_mutation()`.
Runtime queries are schema-qualified too, so the host's `search_path` is
irrelevant and no connection configuration is required. Index, trigger, and
named-constraint identifiers stay unqualified (SQL does not allow qualifying
them at creation) and drop their prefix; they inherit the table's schema.

sqlc derives Go struct names from the qualified table names, so
`credbound.users` becomes `CredboundUser`. (This section originally also
justified keeping those names aligned with SQLite's `credbound_users`, which
[ADR-019](ADR-019-postgresql-only-persistence.md) made moot when SQLite was
dropped.)

Integration tests isolate by dropping and letting the first migration recreate
the `credbound` schema; CI provides one PostgreSQL service per job.

### Timestamp migration versions

Migration files are versioned with `YYYYMMDDHHMMSS` timestamps (the standard
`goose create` format) instead of small sequential integers. Host services
that merge Credbound's embedded migrations into their own Goose set no longer
risk version collisions, and future Credbound migrations always sort after the
host's historical ones by date.

## Consequences

- Breaking for any deployment that applied the `v0` sequential migrations:
  version numbers changed and PostgreSQL objects moved schema. `v0` allows
  this; there is no supported upgrade path from the previous layout, and a
  fresh migration run is required.
- A released migration file is never edited or renumbered again (RELEASING
  policy); this reset is the exception granted by pre-release status.
- `migrations.PostgreSQL()` and store code are otherwise
  unchanged for hosts.
