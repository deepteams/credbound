# ADR-019 — PostgreSQL-only SQL persistence

- Status: accepted
- Date: 2026-08-19
- Supersedes: [ADR-003](ADR-003-dual-database.md)

## Context

ADR-003 shipped two semantically equivalent SQL backends. Keeping them
equivalent turned out to cost more than it returned, and the cost fell on the
wrong engine.

The PostgreSQL store was *derived* from the SQLite one: a generator copied the
SQLite implementation and patched the dialect differences. Whatever the two
engines could not both express was therefore unavailable to PostgreSQL. The
shared statements used `?` placeholders rewritten at run time, a boolean guard
around the keyset cursor instead of a plain comparison, and Go types widened to
SQLite's single integer width. CTEs, `INSERT … ON CONFLICT … RETURNING`,
`jsonb` operators, `DISTINCT ON` and `FOR NO KEY UPDATE` were all out of reach
by construction.

That is backwards. SQLite serves single-node deployments and local
experiments, where load is never the constraint. PostgreSQL is the engine that
takes production traffic — and it was the one being held to the smaller
dialect. An index audit made the cost concrete: the portable cursor guard is
what prevented `oauth_grants_page_idx` from being used when the grant filter
was optional.

## Decision

SQLite is dropped. PostgreSQL is the only SQL engine, and its store is written
against PostgreSQL directly: typed `uuid` parameters, `jsonb` operators,
`SELECT … FOR UPDATE` for the read-then-write invariants, and predicates
written so the planner can use the indexes.

The in-memory store (`memory`) remains, and is the answer for hosts that want
no database at all — local development, tests, and `credboundtest`'s default.
It carries no schema, no migrations and no driver dependency, which is what
made SQLite attractive for those uses in the first place.

Lists keep the shape ADR-003 defined: not generated as `:many`, streamed
through `pgx.Rows` at the consumer's pace behind `iter.Seq2`, with an opaque
cursor over a stable `(created_at, id)` ordering.

## Consequences

- Breaking for hosts on SQLite. There is no automated migration path; data has
  to be moved to PostgreSQL before upgrading. `sqlstore/sqlite`,
  `migrations.SQLite`, `migrations.ApplySQLite`, `credbound.StoreSQLite` and
  the `modernc.org/sqlite` dependency are gone.
- The generator (`internal/cmd/genpostgresstore`) and the portability layer it
  required disappear with it, along with the constraint that every hand-written
  statement be expressible in both dialects.
- Store conformance is still proven by `internal/storetest`, now across the
  in-memory and PostgreSQL implementations. It remains the only thing keeping
  a store honest about the port contract.
- The `credbound` schema, timestamp migration versions and the rest of
  [ADR-013](ADR-013-postgres-schema-and-migration-versions.md) stand, except
  for the table-naming rationale, which existed only to keep the two engines'
  generated types aligned.
