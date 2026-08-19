# ADR-003 — PostgreSQL and SQLite persistence

- Status: superseded by [ADR-019](ADR-019-postgresql-only-persistence.md)
- Date: 2026-08-16

## Decision

> Superseded: SQLite was dropped in favor of a PostgreSQL-only store. The
> streaming and pagination decisions below still hold; see ADR-019 for why the
> dual-engine part did not.

Two versioned, semantically equivalent sets of Goose migrations are delivered.
Mutations and single-record lookups are declared as sqlc queries.

Lists are not generated as `:many`. The adapter uses `pgx.Rows` for PostgreSQL
and `database/sql.Rows` for SQLite, calls `rows.Next()` at the consumer's pace,
and exposes `iter.Seq2`. A page contains 50 items by default, with an opaque
cursor and stable `(created_at, id)` ordering.

## Consequences

Multi-row read code is deliberately handwritten. Repository conformance tests
run against every available engine.
