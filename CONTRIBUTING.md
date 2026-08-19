# Contributing to Credbound

Thank you for considering a contribution. Credbound is a security-sensitive
authentication library, so the bar for changes is deliberately high and the
process is specs-first.

## Before you start

- **Vulnerabilities are never reported through issues or pull requests.**
  Follow [SECURITY.md](SECURITY.md).
- For any behavior change, open an issue first and describe the invariant you
  want to add or change. The product contract lives in
  [`specs/PRD.md`](specs/PRD.md), the Go API in [`specs/API.md`](specs/API.md),
  and architectural decisions in [`specs/adr/`](specs/adr/). A feature that
  changes the contract updates the specs in the same pull request.
- Small fixes (typos, documentation, an obvious bug with a test) can go
  straight to a pull request.

## Development

```sh
make test       # go test ./...
make generate   # sqlc + genevents + genpostgresstore (must be reproducible)
make verify     # gofmt, vet, race tests, maintained coverage >= 89.5%
```

Requirements and conventions:

- Go 1.26 or newer.
- `make verify` must pass. Coverage of maintained code must stay at or above
  the floor in `scripts/coverage.sh` (currently 89.5%); new code ships with
  tests for its failure paths, not only the happy path.
- Generated code is never edited by hand: `internal/sqlc/` comes from `sqlc`,
  `events_generated.go` from `genevents`, and the PostgreSQL store is derived
  from the SQLite store by `genpostgresstore`. Change the source (SQL files,
  `events.go`, the SQLite store, or the generators) and run `make generate`.
- PostgreSQL objects live in the dedicated `credbound` schema; migrations use
  timestamp versions and are forward-only once released — a correction is a
  new migration, never an edit.
- Security invariants are non-negotiable: no secret is ever persisted in
  plaintext or logged, comparisons of secret material are constant-time,
  sensitive mutations commit atomically with their audit event, and error
  paths must not enable account enumeration.
- The PostgreSQL integration test runs when `CREDBOUND_POSTGRES_DSN` is set;
  CI provides a PostgreSQL service.
- Store behavior is contract-tested once for every engine:
  `internal/storetest` holds the Manager-level flows, and `memory`,
  `sqlstore/sqlite` and `sqlstore/postgresql` each run all of them. A change
  to a store — or a new store — belongs in that suite rather than in a
  per-engine test, so the engines cannot drift apart.
- Parsers that read untrusted input ship with a fuzz target, and a failing
  input found by fuzzing is committed under `testdata/fuzz` as a permanent
  seed. A change to the exported surface is acknowledged by regenerating
  `testdata/api.txt` (`go test -run TestPublicAPISurface -update-api`) and
  noting the change in `CHANGELOG.md`.

## Pull requests

- Keep pull requests focused; unrelated refactoring belongs in its own PR.
- Explain the invariant or behavior being changed and reference the issue.
- Update `specs/` and the README when the contract changes.
- Sign off your commits (`git commit -s`) to certify the
  [Developer Certificate of Origin](https://developercertificate.org/).

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
