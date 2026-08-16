# Releasing Credbound

The Git repository and Go module tags are the only version source. Credbound
does not maintain a second version constant or versioned event schema.

## Version policy

- Tags use semantic versions accepted by Go modules: `v0.x.y` before the first
  stable release and `v1.x.y` afterward.
- During `v0`, breaking Go API, migration, or operational changes are allowed
  only when called out in release notes.
- After `v1.0.0`, incompatible public API or persistence changes require a new
  major module version. Security fixes may intentionally reject previously
  accepted unsafe input and are documented explicitly.
- Database migrations are forward-only after publication. A released migration
  file is never edited or reordered; a correction gets a new migration.

## Release checklist

1. Review the PRD, API contract, ADR index, operations guide, and migration
   notes for the release scope.
2. Run `go mod tidy` and confirm that dependency changes are intentional.
3. Run `make generate` twice and confirm the second run changes nothing.
4. Run `make verify` with `CREDBOUND_POSTGRES_DSN` pointing to an isolated
   PostgreSQL database. CI also performs this check with a disposable service.
5. Run `govulncheck ./...` and review all reachable findings.
6. Confirm that no secret, local DSN, coverage profile, or generated temporary
   file is tracked.
7. Prepare release notes covering API changes, migrations, security impact,
   operator actions, and compatibility risks.
8. Create an annotated tag from the reviewed commit and publish the GitHub
   release. Do not reuse or move a published tag.

Example after the reviewed commit is on the default branch:

```sh
git tag -a v0.2.0 -m "Credbound v0.2.0"
git push origin v0.2.0
```

The release is not considered deployed in a consuming SaaS until that
application updates its module version, applies the embedded migrations, and
passes its own session, proxy, rate-limit, recovery, and end-to-end tests.
