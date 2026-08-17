<!-- Never include a security fix for an undisclosed vulnerability in a public
     PR: follow SECURITY.md first. -->

## What and why

<!-- The invariant or behavior being changed, and the issue it closes. -->

## Checklist

- [ ] `make verify` passes (gofmt, vet, race tests, coverage strictly above 90%)
- [ ] `make generate` is reproducible (no hand edits to generated files)
- [ ] `specs/` (PRD, API, ADRs) updated if the contract changed
- [ ] New failure paths are tested, not only the happy path
- [ ] Commits are signed off (`git commit -s`, Developer Certificate of Origin)
