#!/usr/bin/env bash
set -euo pipefail

module="github.com/deepteams/credbound"
packages=(
  "."
  "./memory"
  "./oauthclientadapter"
  "./oauthhttp"
  "./oidcadapter"
  "./password"
  "./totpadapter"
  "./samladapter"
  "./ssoadapter"
  "./webauthnadapter"
  "./otelobserver"
  "./scimhttp"
  "./sqlstore/postgresql"
)
cover_packages=(
  "$module"
  "$module/memory"
  "$module/oauthclientadapter"
  "$module/oauthhttp"
  "$module/oidcadapter"
  "$module/password"
  "$module/totpadapter"
  "$module/samladapter"
  "$module/ssoadapter"
  "$module/webauthnadapter"
  "$module/otelobserver"
  "$module/scimhttp"
)

raw_profile="$(mktemp "${TMPDIR:-/tmp}/credbound-coverage-raw.XXXXXX")"
profile="$(mktemp "${TMPDIR:-/tmp}/credbound-coverage.XXXXXX")"
trap 'rm -f "$raw_profile" "$profile"' EXIT

coverpkg="$(IFS=,; printf '%s' "${cover_packages[*]}")"
go test -coverpkg="$coverpkg" -coverprofile="$raw_profile" "${packages[@]}"
# Generated code is verified for reproducibility by `make generate`; counting it
# as maintained source would make the coverage threshold depend on generators.
awk 'NR == 1 || $1 !~ /events_generated\.go:/' "$raw_profile" > "$profile"
total="$(go tool cover -func="$profile" | awk '/^total:/ {gsub(/%/, "", $3); print $3}')"

# Floor set to the consolidated coverage the suite actually sustains. The bulk
# of the uncovered code is trivial defensive error returns; raising the floor
# further should come with tests that exercise real behavior, not fault
# plumbing for its own sake.
threshold=89.5
if ! awk -v total="$total" -v threshold="$threshold" 'BEGIN { exit !(total >= threshold) }'; then
  printf 'coverage %.1f%% is below the %.1f%% floor\n' "$total" "$threshold" >&2
  exit 1
fi

printf 'maintained-code coverage: %.1f%%\n' "$total"
