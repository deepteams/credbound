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
  "./webauthnadapter"
  "./otelobserver"
  "./scimhttp"
  "./sqlstore/postgresql"
  "./sqlstore/sqlite"
)
cover_packages=(
  "$module"
  "$module/memory"
  "$module/oauthclientadapter"
  "$module/oauthhttp"
  "$module/oidcadapter"
  "$module/password"
  "$module/totpadapter"
  "$module/webauthnadapter"
  "$module/otelobserver"
  "$module/scimhttp"
  "$module/sqlstore/sqlite"
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

if ! awk -v total="$total" 'BEGIN { exit !(total > 90) }'; then
  printf 'coverage %.1f%% is not strictly greater than 90%%\n' "$total" >&2
  exit 1
fi

printf 'maintained-code coverage: %.1f%%\n' "$total"
