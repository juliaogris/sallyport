#!/usr/bin/env bash
# Builds the hub, runs the conformance suite against it under
# `wrangler dev`, and prints one row per test.
#
#   ./run.sh              # build and test
#   NO_BUILD=1 ./run.sh   # use the hub as last built
#   OUT=dir ./run.sh      # write the go test -json output to dir
set -euo pipefail
cd "$(dirname "$0")"
root=$(cd .. && pwd)
out=${OUT:-$(mktemp -d)}
mkdir -p "$out"

if [[ -z "${NO_BUILD:-}" ]]; then
	echo "building the hub" >&2
	NO_OPT=1 "$root/hub/go/build.sh" >/dev/null
fi
echo "testing the hub" >&2
status=0
go test -count=1 -timeout 15m -json . >"$out/go.json" || status=1
go run ./cmd/table "go=$out/go.json"
echo "go test -json output: $out" >&2
exit "$status"
