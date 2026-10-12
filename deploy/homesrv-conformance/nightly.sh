#!/usr/bin/env bash
# Runs the conformance suite against the hub on homesrv, from the latest main.
# Each run writes to ~/sallyport-conformance/<date>/: log.txt (build and
# test output), summary.txt, and go.json (go test -json).
#
# The repo is ~/sallyport-conformance/repo. The suite runs at the lowest CPU
# and I/O priority, so the clusters and the probe on homesrv keep theirs.
set -euo pipefail
base=$HOME/sallyport-conformance
repo=$base/repo
day=$base/$(date +%Y-%m-%d)
mkdir -p "$day"
exec 9>"$base/lock"
if ! flock -n 9; then
	echo "another run holds $base/lock" >&2
	exit 1
fi

export PATH=$HOME/.local/node/bin:$HOME/.local/go/bin:$HOME/go/bin:$PATH
export GOTOOLCHAIN=auto

start=$(date +%s)
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
git -C "$repo" fetch --quiet origin main
git -C "$repo" checkout --quiet --detach FETCH_HEAD
commit=$(git -C "$repo" log -1 --format='%h %s')

status=0
OUT=$day nice -n 19 ionice -c3 timeout 3h "$repo/conformance/run.sh" >"$day/log.txt" 2>&1 || status=$?

{
	# The window lets the probe's numbers for these minutes be set aside.
	echo "window  $started to $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "commit  $commit"
	echo "minutes $(( ($(date +%s) - start) / 60 ))"
	echo "exit    $status"
	f=$day/go.json
	if [[ -s $f ]]; then
		counts=$(jq -r 'select(.Test != null and (.Action == "pass" or .Action == "fail" or .Action == "skip")) | .Action' "$f" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}')
		echo "result  ${counts%, }"
		jq -r 'select(.Action == "fail" and .Test != null) | "  fail " + .Test' "$f"
	else
		echo "result  none"
	fi
} >"$day/summary.txt"
cat "$day/summary.txt"
exit "$status"
