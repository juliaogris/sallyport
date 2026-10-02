#!/usr/bin/env bash
# Runs the conformance suite against both hubs on homesrv, from the latest main.
# Each run writes to ~/sallyport-conformance/<date>/: log.txt (build and
# test output), summary.txt, and go.json and rust.json (go test -json).
#
# The repo is ~/sallyport-conformance/repo. The suite runs at the lowest CPU
# and I/O priority, so the clusters and the probe on homesrv keep theirs. When
# clang is missing, only the Go hub is tested and the summary says so.
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

export PATH=$HOME/.local/node/bin:$HOME/.local/go/bin:$HOME/go/bin:$HOME/.cargo/bin:$PATH
export GOTOOLCHAIN=auto
export LLVM_CLANG=clang LLVM_AR=llvm-ar

start=$(date +%s)
git -C "$repo" fetch --quiet origin main
git -C "$repo" checkout --quiet --detach FETCH_HEAD
commit=$(git -C "$repo" log -1 --format='%h %s')

hubs=(go rust)
note=""
if ! command -v clang >/dev/null || ! command -v llvm-ar >/dev/null; then
	hubs=(go)
	note="rust skipped: clang or llvm-ar is missing"
fi

status=0
OUT=$day nice -n 19 ionice -c3 timeout 3h "$repo/conformance/run.sh" "${hubs[@]}" >"$day/log.txt" 2>&1 || status=$?

{
	echo "date    $(date -Is)"
	echo "commit  $commit"
	echo "minutes $(( ($(date +%s) - start) / 60 ))"
	echo "exit    $status"
	[[ -n $note ]] && echo "note    $note"
	for hub in "${hubs[@]}"; do
		f=$day/$hub.json
		if [[ ! -s $f ]]; then
			echo "$hub: no results"
			continue
		fi
		counts=$(jq -r 'select(.Test != null and (.Action == "pass" or .Action == "fail" or .Action == "skip")) | .Action' "$f" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}')
		echo "$hub: ${counts%, }"
		jq -r 'select(.Action == "fail" and .Test != null) | "  fail " + .Test' "$f"
	done
} >"$day/summary.txt"
cat "$day/summary.txt"
exit "$status"
