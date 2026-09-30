#!/usr/bin/env bash
# Builds the hubs, runs the conformance suite against each under
# `wrangler dev`, and prints one table with a column per hub.
#
#   ./run.sh              # go and rust
#   ./run.sh go           # one hub
#   NO_BUILD=1 ./run.sh   # use the hubs as last built
set -euo pipefail
cd "$(dirname "$0")"
root=$(cd .. && pwd)
out=$(mktemp -d)
hubs=("$@")
if [[ ${#hubs[@]} -eq 0 ]]; then
	hubs=(go rust)
fi

build() {
	case "$1" in
	go)
		NO_OPT=1 "$root/go/hub/build.sh" >/dev/null
		;;
	rust)
		(
			cd "$root/rust/hub"
			CC_wasm32_unknown_unknown="${LLVM_CLANG:-/opt/homebrew/opt/llvm/bin/clang}" \
				AR_wasm32_unknown_unknown="${LLVM_AR:-/opt/homebrew/opt/llvm/bin/llvm-ar}" \
				RUSTFLAGS='--cfg getrandom_backend="wasm_js"' \
				worker-build --release >/dev/null 2>&1
		)
		;;
	*)
		echo "unknown hub $1, want go or rust" >&2
		exit 2
		;;
	esac
}

args=()
status=0
for hub in "${hubs[@]}"; do
	if [[ -z "${NO_BUILD:-}" ]]; then
		echo "building $hub" >&2
		build "$hub"
	fi
	echo "testing $hub" >&2
	SP_HUB=$hub go test -count=1 -timeout 15m -json . >"$out/$hub.json" || status=1
	args+=("$hub=$out/$hub.json")
done
go run ./cmd/table "${args[@]}"
echo "go test -json output: $out" >&2
exit "$status"
