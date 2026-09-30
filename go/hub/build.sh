#!/usr/bin/env bash
# Builds the Go hub for GOOS=js into build/, for wrangler. Set NO_OPT=1 to
# skip wasm-opt, which takes most of the build time.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build
GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o build/hub.raw.wasm .
if [[ -n "${NO_OPT:-}" ]]; then
	cp build/hub.raw.wasm build/hub.wasm
else
	wasm-opt -Oz --enable-bulk-memory --enable-sign-ext --enable-nontrapping-float-to-int --enable-mutable-globals build/hub.raw.wasm -o build/hub.wasm
fi
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" build/wasm_exec.js
for f in build/hub.raw.wasm build/hub.wasm; do
	printf '%-14s raw=%9d gzip=%9d\n' "$(basename "$f")" "$(wc -c <"$f")" "$(gzip -9c "$f" | wc -c)"
done
