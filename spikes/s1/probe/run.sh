#!/usr/bin/env bash
# Build the S1 probe against Teleport's api module exactly as tagged
# v18.10.0, then run it against the address given as $1.
set -euo pipefail
cd "$(dirname "$0")"
core="${CORE:-$HOME/teleport/core/_master}"
if [[ ! -d api-v18.10.0/api ]]; then
  mkdir -p api-v18.10.0
  git -C "$core" archive v18.10.0 api | tar -x -C api-v18.10.0
fi
go build -o probe .
./probe "${1:?usage: run.sh host:port}"
