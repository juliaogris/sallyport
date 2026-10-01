#!/usr/bin/env bash
# Mints fresh app sessions for the probe user in each cluster. Each run signs
# a 24 hour user cert with the fork tctl that knows callout_mode, then asks appsessmint for one app
# session per app. The sessions end with the cert. The timer runs this every
# 6 hours, so a failed run leaves the last sessions valid for 18 more hours.
#
# Output, per cluster: ~/sallyport-probe/secrets/<cluster>/sessions/<app>/
# with session-id and bearer-token.
set -euo pipefail
umask 077

base=$HOME/sallyport-probe
tctl=$HOME/sallyport-lazy/bin/tctl
mint=$base/bin/appsessmint

# renew name config.yaml auth-addr cluster-name proxy-identity app=public-addr...
renew() {
  local name=$1 config=$2 auth=$3 cluster=$4 proxy=$5
  shift 5
  local dir=$base/secrets/$name tmp app addr
  mkdir -p "$dir"
  tmp=$(mktemp -d "$dir/.new.XXXXXX")
  if ! "$tctl" --config="$config" auth sign --user=probe --format=tls --ttl=24h --out="$tmp/probe" >"$tmp/sign.log" 2>&1; then
    grep -av DEBU "$tmp/sign.log" | tail -5 >&2
    rm -rf "$tmp"
    return 1
  fi
  for pair in "$@"; do
    app=${pair%%=*}
    addr=${pair#*=}
    if ! "$mint" -auth "$auth" -user-identity "$tmp/probe" -proxy-identity "$proxy" -user probe -app "$app" -public-addr "$addr" -cluster "$cluster" -out "$tmp/$app"; then
      rm -rf "$tmp"
      return 1
    fi
  done
  rm -f "$tmp/sign.log"
  rm -rf "$dir/sessions.old"
  if [ -d "$dir/sessions" ]; then
    mv "$dir/sessions" "$dir/sessions.old"
  fi
  mv "$tmp" "$dir/sessions"
  rm -rf "$dir/sessions.old"
  echo "$name: renewed $*"
}

failed=0
renew julia "$HOME/sallyport/deploy/teleport.yaml" 127.0.0.1:3025 sallyport "$base/secrets/julia/proxy" \
  bench=bench-julia.example.com octo=octo-julia.example.com octocam=octocam-julia.example.com || failed=1
renew rust "$HOME/sallyport-rust/deploy/teleport.yaml" 127.0.0.1:3126 sallyport-rust "$HOME/sallyport-rust/hub-identity" \
  bench=bench-rust.example.com octo=octo-rust.example.com octocam=octocam-rust.example.com || failed=1
renew go "$HOME/sallyport-go/deploy/teleport.yaml" 127.0.0.1:3226 sallyport-go "$HOME/sallyport-go/hub-identity" \
  bench=bench-go.example.com octo=octo-go.example.com octocam=octocam-go.example.com || failed=1
renew lazy "$HOME/sallyport-lazy/deploy/teleport.yaml" 127.0.0.1:3326 sallyport-lazy "$HOME/sallyport-lazy/hub-identity" \
  bench=bench-lazy.example.com octocam=octocam-lazy.example.com || failed=1
exit "$failed"
