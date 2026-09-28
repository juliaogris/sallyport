#!/bin/sh
# Renews the teleport.julia.example.com cert with a DNS-01 challenge when 30
# days or fewer are left. The proxy reloads the files every 12 hours.
set -eu
cd "$HOME/sallyport"
CF_DNS_API_TOKEN=$(tr -d '\n\r ' < cf-token)
export CF_DNS_API_TOKEN
exec bin/lego run --accept-tos --email julia.ogris@goteleport.com \
  --path "$HOME/sallyport/acme" --dns cloudflare \
  --domains teleport.julia.example.com --renew-days 30 --log.format text
