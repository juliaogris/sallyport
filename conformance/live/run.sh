#!/usr/bin/env bash
# Runs each load scenario against the live go and rust hubs, one hub at a
# time, from homesrv. It tails the hub during each run and prints one table
# that compares the hubs.
#
#   live/run.sh                   # every scenario
#   live/run.sh small mix         # some scenarios
#   SCALE=0.5 live/run.sh         # half the durations
#
# It needs `ssh homesrv`, the load tool at ~/sallyport-probe/bin/load on homesrv,
# the probe's app sessions, and wrangler logged in to the account.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$(cd .. && pwd)
out=${OUT:-$root/conformance/live/results/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$out"
scale=${SCALE:-1}

# scenario workers seconds
all=(
	"small 8 120"
	"page 4 120"
	"bulk 4 120"
	"upload 2 120"
	"stream 8 120"
	"mix 16 300"
)
want=("$@")

go build -o "$out/tailsum" ./cmd/tailsum
go build -o "$out/livetable" ./cmd/livetable

for spec in "${all[@]}"; do
	read -r scenario workers secs <<<"$spec"
	if [[ ${#want[@]} -gt 0 && ! " ${want[*]} " =~ \ $scenario\  ]]; then
		continue
	fi
	secs=$(awk -v s="$secs" -v k="$scale" 'BEGIN { printf "%d", s * k }')
	for hub in go rust; do
		echo "$scenario on $hub: $workers workers, ${secs}s" >&2
		tail_for=$((secs + 40))
		(
			cd "$root/hub/$hub"
			perl -e 'alarm shift; exec @ARGV' "$tail_for" \
				npx wrangler@4 tail --env "$hub" --format json >"$out/$hub-$scenario.tail.json" 2>/dev/null || true
		) &
		tail_pid=$!
		sleep 15
		# shellcheck disable=SC2029
		ssh homesrv "\$HOME/sallyport-probe/bin/load -url https://bench-$hub.example.com \
			-session \$HOME/sallyport-probe/secrets/$hub/sessions/bench \
			-scenario $scenario -c $workers -d ${secs}s -label $hub \
			-json /tmp/sallyport-load-$hub-$scenario.json" >"$out/$hub-$scenario.load.txt" 2>&1 || true
		scp -q "homesrv:/tmp/sallyport-load-$hub-$scenario.json" "$out/$hub-$scenario.load.json" || true
		wait "$tail_pid" || true
		"$out/tailsum" -json "$out/$hub-$scenario.tail.sum.json" "$out/$hub-$scenario.tail.json" >"$out/$hub-$scenario.tail.txt" || true
	done
done
"$out/livetable" "$out" | tee "$out/table.txt"
echo "results: $out" >&2
