#!/usr/bin/env bash
# Runs each load scenario against the live hub on julia.example.com, from
# homesrv. It tails the hub during each run and prints one table.
#
#   live/run.sh                   # every scenario
#   live/run.sh small mix         # some scenarios
#   SCALE=0.5 live/run.sh         # half the durations
#
# It needs `ssh homesrv`, the load tool at ~/sallyport-probe/bin/load on homesrv,
# the probe's app sessions, and wrangler logged in to the account. The
# scenarios use the /t/ paths of cmd/trafficapp, so julia's bench app must
# be trafficapp, not the plain file server that sallyport-bench runs.
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
	echo "$scenario: $workers workers, ${secs}s" >&2
	tail_for=$((secs + 40))
	(
		cd "$root/hub/go"
		perl -e 'alarm shift; exec @ARGV' "$tail_for" \
			npx wrangler@4 tail --env edge --format json >"$out/$scenario.tail.json" 2>/dev/null || true
	) &
	tail_pid=$!
	sleep 15
	# shellcheck disable=SC2029
	ssh homesrv "\$HOME/sallyport-probe/bin/load -url https://bench-julia.example.com \
		-session \$HOME/sallyport-probe/secrets/julia/sessions/bench \
		-scenario $scenario -c $workers -d ${secs}s -label julia \
		-json /tmp/sallyport-load-$scenario.json" >"$out/$scenario.load.txt" 2>&1 || true
	scp -q "homesrv:/tmp/sallyport-load-$scenario.json" "$out/$scenario.load.json" || true
	wait "$tail_pid" || true
	"$out/tailsum" -json "$out/$scenario.tail.sum.json" "$out/$scenario.tail.json" >"$out/$scenario.tail.txt" || true
done
"$out/livetable" "$out" | tee "$out/table.txt"
echo "results: $out" >&2
