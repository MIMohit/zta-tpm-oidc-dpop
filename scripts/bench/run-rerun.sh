#!/usr/bin/env bash
# scripts/bench/run-rerun.sh - Follow-up benchmarks with TLS after the first TLS run:
#   E3 and E9 again with the paired (ABBA) design, which cancels run-order drift in the
#   differences to Full, and E4 at intermediate rates to locate the PEP's saturation point.
# Usage: scripts/bench/run-rerun.sh <out-dir>
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="$1"
mkdir -p "${OUT}"
export ZTA_SWTPM_FLEET_DIR="${ZTA_SWTPM_FLEET_DIR:-$PWD/testbed/cache/swtpm-fleet}"
export ZTA_TLS=1
export NODE_EXTRA_CA_CERTS="${ZTA_TLS_DIR:-$PWD/testbed/state/tls}/ca.pem"
mapfile -t CPUS < <(grep Cpus_allowed_list /proc/self/status | cut -f2 | tr ',' '\n' | while IFS=- read -r a b; do seq "${a}" "${b:-${a}}"; done | sort -n)
N=${#CPUS[@]}
join() { local IFS=,; echo "$*"; }
STACK_CPUS="$(join "${CPUS[@]:0:N-2}")"
CLIENT_CPUS="$(join "${CPUS[@]:N-2:2}")"
step() { echo "== $(date -Is) $*"; }
node --input-type=module -e 'import("./bench/lib.mjs").then((m) => console.log(JSON.stringify(m.environment(), null, 1)))' > "${OUT}/env-start.json"
step "E3 paired (Full, B0-B3)"
taskset -c "${CLIENT_CPUS}" node bench/costs.mjs --configs full,B0,B1,B2,B3 --paired --n 100 --requests 10 --stack-cpus "${STACK_CPUS}" --tag e3 --out "${OUT}/paired"
step "E9 paired (all configurations)"
taskset -c "${CLIENT_CPUS}" node bench/costs.mjs --configs all --paired --n 30 --requests 10 --stack-cpus "${STACK_CPUS}" --tag e9 --out "${OUT}/paired"
step "E4 knee (250, 300, 350 req/s)"
taskset -c "${CLIENT_CPUS}" node bench/load.mjs --rates 250,300,350 --duration 60 --warmup 10 --runs 5 --clients 64 --stack-cpus "${STACK_CPUS}" --out "${OUT}/e4-knee"
node --input-type=module -e 'import("./bench/lib.mjs").then((m) => console.log(JSON.stringify(m.environment(), null, 1)))' > "${OUT}/env-end.json"
step "rerun done"
