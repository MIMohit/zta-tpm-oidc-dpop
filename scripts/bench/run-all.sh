#!/usr/bin/env bash
# scripts/bench/run-all.sh - The timing benchmarks for the paper (E2-E5, E7, E9) on an idle
# host. Servers run on all but the last two usable CPUs, clients and load generators on the last
# two, TPM micro-benchmarks on the last one. E8 is derived from E2 and E3 in paper-figures/make_figures.py.
# Usage: [ZTA_TLS=1] [BENCH_ONLY=E3,E4,...] scripts/bench/run-all.sh <out-dir>
#   ZTA_TLS=1: every service on HTTPS (testbed/tls.sh), Keycloak on its HTTPS endpoint
#   BENCH_ONLY: subset of E2,E3,E3hw,E5,E4,E7,E9 (default: all)
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="$1"
mkdir -p "${OUT}"
export ZTA_SWTPM_FLEET_DIR="${ZTA_SWTPM_FLEET_DIR:-$PWD/testbed/cache/swtpm-fleet}"
# CPU ids come from the CPUs this process may use (online and allowed by its cgroup/affinity):
# with SMT off they are not contiguous (0,2,4,...), and a slice may reserve some cores.
# Servers get all but the last two, clients the last two, TPM micro-benchmarks the last.
mapfile -t ONLINE < <(grep Cpus_allowed_list /proc/self/status | cut -f2 | tr ',' '\n' | while IFS=- read -r a b; do
  seq "${a}" "${b:-${a}}"
done | sort -n)
if [ "${#ONLINE[@]}" -lt 4 ]; then echo "need at least 4 online CPUs, have ${#ONLINE[@]}" >&2; exit 1; fi
join() { local IFS=,; echo "$*"; }
N=${#ONLINE[@]}
STACK_CPUS="${STACK_CPUS:-$(join "${ONLINE[@]:0:N-2}")}"
CLIENT_CPUS="${CLIENT_CPUS:-$(join "${ONLINE[@]:N-2:2}")}"
TPM_CPU="${TPM_CPU:-${ONLINE[N-1]}}"
step() { echo "== $(date -Is) $*"; }
step "CPUs: stack ${STACK_CPUS}, clients ${CLIENT_CPUS}, TPM micro ${TPM_CPU}"
if [ "${ZTA_TLS:-0}" = "1" ]; then
  TLS_DIR="${ZTA_TLS_DIR:-$PWD/testbed/state/tls}"
  [ -s "${TLS_DIR}/server.pem" ] || testbed/tls.sh
  export NODE_EXTRA_CA_CERTS="${TLS_DIR}/ca.pem"
  step "TLS on: CA ${NODE_EXTRA_CA_CERTS}"
fi
want() { [ -z "${BENCH_ONLY:-}" ] || [[ ",${BENCH_ONLY}," == *",$1,"* ]]; }

step "stopping the idle fleet VMs (background noise)"
testbed/fleet.sh down || true
powerprofilesctl set performance 2>/dev/null || echo "power profile unchanged (needs an active session)"
node --input-type=module -e 'import("./bench/lib.mjs").then((m) => console.log(JSON.stringify(m.environment(), null, 1)))' > "${OUT}/env-start.json"

# Each benchmark is independent: a failure is logged and the next one still runs.
FAILED=()
bench() {
  local name="$1"
  shift
  step "${name}"
  if ! "$@"; then
    echo "!! FAILED: ${name}"
    FAILED+=("${name}")
  fi
}

want E2 && bench "E2 TPM commands: hardware fTPM" env TPM_EK_TYPE=rsa TPM_SRK_HANDLE=0x81000101 taskset -c "${TPM_CPU}" node bench/tpm-micro.mjs --device linux --runs 200 --warmup 20 --out "${OUT}"
want E2 && bench "E2 TPM commands: swtpm" taskset -c "${TPM_CPU}" node bench/tpm-micro.mjs --device swtpm --runs 200 --warmup 20 --out "${OUT}"

want E3 && bench "E3 end-to-end costs (Full, B0-B3)" taskset -c "${CLIENT_CPUS}" node bench/costs.mjs --configs full,B0,B1,B2,B3 --n 100 --requests 10 --stack-cpus "${STACK_CPUS}" --tag e3 --out "${OUT}"

want E3hw && bench "E3 end-to-end costs on the hardware fTPM (Full)" env TPM_SRK_HANDLE=0x81000101 taskset -c "${CLIENT_CPUS}" node bench/costs.mjs --configs full --hw --n 30 --requests 5 --stack-cpus "${STACK_CPUS}" --tag e3-hw --out "${OUT}"

want E5 && bench "E5 revocation latency" taskset -c "${CLIENT_CPUS}" node bench/revocation.mjs --configs "${BENCH_E5_CONFIGS:-full:100,B3:5}" --interval 20 --stack-cpus "${STACK_CPUS}" --out "${OUT}"

want E4 && bench "E4 PEP under load" taskset -c "${CLIENT_CPUS}" node bench/load.mjs --rates 50,100,200,400,600,800,1000 --duration 60 --warmup 10 --runs 5 --clients 64 --stack-cpus "${STACK_CPUS}" --out "${OUT}"

want E7 && bench "E7 verifier throughput vs fleet size" taskset -c "${CLIENT_CPUS}" node bench/verifier-scale.mjs --sizes 10,25,50,100,200 --duration 30 --stack-cpus "${STACK_CPUS}" --out "${OUT}"

want E9 && bench "E9 per-mechanism cost (all configurations)" taskset -c "${CLIENT_CPUS}" node bench/costs.mjs --configs all --n 30 --requests 10 --stack-cpus "${STACK_CPUS}" --tag e9 --out "${OUT}"

node --input-type=module -e 'import("./bench/lib.mjs").then((m) => console.log(JSON.stringify(m.environment(), null, 1)))' > "${OUT}/env-end.json"
if [ "${#FAILED[@]}" -gt 0 ]; then
  step "benchmarks done with ${#FAILED[@]} failure(s): ${FAILED[*]}"
  exit 1
fi
step "benchmarks done"
