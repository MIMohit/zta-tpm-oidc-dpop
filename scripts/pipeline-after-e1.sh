#!/usr/bin/env bash
# scripts/pipeline-after-e1.sh - Runs the timing benchmarks and the live E1 run only when the
# host is fit for them: after the in-process E1 run, once the host is idle (no compiler jobs,
# load < 1.5 for 10 minutes), and once the benchmark harness is marked ready
# (testbed/state/bench-ready). Other users' work is never stopped; this only waits for it.
# Usage: scripts/pipeline-after-e1.sh <e1-out-dir>
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$1"
LOG="${OUT}/pipeline.log"
log() { echo "$(date -Is) $*" >> "${LOG}"; }

log "waiting for the in-process E1 run"
while pgrep -f "[m]atrix.mjs --tpm swtpm --reps 10" > /dev/null; do sleep 60; done
log "in-process E1 finished"
# The idle fleet VMs only add background load; the benchmarks and live E1 use host-side swtpm
testbed/fleet.sh down >> "${LOG}" 2>&1 || true

quiet=0
while [ "${quiet}" -lt 10 ]; do
  sleep 60
  load="$(cut -d' ' -f1 /proc/loadavg)"
  if ! pgrep -x 'cc1plus|cc1|clang|clang\+\+|ld|ld.lld|ninja|rustc' > /dev/null && awk "BEGIN { exit !(${load} < 1.5) }"; then
    quiet=$((quiet + 1))
  else
    quiet=0
  fi
done
log "host idle for 10 minutes (load ${load})"

while [ ! -f testbed/state/bench-ready ]; do sleep 60; done
log "benchmarks start"
if scripts/bench/run-all.sh "${OUT}/bench" > "${OUT}/bench.log" 2>&1; then log "benchmarks done"; else log "benchmarks FAILED (see bench.log)"; fi

log "live E1 start"
if node scripts/attacks/matrix.mjs --mode live --orchestrate --idp keycloak --tpm swtpm --reps 3 --out "${OUT}/live" > "${OUT}/live.log" 2>&1; then log "live E1 done"; else log "live E1 FAILED (see live.log)"; fi
log "pipeline finished"
