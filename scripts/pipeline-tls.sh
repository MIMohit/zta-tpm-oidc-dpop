#!/usr/bin/env bash
# scripts/pipeline-tls.sh - TLS re-run of the network-facing benchmarks on the testbed host:
# issues the host's TLS certificate, restarts Keycloak with its HTTPS endpoint, waits for an idle
# host (as scripts/pipeline-after-e1.sh), then runs run-all.sh with ZTA_TLS=1.
# Usage: scripts/pipeline-tls.sh <out-dir>   (results in <out-dir>/bench-tls)
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$1"
LOG="${OUT}/pipeline.log"
log() { echo "$(date -Is) $*" >> "${LOG}"; }

log "TLS pipeline: waiting for any running benchmark"
while pgrep -f "[r]un-all.sh" > /dev/null; do sleep 60; done
testbed/tls.sh >> "${LOG}" 2>&1
testbed/keycloak.sh start >> "${LOG}" 2>&1
log "TLS material issued, Keycloak restarted with HTTPS"

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
log "host idle for 10 minutes (load ${load}); TLS benchmarks start"
if ZTA_TLS=1 BENCH_ONLY="${BENCH_ONLY:-E3,E3hw,E5,E4,E7,E9}" BENCH_E5_CONFIGS="${BENCH_E5_CONFIGS:-full:100}" \
  scripts/bench/run-all.sh "${OUT}/bench-tls" > "${OUT}/bench-tls.log" 2>&1; then
  log "TLS benchmarks done"
else
  log "TLS benchmarks FAILED (see bench-tls.log)"
fi
