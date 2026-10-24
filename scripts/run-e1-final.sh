#!/usr/bin/env bash
# scripts/run-e1-final.sh - E1 ablation runs for the paper, in sequence:
#   1. in-process stack, real swtpm devices, 10 repetitions
#   2. live stack (separate processes, Keycloak, HSM, fresh stack per trial), 3 repetitions
# Usage: scripts/run-e1-final.sh [out-dir]   (Keycloak must be running: testbed/keycloak.sh start)
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-results/e1-final/$(date +%Y%m%d-%H%M)}"
mkdir -p "${OUT}"
export ZTA_SWTPM_FLEET_DIR="${ZTA_SWTPM_FLEET_DIR:-$PWD/testbed/cache/swtpm-fleet}"
{
  echo "start $(date -Is)"; uname -r; node -v; git rev-parse HEAD 2>/dev/null || true
  testbed/keycloak.sh status
} > "${OUT}/env.txt" 2>&1
node scripts/attacks/matrix.mjs --tpm swtpm --reps 10 --out "${OUT}/inproc-swtpm" > "${OUT}/inproc-swtpm.log" 2>&1
echo "inproc done $(date -Is)" >> "${OUT}/env.txt"
node scripts/attacks/matrix.mjs --mode live --orchestrate --idp keycloak --tpm swtpm --reps 3 --out "${OUT}/live" > "${OUT}/live.log" 2>&1
echo "live done $(date -Is)" >> "${OUT}/env.txt"
