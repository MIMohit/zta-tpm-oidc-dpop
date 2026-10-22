#!/usr/bin/env bash
# testbed/rv-capture.sh - Boot golden VM, capture binary_bios_measurements and record reference values
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=config.env
source "${SCRIPT_DIR}/config.env"

DEV="dev-good"
PORT_SSH="${PORT_SSH_dev_good:-2221}"
OUT_LOG="${SCRIPT_DIR}/cache/golden_binary_bios_measurements.bin"
RV_OUT="${REPO_ROOT}/fixtures/rv/ubuntu-noble-golden.json"

log_info "Capturing Reference Values from golden VM (${DEV})..."

if [ "${DRY_RUN:-0}" = "1" ]; then
  run "${SCRIPT_DIR}/vm.sh" "${DEV}" start
  run scp -P "${PORT_SSH}" -o StrictHostKeyChecking=no "zta@127.0.0.1:/run/zta/binary_bios_measurements" "${OUT_LOG}"
  run node "${REPO_ROOT}/scripts/rv-capture.mjs" --log "${OUT_LOG}" --name "ubuntu-noble-golden" --out "${RV_OUT}"
  run "${SCRIPT_DIR}/vm.sh" "${DEV}" stop
  exit 0
fi

mkdir -p "${SCRIPT_DIR}/cache" "$(dirname "${RV_OUT}")"

# Start dev-good VM
"${SCRIPT_DIR}/vm.sh" "${DEV}" start

# Wait for SSH
log_info "Waiting for VM SSH on port ${PORT_SSH}..."
for _ in $(seq 1 60); do
  if nc -z 127.0.0.1 "${PORT_SSH}" 2>/dev/null; then
    break
  fi
  sleep 2
done

# Copy binary BIOS measurements
log_info "Fetching /run/zta/binary_bios_measurements via scp..."
scp -P "${PORT_SSH}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "zta@127.0.0.1:/run/zta/binary_bios_measurements" "${OUT_LOG}"

# Compute QEMU fingerprint (SHA-256 of normalized device topology per X4)
QEMU_FINGERPRINT="$(printf '%s %s %s' "${QEMU_MACHINE}" "${TPM_DEVICE_MODEL}" "${RAM}" | shasum -a 256 | awk '{print $1}')"

# Run rv-capture script if present
if [ -f "${REPO_ROOT}/scripts/rv-capture.mjs" ]; then
  log_info "Processing log with scripts/rv-capture.mjs..."
  node "${REPO_ROOT}/scripts/rv-capture.mjs" \
    --log "${OUT_LOG}" \
    --name "ubuntu-noble-golden" \
    --qemu-fingerprint "${QEMU_FINGERPRINT}" \
    --out "${RV_OUT}"
else
  log_warn "scripts/rv-capture.mjs not found. Raw log captured to ${OUT_LOG}."
fi

# Stop VM
"${SCRIPT_DIR}/vm.sh" "${DEV}" stop
log_info "Reference Values capture completed."
