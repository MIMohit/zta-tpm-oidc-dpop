#!/usr/bin/env bash
# testbed/export-ek.sh - Export TPM NV certificates and persistent public keys
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=config.env
source "${SCRIPT_DIR}/config.env"

if [ $# -lt 1 ]; then
  log_err "Usage: $0 <dev>"
  exit 1
fi

DEV="$1"
STATE_DIR="${SCRIPT_DIR}/state/${DEV}"
TPM_STATE="${STATE_DIR}/tpm"
EK_DIR="${STATE_DIR}/ek"

SWTPM_PORT="$(get_dev_var "${DEV}" "PORT_SWTPM")"
CTRL_PORT="$(get_dev_var "${DEV}" "PORT_CTRL")"
if [ -z "${SWTPM_PORT}" ]; then
  SWTPM_PORT=6101
fi
if [ -z "${CTRL_PORT}" ]; then
  CTRL_PORT=6201
fi

log_info "Exporting TPM state for ${DEV}..."

if [ "${DRY_RUN:-0}" = "1" ]; then
  run swtpm socket --tpm2 --tpmstate "dir=${TPM_STATE}" \
    --server "type=tcp,port=${SWTPM_PORT}" --ctrl "type=tcp,port=${CTRL_PORT}" \
    --flags not-need-init,startup-clear
  run python3 "${SCRIPT_DIR}/tools/ek-export.py" "${SWTPM_PORT}" "${EK_DIR}"
  exit 0
fi

if [ ! -d "${TPM_STATE}" ]; then
  log_err "TPM state directory ${TPM_STATE} does not exist. Run manufacture.sh first."
  exit 1
fi

mkdir -p "${EK_DIR}"

# Start swtpm temporarily in the background
TMP_PIDFILE="$(mktemp /tmp/swtpm-export-pid.XXXXXX)"
swtpm socket --tpm2 --tpmstate "dir=${TPM_STATE}" \
  --server "type=tcp,port=${SWTPM_PORT}" --ctrl "type=tcp,port=${CTRL_PORT}" \
  --flags not-need-init,startup-clear \
  --pid "file=${TMP_PIDFILE}" &
SWTPM_PROC_PID=$!

# Wait for TCP port to be listening
READY=0
for _ in $(seq 1 50); do
  if python3 -c "import socket; s = socket.create_connection(('127.0.0.1', ${SWTPM_PORT}), timeout=0.2); s.close()" 2>/dev/null; then
    READY=1
    break
  fi
  sleep 0.1
done

if [ "${READY}" -ne 1 ]; then
  log_err "swtpm failed to start on port ${SWTPM_PORT}"
  kill "${SWTPM_PROC_PID}" 2>/dev/null || true
  rm -f "${TMP_PIDFILE}"
  exit 1
fi

# Run the export tool
python3 "${SCRIPT_DIR}/tools/ek-export.py" "${SWTPM_PORT}" "${EK_DIR}"

# Clean up swtpm process
if [ -s "${TMP_PIDFILE}" ]; then
  SWTPM_PID="$(cat "${TMP_PIDFILE}")"
  kill "${SWTPM_PID}" 2>/dev/null || true
else
  kill "${SWTPM_PROC_PID}" 2>/dev/null || true
fi
rm -f "${TMP_PIDFILE}"

log_info "Successfully exported EK materials to ${EK_DIR}"
