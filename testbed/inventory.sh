#!/usr/bin/env bash
# testbed/inventory.sh - Add fleet device to inventory using exported EK devId
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=config.env
source "${SCRIPT_DIR}/config.env"

if [ $# -lt 2 ]; then
  log_err "Usage: $0 <dev> <user>"
  exit 1
fi

DEV="$1"
USER="$2"

# CRITICAL SECURITY RULE: dev-rogue is deliberately omitted from inventory to test rogue device detection (A01)
if [ "${DEV}" = "dev-rogue" ]; then
  log_info "Skipping dev-rogue on purpose (inventory exclusion check)"
  exit 0
fi

STATE_DIR="${SCRIPT_DIR}/state/${DEV}"
DEVID_FILE="${STATE_DIR}/ek/devid.txt"

if [ "${DRY_RUN:-0}" = "1" ]; then
  run node "${REPO_ROOT}/scripts/inventory-add.js" --devId "<${DEV}-devId>" --user "${USER}"
  exit 0
fi

if [ ! -f "${DEVID_FILE}" ]; then
  log_err "devId file not found: ${DEVID_FILE}. Run manufacture.sh first."
  exit 1
fi

DEVID="$(tr -d ' \n\r' < "${DEVID_FILE}")"
log_info "Adding ${DEV} (${DEVID}) to inventory for user '${USER}'..."

run node "${REPO_ROOT}/scripts/inventory-add.js" --devId "${DEVID}" --user "${USER}"
log_info "Device ${DEV} enrolled in inventory."
