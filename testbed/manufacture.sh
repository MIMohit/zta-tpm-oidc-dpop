#!/usr/bin/env bash
# testbed/manufacture.sh - Manufacture swtpm instance with EK certs and platform certs
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=config.env
source "${SCRIPT_DIR}/config.env"

if [ $# -lt 1 ]; then
  log_err "Usage: $0 <dev> --ca good|foreign [--profile rsa2048|p384|both]"
  exit 1
fi

DEV="$1"
shift

CA_NAME=""
PROFILE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --ca)
      CA_NAME="$2"
      shift 2
      ;;
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    *)
      log_err "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [ -z "${CA_NAME}" ]; then
  CA_NAME="$(get_dev_var "${DEV}" "CA")"
fi
if [ -z "${CA_NAME}" ]; then
  log_err "Missing --ca parameter. Must specify --ca good|foreign"
  exit 1
fi

if [ -z "${PROFILE}" ]; then
  PROFILE="$(get_dev_var "${DEV}" "PROFILE")"
fi
if [ -z "${PROFILE}" ]; then
  PROFILE="p384"
fi

CA_CONF="${SCRIPT_DIR}/ca/${CA_NAME}/swtpm_setup.conf"
STATE_DIR="${SCRIPT_DIR}/state/${DEV}"
TPM_STATE="${STATE_DIR}/tpm"

log_info "Manufacturing vTPM for ${DEV} with CA '${CA_NAME}', profile '${PROFILE}'..."

if [ "${DRY_RUN:-0}" = "1" ]; then
  run swtpm_setup --tpm2 --tpmstate "${TPM_STATE}" \
    --create-ek-cert --create-platform-cert --lock-nvram \
    --pcr-banks sha256 --config "${CA_CONF}"
  run "${SCRIPT_DIR}/export-ek.sh" "${DEV}"
  exit 0
fi

# Ensure CA configuration exists
if [ ! -f "${CA_CONF}" ]; then
  log_info "CA configuration ${CA_CONF} not found. Running ca-init.sh ${CA_NAME}..."
  "${SCRIPT_DIR}/ca-init.sh" "${CA_NAME}"
fi

mkdir -p "${TPM_STATE}"

# swtpm_setup provisions BOTH RSA and ECC P-384 EKs in a single run (finding X6)
run swtpm_setup --tpm2 --tpmstate "${TPM_STATE}" \
  --create-ek-cert --create-platform-cert --lock-nvram \
  --pcr-banks sha256 --config "${CA_CONF}" --overwrite

# Record chosen agent EK profile
case "${PROFILE}" in
  rsa|rsa2048)
    AGENT_EK_TYPE="rsa"
    ;;
  p384|ecc384|both)
    AGENT_EK_TYPE="ecc384"
    ;;
  *)
    AGENT_EK_TYPE="ecc384"
    ;;
esac

cat << EOF > "${STATE_DIR}/profile.env"
TPM_EK_TYPE=${AGENT_EK_TYPE}
CA_NAME=${CA_NAME}
EOF

# Export EK materials
"${SCRIPT_DIR}/export-ek.sh" "${DEV}"

log_info "Successfully manufactured vTPM for ${DEV}"
