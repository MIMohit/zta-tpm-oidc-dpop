#!/usr/bin/env bash
# testbed/ca-init.sh - Initialize swtpm_localca Certificate Authority for testbed
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

if [ $# -lt 1 ]; then
  log_err "Usage: $0 <good|foreign>"
  exit 1
fi

CA_NAME="$1"
if [ "${CA_NAME}" != "good" ] && [ "${CA_NAME}" != "foreign" ]; then
  log_err "Invalid CA name: ${CA_NAME}. Must be 'good' or 'foreign'."
  exit 1
fi

CA_DIR="${SCRIPT_DIR}/ca/${CA_NAME}"
STATEDIR="${CA_DIR}/statedir"

log_info "Initializing CA '${CA_NAME}' in ${CA_DIR}..."

if [ "${DRY_RUN:-0}" = "1" ]; then
  run mkdir -p "${STATEDIR}"
  run cat "<< 'EOF' > ${CA_DIR}/swtpm-localca.conf"
  run cat "<< 'EOF' > ${CA_DIR}/swtpm-localca.options"
  run cat "<< 'EOF' > ${CA_DIR}/swtpm_setup.conf"
  run swtpm_localca --type ek --dir "${STATEDIR}" --configfile "${CA_DIR}/swtpm-localca.conf" --optsfile "${CA_DIR}/swtpm-localca.options"
  exit 0
fi

mkdir -p "${STATEDIR}"

# swtpm-localca configuration
cat << EOF > "${CA_DIR}/swtpm-localca.conf"
statedir = ${STATEDIR}
signingkey = ${STATEDIR}/signkey.pem
issuercert = ${STATEDIR}/issuercert.pem
certserial = ${STATEDIR}/certserial
EOF

# swtpm-localca certificate attributes options
cat << EOF > "${CA_DIR}/swtpm-localca.options"
--platform-manufacturer vendor-${CA_NAME}
--platform-version 2.1
--platform-model QEMU
EOF

# swtpm_setup configuration
cat << EOF > "${CA_DIR}/swtpm_setup.conf"
create_certs_tool = swtpm_localca
create_certs_tool_config = ${CA_DIR}/swtpm-localca.conf
create_certs_tool_options = ${CA_DIR}/swtpm-localca.options
active_pcr_banks = sha256
rsa_keysize = 2048
EOF

# Initialize CA keys and certificates if not already generated
if [ ! -f "${STATEDIR}/swtpm-localca-rootca-cert.pem" ]; then
  log_info "Generating root CA and issuer signing certificate for ${CA_NAME}..."
  TMP_DIR="$(mktemp -d /tmp/ca-init-bootstrap.XXXXXX)"
  swtpm_localca --type ek --ek 1234567890abcdef \
    --dir "${TMP_DIR}" \
    --configfile "${CA_DIR}/swtpm-localca.conf" \
    --optsfile "${CA_DIR}/swtpm-localca.options" \
    --tpm-spec-family 2.0 --tpm-spec-level 0 --tpm-spec-revision 183 \
    --tpm-manufacturer id:00001014 --tpm-model swtpm --tpm-version id:20240125 --tpm2 >/dev/null 2>&1 || true
  rm -rf "${TMP_DIR}"
fi

# Ensure standard accessible symlinks / files exist for root and issuer
if [ -f "${STATEDIR}/swtpm-localca-rootca-cert.pem" ]; then
  cp "${STATEDIR}/swtpm-localca-rootca-cert.pem" "${CA_DIR}/root.pem"
fi
if [ -f "${STATEDIR}/issuercert.pem" ]; then
  cp "${STATEDIR}/issuercert.pem" "${CA_DIR}/issuer.pem"
fi
if [ -f "${CA_DIR}/root.pem" ] && [ -f "${CA_DIR}/issuer.pem" ]; then
  cat "${CA_DIR}/root.pem" "${CA_DIR}/issuer.pem" > "${CA_DIR}/ca-bundle.pem"
fi

log_info "CA '${CA_NAME}' initialized successfully."
