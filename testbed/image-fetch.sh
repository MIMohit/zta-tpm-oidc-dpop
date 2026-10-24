#!/usr/bin/env bash
# testbed/image-fetch.sh - Download and verify Ubuntu noble cloud image for host architecture
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

CACHE_DIR="${SCRIPT_DIR}/cache"

if [ "${ARCH_TYPE}" = "x86_64" ] || [ "${ARCH_TYPE}" = "amd64" ]; then
  UBUNTU_ARCH="amd64"
elif [ "${ARCH_TYPE}" = "aarch64" ] || [ "${ARCH_TYPE}" = "arm64" ]; then
  UBUNTU_ARCH="arm64"
else
  UBUNTU_ARCH="amd64"
fi

IMAGE_FILENAME="noble-server-cloudimg-${UBUNTU_ARCH}.img"
BASE_URL="https://cloud-images.ubuntu.com/noble/current"
IMAGE_URL="${BASE_URL}/${IMAGE_FILENAME}"
SUMS_URL="${BASE_URL}/SHA256SUMS"
GPG_URL="${BASE_URL}/SHA256SUMS.gpg"

log_info "Cloud image target: ${IMAGE_FILENAME} (${UBUNTU_ARCH})"

if [ "${DRY_RUN:-0}" = "1" ]; then
  run curl -fsSL "${IMAGE_URL}" -o "${CACHE_DIR}/${IMAGE_FILENAME}"
  run curl -fsSL "${SUMS_URL}" -o "${CACHE_DIR}/SHA256SUMS"
  run curl -fsSL "${GPG_URL}" -o "${CACHE_DIR}/SHA256SUMS.gpg"
  run sha256sum --check --ignore-missing "${CACHE_DIR}/SHA256SUMS"
  exit 0
fi

mkdir -p "${CACHE_DIR}"

if [ ! -f "${CACHE_DIR}/${IMAGE_FILENAME}" ]; then
  log_info "Downloading ${IMAGE_FILENAME} from ${IMAGE_URL}..."
  curl -fSL "${IMAGE_URL}" -o "${CACHE_DIR}/${IMAGE_FILENAME}"
fi

if [ ! -f "${CACHE_DIR}/SHA256SUMS" ]; then
  log_info "Downloading SHA256SUMS..."
  curl -fsSL "${SUMS_URL}" -o "${CACHE_DIR}/SHA256SUMS"
fi

if [ ! -f "${CACHE_DIR}/SHA256SUMS.gpg" ]; then
  log_info "Downloading SHA256SUMS.gpg..."
  curl -fsSL "${GPG_URL}" -o "${CACHE_DIR}/SHA256SUMS.gpg" || true
fi

# Verify SHA256
log_info "Verifying image checksum..."
(
  cd "${CACHE_DIR}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum --check --ignore-missing SHA256SUMS
  else
    EXPECTED_SUM="$(grep -E "\*?${IMAGE_FILENAME}$" SHA256SUMS | awk '{print $1}')"
    ACTUAL_SUM="$(shasum -a 256 "${IMAGE_FILENAME}" | awk '{print $1}')"
    if [ "${EXPECTED_SUM}" != "${ACTUAL_SUM}" ]; then
      log_err "Checksum mismatch! Expected: ${EXPECTED_SUM}, Actual: ${ACTUAL_SUM}"
      exit 1
    fi
    log_info "Checksum OK."
  fi
)

# Optional GPG verification
if command -v gpg >/dev/null 2>&1 && [ -f "${CACHE_DIR}/SHA256SUMS.gpg" ]; then
  log_info "Verifying GPG signature..."
  gpg --verify "${CACHE_DIR}/SHA256SUMS.gpg" "${CACHE_DIR}/SHA256SUMS" 2>/dev/null || log_warn "GPG keyring does not contain Ubuntu release key (checksum passed)."
fi

log_info "Image cached at ${CACHE_DIR}/${IMAGE_FILENAME}"

# Node.js for the fleet agents. The VMs run it from the read-only repo mount,
# so they need no internet or apt. Official linux build of the host's version.
NODE_VERSION="${NODE_VERSION:-$(node -v 2>/dev/null | sed 's/^v//')}"
if [ -z "${NODE_VERSION}" ]; then
  log_err "NODE_VERSION is not set and node is not on PATH."
  exit 1
fi
if [ "${UBUNTU_ARCH}" = "amd64" ]; then NODE_ARCH="x64"; else NODE_ARCH="arm64"; fi
NODE_TARBALL="node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"
NODE_BASE_URL="https://nodejs.org/dist/v${NODE_VERSION}"

if [ ! -x "${CACHE_DIR}/node/bin/node" ] || [ "$("${CACHE_DIR}/node/bin/node" -v 2>/dev/null)" != "v${NODE_VERSION}" ]; then
  log_info "Downloading ${NODE_TARBALL}..."
  curl -fSL "${NODE_BASE_URL}/${NODE_TARBALL}" -o "${CACHE_DIR}/${NODE_TARBALL}"
  curl -fsSL "${NODE_BASE_URL}/SHASUMS256.txt" -o "${CACHE_DIR}/NODE_SHASUMS256.txt"
  (
    cd "${CACHE_DIR}"
    EXPECTED_SUM="$(grep " ${NODE_TARBALL}$" NODE_SHASUMS256.txt | awk '{print $1}')"
    ACTUAL_SUM="$(sha256sum "${NODE_TARBALL}" | awk '{print $1}')"
    if [ -z "${EXPECTED_SUM}" ] || [ "${EXPECTED_SUM}" != "${ACTUAL_SUM}" ]; then
      log_err "Node checksum mismatch for ${NODE_TARBALL}"
      exit 1
    fi
    log_info "Node checksum OK."
  )
  rm -rf "${CACHE_DIR}/node"
  mkdir -p "${CACHE_DIR}/node"
  tar -xJf "${CACHE_DIR}/${NODE_TARBALL}" -C "${CACHE_DIR}/node" --strip-components=1
  rm -f "${CACHE_DIR}/${NODE_TARBALL}"
fi
log_info "Node $("${CACHE_DIR}/node/bin/node" -v) cached at ${CACHE_DIR}/node"
