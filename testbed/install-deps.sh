#!/usr/bin/env bash
# testbed/install-deps.sh - Install host dependencies for testbed
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

YES_FLAG=0
for arg in "$@"; do
  if [ "$arg" = "--yes" ] || [ "$arg" = "-y" ]; then
    YES_FLAG=1
  fi
done

case "${PKG_MANAGER}" in
  pacman)
    log_info "Detected Arch Linux (pacman)"
    run sudo pacman -S --needed --noconfirm \
      qemu-base qemu-img swtpm edk2-ovmf tpm2-tools openssl xorriso cdrtools python
    ;;
  apt)
    log_info "Detected Debian/Ubuntu (apt)"
    run sudo apt-get update -y
    run sudo apt-get install -y \
      qemu-system-x86 qemu-utils swtpm swtpm-tools ovmf tpm2-tools openssl cloud-image-utils python3
    ;;
  brew)
    log_info "Detected macOS (Homebrew - development only)"
    echo "Recommended Homebrew command: brew install qemu swtpm"
    if [ "${YES_FLAG}" -eq 1 ]; then
      run brew install qemu swtpm
    else
      log_info "Skipping Homebrew installation (pass --yes to execute)"
    fi
    ;;
  *)
    log_err "Unknown package manager. Please install QEMU, swtpm, OVMF/EDK2, tpm2-tools, and Python manually."
    exit 1
    ;;
esac
