#!/usr/bin/env bash
# testbed/lib/common.sh - Common environment, platform detection, and helpers for testbed
# shellcheck disable=SC2034
set -euo pipefail

# Platform and Architecture Detection
OS_TYPE="${UNAME_S:-$(uname -s)}"
ARCH_TYPE="${UNAME_M:-$(uname -m)}"

# Package Manager Detection
if [ -n "${PKG:-}" ]; then
  PKG_MANAGER="${PKG}"
elif command -v pacman >/dev/null 2>&1; then
  PKG_MANAGER="pacman"
elif command -v apt-get >/dev/null 2>&1; then
  PKG_MANAGER="apt"
elif command -v brew >/dev/null 2>&1; then
  PKG_MANAGER="brew"
else
  PKG_MANAGER="unknown"
fi

# Acceleration and TPM Device Model Detection
# macOS always uses TCG for TPM devices due to Hypervisor.framework limitation (HVF -> HV_BAD_ARGUMENT).
# Linux uses KVM if /dev/kvm is accessible (or KVM_OK=1 override), otherwise TCG.
if [ "${OS_TYPE}" = "Darwin" ]; then
  ACCEL="tcg"
  TPM_DEVICE_MODEL="tpm-tis-device"
  QEMU_BIN="${QEMU_BIN:-qemu-system-aarch64}"
  QEMU_MACHINE="virt"
  QEMU_CPU="max"
else
  # Check for KVM
  if [ "${KVM_OK:-}" = "1" ] || { [ -z "${KVM_OK:-}" ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; }; then
    ACCEL="kvm"
    QEMU_CPU="host"
  else
    ACCEL="tcg"
    QEMU_CPU="max"
  fi

  if [ "${ARCH_TYPE}" = "x86_64" ] || [ "${ARCH_TYPE}" = "amd64" ]; then
    TPM_DEVICE_MODEL="tpm-crb"
    QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
    QEMU_MACHINE="q35"
  else
    TPM_DEVICE_MODEL="tpm-tis-device"
    QEMU_BIN="${QEMU_BIN:-qemu-system-aarch64}"
    QEMU_MACHINE="virt"
  fi
fi

# UNIX Socket Directory for swtpm (macOS socket path capped at ~104 bytes per X10)
if [ "${OS_TYPE}" = "Darwin" ]; then
  SOCKET_DIR="/tmp/ztamac"
else
  RUNTIME_BASE="${XDG_RUNTIME_DIR:-/run/user/$(id -u 2>/dev/null || echo 1000)}"
  if [ -d "${RUNTIME_BASE}" ] && [ -w "${RUNTIME_BASE}" ]; then
    SOCKET_DIR="${RUNTIME_BASE}/zta"
  else
    SOCKET_DIR="/tmp/zta"
  fi
fi

# Helper to run commands or print them under DRY_RUN=1
run() {
  if [ "${DRY_RUN:-0}" = "1" ]; then
    printf '%q ' "$@"
    printf '\n'
  else
    "$@"
  fi
}

# Logging helpers
log_info() {
  echo "[testbed] $*"
}

log_warn() {
  echo "[testbed:WARN] $*" >&2
}

log_err() {
  echo "[testbed:ERROR] $*" >&2
}
