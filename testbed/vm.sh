#!/usr/bin/env bash
# testbed/vm.sh - Manage lifecycle of a fleet virtual machine (start, stop, status, ssh, console)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=config.env
source "${SCRIPT_DIR}/config.env"

if [ $# -lt 2 ]; then
  log_err "Usage: $0 <dev> start|stop|status|refresh|ssh|console"
  exit 1
fi

DEV="$1"
ACTION="$2"

STATE_DIR="${SCRIPT_DIR}/state/${DEV}"
TPM_STATE="${STATE_DIR}/tpm"
SOCKET_PATH="${SOCKET_DIR}/${DEV}.sock"

# Safety check on UNIX socket length (macOS limit ~104 bytes per X10)
if [ "${#SOCKET_PATH}" -gt 100 ]; then
  SOCKET_PATH="/tmp/zta-${DEV}.sock"
fi

PORT_SSH="$(get_dev_var "${DEV}" "PORT_SSH")"
PORT_AGENT="$(get_dev_var "${DEV}" "PORT_AGENT")"
IMAGE_NAME="$(get_dev_var "${DEV}" "IMAGE")"
if [ -z "${PORT_SSH}" ]; then PORT_SSH=2221; fi
if [ -z "${PORT_AGENT}" ]; then PORT_AGENT=7101; fi
if [ -z "${IMAGE_NAME}" ]; then IMAGE_NAME="golden"; fi

BASE_DISK="${SCRIPT_DIR}/images/${IMAGE_NAME}.qcow2"
# Each device writes to its own overlay; devices sharing an image never share a writable disk
DISK_IMG="${STATE_DIR}/disk.qcow2"
SEED_ISO="${SCRIPT_DIR}/images/${IMAGE_NAME}-seed.iso"

# Address of the server stack as every component sees it: the VMs (through QEMU
# user networking), the host and the load/attack host all route to it, so token
# issuers and DPoP htu values are identical everywhere.
if [ -z "${ZTA_PUBLIC_HOST:-}" ] && command -v ip >/dev/null 2>&1; then
  ZTA_PUBLIC_HOST="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')"
fi
ZTA_PUBLIC_HOST="${ZTA_PUBLIC_HOST:-10.0.2.2}"

# Resolve firmware code and vars templates
if [ "${OS_TYPE}" = "Darwin" ]; then
  BREW_QEMU="$(brew --prefix qemu 2>/dev/null || echo "/opt/homebrew")"
  FIRMWARE_CODE="${BREW_QEMU}/share/qemu/edk2-aarch64-code.fd"
  FIRMWARE_VARS_TMPL="${BREW_QEMU}/share/qemu/edk2-arm-vars.fd"
else
  if [ "${ARCH_TYPE}" = "x86_64" ] || [ "${ARCH_TYPE}" = "amd64" ]; then
    # Arch / Debian OVMF locations (Arch's edk2-ovmf ships the 4 MB builds under /usr/share/edk2)
    if [ -f "/usr/share/edk2/x64/OVMF_CODE.4m.fd" ]; then
      FIRMWARE_CODE="/usr/share/edk2/x64/OVMF_CODE.4m.fd"
      FIRMWARE_VARS_TMPL="/usr/share/edk2/x64/OVMF_VARS.4m.fd"
    elif [ -f "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd" ]; then
      FIRMWARE_CODE="/usr/share/edk2-ovmf/x64/OVMF_CODE.fd"
      FIRMWARE_VARS_TMPL="/usr/share/edk2-ovmf/x64/OVMF_VARS.fd"
    elif [ -f "/usr/share/OVMF/OVMF_CODE.fd" ]; then
      FIRMWARE_CODE="/usr/share/OVMF/OVMF_CODE.fd"
      FIRMWARE_VARS_TMPL="/usr/share/OVMF/OVMF_VARS.fd"
    else
      FIRMWARE_CODE="/usr/share/ovmf/OVMF.fd"
      FIRMWARE_VARS_TMPL="/usr/share/ovmf/OVMF_VARS.fd"
    fi
  else
    FIRMWARE_CODE="/usr/share/qemu/edk2-aarch64-code.fd"
    FIRMWARE_VARS_TMPL="/usr/share/qemu/edk2-arm-vars.fd"
  fi
fi

# The VMs see a code-only copy of the repo (never TPM state, CA keys or data/), plus the
# per-device agent settings read in the VM from /mnt/devstate/agent.env
AGENT_ROOT="${SCRIPT_DIR}/state/agent-root"
SHARE_DIR="${STATE_DIR}/share"
EK_TYPE="ecc384"
if [ "$(get_dev_var "${DEV}" "PROFILE")" = "rsa2048" ]; then EK_TYPE="rsa"; fi
prepare_agent_share() {
  mkdir -p "${AGENT_ROOT}" "${SHARE_DIR}"
  rsync -a --delete --delete-excluded \
    --exclude '/.git' --exclude '/data' --exclude '/results' \
    --exclude '/testbed/state' --exclude '/testbed/ca' --exclude '/testbed/images' \
    --include '/testbed/cache/node/***' --exclude '/testbed/cache/*' \
    "${REPO_ROOT}/" "${AGENT_ROOT}/"
  cat > "${SHARE_DIR}/agent.env" << EOF
AGENT_ID=${DEV}
AGENT_URL=http://${ZTA_PUBLIC_HOST}:${PORT_AGENT}
IDP_ISSUER=http://${ZTA_PUBLIC_HOST}:${PORT_IDP:-5173}
VERIFIER_URL=http://${ZTA_PUBLIC_HOST}:${PORT_VERIFIER:-4005}
PIP_URL=http://${ZTA_PUBLIC_HOST}:${PORT_PIP:-4003}
PEP_PUBLIC_URL=http://${ZTA_PUBLIC_HOST}:${PORT_PEP:-4001}
TPM_EK_TYPE=${EK_TYPE}
EOF
}

case "${ACTION}" in
  refresh)
    # New agent code and settings without a reboot (boot measurements stay as they are)
    prepare_agent_share
    ssh -p "${PORT_SSH}" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
      zta@127.0.0.1 "sudo systemctl restart zta-agent"
    log_info "Agent refreshed in ${DEV}."
    ;;

  start)
    log_info "Starting VM for ${DEV}..."
    if [ "${DRY_RUN:-0}" = "1" ]; then
      run swtpm socket --tpm2 --tpmstate "dir=${TPM_STATE}" \
        --ctrl "type=unixio,path=${SOCKET_PATH}" \
        --flags startup-clear --log "file=${STATE_DIR}/swtpm.log"

      if [ "${OS_TYPE}" = "Darwin" ]; then
        run "${QEMU_BIN}" -M virt -accel tcg -cpu max \
          -device "${TPM_DEVICE_MODEL},tpmdev=tpm0"
      else
        run "${QEMU_BIN}" -machine "${QEMU_MACHINE},accel=${ACCEL}" -cpu "${QEMU_CPU}" \
          -device "${TPM_DEVICE_MODEL},tpmdev=tpm0"
      fi
      exit 0
    fi

    mkdir -p "${STATE_DIR}" "${SOCKET_DIR}"
    if [ ! -d "${TPM_STATE}" ]; then
      log_warn "TPM state not found. Manufacturing ${DEV} first..."
      "${SCRIPT_DIR}/manufacture.sh" "${DEV}"
    fi

    # Prepare per-device vars.fd copy
    if [ ! -f "${STATE_DIR}/vars.fd" ] && [ -f "${FIRMWARE_VARS_TMPL}" ]; then
      cp "${FIRMWARE_VARS_TMPL}" "${STATE_DIR}/vars.fd"
    fi

    # Per-device writable overlay on the shared image
    if [ ! -f "${DISK_IMG}" ] && [ -f "${BASE_DISK}" ]; then
      # Same size for every device: the GPT is measured into PCR5. First boot grows the
      # root partition, so reference values come from the second boot onwards.
      qemu-img create -f qcow2 -b "${BASE_DISK}" -F qcow2 "${DISK_IMG}" "${DISK_SIZE:-12G}" >/dev/null
    fi

    prepare_agent_share

    # Remove stale socket
    rm -f "${SOCKET_PATH}"

    # Start swtpm daemon
    swtpm socket --tpm2 --tpmstate "dir=${TPM_STATE}" \
      --ctrl "type=unixio,path=${SOCKET_PATH}" \
      --flags startup-clear \
      --log "file=${STATE_DIR}/swtpm.log" \
      --pid "file=${STATE_DIR}/swtpm.pid" --daemon

    # Wait for socket
    for _ in $(seq 1 50); do
      if [ -S "${SOCKET_PATH}" ]; then break; fi
      sleep 0.1
    done

    # Build QEMU arguments
    QEMU_ARGS=()
    if [ "${OS_TYPE}" = "Darwin" ]; then
      QEMU_ARGS+=("-M" "virt" "-accel" "tcg" "-cpu" "max")
    else
      QEMU_ARGS+=("-machine" "${QEMU_MACHINE},accel=${ACCEL}" "-cpu" "${QEMU_CPU}")
    fi

    QEMU_ARGS+=(
      "-m" "${RAM}"
      "-smp" "${SMP}"
      "-drive" "if=pflash,format=raw,readonly=on,file=${FIRMWARE_CODE}"
    )
    if [ -f "${STATE_DIR}/vars.fd" ]; then
      QEMU_ARGS+=("-drive" "if=pflash,format=raw,file=${STATE_DIR}/vars.fd")
    fi

    QEMU_ARGS+=(
      "-chardev" "socket,id=chrtpm,path=${SOCKET_PATH}"
      "-tpmdev" "emulator,id=tpm0,chardev=chrtpm"
      "-device" "${TPM_DEVICE_MODEL},tpmdev=tpm0"
    )

    if [ -f "${DISK_IMG}" ]; then
      QEMU_ARGS+=("-drive" "file=${DISK_IMG},if=virtio,format=qcow2")
    fi
    if [ -f "${SEED_ISO}" ]; then
      QEMU_ARGS+=("-drive" "file=${SEED_ISO},if=virtio,media=cdrom")
    fi

    QEMU_ARGS+=(
      "-netdev" "user,id=net0,hostfwd=tcp::${PORT_SSH}-:22,hostfwd=tcp::${PORT_AGENT}-:7101"
      "-device" "virtio-net-pci,netdev=net0"
      "-virtfs" "local,path=${AGENT_ROOT},mount_tag=repo,security_model=none,readonly=on"
      "-virtfs" "local,path=${SHARE_DIR},mount_tag=devstate,security_model=none,readonly=on"
      "-display" "none"
      "-pidfile" "${STATE_DIR}/qemu.pid"
      "-daemonize"
    )

    "${QEMU_BIN}" "${QEMU_ARGS[@]}"
    log_info "VM ${DEV} started (SSH :${PORT_SSH}, Agent :${PORT_AGENT})."
    ;;

  stop)
    log_info "Stopping VM for ${DEV}..."
    if [ "${DRY_RUN:-0}" = "1" ]; then
      run kill -TERM "<${DEV}-qemu-pid>"
      run kill -TERM "<${DEV}-swtpm-pid>"
      exit 0
    fi

    if [ -f "${STATE_DIR}/qemu.pid" ]; then
      Q_PID="$(cat "${STATE_DIR}/qemu.pid")"
      kill "${Q_PID}" 2>/dev/null || true
      rm -f "${STATE_DIR}/qemu.pid"
    fi
    if [ -f "${STATE_DIR}/swtpm.pid" ]; then
      S_PID="$(cat "${STATE_DIR}/swtpm.pid")"
      kill "${S_PID}" 2>/dev/null || true
      rm -f "${STATE_DIR}/swtpm.pid"
    fi
    rm -f "${SOCKET_PATH}"
    log_info "VM ${DEV} stopped."
    ;;

  status)
    QEMU_STATUS="stopped"
    SWTPM_STATUS="stopped"
    if [ -f "${STATE_DIR}/qemu.pid" ]; then
      if kill -0 "$(cat "${STATE_DIR}/qemu.pid")" 2>/dev/null; then
        QEMU_STATUS="running (PID $(cat "${STATE_DIR}/qemu.pid"))"
      fi
    fi
    if [ -f "${STATE_DIR}/swtpm.pid" ]; then
      if kill -0 "$(cat "${STATE_DIR}/swtpm.pid")" 2>/dev/null; then
        SWTPM_STATUS="running (PID $(cat "${STATE_DIR}/swtpm.pid"))"
      fi
    fi
    echo "Device: ${DEV}"
    echo "  swtpm: ${SWTPM_STATUS}"
    echo "  qemu:  ${QEMU_STATUS}"
    echo "  ssh:   localhost:${PORT_SSH}"
    echo "  agent: localhost:${PORT_AGENT}"
    ;;

  ssh)
    exec ssh -p "${PORT_SSH}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null zta@127.0.0.1
    ;;

  console)
    log_info "Console connect not configured for daemonized VM (use ssh or inspect logs)."
    ;;

  *)
    log_err "Unknown action: ${ACTION}. Valid actions: start, stop, status, refresh, ssh, console"
    exit 1
    ;;
esac
