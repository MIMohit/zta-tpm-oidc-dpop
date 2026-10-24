#!/usr/bin/env bash
# testbed/image-build.sh - Build golden or tampered VM overlay and cloud-init seed
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

if [ $# -lt 1 ]; then
  log_err "Usage: $0 <golden|tampered>"
  exit 1
fi

TARGET="$1"
if [ "${TARGET}" != "golden" ] && [ "${TARGET}" != "tampered" ]; then
  log_err "Invalid target: ${TARGET}. Must be 'golden' or 'tampered'."
  exit 1
fi

CACHE_DIR="${SCRIPT_DIR}/cache"
IMAGES_DIR="${SCRIPT_DIR}/images"

if [ "${ARCH_TYPE}" = "x86_64" ] || [ "${ARCH_TYPE}" = "amd64" ]; then
  UBUNTU_ARCH="amd64"
elif [ "${ARCH_TYPE}" = "aarch64" ] || [ "${ARCH_TYPE}" = "arm64" ]; then
  UBUNTU_ARCH="arm64"
else
  UBUNTU_ARCH="amd64"
fi

BASE_IMG="${CACHE_DIR}/noble-server-cloudimg-${UBUNTU_ARCH}.img"
TARGET_QCOW2="${IMAGES_DIR}/${TARGET}.qcow2"
SEED_ISO="${IMAGES_DIR}/${TARGET}-seed.iso"

log_info "Building image and cloud-init seed for target: ${TARGET} (${UBUNTU_ARCH})..."

if [ "${DRY_RUN:-0}" = "1" ]; then
  run qemu-img create -f qcow2 -b "${BASE_IMG}" -F qcow2 "${TARGET_QCOW2}"
  run xorriso -as mkisofs -R -V cidata -o "${SEED_ISO}" "${IMAGES_DIR}/cloud-init/${TARGET}"
  exit 0
fi

mkdir -p "${IMAGES_DIR}"
CI_DIR="${IMAGES_DIR}/cloud-init/${TARGET}"
mkdir -p "${CI_DIR}"

# Ensure base cloud image is fetched
if [ ! -f "${BASE_IMG}" ]; then
  log_info "Base image not found. Running image-fetch.sh..."
  "${SCRIPT_DIR}/image-fetch.sh"
fi

# Create qcow2 overlay
log_info "Creating qcow2 overlay at ${TARGET_QCOW2}..."
qemu-img create -f qcow2 -b "${BASE_IMG}" -F qcow2 "${TARGET_QCOW2}"

# Prepare SSH key for VM user
SSH_KEY_PUB=""
if [ -f "${HOME}/.ssh/id_rsa.pub" ]; then
  SSH_KEY_PUB="$(cat "${HOME}/.ssh/id_rsa.pub")"
elif [ -f "${HOME}/.ssh/id_ed25519.pub" ]; then
  SSH_KEY_PUB="$(cat "${HOME}/.ssh/id_ed25519.pub")"
fi

# Generate meta-data
cat << EOF > "${CI_DIR}/meta-data"
instance-id: iid-zta-${TARGET}
local-hostname: zta-${TARGET}
EOF

# Generate user-data
cat << EOF > "${CI_DIR}/user-data"
#cloud-config
# Golden boot measurements must not drift: no package changes at first boot
package_update: false
package_upgrade: false
# The tss group already exists in the Ubuntu cloud image
users:
  - name: zta
    gecos: ZTA Fleet Agent
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: sudo, tss
    shell: /bin/bash
    lock_passwd: false
    passwd: \$6\$rounds=4096\$salt\$eD8XwVv9R5L8C9M4Q7J2T6.X4K3P0L1N8.H6D4A2O9S7F5U3I1Y8Z6W4E2R0T8Y6U4I2O0P8A6S4D2F0G8H6J4K2L0
EOF

if [ -n "${SSH_KEY_PUB}" ]; then
  cat << EOF >> "${CI_DIR}/user-data"
    ssh_authorized_keys:
      - ${SSH_KEY_PUB}
EOF
fi

cat << 'EOF' >> "${CI_DIR}/user-data"
write_files:
  - path: /etc/systemd/system/zta-eventlog.service
    permissions: '0644'
    content: |
      [Unit]
      Description=ZTA Event Log Copy (root oneshot for non-root agent access)
      DefaultDependencies=no
      Before=zta-agent.service
      ConditionPathExists=/sys/kernel/security/tpm0/binary_bios_measurements

      [Service]
      Type=oneshot
      ExecStart=/bin/sh -c 'mkdir -p /run/zta && cp /sys/kernel/security/tpm0/binary_bios_measurements /run/zta/binary_bios_measurements && chmod 0444 /run/zta/binary_bios_measurements'
      RemainAfterExit=yes

      [Install]
      WantedBy=multi-user.target

  - path: /etc/systemd/system/zta-agent.service
    permissions: '0644'
    content: |
      [Unit]
      Description=ZTA Real TPM Agent
      After=network-online.target zta-eventlog.service
      Wants=network-online.target zta-eventlog.service
      RequiresMountsFor=/mnt/repo /mnt/devstate

      [Service]
      Type=simple
      User=zta
      Group=tss
      Environment=TPM_BACKEND=tpm
      Environment=TPM_DEVICE=linux
      Environment=TPM_EVENTLOG_PATH=/run/zta/binary_bios_measurements
      Environment=PORT=7101
      Environment=HOST=0.0.0.0
      Environment=TPM_STATE_DIR=/var/lib/zta-agent/tpm
      Environment=ZTA_DATA_DIR=/var/lib/zta-agent/data
      # Per-device settings written by vm.sh on the host (AGENT_ID, server URLs)
      EnvironmentFile=/mnt/devstate/agent.env
      WorkingDirectory=/mnt/repo
      # Node comes from the host's checksum-verified download (image-fetch.sh)
      ExecStart=/mnt/repo/testbed/cache/node/bin/node tpm-agent.js
      Restart=always
      RestartSec=2

      [Install]
      WantedBy=multi-user.target

  - path: /etc/udev/rules.d/60-zta-tpm.rules
    permissions: '0644'
    content: |
      KERNEL=="tpmrm[0-9]*", GROUP="tss", MODE="0660"

mounts:
  - [ repo, /mnt/repo, 9p, "trans=virtio,version=9p2000.L,ro", "0", "0" ]
  - [ devstate, /mnt/devstate, 9p, "trans=virtio,version=9p2000.L,ro", "0", "0" ]

runcmd:
  - mkdir -p /run/zta /mnt/repo /mnt/devstate
  - install -d -o zta -g tss -m 0750 /var/lib/zta-agent /var/lib/zta-agent/tpm /var/lib/zta-agent/data
  - udevadm control --reload && udevadm trigger --subsystem-match=tpmrm
  - systemctl disable --now apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service || true
  # The official Node build needs libatomic; user space only, so PCR0-7 are unaffected
  - apt-get update -y && apt-get install -y --no-install-recommends libatomic1
  - systemctl daemon-reload
  - systemctl enable --now zta-eventlog.service zta-agent.service
EOF

# For tampered image: modify measured kernel binary loaded by bootloader (per X5)
if [ "${TARGET}" = "tampered" ]; then
  cat << 'EOF' >> "${CI_DIR}/user-data"
  # Finding X5: Kernel binary is measured into PCR4 via EFI stub LoadImage.
  # Alter default kernel binary to trigger genuine PCR4 deviation.
  # No "|| true": an untampered dev-tampered would silently invalidate A06
  - apt-get update -y && apt-get install -y --no-install-recommends linux-image-generic-hwe-24.04
  - update-grub
# The new kernel is measured only once it boots
power_state:
  mode: reboot
  condition: true
EOF
fi

# Build cloud-init ISO
log_info "Generating NoCloud seed ISO at ${SEED_ISO}..."
if command -v cloud-localds >/dev/null 2>&1; then
  cloud-localds "${SEED_ISO}" "${CI_DIR}/user-data" "${CI_DIR}/meta-data"
elif command -v xorriso >/dev/null 2>&1; then
  xorriso -as mkisofs -R -V cidata -o "${SEED_ISO}" "${CI_DIR}/user-data" "${CI_DIR}/meta-data"
elif command -v genisoimage >/dev/null 2>&1; then
  genisoimage -output "${SEED_ISO}" -volid cidata -joliet -rock "${CI_DIR}/user-data" "${CI_DIR}/meta-data"
else
  log_err "Neither cloud-localds, xorriso, nor genisoimage found. Cannot build seed ISO."
  exit 1
fi

log_info "Image build completed for ${TARGET}."
