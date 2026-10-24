#!/usr/bin/env bash
# testbed/tests/dry-run.sh - Golden assertions on DRY_RUN=1 command execution
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTBED_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "==> Running testbed dry-run test suite..."

pass_count=0
fail_count=0

assert_contains() {
  local label="$1"
  local needle="$2"
  local haystack="$3"
  if [[ "${haystack}" == *"${needle}"* ]]; then
    echo "  [PASS] ${label}"
    pass_count=$((pass_count + 1))
  else
    echo "  [FAIL] ${label}"
    echo "    Expected to find: '${needle}'"
    echo "    In output: '${haystack}'"
    fail_count=$((fail_count + 1))
  fi
}

assert_not_contains() {
  local label="$1"
  local needle="$2"
  local haystack="$3"
  if [[ "${haystack}" != *"${needle}"* ]]; then
    echo "  [PASS] ${label}"
    pass_count=$((pass_count + 1))
  else
    echo "  [FAIL] ${label}"
    echo "    Did not expect to find: '${needle}'"
    echo "    In output: '${haystack}'"
    fail_count=$((fail_count + 1))
  fi
}

assert_true() {
  local label="$1"
  local condition="$2"
  if [ "${condition}" -eq 1 ]; then
    echo "  [PASS] ${label}"
    pass_count=$((pass_count + 1))
  else
    echo "  [FAIL] ${label}"
    fail_count=$((fail_count + 1))
  fi
}

echo ""
echo "Test 1: macOS acceleration and TPM device model..."
OUT_MACOS="$(DRY_RUN=1 UNAME_S=Darwin "${TESTBED_DIR}/vm.sh" dev-good start)"
assert_contains "macOS has -accel tcg" "-accel tcg" "${OUT_MACOS}"
assert_contains "macOS uses tpm-tis-device" "tpm-tis-device" "${OUT_MACOS}"

echo ""
echo "Test 2: Linux simulation with KVM acceleration..."
OUT_LINUX="$(DRY_RUN=1 UNAME_S=Linux UNAME_M=x86_64 KVM_OK=1 "${TESTBED_DIR}/vm.sh" dev-good start)"
assert_contains "Linux with KVM has accel=kvm" "accel=kvm" "${OUT_LINUX}"
assert_contains "Linux x86_64 uses tpm-crb" "tpm-crb" "${OUT_LINUX}"

echo ""
echo "Test 3: Package manager branches (pacman vs apt)..."
OUT_PACMAN="$(DRY_RUN=1 PKG=pacman "${TESTBED_DIR}/install-deps.sh")"
assert_contains "pacman branch runs pacman" "pacman" "${OUT_PACMAN}"
assert_contains "pacman installs qemu-base" "qemu-base" "${OUT_PACMAN}"
assert_contains "pacman installs swtpm" "swtpm" "${OUT_PACMAN}"

OUT_APT="$(DRY_RUN=1 PKG=apt "${TESTBED_DIR}/install-deps.sh")"
assert_contains "apt branch runs apt-get" "apt-get" "${OUT_APT}"
assert_contains "apt installs qemu-system-x86" "qemu-system-x86" "${OUT_APT}"
assert_contains "apt installs swtpm" "swtpm" "${OUT_APT}"

echo ""
echo "Test 4: Fleet distinct state dirs and short socket paths..."
FLEET=("dev-good" "dev-tampered" "dev-rogue" "dev-foreign")
STATE_DIRS=()
SOCKETS=()

for dev in "${FLEET[@]}"; do
  OUT_DEV="$(DRY_RUN=1 "${TESTBED_DIR}/vm.sh" "${dev}" start)"
  # Extract state dir
  STATE_DIR="$(echo "${OUT_DEV}" | grep -o 'dir=[^ ]*' | head -n1 | cut -d= -f2)"
  STATE_DIRS+=("${STATE_DIR}")
  # Extract socket path
  SOCK_PATH="$(echo "${OUT_DEV}" | grep -o 'path=[^ ]*' | head -n1 | cut -d= -f2)"
  SOCKETS+=("${SOCK_PATH}")

  SOCK_LEN="${#SOCK_PATH}"
  if [ "${SOCK_LEN}" -le 100 ]; then
    echo "  [PASS] ${dev} socket length <= 100 chars (${SOCK_LEN} chars: ${SOCK_PATH})"
    pass_count=$((pass_count + 1))
  else
    echo "  [FAIL] ${dev} socket length exceeds 100 chars (${SOCK_LEN} chars: ${SOCK_PATH})"
    fail_count=$((fail_count + 1))
  fi
done

# Check uniqueness of state dirs
UNIQUE_STATE_COUNT="$(printf "%s\n" "${STATE_DIRS[@]}" | sort -u | wc -l | tr -d ' ')"
assert_true "All 4 devices have distinct swtpm state dirs" "$(( UNIQUE_STATE_COUNT == 4 ))"

# Check uniqueness of sockets
UNIQUE_SOCK_COUNT="$(printf "%s\n" "${SOCKETS[@]}" | sort -u | wc -l | tr -d ' ')"
assert_true "All 4 devices have distinct swtpm socket paths" "$(( UNIQUE_SOCK_COUNT == 4 ))"

echo ""
echo "Test 5: Inventory exclusion of dev-rogue..."
OUT_ROGUE="$(DRY_RUN=1 "${TESTBED_DIR}/inventory.sh" dev-rogue alice)"
assert_contains "dev-rogue triggers skipping message" "Skipping dev-rogue on purpose" "${OUT_ROGUE}"
assert_not_contains "dev-rogue does NOT invoke inventory-add.js" "inventory-add.js" "${OUT_ROGUE}"

OUT_GOOD="$(DRY_RUN=1 "${TESTBED_DIR}/inventory.sh" dev-good alice)"
assert_contains "dev-good invokes inventory-add.js" "inventory-add.js" "${OUT_GOOD}"
assert_contains "dev-good specifies devId" "--devId" "${OUT_GOOD}"

echo ""
echo "Test 6: dev-foreign uses CA 'foreign'..."
OUT_FOREIGN="$(DRY_RUN=1 "${TESTBED_DIR}/manufacture.sh" dev-foreign)"
assert_contains "dev-foreign references CA 'foreign' config" "ca/foreign/swtpm_setup.conf" "${OUT_FOREIGN}"

echo ""
echo "Test 7: Overall fleet lifecycle scripts dry-run..."
DRY_RUN=1 "${TESTBED_DIR}/ca-init.sh" good >/dev/null
DRY_RUN=1 "${TESTBED_DIR}/ca-init.sh" foreign >/dev/null
echo "  [PASS] ca-init.sh runs cleanly in dry-run mode"
pass_count=$((pass_count + 1))

DRY_RUN=1 "${TESTBED_DIR}/fleet.sh" up >/dev/null
echo "  [PASS] fleet.sh up runs cleanly in dry-run mode"
pass_count=$((pass_count + 1))

DRY_RUN=1 "${TESTBED_DIR}/fleet.sh" down >/dev/null
echo "  [PASS] fleet.sh down runs cleanly in dry-run mode"
pass_count=$((pass_count + 1))

DRY_RUN=1 "${TESTBED_DIR}/image-fetch.sh" >/dev/null
echo "  [PASS] image-fetch.sh runs cleanly in dry-run mode"
pass_count=$((pass_count + 1))

DRY_RUN=1 "${TESTBED_DIR}/image-build.sh" golden >/dev/null
DRY_RUN=1 "${TESTBED_DIR}/image-build.sh" tampered >/dev/null
echo "  [PASS] image-build.sh runs cleanly in dry-run mode"
pass_count=$((pass_count + 1))

DRY_RUN=1 "${TESTBED_DIR}/rv-capture.sh" >/dev/null
echo "  [PASS] rv-capture.sh runs cleanly in dry-run mode"
pass_count=$((pass_count + 1))

echo ""
echo "========================================="
echo "Dry-run results: ${pass_count} passed, ${fail_count} failed."
echo "========================================="

if [ "${fail_count}" -gt 0 ]; then
  exit 1
fi
exit 0
