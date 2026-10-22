#!/usr/bin/env bash
# testbed/tests/lint.sh - Lint all testbed shell scripts with bash -n and shellcheck
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTBED_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "==> Running bash -n syntax checks on testbed scripts..."
SCRIPTS=()
while IFS= read -r file; do
  SCRIPTS+=("${file}")
done < <(find "${TESTBED_DIR}" -name "*.sh" | sort)

if [ "${#SCRIPTS[@]}" -eq 0 ]; then
  echo "No shell scripts found to lint."
  exit 1
fi

FAIL=0
for s in "${SCRIPTS[@]}"; do
  if ! bash -n "${s}"; then
    echo "FAIL (syntax): ${s}"
    FAIL=1
  else
    echo "PASS (syntax): ${s}"
  fi
done

if [ "${FAIL}" -ne 0 ]; then
  echo "bash -n syntax check failed."
  exit 1
fi

echo ""
echo "==> Running shellcheck (-S warning) on testbed scripts..."

SHELLCHECK_BIN=""
if [ -x "/opt/homebrew/bin/shellcheck" ]; then
  SHELLCHECK_BIN="/opt/homebrew/bin/shellcheck"
elif command -v shellcheck >/dev/null 2>&1; then
  SHELLCHECK_BIN="$(command -v shellcheck)"
fi

if [ -z "${SHELLCHECK_BIN}" ]; then
  echo "WARNING: shellcheck not found on PATH. Skipping static analysis."
  exit 0
fi

echo "Using shellcheck: ${SHELLCHECK_BIN}"
for s in "${SCRIPTS[@]}"; do
  echo "Checking ${s}..."
  "${SHELLCHECK_BIN}" -S warning -x "${s}"
done

echo ""
echo "All ${#SCRIPTS[@]} shell scripts passed lint successfully (0 findings >= warning)."
