#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIM_DIR="$REPO_ROOT/.tpm-sim"
STATE_DIR="${TPM_STATE_DIR:-$REPO_ROOT/data/tpm-sim}"
PORT="${TPM_TCP_PORT:-2321}"
TPM_SERVER_BIN="$SIM_DIR/ibmswtpm2/src/tpm_server"
PINNED_COMMIT="e1df46e46fc2671e55372d65f27ecbb3c789d992"
PREBUILT_BIN="${TPM_SERVER_PREBUILT:-}"  # optional path to an already-built tpm_server

# Ensure simulator binary exists
if [ ! -x "$TPM_SERVER_BIN" ]; then
  mkdir -p "$SIM_DIR"

  if [ -x "$PREBUILT_BIN" ]; then
    echo "==> Reusing prebuilt IBM tpm_server from tpmlab scratchpad..."
    mkdir -p "$SIM_DIR/ibmswtpm2/src"
    cp "$PREBUILT_BIN" "$TPM_SERVER_BIN"
    chmod +x "$TPM_SERVER_BIN"
  else
    echo "==> Cloning IBM swtpm2 (commit $PINNED_COMMIT)..."
    if [ ! -d "$SIM_DIR/ibmswtpm2" ]; then
      git clone --depth 10 https://github.com/kgoldman/ibmswtpm2.git "$SIM_DIR/ibmswtpm2"
    fi
    (
      cd "$SIM_DIR/ibmswtpm2"
      git fetch --depth 50 origin "$PINNED_COMMIT" 2>/dev/null || true
      git checkout "$PINNED_COMMIT" 2>/dev/null || true
      cd src
      OS="$(uname -s)"
      if [ "$OS" = "Darwin" ]; then
        OPENSSL_PREFIX="$(brew --prefix openssl@3 2>/dev/null || true)"
        if [ -z "$OPENSSL_PREFIX" ] || [ ! -d "$OPENSSL_PREFIX" ]; then
          for candidate in /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3; do
            if [ -d "$candidate" ]; then OPENSSL_PREFIX="$candidate"; break; fi
          done
        fi
        if [ -z "$OPENSSL_PREFIX" ] || [ ! -d "$OPENSSL_PREFIX" ]; then
          echo "ERROR: OpenSSL 3 not found. Run 'brew install openssl@3' on macOS." >&2
          exit 1
        fi
        NCPU="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"
        echo "==> Compiling tpm_server for macOS with OpenSSL 3 ($OPENSSL_PREFIX)..."
        make -f makefile.mac -j"$NCPU" CC="clang -I$OPENSSL_PREFIX/include" LNFLAGS="-L$OPENSSL_PREFIX/lib -lcrypto -lpthread"
      else
        NCPU="$(nproc 2>/dev/null || echo 4)"
        echo "==> Compiling tpm_server for Linux..."
        make -f makefile -j"$NCPU" || {
          echo "ERROR: Linux build failed. Ensure libssl-dev, gcc, make are installed." >&2
          exit 1
        }
      fi
    )
  fi
fi

if [ ! -x "$TPM_SERVER_BIN" ]; then
  echo "ERROR: $TPM_SERVER_BIN could not be built or executed." >&2
  exit 1
fi

mkdir -p "$STATE_DIR"

ARGS=()
# Fresh NV requested or no prior state
if [ "${1:-}" = "--fresh" ] || [ ! -f "$STATE_DIR/NVChip" ]; then
  ARGS+=("-rm")
fi

if [ "$PORT" != "2321" ]; then
  ARGS+=("-port" "$PORT")
fi

echo "==> Starting IBM tpm_server in $STATE_DIR on port $PORT (platform port $((PORT + 1)))..."
cd "$STATE_DIR"
exec "$TPM_SERVER_BIN" ${ARGS[@]+"${ARGS[@]}"}
