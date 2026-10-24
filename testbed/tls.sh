#!/usr/bin/env bash
# testbed/tls.sh - TLS material for the testbed services and Keycloak (requirements S2, S4):
# a testbed CA (kept across runs) and a server certificate for this host's names and addresses.
#   testbed/tls.sh [extra-SAN ...]      -> testbed/state/tls/{ca.pem,ca.key,server.pem,server.key}
# Clients trust the CA through NODE_EXTRA_CA_CERTS (Node) or --cacert (curl); nothing disables
# certificate verification. ECDSA P-256, SHA-256; server certificate valid for 397 days.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${ZTA_TLS_DIR:-${SCRIPT_DIR}/state/tls}"
mkdir -p "${OUT}"
cd "${OUT}"

if [ -z "${ZTA_PUBLIC_HOST:-}" ] && command -v ip >/dev/null 2>&1; then
  ZTA_PUBLIC_HOST="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')"
fi

if [ ! -s ca.key ]; then
  (umask 077 && openssl ecparam -name prime256v1 -genkey -noout -out ca.key)
  openssl req -x509 -new -key ca.key -sha256 -days 3650 -subj "/CN=ZTA testbed TLS CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem
fi

sans="DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1,IP:::1"
for h in ${ZTA_PUBLIC_HOST:-} "$@"; do
  if [[ "${h}" =~ ^[0-9.]+$ || "${h}" == *:* ]]; then entry="IP:${h}"; else entry="DNS:${h}"; fi
  [[ ",${sans}," == *",${entry},"* ]] || sans+=",${entry}"
done

(umask 077 && openssl ecparam -name prime256v1 -genkey -noout -out server.key)
openssl req -new -key server.key -subj "/CN=${ZTA_PUBLIC_HOST:-localhost}" -out server.csr
cat > server.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=${sans}
EOF
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 397 -sha256 -extfile server.ext -out server.pem
rm -f server.csr server.ext
# Keycloak's container user must read the key; the directory itself stays private to this user
chmod 0700 "${OUT}"
chmod 0644 server.key
echo "TLS: ${OUT}/server.pem (SAN ${sans}), CA ${OUT}/ca.pem"
