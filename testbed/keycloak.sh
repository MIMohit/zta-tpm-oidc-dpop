#!/usr/bin/env bash
# testbed/keycloak.sh - Run the testbed's Keycloak (main IdP) in Docker: start | stop | status | env
# Serves HTTP on KC_PORT (8080) and, with the testbed TLS material (testbed/tls.sh), HTTPS on
# KC_TLS_PORT (8443). `env` prints the gate's settings for HTTPS when ZTA_TLS=1.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

KC_IMAGE="${KC_IMAGE:-quay.io/keycloak/keycloak:26.0.7}"
KC_NAME="${KC_NAME:-zta-keycloak}"
KC_PORT="${KC_PORT:-8080}"
KC_TLS_PORT="${KC_TLS_PORT:-8443}"
TLS_DIR="${ZTA_TLS_DIR:-${SCRIPT_DIR}/state/tls}"
STATE="${SCRIPT_DIR}/state/keycloak"

if [ -z "${ZTA_PUBLIC_HOST:-}" ] && command -v ip >/dev/null 2>&1; then
  ZTA_PUBLIC_HOST="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')"
fi
ZTA_PUBLIC_HOST="${ZTA_PUBLIC_HOST:-127.0.0.1}"
KC_URL="http://${ZTA_PUBLIC_HOST}:${KC_PORT}"
KC_TLS_URL="https://${ZTA_PUBLIC_HOST}:${KC_TLS_PORT}"
GATE_URL="${GATE_URL:-http://${ZTA_PUBLIC_HOST}:5173}"
GATE_TLS_URL="${GATE_TLS_URL:-https://${ZTA_PUBLIC_HOST}:5173}"

secret() {
  local f="${STATE}/$1"
  if [ ! -s "${f}" ]; then
    mkdir -p "${STATE}"
    (umask 077 && openssl rand -hex 24 > "${f}")
  fi
  cat "${f}"
}

case "${1:-}" in
  start)
    mkdir -p "${STATE}/import"
    CLIENT_SECRET="$(secret client-secret)"
    sed -e "s#__CLIENT_SECRET__#${CLIENT_SECRET}#" \
        -e "s#__GATE_URL__#${GATE_URL}#g" \
        -e "s#__GATE_TLS_URL__#${GATE_TLS_URL}#g" \
        -e "s#__ALICE_PASSWORD__#${ALICE_PASSWORD:-alice-pass}#" \
        -e "s#__BOB_PASSWORD__#${BOB_PASSWORD:-bob-pass}#" \
        "${SCRIPT_DIR}/keycloak/zta-realm.template.json" > "${STATE}/import/zta-realm.json"
    chmod 0644 "${STATE}/import/zta-realm.json"
    tls_args=()
    if [ -s "${TLS_DIR}/server.pem" ] && [ -s "${TLS_DIR}/server.key" ]; then
      tls_args=(-p "${KC_TLS_PORT}:8443" -v "${TLS_DIR}:/opt/keycloak/conf/tls:ro")
      kc_tls=(--https-certificate-file=/opt/keycloak/conf/tls/server.pem --https-certificate-key-file=/opt/keycloak/conf/tls/server.key)
    else
      kc_tls=()
      log_warn "No TLS material in ${TLS_DIR} (testbed/tls.sh): Keycloak serves HTTP only"
    fi
    docker rm -f "${KC_NAME}" >/dev/null 2>&1 || true
    # No fixed hostname: the issuer follows the URL a client uses, so the HTTP and the HTTPS
    # endpoint each issue tokens with their own (consistent) issuer
    run docker run -d --name "${KC_NAME}" -p "${KC_PORT}:8080" ${tls_args[@]+"${tls_args[@]}"} \
      -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
      -e KC_BOOTSTRAP_ADMIN_PASSWORD="$(secret admin-password)" \
      -e KC_HEALTH_ENABLED=true \
      -v "${STATE}/import:/opt/keycloak/data/import:ro" \
      "${KC_IMAGE}" start-dev --import-realm --hostname-strict=false ${kc_tls[@]+"${kc_tls[@]}"}
    log_info "Waiting for Keycloak at ${KC_URL}..."
    for _ in $(seq 1 120); do
      if curl -fsS "${KC_URL}/realms/zta-realm/.well-known/openid-configuration" >/dev/null 2>&1; then
        log_info "Keycloak ready: ${KC_URL}/realms/zta-realm"
        exit 0
      fi
      sleep 2
    done
    log_err "Keycloak did not become ready; see: docker logs ${KC_NAME}"
    exit 1
    ;;
  stop)
    docker rm -f "${KC_NAME}" >/dev/null 2>&1 || true
    log_info "Keycloak stopped."
    ;;
  status)
    docker ps --filter "name=${KC_NAME}" --format '{{.Names}} {{.Image}} {{.Status}}'
    ;;
  env)
    # Settings for the gate (IDP_MODE=keycloak)
    echo "IDP_MODE=keycloak"
    if [ "${ZTA_TLS:-0}" = "1" ]; then
      echo "KEYCLOAK_ISSUER=${KC_TLS_URL}/realms/zta-realm"
    else
      echo "KEYCLOAK_ISSUER=${KC_URL}/realms/zta-realm"
    fi
    echo "KEYCLOAK_CLIENT_ID=zta-gate"
    echo "KEYCLOAK_CLIENT_SECRET=$(secret client-secret)"
    ;;
  *)
    log_err "Usage: $0 start|stop|status|env"
    exit 1
    ;;
esac
