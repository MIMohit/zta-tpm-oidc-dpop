#!/usr/bin/env bash
# testbed/fleet.sh - Manage entire fleet of testbed virtual machines
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=config.env
source "${SCRIPT_DIR}/config.env"

ACTION="${1:-status}"

case "${ACTION}" in
  up)
    log_info "Bringing up fleet: ${FLEET_DEVICES[*]}..."
    for dev in "${FLEET_DEVICES[@]}"; do
      "${SCRIPT_DIR}/vm.sh" "${dev}" start
    done

    # Write attack targets configuration for attack runner
    TARGETS_FILE="${SCRIPT_DIR}/attack-targets.json"
    log_info "Writing attack targets configuration to ${TARGETS_FILE}..."
    if [ "${DRY_RUN:-0}" = "1" ]; then
      run cp "${SCRIPT_DIR}/attack-targets.example.json" "${TARGETS_FILE}"
    else
      TARGET_DEVS=("${FLEET_DEVICES[@]}" "dev-hw")
      {
        echo "{"
        echo '  "pepUrl": "http://127.0.0.1:4000",'
        echo '  "idpUrl": "http://127.0.0.1:4001",'
        echo '  "verifierUrl": "http://127.0.0.1:4002",'
        echo '  "registryUrl": "http://127.0.0.1:4004",'
        echo '  "resourceUrl": "http://127.0.0.1:4003",'
        echo '  "adminToken": "dev-admin-secret",'
        echo '  "devices": {'
        for i in "${!TARGET_DEVS[@]}"; do
          d="${TARGET_DEVS[$i]}"
          port_agent="$(get_dev_var "${d}" "PORT_AGENT")"
          user_dev="$(get_dev_var "${d}" "USER")"
          port_ssh="$(get_dev_var "${d}" "PORT_SSH")"
          comma=","
          if [ "$i" -eq $((${#TARGET_DEVS[@]} - 1)) ]; then
            comma=""
          fi
          echo "    \"${d}\": {"
          echo "      \"agentUrl\": \"http://127.0.0.1:${port_agent}\","
          echo "      \"user\": \"${user_dev}\","
          echo "      \"sshPort\": ${port_ssh}"
          echo "    }${comma}"
        done
        echo "  },"
        echo '  "users": {'
        echo '    "alice": {'
        echo '      "password": "password123"'
        echo "    },"
        echo '    "bob": {'
        echo '      "password": "password123"'
        echo "    }"
        echo "  }"
        echo "}"
      } > "${TARGETS_FILE}"
    fi
    log_info "Fleet is up."
    ;;

  down)
    log_info "Stopping fleet: ${FLEET_DEVICES[*]}..."
    for dev in "${FLEET_DEVICES[@]}"; do
      "${SCRIPT_DIR}/vm.sh" "${dev}" stop
    done
    log_info "Fleet is stopped."
    ;;

  status)
    for dev in "${FLEET_DEVICES[@]}"; do
      "${SCRIPT_DIR}/vm.sh" "${dev}" status
      echo ""
    done
    ;;

  *)
    log_err "Unknown action: ${ACTION}. Valid actions: up, down, status"
    exit 1
    ;;
esac
