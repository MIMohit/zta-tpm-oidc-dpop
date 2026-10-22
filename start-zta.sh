#!/bin/bash

# Zero-Trust Architecture (ZTA) Multi-Service Start Script
# Spin up all backend services and coordinate exit gracefully

# Trap Ctrl+C (SIGINT) and exit of script to kill all background processes
trap 'echo "🛑 Stopping all ZTA services..."; kill $(jobs -p) 2>/dev/null; exit' INT TERM EXIT

echo "=========================================================="
echo "🛡️  STARTING ZERO-TRUST ARCHITECTURE DEMO SERVICES  🛡️"
echo "=========================================================="

# 0. Seed dev environment if missing
if [ ! -f "data/secrets.json" ] || [ ! -f "data/dev-enrolment-codes.json" ]; then
  echo "🌱 Seeding development environment and cryptographic credentials..."
  node scripts/seed-dev.js
  echo ""
fi

# 0b. TPM backend (TPM_BACKEND=sim|tpm|auto, default sim; env is passed through to every service)
if [ -z "${TPM_BACKEND:-}" ] && [ -f .env ]; then
  TPM_BACKEND=$(sed -n 's/^TPM_BACKEND=//p' .env | tail -1 | tr -d '"'"'"'\r')
fi
export TPM_BACKEND="${TPM_BACKEND:-sim}"
if [ "$TPM_BACKEND" = "tpm" ] || [ "$TPM_BACKEND" = "auto" ]; then
  export TPM_DEVICE="${TPM_DEVICE:-auto}"
  echo "🔐 TPM_BACKEND=$TPM_BACKEND TPM_DEVICE=$TPM_DEVICE (real TPM 2.0 via tss.js)"
  if [ "${TPM_SIM_AUTOSTART:-0}" = "1" ] && [ "$TPM_DEVICE" = "tcp" ]; then
    TPM_PORT="${TPM_TCP_PORT:-2321}"
    echo "🧪 TPM_SIM_AUTOSTART=1: starting the software TPM (IBM tpm_server) on port $TPM_PORT..."
    scripts/tpm-sim-server.sh &
    for _ in $(seq 1 50); do
      nc -z "${TPM_TCP_HOST:-127.0.0.1}" "$TPM_PORT" 2>/dev/null && break
      sleep 0.2
    done
    echo "📜 Provisioning dev EK certificate into the software TPM NV..."
    node scripts/tpm-provision-ek-cert.mjs || echo "⚠️  EK cert provisioning failed"
    if [ -z "$(node -p "try { JSON.parse(require('fs').readFileSync('./data/dev-enrolment-codes.json','utf8'))['alice-laptop-tpm'] || '' } catch(e){''}")" ]; then
      echo "📋 Registering the real TPM EK in the verifier inventory..."
      node scripts/inventory-add.js --backend tpm --agent alice-laptop --user alice || echo "⚠️  inventory add failed"
    fi
  fi
else
  echo "🔐 TPM_BACKEND=$TPM_BACKEND (simulated TPM)"
fi
echo ""

# 1. Start Policy Information Point (PIP) - Port 4003
echo "🔍 Starting PIP (Port 4003)..."
node pip.js &
sleep 0.5

# 2. Start Policy Decision Point (PDP) - Port 4002
echo "🧠 Starting PDP (Port 4002)..."
node pdp.js &
sleep 0.5

# 3. Start Attestation Verifier - Port 4005
echo "🧪 Starting Attestation Verifier (Port 4005)..."
node services/attestation-service.js &
sleep 0.5

# 4. Start Device Registry Admin - Port 4004
echo "📘 Starting Device Registry Admin (Port 4004)..."
node services/device-registry.js &
sleep 0.5

# 5. Start Protected Resource Server - Port 5001
echo "📊 Starting Protected Resource Server (Port 5001)..."
node services/resource-server.js &
sleep 0.5

# 6. Start Policy Enforcement Point (PEP) - Port 4001
echo "🛂 Starting PEP (Port 4001)..."
node pep.js &
sleep 0.5

# 7. Start Main Gateway & Web Server (Portal + IdP Gate) - Port 5173
echo "🔑 Starting Web Portal & IdP Gate (Port 5173)..."
node server.js &
sleep 0.5

# 8. Start Client TPM Agent - Port 7000
echo "🧩 Starting Client TPM Agent (Port 7000)..."
node tpm-agent.js &
sleep 0.5

# Report the backend the agent actually activated (auto may fall back to sim)
ACTIVE_TPM=""
for _ in $(seq 1 25); do
  ACTIVE_TPM=$(curl -s --max-time 2 http://127.0.0.1:7000/agent/status 2>/dev/null | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{const s=JSON.parse(d);process.stdout.write((s.backend||'')+(s.fallback?' (FALLBACK: '+s.reason+')':'')+(s.tpm==='unavailable'?' (UNAVAILABLE: '+s.reason+')':''))}catch{}})")
  [ -n "$ACTIVE_TPM" ] && break
  sleep 0.2
done

echo ""
echo "=========================================================="
echo "✅ All local services successfully spawned in background!"
echo "🔐 TPM backend:    TPM_BACKEND=$TPM_BACKEND -> active: ${ACTIVE_TPM:-unknown}"
echo "👉 Web Portal:     http://localhost:5173"
echo "👉 Client Agent:   http://localhost:7000"
echo "👉 PEP Proxy:      http://localhost:4001"
echo "----------------------------------------------------------"
echo "📋 Dev Enrolment Codes:  data/dev-enrolment-codes.json"
if [ -f "data/dev-enrolment-codes.json" ]; then
  ALICE_CODE=$(node -p "try { JSON.parse(require('fs').readFileSync('./data/dev-enrolment-codes.json','utf8'))['alice-laptop'] || '' } catch(e){''}")
  if [ -n "$ALICE_CODE" ]; then
    echo "   Alice laptop code:    $ALICE_CODE"
  fi
  ALICE_TPM_CODE=$(node -p "try { JSON.parse(require('fs').readFileSync('./data/dev-enrolment-codes.json','utf8'))['alice-laptop-tpm'] || '' } catch(e){''}")
  if [ -n "$ALICE_TPM_CODE" ] && [ "$TPM_BACKEND" != "sim" ]; then
    echo "   Alice real-TPM code:  $ALICE_TPM_CODE"
  fi
fi
echo "👤 Dev Credentials:      alice / alice-pass (auditor), bob / bob-pass (employee)"
echo "🔑 Secrets & Tokens:     data/secrets.json"
echo "🚫 Press Ctrl+C to terminate all services."
echo "=========================================================="

# Wait for all background jobs to finish
wait
