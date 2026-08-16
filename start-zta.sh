#!/bin/bash

# Zero-Trust Architecture (ZTA) Multi-Service Start Script
# Spin up all backend services and coordinate exit gracefully

# Trap Ctrl+C (SIGINT) and exit of script to kill all background processes
trap 'echo "🛑 Stopping all ZTA services..."; kill $(jobs -p) 2>/dev/null; exit' INT TERM EXIT

echo "=========================================================="
echo "🛡️  STARTING ZERO-TRUST ARCHITECTURE DEMO SERVICES  🛡️"
echo "=========================================================="

# 1. Start Policy Information Point (PIP) - Port 4003
echo "🔍 Starting PIP (Port 4003)..."
node pip.js &
sleep 0.5

# 2. Start Policy Decision Point (PDP) - Port 4002
echo "🧠 Starting PDP (Port 4002)..."
node pdp.js &
sleep 0.5

# 3. Start Policy Enforcement Point (PEP) - Port 4001
echo "🛂 Starting PEP (Port 4001)..."
node pep.js &
sleep 0.5

# 4. Start Firebase Device Registry - Port 4004
echo "📘 Starting Firebase Device Registry (Port 4004)..."
node services/device-registry.js &
sleep 0.5

# 5. Start Attestation Service - Port 4005
echo "🧪 Starting Attestation Service (Port 4005)..."
node services/attestation-service.js &
sleep 0.5

# 6. Start Protected Resource Server - Port 5001
echo "📊 Starting Protected Resource Server (Port 5001)..."
node services/resource-server.js &
sleep 0.5

# 7. Start Decision Controller - Port 4000
echo "🎯 Starting Decision Controller (Port 4000)..."
node decision-controller.js &
sleep 0.5

# 8. Start Main Gateway & Web Server - Port 5173
echo "🔑 Starting Web Portal & Auth Gateway (Port 5173)..."
node server.js &

echo ""
echo "✅ All local services successfully spawned in background!"
echo "👉 Web Portal: http://localhost:5173"
echo "🚫 Press Ctrl+C to terminate all services."
echo "=========================================================="

# Wait for all background jobs to finish
wait
