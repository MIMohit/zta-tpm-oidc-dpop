/**
 * @file scripts/attacks/run-live-demo.mjs
 * Orchestrates live mode acceptance check against ./start-zta.sh for Full and an ablation config.
 */

import { spawn } from "node:child_process";
import process from "node:process";

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForHealth(expectedLabel, maxAttempts = 30) {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const res = await fetch("http://localhost:4001/health");
      if (res.ok) {
        const data = await res.json();
        if (data.ablation?.label === expectedLabel) {
          return true;
        }
      }
    } catch {}
    await sleep(500);
  }
  throw new Error(`Timeout waiting for live services with ablation label: ${expectedLabel}`);
}

async function runCommand(cmd, args) {
  return new Promise((resolve, reject) => {
    console.log(`\n▶ Running: ${cmd} ${args.join(" ")}`);
    const proc = spawn(cmd, args, { stdio: "inherit" });
    proc.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${cmd} exited with code ${code}`));
    });
    proc.on("error", reject);
  });
}

async function stopZta(ztaProc) {
  if (!ztaProc || ztaProc.killed) return;
  console.log("🛑 Stopping ./start-zta.sh and child services...");
  ztaProc.kill("SIGTERM");
  // Give trap time to execute kill $(jobs -p)
  await sleep(1500);
  if (!ztaProc.killed) {
    try {
      process.kill(-ztaProc.pid, "SIGTERM");
    } catch {}
  }
  await sleep(1000);
}

async function main() {
  console.log("================================================================================");
  console.log("🚀 LIVE MODE ACCEPTANCE TEST RUNNER");
  console.log("================================================================================");

  // 1. Live mode under FULL
  console.log("\n[1/2] Starting ZTA stack under FULL configuration...");
  const fullProc = spawn("./start-zta.sh", [], {
    detached: true,
    env: { ...process.env, TPM_BACKEND: "sim" },
    stdio: "ignore",
  });

  try {
    await waitForHealth("full");
    console.log("✅ Services healthy and reporting ablation label 'full'");
    await runCommand("node", [
      "scripts/attacks/run.mjs",
      "--mode",
      "live",
      "--config",
      "full",
      "--attacks",
      "A16,A17,A18,A24",
      "--out",
      "/tmp/live-full-run",
    ]);
    console.log("✅ Live mode tests under FULL succeeded!");
  } finally {
    await stopZta(fullProc);
  }

  // 2. Live mode under -M16 ablation
  console.log("\n[2/2] Starting ZTA stack under -M16 ablation configuration...");
  const ablateProc = spawn("./start-zta.sh", [], {
    detached: true,
    env: { ...process.env, TPM_BACKEND: "sim", ZTA_ABLATE: "M16" },
    stdio: "ignore",
  });

  try {
    await waitForHealth("-M16");
    console.log("✅ Services healthy and reporting ablation label '-M16'");
    await runCommand("node", [
      "scripts/attacks/run.mjs",
      "--mode",
      "live",
      "--config",
      "-M16",
      "--attacks",
      "A17",
      "--out",
      "/tmp/live-m16-run",
    ]);
    console.log("✅ Live mode tests under -M16 ablation succeeded!");
  } finally {
    await stopZta(ablateProc);
  }

  console.log("\n================================================================================");
  console.log("🎉 ALL LIVE MODE ACCEPTANCE CHECKS PASSED!");
  console.log("================================================================================");
}

main().catch(async (err) => {
  console.error("❌ Live mode runner failed:", err);
  process.exit(1);
});
