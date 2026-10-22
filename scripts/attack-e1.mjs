#!/usr/bin/env node
/**
 * @file scripts/attack-e1.mjs
 * Backward compatibility shim for E1 security evaluation attack script.
 * Maps legacy flags to v2 framework:
 *   --ablate cnf   -> config "-M16"
 *   --ablate nonce -> config "-M17"
 *   --base <url>   -> live mode
 *
 * Runs the E1.x-equivalent subset:
 *   [A17, A16, A18, A19, A20, A13, A21, A24]
 * Writes data/results/e1.csv (same columns) + JSONL.
 * Exit codes unchanged: 0 if all rejected, 1 if any accepted.
 */

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import crypto from "node:crypto";

import { getAttack } from "./attacks/index.mjs";
import { createContext } from "./attacks/lib/context.mjs";
import { normaliseResult, appendJsonlRow } from "./attacks/lib/result.mjs";
import { expectedOutcome } from "./attacks/lib/expected.mjs";
import { parseConfigLabel, runManifest } from "../lib/ablation.js";

// Parse CLI flags
const args = process.argv.slice(2);
let mode = "inproc";
let baseUrl = null;
let ablateCnf = false;
let ablateNonce = false;

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === "--inproc") {
    mode = "inproc";
  } else if (arg === "--base" && args[i + 1]) {
    baseUrl = args[++i];
    mode = "live";
  } else if (arg.startsWith("--base=")) {
    baseUrl = arg.split("=")[1];
    mode = "live";
  } else if (arg === "--ablate" && args[i + 1]) {
    const val = args[++i].toLowerCase();
    if (val === "cnf") ablateCnf = true;
    if (val === "nonce") ablateNonce = true;
  } else if (arg === "--ablate=cnf" || arg === "--ablate-cnf") {
    ablateCnf = true;
  } else if (arg === "--ablate=nonce" || arg === "--ablate-nonce") {
    ablateNonce = true;
  }
}

// Map ablation flags to config label
let configLabel = "full";
if (ablateCnf && ablateNonce) {
  configLabel = "-M16,-M17";
} else if (ablateCnf) {
  configLabel = "-M16";
} else if (ablateNonce) {
  configLabel = "-M17";
}

// Subset of attacks equivalent to E1.x
const E1_SUBSET = [
  { id: "E1.1", attackId: "A17", title: "Stolen AT + attacker DPoP key" },
  { id: "E1.2a", attackId: "A18", title: "DPoP proof with missing/stale nonce" },
  { id: "E1.2b", attackId: "A19", title: "Replayed DPoP proof (same jti / stale nonce)" },
  { id: "E1.3", attackId: "A20", title: "Proof reused for another URI or method" },
  { id: "E1.4", attackId: "A13", title: "Stolen password without enrolled device" },
  { id: "E1.8", attackId: "A21", title: "Continued use & token refresh after revocation" },
  { id: "extra-1", attackId: "A16", title: "Bearer downgrade attempt at PEP" },
  { id: "extra-2", attackId: "A24", title: "Direct call to resource server bypassing PEP" },
];

async function main() {
  console.log("================================================================================");
  console.log("🛡️  RUNNING ZTA SECURITY EVALUATION (E1.x COMPATIBILITY SHIM)  🛡️");
  console.log(`Mode: ${mode === "inproc" ? "In-process harness (port 0)" : `External stack (${baseUrl})`}`);
  console.log(`Mapped configuration: ${configLabel}`);
  if (ablateCnf) console.log("⚠️  Ablation active: CNF check disabled (-M16)");
  if (ablateNonce) console.log("⚠️  Ablation active: Nonce validation disabled (-M17)");
  console.log("================================================================================\n");

  const results = [];
  const runId = `run_shim_${crypto.randomUUID().slice(0, 8)}`;
  const manifest = runManifest({ runId, mode });

  const resultsDir = path.resolve("./data/results");
  fs.mkdirSync(resultsDir, { recursive: true });
  const csvPath = path.join(resultsDir, "e1.csv");
  const jsonlPath = path.join(resultsDir, "e1.jsonl");

  const parsedCfg = parseConfigLabel(configLabel);

  for (const item of E1_SUBSET) {
    const attackDef = getAttack(item.attackId);
    if (!attackDef) {
      throw new Error(`Attack ${item.attackId} not found in registry`);
    }

    const mod = attackDef.module;
    let ctx = null;
    let outcome = "error";
    let stoppedAt = null;

    try {
      ctx = await createContext({ mode, config: configLabel });
      const res = await mod.run(ctx, { variant: null });
      outcome = res.outcome;
      stoppedAt = res.stoppedAt;
    } catch (err) {
      outcome = "error";
      stoppedAt = { service: null, status: null, reason: err.message };
    } finally {
      if (ctx && typeof ctx.cleanup === "function") {
        await ctx.cleanup().catch(() => {});
      }
    }

    const isAccepted = outcome === "accepted";
    const expected = expectedOutcome(item.attackId, configLabel);
    const rejectedBy = isAccepted ? "none (ablated)" : stoppedAt?.reason || "rejected";

    results.push({
      id: item.id,
      attackId: item.attackId,
      attack: item.title,
      expected,
      observed: outcome,
      rejectedBy,
    });

    const jsonlRow = normaliseResult({
      runId,
      mode,
      config: configLabel,
      baseline: parsedCfg.baseline,
      mechanismsOff: parsedCfg.off,
      attack: item.attackId,
      variant: null,
      rep: 1,
      goal: attackDef.goal,
      adversary: attackDef.adversary,
      expected: attackDef.expected,
      predicted: expected,
      outcome,
      stoppedAt,
      durationMs: 0,
      manifestHash: manifest.hash,
    });
    appendJsonlRow(jsonlPath, jsonlRow);
  }

  // Output Table
  console.log("\n==========================================================================================================");
  console.log(
    `| ${"ID".padEnd(8)} | ${"Attack".padEnd(52)} | ${"Expected".padEnd(10)} | ${"Observed".padEnd(10)} | ${"Rejected by".padEnd(38)} |`
  );
  console.log("----------------------------------------------------------------------------------------------------------");

  for (const r of results) {
    const statusIcon = r.observed === r.expected ? "✅" : "❌";
    console.log(
      `| ${r.id.padEnd(8)} | ${r.attack.padEnd(52)} | ${r.expected.padEnd(10)} | ${(r.observed + " " + statusIcon).padEnd(10)} | ${r.rejectedBy.slice(0, 38).padEnd(38)} |`
    );
  }
  console.log("==========================================================================================================\n");

  // Write CSV
  const csvRows = [
    "ID,Attack,Expected,Observed,Rejected By",
    ...results.map(
      (r) =>
        `"${r.id}","${r.attack.replace(/"/g, '""')}","${r.expected}","${r.observed}","${r.rejectedBy.replace(/"/g, '""')}"`
    ),
  ];
  fs.writeFileSync(csvPath, csvRows.join("\n") + "\n", "utf8");
  console.log(`📊 Results exported to: ${csvPath}`);
  console.log(`📄 JSONL exported to: ${jsonlPath}`);

  // Exit code: 0 if all rejected, 1 if any accepted
  const acceptedAttacks = results.filter((r) => r.observed === "accepted");
  if (acceptedAttacks.length > 0) {
    console.log(`⚠️  ${acceptedAttacks.length} attack(s) ACCEPTED: ${acceptedAttacks.map((a) => a.id).join(", ")}`);
    process.exit(1);
  } else {
    console.log("🎉 All attacks successfully REJECTED. Security posture verified!");
    process.exit(0);
  }
}

main().catch((err) => {
  console.error("❌ Fatal error in attack-e1 shim:", err);
  process.exit(1);
});
