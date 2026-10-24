#!/usr/bin/env node
/**
 * @file scripts/attacks/run.mjs
 * CLI runner for the ZTA v2 attack evaluation suite.
 *
 * Usage:
 *   node scripts/attacks/run.mjs [--attacks all|A10,A17] [--config full|-M16|B1|all]
 *                               [--reps 1] [--mode inproc|live] [--tpm sim|swtpm] [--orchestrate] [--idp keycloak|local] [--testbed path]
 *                               [--out results/e1/<runId>/] [--seed <str>]
 */

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import crypto from "node:crypto";

import { ATTACKS, getAttack } from "./index.mjs";
import { createContext } from "./lib/context.mjs";
import { killAllSwtpm } from "./lib/swtpm-fleet.mjs";
import { normaliseResult, appendJsonlRow, infrastructureFailure } from "./lib/result.mjs";
import { expectedOutcome, expectedVariantOutcome } from "./lib/expected.mjs";
import { configManifest, writeJson } from "./lib/manifest.mjs";
import { allConfigs, parseConfigLabel, runManifest, writeRunManifest, configureAblation, state } from "../../lib/ablation.js";

/** Rejects after ms, so one hung trial (e.g. a stuck TPM) cannot stall the whole run. */
function withTimeout(promise, ms, what) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${what} timed out after ${ms} ms`)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

const TRIAL_TIMEOUT_MS = Number(process.env.ZTA_TRIAL_TIMEOUT_MS || 120000);

// Parse command line arguments
const args = process.argv.slice(2);
let attacksArg = "all";
let configArg = "full";
let repsArg = 1;
let modeArg = "inproc";
let tpmArg = "sim";
let orchestrateArg = false;
let idpArg = "keycloak";
let testbedArg = null;
let outArg = null;
let seedArg = null;

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === "--attacks" && args[i + 1]) {
    attacksArg = args[++i];
  } else if (arg.startsWith("--attacks=")) {
    attacksArg = arg.split("=")[1];
  } else if (arg === "--config" && args[i + 1]) {
    configArg = args[++i];
  } else if (arg.startsWith("--config=")) {
    configArg = arg.split("=")[1];
  } else if (arg === "--reps" && args[i + 1]) {
    repsArg = parseInt(args[++i], 10);
  } else if (arg.startsWith("--reps=")) {
    repsArg = parseInt(arg.split("=")[1], 10);
  } else if (arg === "--mode" && args[i + 1]) {
    modeArg = args[++i];
  } else if (arg.startsWith("--mode=")) {
    modeArg = arg.split("=")[1];
  } else if (arg === "--orchestrate") {
    orchestrateArg = true;
  } else if (arg === "--idp" && args[i + 1]) {
    idpArg = args[++i];
  } else if (arg === "--tpm" && args[i + 1]) {
    tpmArg = args[++i];
  } else if (arg.startsWith("--tpm=")) {
    tpmArg = arg.split("=")[1];
  } else if (arg === "--testbed" && args[i + 1]) {
    testbedArg = args[++i];
  } else if (arg.startsWith("--testbed=")) {
    testbedArg = arg.split("=")[1];
  } else if (arg === "--out" && args[i + 1]) {
    outArg = args[++i];
  } else if (arg.startsWith("--out=")) {
    outArg = arg.split("=")[1];
  } else if (arg === "--seed" && args[i + 1]) {
    seedArg = args[++i];
  } else if (arg.startsWith("--seed=")) {
    seedArg = arg.split("=")[1];
  }
}

async function main() {
  const runId = seedArg ? `run_${seedArg}` : `run_${crypto.randomUUID().slice(0, 8)}`;
  const outDir = outArg ? path.resolve(outArg) : path.resolve(`./results/e1/${runId}`);
  fs.mkdirSync(outDir, { recursive: true });
  const jsonlPath = path.join(outDir, "attacks.jsonl");

  // Determine attack selection
  let selectedAttacks = [];
  if (attacksArg.toLowerCase() === "all") {
    selectedAttacks = [...ATTACKS];
  } else {
    const ids = attacksArg.split(",").map((s) => s.trim().toUpperCase());
    for (const id of ids) {
      const a = getAttack(id);
      if (!a) {
        console.error(`❌ Unknown attack ID: ${id}`);
        process.exit(3);
      }
      selectedAttacks.push(a);
    }
  }

  // Determine config selection
  let selectedConfigs = [];
  if (configArg.toLowerCase() === "all") {
    selectedConfigs = allConfigs(); // 33 configurations
  } else {
    selectedConfigs = configArg.split(",").map((s) => s.trim());
  }

  console.log("================================================================================");
  console.log(`🛡️  ZTA ATTACK EVALUATION SUITE v2  🛡️   [${runId}]`);
  console.log(`Mode: ${modeArg} | Reps: ${repsArg} | Configs: ${selectedConfigs.length} | Attacks: ${selectedAttacks.length}`);
  console.log(`Output: ${outDir}`);
  console.log("================================================================================");

  const manifest = runManifest({ runId, mode: modeArg, tpm: tpmArg, ...(modeArg === "live" ? { idp: idpArg, orchestrated: orchestrateArg } : {}) });
  const manifestsDir = path.join(outDir, "manifests");
  fs.mkdirSync(manifestsDir, { recursive: true });
  const configManifests = new Map();

  const allRows = [];
  let totalErrors = 0;
  let fullAcceptedCount = 0;

  for (const cfgLabel of selectedConfigs) {
    const parsedCfg = parseConfigLabel(cfgLabel);
    let ablationInfo = null;
    if (modeArg === "inproc") {
      configureAblation(parsedCfg);
      const st = state();
      ablationInfo = {
        label: st.label,
        baseline: st.baseline ?? null,
        off: [...st.off],
        hash: st.hash,
      };
    } else {
      ablationInfo = {
        label: cfgLabel,
        baseline: parsedCfg.baseline ?? null,
        off: [...parsedCfg.off],
        hash: crypto.createHash("sha256").update(JSON.stringify(parsedCfg.off)).digest("hex").slice(0, 12),
      };
    }
    const cfgManifest = configManifest({ runId, mode: modeArg, tpm: tpmArg, config: cfgLabel, ablation: ablationInfo });
    writeJson(path.join(manifestsDir, `${cfgLabel}.json`), cfgManifest);
    configManifests.set(cfgLabel, cfgManifest);

    for (let rep = 1; rep <= repsArg; rep++) {
      for (const attack of selectedAttacks) {
        const mod = attack.module;
        const variants = Array.isArray(mod.variants) && mod.variants.length > 0 ? mod.variants : [null];

        for (const variant of variants) {
          const varLabel = variant ? `:${variant}` : "";
          const testLabel = `${attack.id}${varLabel} [${cfgLabel} rep ${rep}/${repsArg}]`;

          // Check applicability
          const appCheck = typeof mod.applicable === "function" ? mod.applicable(parsedCfg, modeArg, { tpm: tpmArg, variant }) : true;
          if (appCheck !== true) {
            const reason = typeof appCheck === "string" ? appCheck : "not applicable";
            const row = normaliseResult({
              runId,
              mode: modeArg,
              tpm: tpmArg,
              config: cfgLabel,
              baseline: cfgManifest.baseline,
              mechanismsOff: cfgManifest.off,
              ablation: {
                label: cfgManifest.label,
                baseline: cfgManifest.baseline,
                off: cfgManifest.off,
                hash: cfgManifest.hash,
              },
              attack: attack.id,
              variant,
              rep,
              goal: attack.goal,
              adversary: attack.adversary,
              expected: attack.expected,
              predicted: "n/a",
              outcome: "n/a",
              stoppedAt: { service: null, status: null, reason },
              durationMs: 0,
              codeHash: cfgManifest.code?.sha256 ?? null,
              manifestHash: cfgManifest.manifestHash,
            });

            appendJsonlRow(jsonlPath, row);
            allRows.push(row);
            console.log(`  ⚪ ${testLabel.padEnd(45)} -> n/a (${reason})`);
            continue;
          }

          // In live mode, skip attacks without runLive
          if (modeArg === "live" && typeof mod.runLive !== "function") {
            const row = normaliseResult({
              runId,
              mode: modeArg,
              tpm: tpmArg,
              config: cfgLabel,
              baseline: cfgManifest.baseline,
              mechanismsOff: cfgManifest.off,
              ablation: {
                label: cfgManifest.label,
                baseline: cfgManifest.baseline,
                off: cfgManifest.off,
                hash: cfgManifest.hash,
              },
              attack: attack.id,
              variant,
              rep,
              goal: attack.goal,
              adversary: attack.adversary,
              expected: attack.expected,
              predicted: variant ? expectedVariantOutcome(attack.id, variant, cfgLabel) : expectedOutcome(attack.id, cfgLabel),
              outcome: "n/a",
              stoppedAt: { service: null, status: null, reason: "live mode not implemented" },
              durationMs: 0,
              codeHash: cfgManifest.code?.sha256 ?? null,
              manifestHash: cfgManifest.manifestHash,
            });
            appendJsonlRow(jsonlPath, row);
            allRows.push(row);
            console.log(`  ⚪ ${testLabel.padEnd(45)} -> n/a (live mode not implemented)`);
            continue;
          }

          const startTs = Date.now();
          let ctx = null;
          let outcome = "error";
          let stoppedAt = null;
          let evidence = null;
          let stackInfo = null;

          try {
            const res = await withTimeout(
              (async () => {
                ctx = await createContext({ mode: modeArg, tpm: tpmArg, config: cfgLabel, testbedPath: testbedArg, orchestrate: orchestrateArg, idp: idpArg });
                return await (modeArg === "live" ? mod.runLive(ctx, { variant }) : mod.run(ctx, { variant }));
              })(),
              TRIAL_TIMEOUT_MS,
              "Trial"
            );
            outcome = res.outcome;
            stoppedAt = res.stoppedAt;
            evidence = res.evidence ?? null;
            stackInfo = ctx?.stackInfo ?? null;
            const infra = infrastructureFailure(res);
            if (infra) {
              totalErrors++;
              outcome = "error";
              stoppedAt = { service: res.stoppedAt?.service ?? null, status: null, reason: `infrastructure failure: ${infra}` };
            }
          } catch (err) {
            totalErrors++;
            outcome = "error";
            stoppedAt = { service: null, status: null, reason: err.message };
            if (/timed out/.test(err.message)) {
              const killed = killAllSwtpm();
              if (killed) console.error(`⚠️ Killed ${killed} swtpm process(es) left by the timed-out trial`);
            }
          } finally {
            if (ctx && typeof ctx.cleanup === "function") {
              await withTimeout(ctx.cleanup(), 30000, "Cleanup").catch((err) => console.error(`⚠️ ${err.message}`));
            }
          }

          const durationMs = Date.now() - startTs;
          const predicted = variant ? expectedVariantOutcome(attack.id, variant, cfgLabel) : expectedOutcome(attack.id, cfgLabel);
          const liveAblation = ctx?.ablation ?? {
            label: cfgManifest.label,
            baseline: cfgManifest.baseline,
            off: cfgManifest.off,
            hash: cfgManifest.hash,
          };

          const row = normaliseResult({
            runId,
            mode: modeArg,
            tpm: tpmArg,
            config: cfgLabel,
            baseline: liveAblation.baseline,
            mechanismsOff: liveAblation.off,
            ablation: liveAblation,
            attack: attack.id,
            variant,
            rep,
            goal: attack.goal,
            adversary: attack.adversary,
            expected: attack.expected,
            predicted,
            outcome,
            stoppedAt,
            evidence,
            stack: stackInfo,
            durationMs,
            codeHash: cfgManifest.code?.sha256 ?? null,
            manifestHash: cfgManifest.manifestHash,
          });

          appendJsonlRow(jsonlPath, row);
          allRows.push(row);

          if (cfgLabel === "full" && outcome === "accepted") {
            fullAcceptedCount++;
          }

          const icon = outcome === "rejected" ? "🛡️ [R]" : outcome === "accepted" ? "⚠️ [A]" : outcome === "n/a" ? "⚪ [n/a]" : "❌ [ERR]";
          const reasonStr = stoppedAt?.reason ? `(${stoppedAt.reason})` : "";
          console.log(`  ${icon} ${testLabel.padEnd(45)} -> ${outcome.toUpperCase()} ${reasonStr} [${durationMs}ms]`);
        }
      }
    }
  }

  writeJson(path.join(outDir, "manifest.json"), {
    schema: "zta-run-manifest/1",
    runId,
    mode: modeArg,
    tpm: tpmArg,
    startedAt: manifest.startedAt,
    completedAt: new Date().toISOString(),
    git: manifest.git,
    code: manifest.code,
    node: manifest.node,
    platform: manifest.platform,
    arch: manifest.arch,
    cpus: manifest.cpus,
    env: manifest.env,
    configs: Array.from(configManifests.values()).map((cm) => ({
      config: cm.config,
      label: cm.label,
      baseline: cm.baseline,
      off: cm.off,
      hash: cm.hash,
      manifestHash: cm.manifestHash,
    })),
  });

  console.log("--------------------------------------------------------------------------------");
  console.log(`📊 Total trials: ${allRows.length} | Errors: ${totalErrors} | Full config accepted: ${fullAcceptedCount}`);
  console.log(`📁 Log written to: ${jsonlPath}`);
  console.log("================================================================================\n");

  // Determine exit code
  if (totalErrors > 0) {
    process.exit(3);
  }

  // If Full configuration was evaluated and any attack was accepted, exit 2
  if (selectedConfigs.includes("full") && fullAcceptedCount > 0) {
    console.error(`🚨 Security failure: ${fullAcceptedCount} attack(s) ACCEPTED under full configuration.`);
    process.exit(2);
  }

  process.exit(0);
}

main().catch((err) => {
  console.error("❌ Fatal runner error:", err);
  process.exit(3);
});
