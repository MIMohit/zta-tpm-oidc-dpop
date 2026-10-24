import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { isMain } from "../lib/main.js";
import { loadConfig } from "../lib/config.js";

/**
 * Seed steps to be populated by subsequent work packages.
 */
export const steps = [
  { name: "SimTPM", module: "../lib/sim-tpm/seed.js" },
  { name: "Verifier", module: "../lib/verifier/seed.js" },
  { name: "IdP", module: "../lib/idp/seed.js" },
];

/**
 * Runs the development environment seed process.
 * Creates data/secrets.json if missing, and executes any available seed steps.
 * If backend is 'tpm', also seeds the real TPM EK in inventory.
 * @param {Record<string, any>} [cfg]
 * @returns {Promise<Record<string, string>>}
 */
export async function runSeeds(cfg) {
  const effectiveCfg = cfg?.dataDir ? cfg : loadConfig(cfg);
  const dataDir = path.resolve(effectiveCfg.dataDir || "./data");
  fs.mkdirSync(dataDir, { recursive: true });

  const secretsPath = path.join(dataDir, "secrets.json");
  let secrets = {};
  if (fs.existsSync(secretsPath)) {
    try {
      secrets = JSON.parse(fs.readFileSync(secretsPath, "utf8"));
    } catch (err) {
      console.warn("⚠️ [seed] Could not parse existing secrets.json, regenerating:", err.message);
    }
  }

  let modified = false;
  if (!secrets.ZTA_INTERNAL_TOKEN) {
    secrets.ZTA_INTERNAL_TOKEN = crypto.randomBytes(32).toString("hex");
    modified = true;
  }
  if (!secrets.ADMIN_TOKEN) {
    secrets.ADMIN_TOKEN = crypto.randomBytes(32).toString("hex");
    modified = true;
  }
  if (!secrets.SESSION_SECRET) {
    secrets.SESSION_SECRET = crypto.randomBytes(32).toString("hex");
    modified = true;
  }

  if (modified || !fs.existsSync(secretsPath)) {
    fs.writeFileSync(secretsPath, JSON.stringify(secrets, null, 2), {
      encoding: "utf8",
      mode: 0o600,
    });
    try {
      fs.chmodSync(secretsPath, 0o600);
    } catch {
      // Ignore mode failures on unsupported filesystems
    }
    console.log("🔑 [seed] Initialized secrets in", secretsPath);
  } else {
    console.log("🔑 [seed] Secrets already exist in", secretsPath);
  }

  // Run registered seed steps with guarded dynamic imports
  for (const step of steps) {
    try {
      const mod = await import(step.module);
      const seedFn = mod.seed || mod.default;
      if (typeof seedFn === "function") {
        console.log(`🌱 [seed] Running ${step.name} seed step...`);
        await seedFn(effectiveCfg);
      } else {
        console.log(`ℹ️ [seed] Step ${step.name} loaded but has no executable seed function`);
      }
    } catch (err) {
      if (err.code === "ERR_MODULE_NOT_FOUND" || err.message?.includes("Cannot find module")) {
        console.log(`ℹ️ [seed] Skipping ${step.name} (module not present yet)`);
      } else {
        console.warn(`⚠️ [seed] Error running step ${step.name}:`, err.message);
      }
    }
  }

  // If TPM_BACKEND=tpm, seed real TPM device in inventory if reachable
  const backend = (effectiveCfg.tpmBackend || process.env.TPM_BACKEND || "sim").toLowerCase();
  if (backend === "tpm") {
    try {
      const { tpmReachable, RealTpm } = await import("../lib/tpm-real/index.js");
      if (await tpmReachable({
        host: effectiveCfg.tpmTcpHost || process.env.TPM_TCP_HOST || "127.0.0.1",
        port: +(effectiveCfg.tpmTcpPort || process.env.TPM_TCP_PORT || 2321),
      })) {
        const { devIdOf } = await import("../lib/sim-tpm/public-area.js");
        const { addToInventory } = await import("../lib/verifier/inventory.js");
        const { createStore } = await import("../lib/store.js");
        const store = effectiveCfg.storeInstance || createStore("verifier", effectiveCfg);
        const { realTpmOptions } = await import("../lib/tpm-factory.js");
        const tpm = new RealTpm(realTpmOptions(effectiveCfg, path.join(dataDir, "agent", "alice-laptop")));
        await tpm.open();
        let ek;
        try {
          ek = await tpm.getEk();
        } finally {
          await tpm.close();
        }
        const devId = await devIdOf(ek.publicArea);
        const res = await addToInventory(store, {
          devId,
          user: "alice",
          ttlMs: 365 * 24 * 3600 * 1000,
          clock: effectiveCfg.clock,
        });

        const codesFile = path.join(dataDir, "dev-enrolment-codes.json");
        if (fs.existsSync(codesFile)) {
          const codes = JSON.parse(fs.readFileSync(codesFile, "utf8"));
          codes[devId] = res.code;
          // Separate key: the SimTPM "alice-laptop" code stays valid for TPM_BACKEND=sim
          codes["alice-laptop-tpm"] = res.code;
          fs.writeFileSync(codesFile, JSON.stringify(codes, null, 2), { mode: 0o600 });
        }
        console.log(`📋 [seed-real-tpm] Seeded real TPM device (${devId}) for alice`);
      }
    } catch (err) {
      console.warn("⚠️ [seed-real-tpm] Could not seed real TPM device:", err.message);
    }
  }

  console.log("✅ [seed] Seed process complete.");
  return secrets;
}

if (isMain(import.meta.url)) {
  const args = process.argv.slice(2);
  let backend = null;
  for (let i = 0; i < args.length; i++) {
    if ((args[i] === "--backend" || args[i] === "-b") && i + 1 < args.length) {
      backend = args[++i];
    } else if (args[i].startsWith("--backend=")) {
      backend = args[i].slice(10);
    }
  }
  const overrides = backend ? { tpmBackend: backend } : {};
  runSeeds(overrides).catch((err) => {
    console.error("❌ [seed] Fatal error:", err);
    process.exit(1);
  });
}

export default {
  steps,
  runSeeds,
};
