/**
 * @file seed.js
 * Seed step for Attestation Verifier.
 * Seeds initial inventory records for alice-laptop (and bob-laptop if provisioned),
 * and writes plaintext enrolment codes to data/dev-enrolment-codes.json (dev only).
 */

import fs from "node:fs";
import path from "node:path";
import { loadConfig } from "../config.js";
import { createStore } from "../store.js";
import { devIdOf } from "../sim-tpm/public-area.js";
import { addToInventory } from "./inventory.js";

/**
 * Seeds the verifier inventory.
 *
 * @param {Record<string, any>} [cfg]
 * @returns {Promise<Record<string, string>>} Map of device names/ids to enrolment codes
 */
export async function seed(cfg = {}) {
  const effectiveCfg = cfg?.dataDir ? cfg : loadConfig(cfg);
  const dataDir = path.resolve(effectiveCfg.dataDir || effectiveCfg.ZTA_DATA_DIR || "./data");
  const agentDir = path.join(dataDir, "agent");
  const store = effectiveCfg.storeInstance || createStore("verifier", effectiveCfg);

  const codes = {};

  // 1. Ensure alice-laptop TPM exists; read its EK from tpm.json
  const aliceTpmFile = path.join(agentDir, "alice-laptop", "tpm.json");
  if (!fs.existsSync(aliceTpmFile)) {
    try {
      const { seed: seedSimTpm } = await import("../sim-tpm/seed.js");
      await seedSimTpm(effectiveCfg);
    } catch (err) {
      console.warn("⚠️ [seed-verifier] Could not auto-run SimTPM seed:", err.message);
    }
  }

  if (fs.existsSync(aliceTpmFile)) {
    try {
      const aliceData = JSON.parse(fs.readFileSync(aliceTpmFile, "utf8"));
      const aliceEkPub = aliceData.ek?.publicArea;
      if (aliceEkPub) {
        const aliceDevId = await devIdOf(aliceEkPub);
        const aliceInv = await addToInventory(store, {
          devId: aliceDevId,
          user: "alice",
          ttlMs: 365 * 24 * 3600 * 1000,
          clock: effectiveCfg.clock,
        });

        codes["alice-laptop"] = aliceInv.code;
        codes[aliceDevId] = aliceInv.code;
        console.log(`📋 [seed-verifier] Seeded alice-laptop (${aliceDevId}) for alice`);
      }
    } catch (err) {
      console.warn("⚠️ [seed-verifier] Error reading alice-laptop tpm.json:", err.message);
    }
  }

  // 2. Seed bob-laptop for bob if provisioned
  const bobTpmFile = path.join(agentDir, "bob-laptop", "tpm.json");
  if (fs.existsSync(bobTpmFile)) {
    try {
      const bobData = JSON.parse(fs.readFileSync(bobTpmFile, "utf8"));
      const bobEkPub = bobData.ek?.publicArea;
      if (bobEkPub) {
        const bobDevId = await devIdOf(bobEkPub);
        const bobInv = await addToInventory(store, {
          devId: bobDevId,
          user: "bob",
          ttlMs: 365 * 24 * 3600 * 1000,
          clock: effectiveCfg.clock,
        });

        codes["bob-laptop"] = bobInv.code;
        codes[bobDevId] = bobInv.code;
        console.log(`📋 [seed-verifier] Seeded bob-laptop (${bobDevId}) for bob`);
      }
    } catch (err) {
      console.warn("⚠️ [seed-verifier] Could not seed bob-laptop:", err.message);
    }
  }

  // 3. Write codes to data/dev-enrolment-codes.json
  const codesFile = path.join(dataDir, "dev-enrolment-codes.json");
  console.warn("⚠️ [seed-verifier] Writing dev enrolment codes to data/dev-enrolment-codes.json (dev only)");
  fs.writeFileSync(codesFile, JSON.stringify(codes, null, 2), {
    encoding: "utf8",
    mode: 0o600,
  });
  try {
    fs.chmodSync(codesFile, 0o600);
  } catch {
    // Ignore on non-POSIX
  }

  return codes;
}

export default seed;
