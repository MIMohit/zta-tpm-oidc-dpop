#!/usr/bin/env node
/**
 * @file scripts/inventory-add.js
 * CLI tool to add a device to the inventory and generate a one-time enrolment code.
 *
 * Usage:
 *   node scripts/inventory-add.js --devId <devId> --user <username> [--code <code>]
 *   node scripts/inventory-add.js --backend tpm [--agent alice-laptop] [--golden-pcr <hex> | --capture-golden-pcr] [--ek-pub]
 *   node scripts/inventory-add.js --dir <agentDir> --user <username>
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { isMain } from "../lib/main.js";
import { loadConfig } from "../lib/config.js";
import { createStore } from "../lib/store.js";
import { SimTpm } from "../lib/sim-tpm/tpm.js";
import { devIdOf } from "../lib/sim-tpm/public-area.js";
import { addToInventory } from "../lib/verifier/inventory.js";
import { realTpmOptions } from "../lib/tpm-factory.js";

/**
 * Parses command-line arguments.
 * @param {string[]} args
 * @returns {Record<string, any>}
 */
export function parseArgs(args = process.argv.slice(2)) {
  const options = {
    devId: null,
    dir: null,
    agent: null,
    backend: process.env.TPM_BACKEND || "sim",
    user: null,
    code: null,
    ttlHours: 720, // 30 days default
    goldenPcr: null,
    goldenPcrs: null,
    ekPub: false,
    ekTrust: null,
    captureGoldenPcr: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if ((arg === "--devId" || arg === "--dev" || arg === "-d") && i + 1 < args.length) {
      options.devId = args[++i];
    } else if (arg.startsWith("--devId=")) {
      options.devId = arg.slice(8);
    } else if (arg.startsWith("--dev=")) {
      options.devId = arg.slice(6);
    } else if (arg === "--dir" && i + 1 < args.length) {
      options.dir = args[++i];
    } else if (arg.startsWith("--dir=")) {
      options.dir = arg.slice(6);
    } else if (arg === "--agent" && i + 1 < args.length) {
      options.agent = args[++i];
    } else if (arg.startsWith("--agent=")) {
      options.agent = arg.slice(8);
    } else if ((arg === "--backend" || arg === "-b") && i + 1 < args.length) {
      options.backend = args[++i];
    } else if (arg.startsWith("--backend=")) {
      options.backend = arg.slice(10);
    } else if ((arg === "--user" || arg === "-u") && i + 1 < args.length) {
      options.user = args[++i];
    } else if (arg.startsWith("--user=")) {
      options.user = arg.slice(7);
    } else if ((arg === "--code" || arg === "-c") && i + 1 < args.length) {
      options.code = args[++i];
    } else if (arg.startsWith("--code=")) {
      options.code = arg.slice(7);
    } else if (arg === "--ttl" && i + 1 < args.length) {
      options.ttlHours = Number(args[++i]);
    } else if (arg === "--golden-pcr" && i + 1 < args.length) {
      options.goldenPcr = args[++i];
    } else if (arg.startsWith("--golden-pcr=")) {
      options.goldenPcr = arg.slice(13);
    } else if (arg === "--golden-pcrs" && i + 1 < args.length) {
      options.goldenPcrs = args[++i].split(",").map((s) => s.trim());
    } else if (arg === "--capture-golden-pcr") {
      options.captureGoldenPcr = true;
    } else if (arg === "--ek-pub") {
      options.ekPub = true;
    } else if (arg === "--ek-trust" && i + 1 < args.length) {
      options.ekTrust = args[++i];
    }
  }

  return options;
}

/**
 * Reads SHA-256 PCR0..7 from an open RealTpm and returns their digest (hex).
 * @param {import("../lib/tpm-real/backend.js").RealTpm} tpm
 */
async function readPcrDigest(tpm) {
  const { default: tss } = await import("tss.js");
  const sel = [new tss.TPMS_PCR_SELECTION(tss.TPM_ALG_ID.SHA256, Buffer.from([0xff, 0, 0]))];
  const pr = await tpm.conn.call("PCR_Read", sel);
  const pcrs = (pr.pcrValues || []).map((d) => Buffer.from(d.buffer));
  if (pcrs.length !== 8) throw new Error(`PCR_Read returned ${pcrs.length} PCRs, expected 8`);
  return crypto.createHash("sha256").update(Buffer.concat(pcrs)).digest("hex");
}

/**
 * Adds device to inventory.
 * @param {Record<string, any>} options
 * @param {Record<string, any>} [cfg]
 * @returns {Promise<{ devId: string, user: string, code: string, codeExp: number }>}
 */
export async function inventoryAdd(options, cfg = loadConfig()) {
  let devId = options.devId;
  const backend = (options.backend || cfg.tpmBackend || "sim").toLowerCase();
  let ekPublic = null;
  let ekTrust = options.ekTrust || null;

  // Resolve devId from Real TPM
  if (backend === "tpm" && !devId) {
    const { RealTpm } = await import("../lib/tpm-real/index.js");
    const agentDir = options.dir
      ? path.resolve(options.dir)
      : options.agent
      ? path.resolve(cfg.dataDir || "./data", "agent", options.agent)
      : undefined;

    const tpm = new RealTpm(realTpmOptions(cfg, agentDir || path.resolve(cfg.dataDir || "./data", "agent", "alice-laptop")));

    await tpm.open();
    let ekPub;
    try {
      ({ publicArea: ekPub } = await tpm.getEk());
      if (options.captureGoldenPcr && !options.goldenPcr && !options.goldenPcrs) {
        // Golden PCR capture: SHA-256 over PCR0..7 as currently measured (== quote pcrDigest)
        options.goldenPcr = await readPcrDigest(tpm);
        console.log(`🛡️ Captured golden PCR digest (PCR0..7): ${options.goldenPcr}`);
      }
    } finally {
      await tpm.close();
    }
    devId = await devIdOf(ekPub);

    if (options.ekPub || options.ekTrust === "pinned") {
      ekPublic = ekPub;
      ekTrust = "pinned";
    }
  }

  // Resolve devId from SimTPM
  if (!devId && options.dir) {
    const resolvedDir = path.resolve(options.dir);
    const tpm = new SimTpm({ dir: resolvedDir });
    await tpm.init();
    const { publicArea: ekPub } = await tpm.getEk();
    devId = await devIdOf(ekPub);
  } else if (!devId && options.agent && backend !== "tpm") {
    const resolvedDir = path.resolve(cfg.dataDir || "./data", "agent", options.agent);
    const tpm = new SimTpm({ dir: resolvedDir });
    await tpm.init();
    const { publicArea: ekPub } = await tpm.getEk();
    devId = await devIdOf(ekPub);
  }

  if (!devId) {
    throw new Error("Must provide either --devId <id>, --backend tpm, or --dir/--agent <agentDirectory>");
  }

  let user = options.user;
  if (!user && options.agent) {
    user = options.agent.replace(/-.*$/, "");
  }
  if (!user) {
    user = "alice"; // Default to primary user if unspecified
  }

  const store = cfg.storeInstance || createStore("verifier", cfg);
  const ttlMs = (options.ttlHours || 720) * 3600 * 1000;

  const goldenPcrDigests = options.goldenPcrs
    ? options.goldenPcrs
    : options.goldenPcr
    ? [options.goldenPcr]
    : undefined;

  const result = await addToInventory(store, {
    devId,
    user,
    code: options.code,
    ttlMs,
    goldenPcrDigests,
    ekTrust,
    ekPublic,
    clock: cfg.clock,
  });

  // Update data/dev-enrolment-codes.json in dev mode
  try {
    const dataDir = path.resolve(cfg.dataDir || "./data");
    const codesFile = path.join(dataDir, "dev-enrolment-codes.json");
    let codes = {};
    if (fs.existsSync(codesFile)) {
      codes = JSON.parse(fs.readFileSync(codesFile, "utf8"));
    }
    codes[devId] = result.code;
    if (backend === "tpm") {
      // Real-TPM codes live under "<agent>-tpm" so the SimTPM "<agent>" code stays valid
      codes[`${options.agent || "alice-laptop"}-tpm`] = result.code;
    } else if (options.agent) {
      codes[options.agent] = result.code;
    }
    fs.writeFileSync(codesFile, JSON.stringify(codes, null, 2), { mode: 0o600 });
  } catch {}

  return result;
}

if (isMain(import.meta.url)) {
  const args = parseArgs();
  inventoryAdd(args)
    .then((res) => {
      console.log(`✅ Device ${res.devId} added to inventory for user "${res.user}"`);
      console.log(`🔑 One-time enrolment code: ${res.code}`);
      console.log(`⏰ Expires at: ${new Date(res.codeExp).toISOString()}`);
      if (res.goldenPcrDigests) {
        console.log(`🛡️ Golden PCR digests: ${res.goldenPcrDigests.join(", ")}`);
      }
      if (res.ekTrust) {
        console.log(`🔒 EK Trust: ${res.ekTrust}`);
      }
    })
    .catch((err) => {
      console.error("❌ Inventory add failed:", err.message);
      process.exit(1);
    });
}

export default {
  parseArgs,
  inventoryAdd,
};
