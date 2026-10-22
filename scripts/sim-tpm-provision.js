#!/usr/bin/env node
/**
 * @file sim-tpm-provision.js
 * CLI script to provision a simulated TPM instance with EK and vendor EK certificate.
 *
 * Usage:
 *   node scripts/sim-tpm-provision.js --dir data/agent/<id> [--ca data/vendor-ca/sim-vendor] [--rogue-ca]
 */

import path from "node:path";
import process from "node:process";
import { isMain } from "../lib/main.js";
import { SimTpm } from "../lib/sim-tpm/tpm.js";
import { createVendorCa } from "../lib/sim-tpm/vendor-ca.js";
import { devIdOf } from "../lib/sim-tpm/public-area.js";

/**
 * Parses command-line arguments.
 * @param {string[]} args
 * @returns {Record<string, any>}
 */
export function parseArgs(args = process.argv.slice(2)) {
  const options = {
    dir: null,
    ca: null,
    rogueCa: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--dir" && i + 1 < args.length) {
      options.dir = args[++i];
    } else if (arg.startsWith("--dir=")) {
      options.dir = arg.slice(6);
    } else if (arg === "--ca" && i + 1 < args.length) {
      options.ca = args[++i];
    } else if (arg.startsWith("--ca=")) {
      options.ca = arg.slice(5);
    } else if (arg === "--rogue-ca") {
      options.rogueCa = true;
    }
  }

  return options;
}

/**
 * Provisions a simulated TPM and its vendor certificate.
 * @param {Record<string, any>} options
 * @returns {Promise<{ devId: string, ek: any, ca: any, agentDir: string }>}
 */
export async function provisionSimTpm(options = {}) {
  const agentDir = path.resolve(options.dir || "./data/agent/alice-laptop");

  let caDir;
  let caName;
  let issuer;

  if (options.rogueCa) {
    caDir = options.ca ? path.resolve(options.ca) : path.resolve("./data/vendor-ca/evil");
    caName = "evil";
    issuer = "Untrusted Evil Vendor CA";
  } else if (options.ca) {
    const resolvedCa = path.resolve(options.ca);
    caDir = path.dirname(resolvedCa);
    caName = path.basename(resolvedCa).replace(/\.pub\.jwk$/, "").replace(/\.jwk$/, "");
    issuer = "SimTPM Vendor CA";
  } else {
    caDir = path.resolve("./data/vendor-ca");
    caName = "sim-vendor";
    issuer = "SimTPM Vendor CA";
  }

  const ca = await createVendorCa(caDir, caName, issuer);
  const clientFile = path.join(agentDir, "client.json");
  if (fs.existsSync(clientFile)) {
    try { fs.unlinkSync(clientFile); } catch {}
  }
  const tpm = new SimTpm({ dir: agentDir, caKey: ca });
  await tpm.init();

  const ek = await tpm.getEk();
  const devId = await devIdOf(ek.publicArea);

  console.log("🛡️ [sim-tpm-provision] Agent dir:", agentDir);
  console.log("🔑 [sim-tpm-provision] EK devId:", devId);
  console.log("🏛️ [sim-tpm-provision] Vendor CA:", ca.issuer, `(${ca.name})`);
  console.log("📜 [sim-tpm-provision] EK cert issued (JWS length:", ek.cert.length, "bytes)");

  return { devId, ek, ca, agentDir };
}

if (isMain(import.meta.url)) {
  const options = parseArgs();
  if (!options.dir) {
    console.error("Usage: node scripts/sim-tpm-provision.js --dir data/agent/<id> [--ca <path>] [--rogue-ca]");
    process.exit(1);
  }
  provisionSimTpm(options).catch((err) => {
    console.error("❌ [sim-tpm-provision] Error:", err.message);
    process.exit(1);
  });
}

export default {
  parseArgs,
  provisionSimTpm,
};
