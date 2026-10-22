/**
 * @file seed.js
 * Seed step for Simulated TPM and Vendor CAs.
 * Provisions:
 * - data/vendor-ca/sim-vendor (trusted root CA)
 * - data/vendor-ca/evil (untrusted evil CA)
 * - data/agent/alice-laptop (trusted device)
 * - data/agent/rogue (genuine cert, not in inventory, for A4 attack demo)
 */

import fs from "node:fs";
import path from "node:path";
import { createVendorCa } from "./vendor-ca.js";
import { SimTpm } from "./tpm.js";
import { devIdOf } from "./public-area.js";

/**
 * Seeds the simulated TPM environments and vendor CAs.
 * @param {Record<string, any>} [cfg] - Configuration object
 * @returns {Promise<{ simVendorCa: any, evilCa: any, aliceTpm: any, rogueTpm: any }>}
 */
export async function seed(cfg = {}) {
  const dataDir = path.resolve(cfg.dataDir || cfg.ZTA_DATA_DIR || "./data");
  const vendorCaDir = path.join(dataDir, "vendor-ca");
  const agentDir = path.join(dataDir, "agent");

  // 1. Create trusted vendor CA
  const simVendorCa = await createVendorCa(vendorCaDir, "sim-vendor", "SimTPM Vendor CA");

  // 2. Create untrusted evil CA (for chain validation failure tests)
  const evilCaDir = path.join(vendorCaDir, "evil");
  const evilCa = await createVendorCa(evilCaDir, "evil", "Untrusted Evil Vendor CA");

  // 3. Provision alice-laptop TPM (remove stale client.json if re-provisioning)
  const aliceDir = path.join(agentDir, "alice-laptop");
  const aliceClientFile = path.join(aliceDir, "client.json");
  if (fs.existsSync(aliceClientFile)) {
    try { fs.unlinkSync(aliceClientFile); } catch {}
  }
  const aliceTpm = new SimTpm({ dir: aliceDir, caKey: simVendorCa });
  await aliceTpm.init();
  const aliceEk = await aliceTpm.getEk();
  const aliceDevId = await devIdOf(aliceEk.publicArea);

  // 4. Provision rogue TPM (genuine vendor cert, but omitted from inventory)
  const rogueDir = path.join(agentDir, "rogue");
  const rogueClientFile = path.join(rogueDir, "client.json");
  if (fs.existsSync(rogueClientFile)) {
    try { fs.unlinkSync(rogueClientFile); } catch {}
  }
  const rogueTpm = new SimTpm({ dir: rogueDir, caKey: simVendorCa });
  await rogueTpm.init();
  const rogueEk = await rogueTpm.getEk();
  const rogueDevId = await devIdOf(rogueEk.publicArea);

  console.log(`🛡️ [seed-sim-tpm] Vendor CA created: ${simVendorCa.issuer}`);
  console.log(`🛡️ [seed-sim-tpm] Evil CA created: ${evilCa.issuer}`);
  console.log(`🛡️ [seed-sim-tpm] Alice SimTPM provisioned: ${aliceDevId} (${aliceDir})`);
  console.log(`🛡️ [seed-sim-tpm] Rogue SimTPM provisioned: ${rogueDevId} (${rogueDir})`);

  return {
    simVendorCa,
    evilCa,
    aliceTpm,
    rogueTpm,
  };
}

export default seed;
