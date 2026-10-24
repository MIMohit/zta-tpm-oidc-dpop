#!/usr/bin/env node
/**
 * @file scripts/hw-devid.mjs
 * Prints the devId (H(EKpub)) of the TPM the environment selects (TPM_DEVICE, TPM_EK_TYPE...),
 * for adding a hardware device to the verifier inventory.
 */

import { RealTpm } from "../lib/tpm-real/index.js";
import { devIdOf } from "../lib/sim-tpm/public-area.js";

const tpm = new RealTpm({});
await tpm.init();
try {
  const ek = await tpm.getEk();
  process.stdout.write(`\n${await devIdOf(ek.publicArea)}\n`);
} finally {
  await tpm.close();
}
