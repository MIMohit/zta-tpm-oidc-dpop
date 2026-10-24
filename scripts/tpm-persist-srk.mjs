#!/usr/bin/env node
/**
 * @file scripts/tpm-persist-srk.mjs
 * Persists the agent's SRK (lib/tpm-real/templates.js srkTemplate) at a persistent
 * handle, so RealTpm loads keys under it instead of re-creating the primary on every
 * operation. Refuses to touch a handle that is already in use.
 *
 * Usage:
 *   node scripts/tpm-persist-srk.mjs [--device linux|swtpm|tcp] [--handle 0x81000101]
 *   node scripts/tpm-persist-srk.mjs --remove [--handle 0x81000101]
 */

import process from "node:process";
import tss from "tss.js";

import { isMain } from "../lib/main.js";
import { selectDevice } from "../lib/tpm-real/devices.js";
import { TpmConn } from "../lib/tpm-real/tpm-conn.js";
import { srkTemplate } from "../lib/tpm-real/templates.js";
import { parseSrkHandle } from "../lib/tpm-real/backend.js";

const { TPM_HANDLE, TPM_RH, TPMS_SENSITIVE_CREATE } = tss;

function parseArgs(argv) {
  const opts = { device: process.env.TPM_DEVICE || "linux", handle: process.env.TPM_SRK_HANDLE || "0x81000101", remove: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--device") opts.device = argv[++i];
    else if (argv[i] === "--handle") opts.handle = argv[++i];
    else if (argv[i] === "--remove") opts.remove = true;
    else throw new Error(`Unknown argument: ${argv[i]}`);
  }
  return opts;
}

async function handleInUse(conn, handle) {
  try {
    await conn.call("ReadPublic", new TPM_HANDLE(handle));
    return true;
  } catch {
    return false;
  }
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  const handle = parseSrkHandle(opts.handle);
  const hex = `0x${handle.toString(16)}`;
  const conn = new TpmConn(selectDevice({ device: opts.device }), { device: opts.device });
  await conn.open();
  try {
    const inUse = await handleInUse(conn, handle);
    if (opts.remove) {
      if (!inUse) {
        console.log(`Nothing at ${hex}.`);
        return;
      }
      await conn.call("EvictControl", new TPM_HANDLE(TPM_RH.OWNER), new TPM_HANDLE(handle), new TPM_HANDLE(handle));
      console.log(`Removed persistent object at ${hex}.`);
      return;
    }
    if (inUse) {
      throw new Error(`Handle ${hex} is already in use; choose another with --handle`);
    }
    const srk = await conn.call("CreatePrimary", new TPM_HANDLE(TPM_RH.OWNER), new TPMS_SENSITIVE_CREATE(), srkTemplate, Buffer.alloc(0), []);
    try {
      await conn.call("EvictControl", new TPM_HANDLE(TPM_RH.OWNER), srk.handle, new TPM_HANDLE(handle));
    } finally {
      await conn.call("FlushContext", srk.handle).catch(() => {});
    }
    console.log(`Persisted SRK at ${hex}. Set TPM_SRK_HANDLE=${hex} for the agent.`);
  } finally {
    await conn.close().catch(() => {});
  }
}

if (isMain(import.meta.url)) {
  main().catch((err) => {
    console.error(`❌ ${err.message}`);
    process.exit(1);
  });
}
