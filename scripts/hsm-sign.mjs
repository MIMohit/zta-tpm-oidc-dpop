#!/usr/bin/env node
/**
 * @file scripts/hsm-sign.mjs
 * Signs a JWT with a key held in the PKCS#11 token named by the environment (ZTA_HSM=pkcs11,
 * SOFTHSM2_CONF, ZTA_PKCS11_*). Reads {"key","header","payload"} JSON on stdin and prints the
 * JWT. Used by the attack harness as a test oracle against a stack it started, in a separate
 * process because a PKCS#11 library is initialised once per process.
 */

import process from "node:process";

import { loadOrCreateSigningKey, signJwt } from "../lib/keys.js";
import { closeHsmSessions } from "../lib/hsm.js";

let input = "";
process.stdin.on("data", (c) => (input += c));
process.stdin.on("end", async () => {
  try {
    const { key, header, payload } = JSON.parse(input);
    const k = await loadOrCreateSigningKey(key, { store: "file" });
    process.stdout.write(await signJwt(k, { ...header, kid: k.kid }, payload));
    closeHsmSessions();
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
});
