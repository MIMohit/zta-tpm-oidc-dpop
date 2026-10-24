/**
 * @file eventlog-e2e.test.mjs
 * End-to-end integration tests for TCG crypto-agile binary event log verification.
 * Tests enrol, appraise, tamper, mismatch, stale nonce, and reference value enforcement.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { SimTpm } from "../lib/sim-tpm/tpm.js";
import { createVendorCa } from "../lib/sim-tpm/vendor-ca.js";
import { startStack } from "./helpers/harness.js";
import { devIdOf } from "../lib/sim-tpm/public-area.js";
import { addToInventory } from "../lib/verifier/inventory.js";
import { ZtaClient } from "../lib/agent-client.js";

const FIXTURES_DIR = path.resolve("fixtures/eventlogs");
const CAPTURED_LOG_PATH = path.join(FIXTURES_DIR, "qemu-edk2-swtpm/ubuntu-noble-arm64-edk2.bin");
const GCE_LOG_PATH = path.join(FIXTURES_DIR, "tpm2-tools/event-gce-ubuntu-2104-log.bin");
const ARCH_LOG_PATH = path.join(FIXTURES_DIR, "tpm2-tools/event-arch-linux.bin");
const RV_PATH = path.resolve("fixtures/rv/qemu-edk2-swtpm-arm64.json");

test("TCG Event Log End-to-End Integration", async (t) => {
  const originalRvPath = process.env.VERIFIER_RV_PATH;
  process.env.VERIFIER_RV_PATH = RV_PATH;

  const capturedLogBuf = fs.readFileSync(CAPTURED_LOG_PATH);
  const gceLogBuf = fs.readFileSync(GCE_LOG_PATH);
  const archLogBuf = fs.readFileSync(ARCH_LOG_PATH);

  let stack;

  t.before(async () => {
    stack = await startStack({
      VERIFIER_RV_PATH: RV_PATH,
      tpmFactory: async ({ name, dir, tempDir }) => {
        const ca = await createVendorCa(path.join(tempDir, "vendor-ca"), "sim-vendor");
        const tpm = new SimTpm({ dir, caKey: ca, bootLog: capturedLogBuf });
        await tpm.init();
        return tpm;
      },
    });
  });

  t.after(async () => {
    if (stack) {
      await stack.stop();
    }
    if (originalRvPath !== undefined) {
      process.env.VERIFIER_RV_PATH = originalRvPath;
    } else {
      delete process.env.VERIFIER_RV_PATH;
    }
  });

  await t.test("1. Enrol + appraise with captured log and RV -> ok, AR issued", async () => {
    const { clients, codes, stores } = stack;

    const enrolRes = await clients.alice.enrol(codes.alice);
    assert.strictEqual(enrolRes.enrolled, true);

    const ar = await clients.alice.attest();
    assert.ok(ar, "Expected Attestation Result (AR) token");

    const reg = await stores.verifier.get(`registry/${clients.alice.devId}`);
    assert.strictEqual(reg.status, "active");
  });

  await t.test("2. Tamper (PCR4 extend + synthetic log event) -> appraisal 403 appraisal_failed, registry suspended", async () => {
    const { clients, urls, stores } = stack;

    // Tamper Alice's TPM
    clients.alice.tpm.tamper("unauthorized kernel modification");

    // Request fresh nonce
    const nonceRes = await fetch(`${urls.verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: clients.alice.devId }),
    });
    assert.strictEqual(nonceRes.status, 200);
    const { nonceId, nonce } = await nonceRes.json();

    const quote = await clients.alice.tpm.quote(clients.alice.akHandle, nonce);
    const eventLog = clients.alice.tpm.readEventLog();

    const appRes = await fetch(`${urls.verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: clients.alice.devId,
        nonceId,
        quote,
        eventLog,
      }),
    });

    assert.strictEqual(appRes.status, 403);
    const appData = await appRes.json();
    assert.strictEqual(appData.error, "appraisal_failed");

    const reg = await stores.verifier.get(`registry/${clients.alice.devId}`);
    assert.strictEqual(reg.status, "suspended");
  });

  await t.test("3. Log/quote mismatch (send log of different fixture with fresh quote) -> 403 and suspended", async () => {
    const { clients, codes, urls, stores } = stack;

    // Enrol Bob (fresh clean device)
    const enrolRes = await clients.bob.enrol(codes.bob);
    assert.strictEqual(enrolRes.enrolled, true);

    const regInit = await stores.verifier.get(`registry/${clients.bob.devId}`);
    assert.strictEqual(regInit.status, "active");

    // Request fresh nonce
    const nonceRes = await fetch(`${urls.verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: clients.bob.devId }),
    });
    assert.strictEqual(nonceRes.status, 200);
    const { nonceId, nonce } = await nonceRes.json();

    // Valid quote from Bob's TPM over fresh nonce
    const quote = await clients.bob.tpm.quote(clients.bob.akHandle, nonce);

    // Mismatched binary log (Arch Linux log)
    const mismatchedLog = {
      format: "tcg2-binary",
      data: archLogBuf.toString("base64url"),
    };

    const appRes = await fetch(`${urls.verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: clients.bob.devId,
        nonceId,
        quote,
        eventLog: mismatchedLog,
      }),
    });

    assert.strictEqual(appRes.status, 403);
    const appData = await appRes.json();
    assert.strictEqual(appData.error, "appraisal_failed");
    assert.match(appData.reason, /Replayed TCG event log does not match quoted pcrDigest/);

    const regBob = await stores.verifier.get(`registry/${clients.bob.devId}`);
    assert.strictEqual(regBob.status, "suspended");
  });

  await t.test("4. Stale nonce with mismatch log -> 400 stale_evidence, no state change", async () => {
    const { clients, urls, stores } = stack;

    // Reinstate Bob to active
    const regBob = await stores.verifier.get(`registry/${clients.bob.devId}`);
    await stores.verifier.set(`registry/${clients.bob.devId}`, { ...regBob, status: "active" });

    // Request valid nonce
    const nonceRes = await fetch(`${urls.verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: clients.bob.devId }),
    });
    const { nonceId } = await nonceRes.json();

    // But quote over stale nonce
    const staleNonce = "00".repeat(32);
    const quote = await clients.bob.tpm.quote(clients.bob.akHandle, staleNonce);

    const mismatchedLog = {
      format: "tcg2-binary",
      data: archLogBuf.toString("base64url"),
    };

    const appRes = await fetch(`${urls.verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: clients.bob.devId,
        nonceId,
        quote,
        eventLog: mismatchedLog,
      }),
    });

    assert.strictEqual(appRes.status, 400);
    const appData = await appRes.json();
    assert.strictEqual(appData.error, "stale_evidence");

    // Device state in registry MUST remain active
    const regBobAfter = await stores.verifier.get(`registry/${clients.bob.devId}`);
    assert.strictEqual(regBobAfter.status, "active");
  });

  await t.test("5. A log with RV-unknown digest (GCE log) -> 403 Event digest not in reference values", async () => {
    const { urls, stores, ca } = stack;

    // Create a new SimTpm booted with GCE log
    const gceTpm = new SimTpm({
      dir: path.join(stack.tempDir, "gce-device"),
      caKey: ca.simVendorCa,
      bootLog: gceLogBuf,
    });
    await gceTpm.init();
    const gceEk = await gceTpm.getEk();
    const gceDevId = await devIdOf(gceEk.publicArea);

    // Add to inventory
    const inv = await addToInventory(stores.verifier, {
      devId: gceDevId,
      user: "carol",
      ttlMs: 365 * 24 * 3600 * 1000,
      clock: stack.clock,
    });

    const carolClient = new ZtaClient({
      tpm: gceTpm,
      cfg: {
        verifierUrl: urls.verifierUrl,
        registryUrl: urls.registryUrl,
      },
      clock: stack.clock,
    });

    await assert.rejects(
      async () => {
        await carolClient.enrol(inv.code);
      },
      (err) => {
        assert.match(err.message, /digest not in reference values/);
        return true;
      }
    );
  });
});
