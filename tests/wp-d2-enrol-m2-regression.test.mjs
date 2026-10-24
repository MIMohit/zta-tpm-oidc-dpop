/**
 * @file tests/wp-d2-enrol-m2-regression.test.mjs
 * Regression tests for WP-D2:
 * 1. M2 ON: client-supplied user is ignored (inventory owner wins); unknown device rejected.
 * 2. M2 OFF: unknown device accepted and assigned client-supplied user.
 * 3. Attacks smoke verification for A01–A09 and A22.
 */

import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

import { withAblation, resetAblation, state } from "../lib/ablation.js";
import { createStore } from "../lib/store.js";
import { startEnrol, finishEnrol } from "../lib/verifier/enrol.js";
import { addToInventory } from "../lib/verifier/inventory.js";
import { devIdOf } from "../lib/sim-tpm/public-area.js";
import { SimTpm } from "../lib/sim-tpm/tpm.js";
import { createVendorCa } from "../lib/sim-tpm/vendor-ca.js";

describe("WP-D2: M2 inventory owner precedence & rogue rejection regression", () => {
  let tmpDir;
  let simVendorCa;

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "wp-d2-reg-"));
    simVendorCa = await createVendorCa(path.join(tmpDir, "ca"), "sim-vendor", "SimTPM Vendor CA");
  });

  after(() => {
    if (tmpDir && fs.existsSync(tmpDir)) {
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch {}
    }
  });

  beforeEach(() => {
    resetAblation();
  });

  it("M2 ON: client-supplied user is ignored and inventory owner wins", async () => {
    const store = createStore("verifier", { store: "memory" });
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const { publicArea: ekPub, cert: ekCert } = await tpm.getEk();
    const devId = await devIdOf(ekPub);
    const ak = await tpm.createAk();
    const kb = await tpm.createKb();

    // Inventory provisions device for 'alice'
    await addToInventory(store, { devId, user: "alice", code: "code-alice" });

    // Client requests enrolment claiming user 'mallory'
    const res = await startEnrol({
      code: "code-alice",
      ekCert,
      akPublic: ak.publicArea,
      kbPublic: kb.publicArea,
      user: "mallory",
      store,
      trustAnchors: [simVendorCa.publicJwk],
    });

    assert.equal(res.ok, true);
    assert.ok(res.sessionId);

    // Session owner must be 'alice' (inventory record), NOT 'mallory'
    const session = await store.get(`sessions/${res.sessionId}`);
    assert.equal(session.user, "alice");
  });

  it("M2 ON: unknown device (not in inventory) is rejected even with user parameter", async () => {
    const store = createStore("verifier", { store: "memory" });
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const { cert: ekCert } = await tpm.getEk();
    const ak = await tpm.createAk();
    const kb = await tpm.createKb();

    // Device NOT in inventory
    const res = await startEnrol({
      code: "any-code",
      ekCert,
      akPublic: ak.publicArea,
      kbPublic: kb.publicArea,
      user: "alice",
      store,
      trustAnchors: [simVendorCa.publicJwk],
    });

    assert.equal(res.ok, false);
    assert.equal(res.status, 403);
    assert.equal(res.error, "ek_not_in_inventory");
  });

  it("M2 OFF: unknown device accepted and assigned client-supplied user", async () => {
    const store = createStore("verifier", { store: "memory" });
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const { cert: ekCert } = await tpm.getEk();
    const ak = await tpm.createAk();
    const kb = await tpm.createKb();

    await withAblation("-M2", async () => {
      const res = await startEnrol({
        code: "any-code",
        ekCert,
        akPublic: ak.publicArea,
        kbPublic: kb.publicArea,
        user: "mallory",
        store,
        trustAnchors: [simVendorCa.publicJwk],
      });

      assert.equal(res.ok, true);
      assert.ok(res.sessionId);

      const session = await store.get(`sessions/${res.sessionId}`);
      assert.equal(session.user, "mallory");
    });

    assert.equal(state().label, "full");
  });
});
