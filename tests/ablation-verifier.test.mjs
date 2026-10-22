/**
 * @file tests/ablation-verifier.test.mjs
 * Ablation tests for verifier mechanisms M1–M8 and M23 (WP-C2).
 * Verifies that each guard fires when ON (default/full) and is bypassed when OFF (-Mx).
 */

import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";

import { withAblation, resetAblation, state } from "../lib/ablation.js";
import { createStore } from "../lib/store.js";
import { startEnrol, finishEnrol, verifyQuote, verifyCertify } from "../lib/verifier/enrol.js";
import { requestAppraiseNonce, appraiseDevice } from "../lib/verifier/appraise.js";
import { addToInventory } from "../lib/verifier/inventory.js";
import { devIdOf } from "../lib/sim-tpm/public-area.js";
import { SimTpm } from "../lib/sim-tpm/tpm.js";
import { createVendorCa } from "../lib/sim-tpm/vendor-ca.js";
import { marshalAttest, TPM_ST_ATTEST_QUOTE } from "../lib/sim-tpm/attest.js";
import { loadOrCreateSigningKey } from "../lib/keys.js";
import { loadReferenceValues } from "../lib/verifier/reference-values.js";

describe("WP-C2: Verifier Ablation Guards (M1–M8, M23)", () => {
  let tmpDir;
  let simVendorCa;
  let evilCa;
  let verifierKey;
  let referenceValues;

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ablation-verifier-"));
    simVendorCa = await createVendorCa(path.join(tmpDir, "good-ca"), "sim-vendor", "SimTPM Vendor CA");
    evilCa = await createVendorCa(path.join(tmpDir, "evil-ca"), "evil", "Evil Attacker CA");
    verifierKey = await loadOrCreateSigningKey("verifier", { store: "memory" });
    referenceValues = loadReferenceValues();
  });

  after(() => {
    if (tmpDir && fs.existsSync(tmpDir)) {
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup error
      }
    }
  });

  beforeEach(() => {
    resetAblation();
  });

  it("M1: evil-CA cert accepted off (-M1), rejected on (full)", async () => {
    const store = createStore("verifier", { store: "memory" });
    const tpmGood = new SimTpm({ caKey: simVendorCa });
    await tpmGood.init();
    const ak = await tpmGood.createAk();
    const kb = await tpmGood.createKb();

    const tpmEvil = new SimTpm({ caKey: evilCa });
    await tpmEvil.init();
    const { publicArea: ekPubEvil, cert: evilCert } = await tpmEvil.getEk();
    const evilDevId = await devIdOf(ekPubEvil);
    await addToInventory(store, { devId: evilDevId, user: "alice", code: "m1-test-code" });

    // When M1 is ON (default): evil CA cert is rejected
    const resOn = await startEnrol({
      code: "m1-test-code",
      ekCert: evilCert,
      akPublic: ak.publicArea,
      kbPublic: kb.publicArea,
      store,
      trustAnchors: [simVendorCa.publicJwk],
    });
    assert.equal(resOn.ok, false);
    assert.equal(resOn.status, 403);
    assert.equal(resOn.error, "ek_cert_invalid");

    // When M1 is OFF (-M1): evil CA cert is accepted without vendor verification
    await withAblation("-M1", async () => {
      const resOff = await startEnrol({
        code: "m1-test-code",
        ekCert: evilCert,
        akPublic: ak.publicArea,
        kbPublic: kb.publicArea,
        store,
        trustAnchors: [simVendorCa.publicJwk],
      });
      assert.equal(resOff.ok, true);
      assert.ok(resOff.sessionId);
      const session = await store.get(`sessions/${resOff.sessionId}`);
      assert.equal(session.ekTrust, "unverified");
    });

    assert.equal(state().label, "full");
  });

  it("M2: rogue devId rejected on (full), accepted off (-M2)", async () => {
    const store = createStore("verifier", { store: "memory" });
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const { publicArea: ekPub, cert: ekCert } = await tpm.getEk();
    const ak = await tpm.createAk();
    const kb = await tpm.createKb();

    // Device is NOT added to inventory -> rogue devId
    // When M2 is ON: startEnrol fails with ek_not_in_inventory
    const resOn = await startEnrol({
      code: "some-code",
      ekCert,
      akPublic: ak.publicArea,
      kbPublic: kb.publicArea,
      store,
      trustAnchors: [simVendorCa.publicJwk],
    });
    assert.equal(resOn.ok, false);
    assert.equal(resOn.status, 403);
    assert.equal(resOn.error, "ek_not_in_inventory");

    // When M2 is OFF: startEnrol skips inventory & code checks, sets owner from user param
    await withAblation("-M2", async () => {
      const resOff = await startEnrol({
        code: "any-unverified-code",
        ekCert,
        akPublic: ak.publicArea,
        kbPublic: kb.publicArea,
        store,
        trustAnchors: [simVendorCa.publicJwk],
        user: "mallory",
      });
      assert.equal(resOff.ok, true);
      assert.ok(resOff.sessionId);

      const session = await store.get(`sessions/${resOff.sessionId}`);
      assert.equal(session.user, "mallory");

      // Activation and quote
      const sPrime = await tpm.activateCredential(ak.handle, resOff.blob);
      const quote = await tpm.quote(ak.handle, resOff.nonce);
      const certify = await tpm.certify(kb.handle, ak.handle, resOff.nonce);
      const eventLog = tpm.readEventLog();

      const finishRes = await finishEnrol({
        sessionId: resOff.sessionId,
        secret: sPrime,
        quote,
        certify,
        eventLog,
        store,
      });
      assert.equal(finishRes.ok, true);

      const reg = await store.get(`registry/${finishRes.devId}`);
      assert.equal(reg.status, "active");
      assert.equal(reg.user, "mallory");
    });

    assert.equal(state().label, "full");
  });

  it("M3: wrong secret rejected on (full), accepted off (-M3)", async () => {
    const store = createStore("verifier", { store: "memory" });
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const { publicArea: ekPub, cert: ekCert } = await tpm.getEk();
    const devId = await devIdOf(ekPub);
    const ak = await tpm.createAk();
    const kb = await tpm.createKb();

    await addToInventory(store, { devId, user: "alice", code: "code-m3" });

    // Step 1: Start enrolment (session 1)
    const s1 = await startEnrol({
      code: "code-m3",
      ekCert,
      akPublic: ak.publicArea,
      kbPublic: kb.publicArea,
      store,
      trustAnchors: [simVendorCa.publicJwk],
    });
    assert.equal(s1.ok, true);

    const quote = await tpm.quote(ak.handle, s1.nonce);
    const certify = await tpm.certify(kb.handle, ak.handle, s1.nonce);
    const eventLog = tpm.readEventLog();

    const bogusSecret = crypto.randomBytes(32);

    // When M3 is ON: wrong secret returns secret_mismatch
    const finishOn = await finishEnrol({
      sessionId: s1.sessionId,
      secret: bogusSecret,
      quote,
      certify,
      eventLog,
      store,
    });
    assert.equal(finishOn.ok, false);
    assert.equal(finishOn.status, 403);
    assert.equal(finishOn.error, "secret_mismatch");

    // Session 2 for ablation test
    const s2 = await startEnrol({
      code: "code-m3",
      ekCert,
      akPublic: ak.publicArea,
      kbPublic: kb.publicArea,
      store,
      trustAnchors: [simVendorCa.publicJwk],
    });
    assert.equal(s2.ok, true);

    const quote2 = await tpm.quote(ak.handle, s2.nonce);
    const certify2 = await tpm.certify(kb.handle, ak.handle, s2.nonce);

    // When M3 is OFF (-M3): wrong secret is accepted
    await withAblation("-M3", async () => {
      const finishOff = await finishEnrol({
        sessionId: s2.sessionId,
        secret: bogusSecret,
        quote: quote2,
        certify: certify2,
        eventLog,
        store,
      });
      assert.equal(finishOff.ok, true);
      assert.equal(finishOff.devId, devId);
    });

    assert.equal(state().label, "full");
  });

  it("M4: wrong nonce rejected on (full), accepted off (-M4)", async () => {
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const ak = await tpm.createAk();
    const kb = await tpm.createKb();

    const correctNonce = crypto.randomBytes(32).toString("base64url");
    const wrongNonce = crypto.randomBytes(32).toString("base64url");

    const quote = await tpm.quote(ak.handle, correctNonce);
    const certify = await tpm.certify(kb.handle, ak.handle, correctNonce);
    const eventLog = tpm.readEventLog();

    // 1. verifyQuote extraData
    const qOn = verifyQuote({
      quote,
      akPublic: ak.publicArea,
      expectedNonce: wrongNonce,
      eventLog,
      referenceValues,
    });
    assert.equal(qOn.valid, false);
    assert.match(qOn.error, /extraData does not match expected nonce/);

    await withAblation("-M4", () => {
      const qOff = verifyQuote({
        quote,
        akPublic: ak.publicArea,
        expectedNonce: wrongNonce,
        eventLog,
        referenceValues,
      });
      assert.equal(qOff.valid, true);
    });

    // 2. verifyCertify extraData
    const cOn = verifyCertify({
      certify,
      akPublic: ak.publicArea,
      kbPublic: kb.publicArea,
      expectedNonce: wrongNonce,
    });
    assert.equal(cOn.valid, false);
    assert.match(cOn.error, /extraData does not match expected nonce/);

    await withAblation("-M4", () => {
      const cOff = verifyCertify({
        certify,
        akPublic: ak.publicArea,
        kbPublic: kb.publicArea,
        expectedNonce: wrongNonce,
      });
      assert.equal(cOff.valid, true);
    });

    // 3. appraiseDevice nonce used/expiry
    const store = createStore("verifier", { store: "memory" });
    const { publicArea: ekPub } = await tpm.getEk();
    const devId = await devIdOf(ekPub);
    await store.set(`registry/${devId}`, {
      devId,
      akPub: ak.publicArea,
      status: "active",
      jkt: "some-jkt",
    });

    const nonceRec = await requestAppraiseNonce({ devId, store });
    assert.equal(nonceRec.ok, true);

    const freshQuote = await tpm.quote(ak.handle, nonceRec.nonce);

    // First appraisal succeeds and marks nonce as used
    const app1 = await appraiseDevice({
      devId,
      nonceId: nonceRec.nonceId,
      quote: freshQuote,
      eventLog,
      store,
      verifierKey,
      referenceValues,
    });
    assert.equal(app1.ok, true);

    // Replay with already-used nonce: when M4 is ON, fails with invalid_nonce
    const appOn = await appraiseDevice({
      devId,
      nonceId: nonceRec.nonceId,
      quote: freshQuote,
      eventLog,
      store,
      verifierKey,
      referenceValues,
    });
    assert.equal(appOn.ok, false);
    assert.equal(appOn.reason, "invalid_nonce");

    // When M4 is OFF: used nonce is accepted
    await withAblation("-M4", async () => {
      const appOff = await appraiseDevice({
        devId,
        nonceId: nonceRec.nonceId,
        quote: freshQuote,
        eventLog,
        store,
        verifierKey,
        referenceValues,
      });
      assert.equal(appOff.ok, true);
    });

    assert.equal(state().label, "full");
  });

  it("M5: quote signed by another AK rejected on (full), accepted off (-M5)", async () => {
    const tpm1 = new SimTpm({ caKey: simVendorCa });
    await tpm1.init();
    const ak1 = await tpm1.createAk();

    const tpm2 = new SimTpm({ caKey: simVendorCa });
    await tpm2.init();
    const ak2 = await tpm2.createAk();
    const kb2 = await tpm2.createKb();

    const nonce = crypto.randomBytes(32).toString("base64url");
    const quote2 = await tpm2.quote(ak2.handle, nonce);
    const certify2 = await tpm2.certify(kb2.handle, ak2.handle, nonce);
    const eventLog2 = tpm2.readEventLog();

    // Verify quote2 (signed by ak2) against ak1
    // When M5 is ON: signature or qualifiedSigner fails
    const qOn = verifyQuote({
      quote: quote2,
      akPublic: ak1.publicArea,
      expectedNonce: nonce,
      eventLog: eventLog2,
      referenceValues,
    });
    assert.equal(qOn.valid, false);
    assert.equal(qOn.akSigned, false);

    // When M5 is OFF: signature and qualifiedSigner checks are skipped
    await withAblation("-M5", () => {
      const qOff = verifyQuote({
        quote: quote2,
        akPublic: ak1.publicArea,
        expectedNonce: nonce,
        eventLog: eventLog2,
        referenceValues,
      });
      assert.equal(qOff.valid, true);
      assert.equal(qOff.akSigned, true);
    });

    // Same for verifyCertify
    const cOn = verifyCertify({
      certify: certify2,
      akPublic: ak1.publicArea,
      kbPublic: kb2.publicArea,
      expectedNonce: nonce,
    });
    assert.equal(cOn.valid, false);

    // M5 covers only the quote; the certify signature/signer checks belong to M8
    await withAblation("-M5", () => {
      const cM5Off = verifyCertify({
        certify: certify2,
        akPublic: ak1.publicArea,
        kbPublic: kb2.publicArea,
        expectedNonce: nonce,
      });
      assert.equal(cM5Off.valid, false);
    });

    await withAblation("-M8", () => {
      const cM8Off = verifyCertify({
        certify: certify2,
        akPublic: ak1.publicArea,
        kbPublic: kb2.publicArea,
        expectedNonce: nonce,
      });
      assert.equal(cM8Off.valid, true);
    });

    assert.equal(state().label, "full");
  });

  it("M6: PCR8–15 selection rejected on (full), accepted off (-M6)", async () => {
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const ak = await tpm.createAk();
    const nonce = crypto.randomBytes(32).toString("base64url");

    // Craft quote over PCR8..15 selection
    const akKey = tpm.keys.get(ak.handle);
    const dummyDigest = crypto.randomBytes(32);
    const attest = marshalAttest({
      type: TPM_ST_ATTEST_QUOTE,
      signerName: akKey.name,
      extraData: nonce,
      clockInfo: { clock: Date.now(), resetCount: 1, restartCount: 0, safe: 1 },
      firmwareVersion: 1n,
      attested: {
        pcrSelect: { count: 1, hash: 0x000b, sizeofSelect: 3, pcrSelect: Buffer.from([0x00, 0xff, 0x00]) },
        pcrDigest: dummyDigest,
      },
    });
    const key = crypto.createPrivateKey({
      key: { kty: "EC", crv: "P-256", ...akKey.privateJwk },
      format: "jwk",
    });
    const sig = crypto.sign("sha256", attest, { key, dsaEncoding: "ieee-p1363" }).toString("base64url");
    const quote = { attest, sig };

    const devRecord = {
      goldenPcrDigests: [dummyDigest.toString("hex")],
    };

    // When M6 is ON: quote with PCR8..15 selection is rejected
    const resOn = verifyQuote({
      quote,
      akPublic: ak.publicArea,
      expectedNonce: nonce,
      eventLog: null,
      devRecord,
    });
    assert.equal(resOn.valid, false);
    assert.match(resOn.error, /Invalid PCR selection in quote/);

    // When M6 is OFF: PCR selection check is skipped
    await withAblation("-M6", () => {
      const resOff = verifyQuote({
        quote,
        akPublic: ak.publicArea,
        expectedNonce: nonce,
        eventLog: null,
        devRecord,
      });
      assert.equal(resOff.valid, true);
    });

    assert.equal(state().label, "full");
  });

  it("M7: tampered PCR4 rejected on (full), accepted off (-M7)", async () => {
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const ak = await tpm.createAk();

    // Tamper PCR4 on the TPM
    await tpm.tamper();

    const nonce = crypto.randomBytes(32).toString("base64url");
    const quote = await tpm.quote(ak.handle, nonce);
    const eventLog = tpm.readEventLog();

    // When M7 is ON: quote over tampered PCR4 fails appraisal
    const resOn = verifyQuote({
      quote,
      akPublic: ak.publicArea,
      expectedNonce: nonce,
      eventLog,
      referenceValues,
    });
    assert.equal(resOn.valid, false);
    assert.match(resOn.error, /Event log verification failed/);

    // When M7 is OFF: all appraisal in step 7 is skipped and returns valid
    await withAblation("-M7", () => {
      const resOff = verifyQuote({
        quote,
        akPublic: ak.publicArea,
        expectedNonce: nonce,
        eventLog,
        referenceValues,
      });
      assert.equal(resOff.valid, true);
      assert.equal(resOff.akSigned, true);
      assert.equal(resOff.fresh, true);
    });

    assert.equal(state().label, "full");
  });

  it("M8: certify missing or invalid rejected on (full), accepted off (-M8)", async () => {
    const store = createStore("verifier", { store: "memory" });
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const { publicArea: ekPub, cert: ekCert } = await tpm.getEk();
    const devId = await devIdOf(ekPub);
    const ak = await tpm.createAk();
    const kb = await tpm.createKb();

    await addToInventory(store, { devId, user: "alice", code: "code-m8" });

    // Session 1
    const s1 = await startEnrol({
      code: "code-m8",
      ekCert,
      akPublic: ak.publicArea,
      kbPublic: kb.publicArea,
      store,
      trustAnchors: [simVendorCa.publicJwk],
    });
    assert.equal(s1.ok, true);

    const sPrime1 = await tpm.activateCredential(ak.handle, s1.blob);
    const quote1 = await tpm.quote(ak.handle, s1.nonce);
    const eventLog = tpm.readEventLog();

    const corruptCertify = { attest: "00".repeat(64), sig: "00".repeat(64) };

    // When M8 is ON: corrupt certify fails finishEnrol
    const resOn = await finishEnrol({
      sessionId: s1.sessionId,
      secret: sPrime1,
      quote: quote1,
      certify: corruptCertify,
      eventLog,
      store,
    });
    assert.equal(resOn.ok, false);
    assert.equal(resOn.status, 403);
    assert.equal(resOn.error, "certify_invalid");

    // Session 2
    const s2 = await startEnrol({
      code: "code-m8",
      ekCert,
      akPublic: ak.publicArea,
      kbPublic: kb.publicArea,
      store,
      trustAnchors: [simVendorCa.publicJwk],
    });
    assert.equal(s2.ok, true);

    const sPrime2 = await tpm.activateCredential(ak.handle, s2.blob);
    const quote2 = await tpm.quote(ak.handle, s2.nonce);

    // When M8 is OFF (-M8): verifyCertify is skipped, K_B is accepted unattested
    await withAblation("-M8", async () => {
      const resOff = await finishEnrol({
        sessionId: s2.sessionId,
        secret: sPrime2,
        quote: quote2,
        certify: corruptCertify,
        eventLog,
        store,
      });
      assert.equal(resOff.ok, true);
      assert.equal(resOff.devId, devId);

      const reg = await store.get(`registry/${devId}`);
      assert.equal(reg.status, "active");
    });

    assert.equal(state().label, "full");
  });

  it("M23: replayed stale quote -> unchanged on (full), suspended off (-M23)", async () => {
    const store = createStore("verifier", { store: "memory" });
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const { publicArea: ekPub } = await tpm.getEk();
    const devId = await devIdOf(ekPub);
    const ak = await tpm.createAk();
    const eventLog = tpm.readEventLog();

    // Register device as active
    await store.set(`registry/${devId}`, {
      devId,
      akPub: ak.publicArea,
      status: "active",
      jkt: "test-jkt",
    });

    // Request valid nonce
    const n1 = await requestAppraiseNonce({ devId, store });
    assert.equal(n1.ok, true);

    // Quote over a stale (different) nonce
    const staleNonce = crypto.randomBytes(32).toString("base64url");
    const staleQuote = await tpm.quote(ak.handle, staleNonce);

    // When M23 is ON (full): stale quote returns 400 stale_evidence, registry status unchanged (active)
    const resOn = await appraiseDevice({
      devId,
      nonceId: n1.nonceId,
      quote: staleQuote,
      eventLog,
      store,
      verifierKey,
      referenceValues,
    });
    assert.equal(resOn.ok, false);
    assert.equal(resOn.status, 400);
    assert.equal(resOn.error, "stale_evidence");

    const regAfterOn = await store.get(`registry/${devId}`);
    assert.equal(regAfterOn.status, "active");

    // Request another nonce for ablation test
    const n2 = await requestAppraiseNonce({ devId, store });
    assert.equal(n2.ok, true);

    // When M23 is OFF (-M23): stale quote returns 403 appraisal_failed, registry status suspended!
    await withAblation("-M23", async () => {
      const resOff = await appraiseDevice({
        devId,
        nonceId: n2.nonceId,
        quote: staleQuote,
        eventLog,
        store,
        verifierKey,
        referenceValues,
      });
      assert.equal(resOff.ok, false);
      assert.equal(resOff.status, 403);
      assert.equal(resOff.error, "appraisal_failed");

      const regAfterOff = await store.get(`registry/${devId}`);
      assert.equal(regAfterOff.status, "suspended");
    });

    assert.equal(state().label, "full");
  });
});
