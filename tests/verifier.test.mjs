/**
 * @file verifier.test.mjs
 * Comprehensive test suite for Attestation Verifier (WP2).
 * Tests all required cases from PLAN.md §3 WP2:
 * - Happy enrol returns devId === thumb(EK) and jkt === thumb(K_B)
 * - Wrong code, reused code, rogue EK not in inventory, and EK cert from evil CA -> 403
 * - Activate done with a different AK -> secret mismatch -> 403
 * - Quote over wrong nonce, and tamper -> 403 with status suspended
 * - Certify of a key missing fixedTPM -> 403
 * - Appraise: AR verifies under /v/jwks and has exp - iat === 120, jkt and status: "pass"
 * - Revoked device -> nonce 403
 * - Device Registry admin façade (:4004) proxy, revoke, and inventory endpoints
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import * as jose from "jose";

import { createApp as createVerifierApp } from "../services/attestation-service.js";
import { createApp as createRegistryApp } from "../services/device-registry.js";
import { createApp as createPipApp } from "../pip.js";
import { createStore } from "../lib/store.js";
import { loadConfig } from "../lib/config.js";
import { SimTpm } from "../lib/sim-tpm/tpm.js";
import { createVendorCa, issueEkCert } from "../lib/sim-tpm/vendor-ca.js";
import { makePublicArea, devIdOf, thumbprintOf, TPMA_OBJECT, nameOf } from "../lib/sim-tpm/public-area.js";
import { addToInventory } from "../lib/verifier/inventory.js";
import { verifyAttestationResult } from "../lib/verifier/ar.js";

describe("WP2: Attestation Verifier (Alg. 1), Inventory, AR, Registry Admin", () => {
  let tmpDir;
  let testCfg;
  let verifierApp;
  let verifierServer;
  let verifierUrl;
  let registryApp;
  let registryServer;
  let registryUrl;
  let pipApp;
  let pipServer;
  let pipUrl;
  let simVendorCa;
  let evilCa;
  let verifierStore;
  let pipStore;
  let currentTime;
  const clock = () => currentTime;

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "zta-wp2-test-"));
    currentTime = 1700000000000;

    const vendorCaDir = path.join(tmpDir, "vendor-ca");
    simVendorCa = await createVendorCa(vendorCaDir, "sim-vendor", "SimTPM Vendor CA");
    evilCa = await createVendorCa(path.join(vendorCaDir, "evil"), "evil", "Untrusted Evil CA");

    testCfg = loadConfig({
      dataDir: tmpDir,
      store: "memory",
      ztaInternalToken: "internal-test-secret-token",
      adminToken: "admin-test-secret-token",
      tauAR: 120,
      clock,
    });

    verifierStore = createStore("verifier", { store: "memory" });
    pipStore = createStore("pip", { store: "memory" });

    // Start PIP in-process
    pipApp = createPipApp({
      ...testCfg,
      storeInstance: pipStore,
    });
    pipServer = http.createServer(pipApp);
    await new Promise((res) => pipServer.listen(0, "127.0.0.1", res));
    const pipPort = pipServer.address().port;
    pipUrl = `http://127.0.0.1:${pipPort}`;
    testCfg.pipUrl = pipUrl;

    // Start Verifier in-process
    verifierApp = createVerifierApp({
      ...testCfg,
      storeInstance: verifierStore,
      trustAnchors: [simVendorCa.publicJwk],
    });
    verifierServer = http.createServer(verifierApp);
    await new Promise((res) => verifierServer.listen(0, "127.0.0.1", res));
    const verifierPort = verifierServer.address().port;
    verifierUrl = `http://127.0.0.1:${verifierPort}`;
    testCfg.verifierUrl = verifierUrl;

    // Start Registry Admin in-process
    registryApp = createRegistryApp({
      ...testCfg,
    });
    registryServer = http.createServer(registryApp);
    await new Promise((res) => registryServer.listen(0, "127.0.0.1", res));
    const regPort = registryServer.address().port;
    registryUrl = `http://127.0.0.1:${regPort}`;
    testCfg.registryUrl = registryUrl;
  });

  after(async () => {
    if (verifierServer) verifierServer.close();
    if (registryServer) registryServer.close();
    if (pipServer) pipServer.close();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  });

  it("Happy enrol returns devId === thumb(EK) and jkt === thumb(K_B)", async () => {
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const { publicArea: ekPub, cert: ekCert } = await tpm.getEk();
    const devId = await devIdOf(ekPub);
    const ak = await tpm.createAk();
    const kb = await tpm.createKb();
    const expectedJkt = await thumbprintOf(kb.publicArea);

    const code = "happy-enrol-code-123";
    await addToInventory(verifierStore, { devId, user: "alice", code, clock });

    // Step 1: Start enrolment
    const startRes = await fetch(`${verifierUrl}/v/enrol/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code,
        ekCert,
        akPublic: ak.publicArea,
        kbPublic: kb.publicArea,
      }),
    });

    assert.equal(startRes.status, 200, "Start enrolment should succeed");
    const startBody = await startRes.json();
    assert.ok(startBody.sessionId, "Must return sessionId");
    assert.ok(startBody.blob, "Must return MakeCredential blob");
    assert.ok(startBody.nonce, "Must return nonce");

    // Client-side TPM actions
    const sPrime = await tpm.activateCredential(ak.handle, startBody.blob);
    const quote = await tpm.quote(ak.handle, startBody.nonce);
    const certify = await tpm.certify(kb.handle, ak.handle, startBody.nonce);
    const eventLog = await tpm.readEventLog();

    // Step 2: Finish enrolment
    const finishRes = await fetch(`${verifierUrl}/v/enrol/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId: startBody.sessionId,
        secret: sPrime.toString("hex"),
        quote,
        certify,
        eventLog,
      }),
    });

    assert.equal(finishRes.status, 200, "Finish enrolment should succeed");
    const finishBody = await finishRes.json();
    assert.equal(finishBody.devId, devId, "devId must match thumb(EK)");
    assert.equal(finishBody.jkt, expectedJkt, "jkt must match thumb(K_B)");

    // Verify PIP received synchronous active update
    const pipDeviceRes = await fetch(`${pipUrl}/pip/device/${devId}`, {
      headers: { "X-ZTA-Internal": testCfg.ztaInternalToken },
    });
    const pipDevice = await pipDeviceRes.json();
    assert.equal(pipDevice.status, "active", "PIP device status must be active");
    assert.equal(pipDevice.user, "alice", "PIP device user must be alice");
    assert.equal(pipDevice.jkt, expectedJkt, "PIP device jkt must match K_B thumbprint");
    assert.equal(pipDevice.attestation_age_s, 0, "Attestation age should be 0 immediately after enrol");
  });

  it("Wrong code, reused code, rogue EK not in the inventory, and an EK cert from the evil CA -> 403", async () => {
    // 1. Wrong code -> 403
    {
      const tpm = new SimTpm({ caKey: simVendorCa });
      await tpm.init();
      const { publicArea: ekPub, cert: ekCert } = await tpm.getEk();
      const devId = await devIdOf(ekPub);
      const ak = await tpm.createAk();
      const kb = await tpm.createKb();

      await addToInventory(verifierStore, { devId, user: "alice", code: "correct-code-456", clock });

      const res = await fetch(`${verifierUrl}/v/enrol/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: "wrong-code-789",
          ekCert,
          akPublic: ak.publicArea,
          kbPublic: kb.publicArea,
        }),
      });

      assert.equal(res.status, 403);
      const body = await res.json();
      assert.equal(body.error, "code_invalid");
    }

    // 2. Reused code -> 403
    {
      const tpm = new SimTpm({ caKey: simVendorCa });
      await tpm.init();
      const { publicArea: ekPub, cert: ekCert } = await tpm.getEk();
      const devId = await devIdOf(ekPub);
      const ak = await tpm.createAk();
      const kb = await tpm.createKb();

      const code = "reusable-code-123";
      await addToInventory(verifierStore, { devId, user: "alice", code, clock });

      // Enrol once successfully
      const startRes = await fetch(`${verifierUrl}/v/enrol/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, ekCert, akPublic: ak.publicArea, kbPublic: kb.publicArea }),
      });
      assert.equal(startRes.status, 200);
      const { sessionId, blob, nonce } = await startRes.json();
      const s = await tpm.activateCredential(ak.handle, blob);
      const quote = await tpm.quote(ak.handle, nonce);
      const certify = await tpm.certify(kb.handle, ak.handle, nonce);

      const finishRes = await fetch(`${verifierUrl}/v/enrol/finish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sessionId,
          secret: s.toString("hex"),
          quote,
          certify,
          eventLog: await tpm.readEventLog(),
        }),
      });
      assert.equal(finishRes.status, 200);

      // Attempt to reuse code
      const reuseRes = await fetch(`${verifierUrl}/v/enrol/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, ekCert, akPublic: ak.publicArea, kbPublic: kb.publicArea }),
      });
      assert.equal(reuseRes.status, 403);
      const reuseBody = await reuseRes.json();
      assert.equal(reuseBody.error, "code_invalid");
    }

    // 3. Rogue EK not in inventory -> 403
    {
      const rogueTpm = new SimTpm({ caKey: simVendorCa });
      await rogueTpm.init();
      const { publicArea: ekPub, cert: ekCert } = await rogueTpm.getEk();
      const ak = await rogueTpm.createAk();
      const kb = await rogueTpm.createKb();

      const res = await fetch(`${verifierUrl}/v/enrol/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: "some-code",
          ekCert,
          akPublic: ak.publicArea,
          kbPublic: kb.publicArea,
        }),
      });

      assert.equal(res.status, 403);
      const body = await res.json();
      assert.equal(body.error, "ek_not_in_inventory");
    }

    // 4. EK cert from evil CA -> 403
    {
      const evilTpm = new SimTpm({ caKey: evilCa });
      await evilTpm.init();
      const { publicArea: ekPub, cert: ekCert } = await evilTpm.getEk();
      const devId = await devIdOf(ekPub);
      const ak = await evilTpm.createAk();
      const kb = await evilTpm.createKb();

      await addToInventory(verifierStore, { devId, user: "alice", code: "evil-code-123", clock });

      const res = await fetch(`${verifierUrl}/v/enrol/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: "evil-code-123",
          ekCert,
          akPublic: ak.publicArea,
          kbPublic: kb.publicArea,
        }),
      });

      assert.equal(res.status, 403);
      const body = await res.json();
      assert.equal(body.error, "ek_cert_invalid");
    }
  });

  it("Activate done with a different AK -> secret mismatch -> 403", async () => {
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const { publicArea: ekPub, cert: ekCert } = await tpm.getEk();
    const devId = await devIdOf(ekPub);
    const ak1 = await tpm.createAk();
    const kb = await tpm.createKb();

    const code = "secret-mismatch-code";
    await addToInventory(verifierStore, { devId, user: "alice", code, clock });

    const startRes = await fetch(`${verifierUrl}/v/enrol/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, ekCert, akPublic: ak1.publicArea, kbPublic: kb.publicArea }),
    });
    assert.equal(startRes.status, 200);
    const { sessionId, nonce } = await startRes.json();

    const quote = await tpm.quote(ak1.handle, nonce);
    const certify = await tpm.certify(kb.handle, ak1.handle, nonce);

    // Client presents wrong secret s'
    const wrongSecret = crypto.randomBytes(32).toString("hex");

    const finishRes = await fetch(`${verifierUrl}/v/enrol/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId,
        secret: wrongSecret,
        quote,
        certify,
        eventLog: await tpm.readEventLog(),
      }),
    });

    assert.equal(finishRes.status, 403);
    const body = await finishRes.json();
    assert.equal(body.error, "secret_mismatch");
  });

  it("Quote over the wrong nonce -> 400 no state change (N1); tamper -> 403 with status suspended", async () => {
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const { publicArea: ekPub, cert: ekCert } = await tpm.getEk();
    const devId = await devIdOf(ekPub);
    const ak = await tpm.createAk();
    const kb = await tpm.createKb();

    const code = "nonce-and-tamper-code";
    await addToInventory(verifierStore, { devId, user: "alice", code, clock });

    // Enrol successfully
    const startRes = await fetch(`${verifierUrl}/v/enrol/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, ekCert, akPublic: ak.publicArea, kbPublic: kb.publicArea }),
    });
    const { sessionId, blob, nonce } = await startRes.json();
    const s = await tpm.activateCredential(ak.handle, blob);
    const quote = await tpm.quote(ak.handle, nonce);
    const certify = await tpm.certify(kb.handle, ak.handle, nonce);
    await fetch(`${verifierUrl}/v/enrol/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId,
        secret: s.toString("hex"),
        quote,
        certify,
        eventLog: await tpm.readEventLog(),
      }),
    });

    // 1. Quote over wrong nonce during appraisal
    {
      const nonceRes = await fetch(`${verifierUrl}/v/appraise/nonce`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ devId }),
      });
      assert.equal(nonceRes.status, 200);
      const { nonceId } = await nonceRes.json();

      const wrongNonce = crypto.randomBytes(32);
      const wrongQuote = await tpm.quote(ak.handle, wrongNonce);

      const appraiseRes = await fetch(`${verifierUrl}/v/appraise`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          devId,
          nonceId,
          quote: wrongQuote,
          eventLog: await tpm.readEventLog(),
        }),
      });

      // N1: AK-signed but not over the current nonce = stale/replayed evidence -> 400, no state change
      assert.equal(appraiseRes.status, 400);
      const body = await appraiseRes.json();
      assert.equal(body.error, "stale_evidence");

      const devRes = await fetch(`${verifierUrl}/v/devices/${devId}`, {
        headers: { "X-ZTA-Internal": testCfg.ztaInternalToken },
      });
      const dev = await devRes.json();
      assert.equal(dev.status, "active", "Stale/replayed quote must not suspend the device");
    }

    // 2. Tamper PCR digest during appraisal
    {
      const nonceRes = await fetch(`${verifierUrl}/v/appraise/nonce`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ devId }),
      });
      assert.equal(nonceRes.status, 200);
      const { nonceId, nonce: freshNonce } = await nonceRes.json();

      // Tamper PCR4 with unauthorized hash
      await tpm.tamper("Unauthorized rogue rootkit injected into PCR4");

      const tamperedQuote = await tpm.quote(ak.handle, freshNonce);
      const eventLog = await tpm.readEventLog();

      const appraiseRes = await fetch(`${verifierUrl}/v/appraise`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          devId,
          nonceId,
          quote: tamperedQuote,
          eventLog,
        }),
      });

      assert.equal(appraiseRes.status, 403);
      const body = await appraiseRes.json();
      assert.equal(body.error, "appraisal_failed");

      // Verify status is suspended on both Verifier and PIP
      const devRes = await fetch(`${verifierUrl}/v/devices/${devId}`, {
        headers: { "X-ZTA-Internal": testCfg.ztaInternalToken },
      });
      const dev = await devRes.json();
      assert.equal(dev.status, "suspended");

      const pipRes = await fetch(`${pipUrl}/pip/device/${devId}`, {
        headers: { "X-ZTA-Internal": testCfg.ztaInternalToken },
      });
      const pipDev = await pipRes.json();
      assert.equal(pipDev.status, "suspended");
    }
  });

  it("Certify of a key missing fixedTPM -> 403", async () => {
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const { publicArea: ekPub, cert: ekCert } = await tpm.getEk();
    const devId = await devIdOf(ekPub);
    const ak = await tpm.createAk();

    // Create a key missing fixedTPM attribute bit
    const { privateKey, publicKey } = await jose.generateKeyPair("ES256", { extractable: true });
    const publicJwk = await jose.exportJWK(publicKey);
    const attrsMissingFixedTPM =
      TPMA_OBJECT.sign |
      TPMA_OBJECT.fixedParent |
      TPMA_OBJECT.sensitiveDataOrigin |
      TPMA_OBJECT.userWithAuth;
    const badKbPub = makePublicArea(publicJwk, attrsMissingFixedTPM);

    const code = "bad-kb-attrs-code";
    await addToInventory(verifierStore, { devId, user: "alice", code, clock });

    const startRes = await fetch(`${verifierUrl}/v/enrol/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, ekCert, akPublic: ak.publicArea, kbPublic: badKbPub }),
    });
    assert.equal(startRes.status, 200);
    const { sessionId, blob, nonce } = await startRes.json();

    const s = await tpm.activateCredential(ak.handle, blob);
    const quote = await tpm.quote(ak.handle, nonce);

    // Certify bad key
    // Using SimTpm internal certify helper for test object
    const badKeyObj = {
      name: nameOf(badKbPub),
      publicArea: badKbPub,
    };
    tpm.keys.set("bad_kb", badKeyObj);
    const certify = await tpm.certify("bad_kb", ak.handle, nonce);

    const finishRes = await fetch(`${verifierUrl}/v/enrol/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId,
        secret: s.toString("hex"),
        quote,
        certify,
        eventLog: await tpm.readEventLog(),
      }),
    });

    assert.equal(finishRes.status, 403);
    const body = await finishRes.json();
    assert.equal(body.error, "certify_invalid");
  });

  it("Appraise: the AR verifies under /v/jwks and has exp - iat === 120, jkt and status: 'pass'", async () => {
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const { publicArea: ekPub, cert: ekCert } = await tpm.getEk();
    const devId = await devIdOf(ekPub);
    const ak = await tpm.createAk();
    const kb = await tpm.createKb();
    const expectedJkt = await thumbprintOf(kb.publicArea);

    const code = "appraise-pass-code";
    await addToInventory(verifierStore, { devId, user: "alice", code, clock });

    // Enrol
    const startRes = await fetch(`${verifierUrl}/v/enrol/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, ekCert, akPublic: ak.publicArea, kbPublic: kb.publicArea }),
    });
    const { sessionId, blob, nonce } = await startRes.json();
    const s = await tpm.activateCredential(ak.handle, blob);
    const quote = await tpm.quote(ak.handle, nonce);
    const certify = await tpm.certify(kb.handle, ak.handle, nonce);
    await fetch(`${verifierUrl}/v/enrol/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId,
        secret: s.toString("hex"),
        quote,
        certify,
        eventLog: await tpm.readEventLog(),
      }),
    });

    // Advance clock by 10 seconds
    currentTime += 10000;

    // Request appraisal nonce
    const nonceRes = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId }),
    });
    assert.equal(nonceRes.status, 200);
    const { nonceId, nonce: appraisalNonce } = await nonceRes.json();

    // Generate quote
    const appraisalQuote = await tpm.quote(ak.handle, appraisalNonce);
    const eventLog = await tpm.readEventLog();

    const appraiseRes = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId,
        nonceId,
        quote: appraisalQuote,
        eventLog,
      }),
    });
    assert.equal(appraiseRes.status, 200);
    const { ar } = await appraiseRes.json();
    assert.equal(typeof ar, "string");

    // Fetch public JWKS from /v/jwks
    const jwksRes = await fetch(`${verifierUrl}/v/jwks`);
    assert.equal(jwksRes.status, 200);
    const jwks = await jwksRes.json();
    assert.ok(Array.isArray(jwks.keys), "JWKS must contain keys array");

    // Verify AR
    const { payload, protectedHeader } = await verifyAttestationResult(ar, jwks, { clock });
    assert.equal(protectedHeader.typ, "ar+jwt", "Header typ must be ar+jwt");
    assert.equal(protectedHeader.alg, "ES256", "Header alg must be ES256");
    assert.equal(payload.sub, devId, "sub must be devId");
    assert.equal(payload.dev, devId, "dev claim must be devId");
    assert.equal(payload.jkt, expectedJkt, "jkt claim must match K_B thumbprint");
    assert.equal(payload.status, "pass", "status must be pass");
    assert.equal(payload.nonce, appraisalNonce, "nonce must match requested appraisal nonce");
    assert.equal(payload.exp - payload.iat, 120, "exp - iat must equal tau_AR (120 s)");
  });

  it("Revoked device -> nonce 403", async () => {
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const { publicArea: ekPub, cert: ekCert } = await tpm.getEk();
    const devId = await devIdOf(ekPub);
    const ak = await tpm.createAk();
    const kb = await tpm.createKb();

    const code = "revocation-test-code";
    await addToInventory(verifierStore, { devId, user: "alice", code, clock });

    // Enrol
    const startRes = await fetch(`${verifierUrl}/v/enrol/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, ekCert, akPublic: ak.publicArea, kbPublic: kb.publicArea }),
    });
    const { sessionId, blob, nonce } = await startRes.json();
    const s = await tpm.activateCredential(ak.handle, blob);
    const quote = await tpm.quote(ak.handle, nonce);
    const certify = await tpm.certify(kb.handle, ak.handle, nonce);
    await fetch(`${verifierUrl}/v/enrol/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId,
        secret: s.toString("hex"),
        quote,
        certify,
        eventLog: await tpm.readEventLog(),
      }),
    });

    // Revoke device via Device Registry admin API (:4004)
    const revokeRes = await fetch(`${registryUrl}/registry/${devId}/revoke`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${testCfg.adminToken}`,
      },
    });
    assert.equal(revokeRes.status, 200);
    const revokeBody = await revokeRes.json();
    assert.equal(revokeBody.revoked, true);

    // Verify PIP status became revoked immediately
    const pipCheck = await fetch(`${pipUrl}/pip/device/${devId}`, {
      headers: { "X-ZTA-Internal": testCfg.ztaInternalToken },
    });
    const pipData = await pipCheck.json();
    assert.equal(pipData.status, "revoked", "PIP status must be updated to revoked");

    // Requesting appraisal nonce for revoked device must return 403
    const nonceRes = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId }),
    });
    assert.equal(nonceRes.status, 403, "Revoked device must be denied appraisal nonce with 403");
    const nonceBody = await nonceRes.json();
    assert.equal(nonceBody.error, "device_not_active");
  });

  it("Device Registry admin façade (:4004) inventory, proxy, and retired route", async () => {
    // 1. Add to inventory via admin API
    const newDevId = "dev-admin-test-999";
    const invRes = await fetch(`${registryUrl}/registry/inventory`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${testCfg.adminToken}`,
      },
      body: JSON.stringify({
        devId: newDevId,
        user: "bob",
      }),
    });
    assert.equal(invRes.status, 200);
    const invData = await invRes.json();
    assert.equal(invData.devId, newDevId);
    assert.equal(invData.user, "bob");
    assert.ok(invData.code, "Must generate one-time code");

    // 2. Reject unauthenticated access to admin registry
    const unauthRes = await fetch(`${registryUrl}/registry/inventory`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: "dev-unauth", user: "bob" }),
    });
    assert.equal(unauthRes.status, 401);

    // 3. Legacy enroll returns 410 Gone
    const legacyRes = await fetch(`${registryUrl}/registry/enroll`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${testCfg.adminToken}`,
      },
      body: JSON.stringify({ device_id: "legacy-dev" }),
    });
    assert.equal(legacyRes.status, 410);
    const legacyBody = await legacyRes.json();
    assert.equal(legacyBody.error, "endpoint_retired");
  });

  it("Regression F3: Only AK-signature-valid appraisal failures suspend device; 400 for parse/sig errors; admin reinstate on :4004 restores active", async () => {
    // 1. Enrol a test device
    const tpm = new SimTpm({ caKey: simVendorCa });
    await tpm.init();
    const { publicArea: ekPub, cert: ekCert } = await tpm.getEk();
    const devId = await devIdOf(ekPub);
    const ak = await tpm.createAk();
    const kb = await tpm.createKb();

    const code = "reg-f3-code-123";
    await addToInventory(verifierStore, { devId, user: "carol", code, clock });

    const startRes = await fetch(`${verifierUrl}/v/enrol/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code,
        ekCert,
        akPublic: ak.publicArea,
        kbPublic: kb.publicArea,
      }),
    });
    assert.equal(startRes.status, 200);
    const startBody = await startRes.json();
    const sPrime = await tpm.activateCredential(ak.handle, startBody.blob);
    const q1 = await tpm.quote(ak.handle, startBody.nonce);
    const c1 = await tpm.certify(kb.handle, ak.handle, startBody.nonce);
    const log1 = await tpm.readEventLog();

    const finishRes = await fetch(`${verifierUrl}/v/enrol/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId: startBody.sessionId,
        secret: sPrime.toString("hex"),
        quote: q1,
        certify: c1,
        eventLog: log1,
      }),
    });
    assert.equal(finishRes.status, 200);

    // Verify initial status is active
    let regDev = await verifierStore.get(`registry/${devId}`);
    assert.equal(regDev.status, "active");

    // 2. Appraisal with malformed / unparseable quote -> 400 invalid_quote, device status remains active
    const nonceRes1 = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId }),
    });
    assert.equal(nonceRes1.status, 200);
    const { nonceId: nId1 } = await nonceRes1.json();

    const malformedRes = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId,
        nonceId: nId1,
        quote: { attest: "not-a-valid-attest", sig: "not-a-sig" },
        eventLog: log1,
      }),
    });
    assert.equal(malformedRes.status, 400);
    const malformedBody = await malformedRes.json();
    assert.equal(malformedBody.error, "invalid_quote");

    regDev = await verifierStore.get(`registry/${devId}`);
    assert.equal(regDev.status, "active", "Device must remain active after parse failure");

    // 3. Appraisal with invalid AK signature (tampered signature bytes) -> 400 invalid_quote, status remains active
    const nonceRes2 = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId }),
    });
    assert.equal(nonceRes2.status, 200);
    const { nonceId: nId2, nonce: n2 } = await nonceRes2.json();
    const realQuote = await tpm.quote(ak.handle, n2);
    // Corrupt the signature
    const corruptSigQuote = {
      attest: realQuote.attest,
      sig: Buffer.from("invalid-signature-bytes-not-matching-ak").toString("base64url"),
    };

    const badSigRes = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId,
        nonceId: nId2,
        quote: corruptSigQuote,
        eventLog: log1,
      }),
    });
    assert.equal(badSigRes.status, 400);
    const badSigBody = await badSigRes.json();
    assert.equal(badSigBody.error, "invalid_quote");

    regDev = await verifierStore.get(`registry/${devId}`);
    assert.equal(regDev.status, "active", "Device must remain active after signature failure");

    // 4. N1: genuine AK-signed quote over a WRONG nonce (stale/replayed evidence) -> 400 stale_evidence, NO state change
    const nonceRes3 = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId }),
    });
    assert.equal(nonceRes3.status, 200);
    const { nonceId: nId3 } = await nonceRes3.json();

    // AK genuinely signs wrong nonce "different-nonce-12345"
    const wrongNonceQuote = await tpm.quote(ak.handle, "different-nonce-12345");
    const staleRes = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId,
        nonceId: nId3,
        quote: wrongNonceQuote,
        eventLog: log1,
      }),
    });
    assert.equal(staleRes.status, 400);
    const staleBody = await staleRes.json();
    assert.equal(staleBody.error, "stale_evidence");

    regDev = await verifierStore.get(`registry/${devId}`);
    assert.equal(regDev.status, "active", "Device must remain active after stale/replayed quote");

    // N1: replay a previously accepted genuine quote against a fresh nonce -> 400, NO state change
    const nonceRes3b = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId }),
    });
    const { nonceId: nId3b, nonce: n3b } = await nonceRes3b.json();
    const capturedQuote = await tpm.quote(ak.handle, n3b);
    const firstRes = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId, nonceId: nId3b, quote: capturedQuote, eventLog: log1 }),
    });
    assert.equal(firstRes.status, 200);

    const nonceRes3c = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId }),
    });
    const { nonceId: nId3c } = await nonceRes3c.json();
    const replayRes = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId, nonceId: nId3c, quote: capturedQuote, eventLog: log1 }),
    });
    assert.equal(replayRes.status, 400);
    assert.equal((await replayRes.json()).error, "stale_evidence");

    regDev = await verifierStore.get(`registry/${devId}`);
    assert.equal(regDev.status, "active", "Device must remain active after replayed genuine quote");

    // 4b. Genuine AK-signed quote over the CURRENT nonce whose event log does not replay to pcrDigest -> 403, SUSPENDED
    const nonceRes3d = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId }),
    });
    const { nonceId: nId3d, nonce: n3d } = await nonceRes3d.json();
    const freshQuote = await tpm.quote(ak.handle, n3d);
    const appraisalFailRes = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId,
        nonceId: nId3d,
        quote: freshQuote,
        eventLog: log1.slice(0, -1),
      }),
    });
    assert.equal(appraisalFailRes.status, 403);
    const appraisalFailBody = await appraisalFailRes.json();
    assert.equal(appraisalFailBody.error, "appraisal_failed");

    regDev = await verifierStore.get(`registry/${devId}`);
    assert.equal(regDev.status, "suspended", "Device must be suspended after appraisal failure");

    // Also check PIP received suspended
    const pipDevRes = await fetch(`${pipUrl}/pip/device/${devId}`, {
      headers: { "X-ZTA-Internal": testCfg.ztaInternalToken },
    });
    const pipDev = await pipDevRes.json();
    assert.equal(pipDev.status, "suspended");

    // 5. Admin reinstate route on :4004 (POST /registry/:devId/reinstate) restores active
    const reinstateRes = await fetch(`${registryUrl}/registry/${devId}/reinstate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${testCfg.adminToken}`,
      },
    });
    assert.equal(reinstateRes.status, 200);
    const reinstateBody = await reinstateRes.json();
    assert.equal(reinstateBody.reinstated, true);

    regDev = await verifierStore.get(`registry/${devId}`);
    assert.equal(regDev.status, "active", "Device must be active after reinstate");

    const pipDevResAfter = await fetch(`${pipUrl}/pip/device/${devId}`, {
      headers: { "X-ZTA-Internal": testCfg.ztaInternalToken },
    });
    const pipDevAfter = await pipDevResAfter.json();
    assert.equal(pipDevAfter.status, "active", "PIP device must be active after reinstate");

    // 6. Device can now successfully appraise again
    const nonceRes4 = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId }),
    });
    assert.equal(nonceRes4.status, 200);
    const { nonceId: nId4, nonce: n4 } = await nonceRes4.json();
    const goodQuote = await tpm.quote(ak.handle, n4);

    const goodAppRes = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId,
        nonceId: nId4,
        quote: goodQuote,
        eventLog: log1,
      }),
    });
    assert.equal(goodAppRes.status, 200);
    const goodAppData = await goodAppRes.json();
    assert.ok(goodAppData.ar);
  });
});
