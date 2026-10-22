/**
 * @file tests/idp.test.mjs
 * Comprehensive unit and integration test suite for WP5: IdP Gate (Alg. 2) in server.js.
 * Tests all required acceptance cases:
 * - PAR with an expired AR (clock + 121 s), with AR.jkt != dpop_jkt, and with AR of device A + key of device B -> 400
 * - Login as bob using alice's device -> deny (403)
 * - Token exchange without DPoP -> 400
 * - Token exchange without a nonce -> use_dpop_nonce (400)
 * - Token exchange with a proof signed by another key -> 400
 * - Happy path: AT has cnf.jkt == jkt, exp - iat == 300, role == "auditor", acr == "pwd"
 * - Client-asserted role (e.g. role=admin in PAR) is ignored
 * - Refresh after device revocation in PIP -> 400 invalid_grant ("device_not_active")
 * - Sim-IP Berlin -> Sydney within 1 h gives rho >= 0.5 and redirects to stepup
 * - Failures plus impossible travel plus new ASN give rho >= 0.85 and deny (403)
 * - WebAuthn step-up path: soft-authenticator assertion elevates to acr = "mfa"
 * - Clean import of server.js without Firebase or SoftHSM
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import * as jose from "jose";

import { createApp as createServerApp } from "../server.js";
import { createApp as createVerifierApp } from "../services/attestation-service.js";
import { createApp as createPipApp } from "../pip.js";
import { loadConfig } from "../lib/config.js";
import { createStore } from "../lib/store.js";
import { SimTpm } from "../lib/sim-tpm/tpm.js";
import { createVendorCa } from "../lib/sim-tpm/vendor-ca.js";
import { devIdOf, thumbprintOf, jwkOf } from "../lib/sim-tpm/public-area.js";
import { addToInventory } from "../lib/verifier/inventory.js";
import { signProof } from "../lib/dpop.js";
import { loadOrCreateSigningKey, publicJwks } from "../lib/keys.js";
import { SoftAuthenticator } from "./helpers/soft-webauthn.js";

describe("WP5: IdP Gate (Alg.2) & WebAuthn Step-Up in server.js", () => {
  let tmpDir;
  let testCfg;
  let nowMs = 1700000000000;
  const clock = () => nowMs;

  let pipServer, pipUrl, pipStore;
  let verifierServer, verifierUrl, verifierStore, verifierKey;
  let idpServer, idpUrl, idpStore, idpKey;

  let simVendorCa;
  let aliceTpm, aliceDevId, aliceAk, aliceKb, aliceJkt, aliceEkCert;
  let bobTpm, bobDevId, bobAk, bobKb, bobJkt, bobEkCert;
  let attackerKeyPair, attackerPublicJwk, attackerJkt;

  let arAlice;
  let arBob;

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "zta-wp5-test-"));

    // 1. Vendor CA & SimTPMs
    const vendorCaDir = path.join(tmpDir, "vendor-ca");
    simVendorCa = await createVendorCa(vendorCaDir, "sim-vendor", "SimTPM Vendor CA");

    aliceTpm = new SimTpm({ caKey: simVendorCa });
    await aliceTpm.init();
    const ekA = await aliceTpm.getEk();
    aliceDevId = await devIdOf(ekA.publicArea);
    aliceEkCert = ekA.cert;
    aliceAk = await aliceTpm.createAk();
    aliceKb = await aliceTpm.createKb();
    aliceJkt = await thumbprintOf(aliceKb.publicArea);

    bobTpm = new SimTpm({ caKey: simVendorCa });
    await bobTpm.init();
    const ekB = await bobTpm.getEk();
    bobDevId = await devIdOf(ekB.publicArea);
    bobEkCert = ekB.cert;
    bobAk = await bobTpm.createAk();
    bobKb = await bobTpm.createKb();
    bobJkt = await thumbprintOf(bobKb.publicArea);

    // Attacker standalone software key
    const kp = await jose.generateKeyPair("ES256", { extractable: true });
    attackerKeyPair = kp;
    attackerPublicJwk = await jose.exportJWK(kp.publicKey);
    attackerJkt = await jose.calculateJwkThumbprint(attackerPublicJwk, "sha256");

    // 2. Base Config
    testCfg = loadConfig({
      dataDir: tmpDir,
      store: "memory",
      ztaInternalToken: "internal-test-secret-token",
      adminToken: "admin-test-secret-token",
      sessionSecret: "test-session-secret-zta",
      tauAR: 120,
      tAT: 300,
      tRA: 300,
      tNonce: 60,
      wJti: 120,
      skew: 30,
      thetaLogin: 0.5,
      thetaDeny: 0.85,
      simIpHeader: true,
      clock,
    });

    pipStore = createStore("pip", { store: "memory" });
    verifierStore = createStore("verifier", { store: "memory" });
    idpStore = createStore("idp", { store: "memory" });

    // 3. Start PIP
    const pipApp = createPipApp({
      ...testCfg,
      storeInstance: pipStore,
    });
    pipServer = http.createServer(pipApp);
    await new Promise((res) => pipServer.listen(0, "127.0.0.1", res));
    pipUrl = `http://127.0.0.1:${pipServer.address().port}`;
    testCfg.pipUrl = pipUrl;

    // 4. Start Verifier
    verifierKey = await loadOrCreateSigningKey("verifier", { store: "memory", clock });
    const verifierApp = createVerifierApp({
      ...testCfg,
      storeInstance: verifierStore,
      verifierKey,
      trustAnchors: [simVendorCa.publicJwk],
    });
    verifierServer = http.createServer(verifierApp);
    await new Promise((res) => verifierServer.listen(0, "127.0.0.1", res));
    verifierUrl = `http://127.0.0.1:${verifierServer.address().port}`;
    testCfg.verifierUrl = verifierUrl;

    // 5. Enrol alice and bob in Verifier & PIP
    const aliceInv = await addToInventory(verifierStore, { devId: aliceDevId, user: "alice", clock });
    const bobInv = await addToInventory(verifierStore, { devId: bobDevId, user: "bob", clock });

    // Enrol alice device
    const enrolAliceStart = await fetch(`${verifierUrl}/v/enrol/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: aliceInv.code,
        ekCert: aliceEkCert,
        akPublic: aliceAk.publicArea,
        kbPublic: aliceKb.publicArea,
      }),
    });
    const aliceStartData = await enrolAliceStart.json();
    const aliceSecret = await aliceTpm.activateCredential(aliceAk.handle, aliceStartData.blob);
    const aliceQuote = await aliceTpm.quote(aliceAk.handle, aliceStartData.nonce);
    const aliceCertify = await aliceTpm.certify(aliceKb.handle, aliceAk.handle, aliceStartData.nonce);
    const aliceEventLog = await aliceTpm.readEventLog();

    await fetch(`${verifierUrl}/v/enrol/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId: aliceStartData.sessionId,
        secret: aliceSecret.toString("hex"),
        quote: aliceQuote,
        certify: aliceCertify,
        eventLog: aliceEventLog,
      }),
    });

    // Enrol bob device
    const enrolBobStart = await fetch(`${verifierUrl}/v/enrol/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: bobInv.code,
        ekCert: bobEkCert,
        akPublic: bobAk.publicArea,
        kbPublic: bobKb.publicArea,
      }),
    });
    const bobStartData = await enrolBobStart.json();
    const bobSecret = await bobTpm.activateCredential(bobAk.handle, bobStartData.blob);
    const bobQuote = await bobTpm.quote(bobAk.handle, bobStartData.nonce);
    const bobCertify = await bobTpm.certify(bobKb.handle, bobAk.handle, bobStartData.nonce);
    const bobEventLog = await bobTpm.readEventLog();

    await fetch(`${verifierUrl}/v/enrol/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId: bobStartData.sessionId,
        secret: bobSecret.toString("hex"),
        quote: bobQuote,
        certify: bobCertify,
        eventLog: bobEventLog,
      }),
    });

    // Obtain fresh AR for alice
    const nonceResA = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: aliceDevId }),
    });
    const { nonceId: nIdA, nonce: nA } = await nonceResA.json();
    const qA = await aliceTpm.quote(aliceAk.handle, nA);
    const logA = await aliceTpm.readEventLog();
    const appResA = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: aliceDevId,
        nonceId: nIdA,
        quote: qA,
        eventLog: logA,
      }),
    });
    const appDataA = await appResA.json();
    arAlice = appDataA.ar;

    // Obtain fresh AR for bob
    const nonceResB = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: bobDevId }),
    });
    const { nonceId: nIdB, nonce: nB } = await nonceResB.json();
    const qB = await bobTpm.quote(bobAk.handle, nB);
    const logB = await bobTpm.readEventLog();
    const appResB = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: bobDevId,
        nonceId: nIdB,
        quote: qB,
        eventLog: logB,
      }),
    });
    const appDataB = await appResB.json();
    arBob = appDataB.ar;

    // 6. Start IdP Gate / server.js
    idpKey = await loadOrCreateSigningKey("idp", { store: "memory", clock });
    const idpApp = createServerApp({
      ...testCfg,
      storeInstance: idpStore,
      idpKey,
      verifierJwks: publicJwks(verifierKey),
    });
    idpServer = http.createServer(idpApp);
    await new Promise((res) => idpServer.listen(0, "127.0.0.1", res));
    idpUrl = `http://127.0.0.1:${idpServer.address().port}`;
    testCfg.idpIssuer = idpUrl;
  });

  after(async () => {
    if (idpServer) idpServer.close();
    if (verifierServer) verifierServer.close();
    if (pipServer) pipServer.close();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  });

  // Helper to extract session cookies
  function extractCookie(res) {
    const raw = res.headers.get("set-cookie");
    if (!raw) return "";
    return raw.split(";")[0];
  }

  async function freshArAlice() {
    const nonceRes = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: aliceDevId }),
    });
    const { nonceId, nonce } = await nonceRes.json();
    const appRes = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: aliceDevId,
        nonceId,
        quote: await aliceTpm.quote(aliceAk.handle, nonce),
        eventLog: await aliceTpm.readEventLog(),
      }),
    });
    const { ar } = await appRes.json();
    return ar;
  }

  async function freshArBob() {
    const nonceRes = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: bobDevId }),
    });
    const { nonceId, nonce } = await nonceRes.json();
    const appRes = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: bobDevId,
        nonceId,
        quote: await bobTpm.quote(bobAk.handle, nonce),
        eventLog: await bobTpm.readEventLog(),
      }),
    });
    const { ar } = await appRes.json();
    return ar;
  }

  it("PAR with expired AR (clock + 121 s) -> 400", async () => {
    const savedTime = nowMs;
    nowMs += 121 * 1000; // Advance past tauAR (120 s)

    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

    const res = await fetch(`${idpUrl}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: "zta-agent",
        response_type: "code",
        redirect_uri: "http://127.0.0.1:7000/callback",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        dpop_jkt: aliceJkt,
        attestation_result: arAlice,
      }),
    });

    nowMs = savedTime; // Restore clock
    assert.equal(res.status, 400, "Expired AR must return 400");
    const data = await res.json();
    assert.equal(data.error, "invalid_request");
  });

  it("PAR with AR.jkt != dpop_jkt (check C2) -> 400 ar_jkt_mismatch", async () => {
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

    const res = await fetch(`${idpUrl}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: "zta-agent",
        response_type: "code",
        redirect_uri: "http://127.0.0.1:7000/callback",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        dpop_jkt: attackerJkt, // Mismatched dpop_jkt vs arAlice.jkt
        attestation_result: arAlice,
      }),
    });

    assert.equal(res.status, 400, "AR jkt mismatch must return 400");
    const data = await res.json();
    assert.equal(data.error_description, "ar_jkt_mismatch");
  });

  it("PAR with AR of device A plus key of device B -> 400 ar_jkt_mismatch", async () => {
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

    const res = await fetch(`${idpUrl}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: "zta-agent",
        response_type: "code",
        redirect_uri: "http://127.0.0.1:7000/callback",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        dpop_jkt: bobJkt, // Key of device B
        attestation_result: arAlice, // AR of device A
      }),
    });

    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.error_description, "ar_jkt_mismatch");
  });

  it("Login as bob using alice's device -> deny (403)", async () => {
    // 1. Fresh PAR for alice's device
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

    // Fresh AR for alice
    const nRes = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: aliceDevId }),
    });
    const { nonceId, nonce } = await nRes.json();
    const appRes = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: aliceDevId,
        nonceId,
        quote: await aliceTpm.quote(aliceAk.handle, nonce),
        eventLog: await aliceTpm.readEventLog(),
      }),
    });
    const { ar: freshArAlice } = await appRes.json();

    const parRes = await fetch(`${idpUrl}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: "zta-agent",
        response_type: "code",
        redirect_uri: "http://127.0.0.1:7000/callback",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        dpop_jkt: aliceJkt,
        attestation_result: freshArAlice,
      }),
    });
    assert.equal(parRes.status, 201);
    const { request_uri } = await parRes.json();

    // 2. Authorize with session cookie
    const authRes = await fetch(`${idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(request_uri)}`, {
      redirect: "manual",
    });
    assert.equal(authRes.status, 200);
    const cookie = extractCookie(authRes);

    // 3. Login as bob with bob's valid password on alice's device
    const loginRes = await fetch(`${idpUrl}/oauth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: cookie,
      },
      body: JSON.stringify({
        username: "bob",
        password: "bob-pass",
      }),
    });

    assert.equal(loginRes.status, 403, "Bob using Alice's device must be denied");
    const data = await loginRes.json();
    assert.equal(data.error, "access_denied");
  });

  it("Happy path: AT has cnf.jkt == jkt, exp - iat == 300, role == 'auditor', acr == 'pwd'; client-asserted role is ignored", async () => {
    // 1. Fresh PAR for alice
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

    const nRes = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: aliceDevId }),
    });
    const { nonceId, nonce } = await nRes.json();
    const appRes = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: aliceDevId,
        nonceId,
        quote: await aliceTpm.quote(aliceAk.handle, nonce),
        eventLog: await aliceTpm.readEventLog(),
      }),
    });
    const { ar } = await appRes.json();

    // Include attacker-injected role="admin" in PAR body (must be ignored)
    const parRes = await fetch(`${idpUrl}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: "zta-agent",
        response_type: "code",
        redirect_uri: "http://127.0.0.1:7000/callback",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        dpop_jkt: aliceJkt,
        attestation_result: ar,
        role: "admin", // Must be ignored!
      }),
    });
    assert.equal(parRes.status, 201);
    const { request_uri } = await parRes.json();

    // 2. Authorize
    const authRes = await fetch(`${idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(request_uri)}`);
    const cookie = extractCookie(authRes);

    // 3. Login as alice
    const loginRes = await fetch(`${idpUrl}/oauth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        Cookie: cookie,
      },
      body: JSON.stringify({
        username: "alice",
        password: "alice-pass",
      }),
    });

    assert.equal(loginRes.status, 200);
    const loginData = await loginRes.json();
    assert.ok(loginData.redirect, "Should provide redirect URL with authorization code");
    const code = loginData.code || new URL(loginData.redirect).searchParams.get("code");
    assert.ok(code, "Authorization code must be present");

    // 4. Token exchange without DPoP -> 400
    const noDpopRes = await fetch(`${idpUrl}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        code_verifier: codeVerifier,
      }),
    });
    assert.equal(noDpopRes.status, 400, "Token request without DPoP must fail 400");

    // 5. Token exchange with DPoP but missing/stale nonce -> 400 use_dpop_nonce
    const tokenUrl = `${idpUrl}/oauth/token`;
    const proofNoNonce = await signProof({
      signer: (data) => aliceTpm.sign(aliceKb.handle, data),
      publicJwk: jwkOf(aliceKb.publicArea),
      htm: "POST",
      htu: tokenUrl,
      clock,
    });

    const nonceChallengeRes = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        DPoP: proofNoNonce,
      },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        code_verifier: codeVerifier,
      }),
    });
    assert.equal(nonceChallengeRes.status, 400, "Missing nonce must return 400");
    const nonceData = await nonceChallengeRes.json();
    assert.equal(nonceData.error, "use_dpop_nonce");
    const serverNonce = nonceChallengeRes.headers.get("DPoP-Nonce");
    assert.ok(serverNonce, "Server must supply DPoP-Nonce header");

    // 6. Token exchange with proof signed by another key -> 400
    const attackerProof = await signProof({
      privateKey: attackerKeyPair.privateKey,
      publicJwk: attackerPublicJwk,
      htm: "POST",
      htu: tokenUrl,
      nonce: serverNonce,
      clock,
    });

    const badKeyRes = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        DPoP: attackerProof,
      },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        code_verifier: codeVerifier,
      }),
    });
    assert.equal(badKeyRes.status, 400, "Proof signed by other key must return 400");

    // 7. Token exchange happy path: proof signed by alice's K_B with nonce
    // Note: get a fresh server nonce
    const freshNonceRes = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ grant_type: "authorization_code" }),
    });
    const freshNonce = freshNonceRes.headers.get("DPoP-Nonce");

    const validProof = await signProof({
      signer: (data) => aliceTpm.sign(aliceKb.handle, data),
      publicJwk: jwkOf(aliceKb.publicArea),
      htm: "POST",
      htu: tokenUrl,
      nonce: freshNonce,
      clock,
    });

    const tokenRes = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        DPoP: validProof,
      },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        code_verifier: codeVerifier,
      }),
    });

    assert.equal(tokenRes.status, 200, "Valid token exchange must return 200");
    const tokens = await tokenRes.json();
    assert.equal(tokens.token_type, "DPoP");
    assert.equal(tokens.expires_in, 300);
    assert.ok(tokens.access_token);
    assert.ok(tokens.refresh_token);

    // Verify AT claims
    const atParts = tokens.access_token.split(".");
    const atPayload = JSON.parse(Buffer.from(atParts[1], "base64url").toString("utf8"));

    assert.equal(atPayload.sub, "alice");
    assert.equal(atPayload.cnf?.jkt, aliceJkt);
    assert.equal(atPayload.exp - atPayload.iat, 300);
    assert.equal(atPayload.role, "auditor", "Role must be auditor from directory (not admin from PAR)");
    assert.equal(atPayload.acr, "pwd");
    assert.equal(atPayload.dev, aliceDevId);
  });

  it("Refresh after device revocation in PIP -> 400 invalid_grant (device_not_active)", async () => {
    // 1. Obtain an AT + RT for alice
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

    const nRes = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: aliceDevId }),
    });
    const { nonceId, nonce } = await nRes.json();
    const appRes = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: aliceDevId,
        nonceId,
        quote: await aliceTpm.quote(aliceAk.handle, nonce),
        eventLog: await aliceTpm.readEventLog(),
      }),
    });
    const { ar } = await appRes.json();

    const parRes = await fetch(`${idpUrl}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: "zta-agent",
        response_type: "code",
        redirect_uri: "http://127.0.0.1:7000/callback",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        dpop_jkt: aliceJkt,
        attestation_result: ar,
      }),
    });
    const { request_uri } = await parRes.json();

    const authRes = await fetch(`${idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(request_uri)}`);
    const cookie = extractCookie(authRes);

    const loginRes = await fetch(`${idpUrl}/oauth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        Cookie: cookie,
      },
      body: JSON.stringify({ username: "alice", password: "alice-pass" }),
    });
    const { code } = await loginRes.json();

    const tokenUrl = `${idpUrl}/oauth/token`;
    const noncePre = (await (await fetch(tokenUrl, { method: "POST", body: "{}" })).headers.get("DPoP-Nonce"));

    const dpopExchange = await signProof({
      signer: (data) => aliceTpm.sign(aliceKb.handle, data),
      publicJwk: jwkOf(aliceKb.publicArea),
      htm: "POST",
      htu: tokenUrl,
      nonce: noncePre,
      clock,
    });

    const tokenRes = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", DPoP: dpopExchange },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        code_verifier: codeVerifier,
      }),
    });
    const { refresh_token } = await tokenRes.json();
    assert.ok(refresh_token);

    // 2. Revoke Alice's device in PIP
    await fetch(`${pipUrl}/pip/device/${aliceDevId}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ZTA-Internal": testCfg.ztaInternalToken,
      },
      body: JSON.stringify({ status: "revoked" }),
    });

    // 3. Attempt refresh with valid DPoP proof
    const nonceRefresh = (await (await fetch(tokenUrl, { method: "POST", body: "{}" })).headers.get("DPoP-Nonce"));
    const dpopRefresh = await signProof({
      signer: (data) => aliceTpm.sign(aliceKb.handle, data),
      publicJwk: jwkOf(aliceKb.publicArea),
      htm: "POST",
      htu: tokenUrl,
      nonce: nonceRefresh,
      clock,
    });

    const refreshRes = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        DPoP: dpopRefresh,
      },
      body: JSON.stringify({
        grant_type: "refresh_token",
        refresh_token,
      }),
    });

    assert.equal(refreshRes.status, 400, "Refresh on revoked device must fail with 400");
    const refreshData = await refreshRes.json();
    assert.equal(refreshData.error, "invalid_grant");
    assert.equal(refreshData.error_description, "device_not_active");

    // Restore device status to active for subsequent tests
    await fetch(`${pipUrl}/pip/device/${aliceDevId}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ZTA-Internal": testCfg.ztaInternalToken,
      },
      body: JSON.stringify({ status: "active" }),
    });
  });

  it("Sim-IP Berlin -> Sydney within 1 h gives rho >= 0.5 and redirects to stepup", async () => {
    // Set up prior successful login in Berlin at t0
    const t0 = nowMs - 1800 * 1000; // 30 minutes ago
    await fetch(`${pipUrl}/pip/login-event`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ZTA-Internal": testCfg.ztaInternalToken,
      },
      body: JSON.stringify({
        sub: "alice",
        dev: aliceDevId,
        ip: "192.0.2.10", // Berlin (AS6805)
        t: t0,
        success: true,
      }),
    });

    // Register a WebAuthn credential for Alice on device so step-up has an enrolled credential
    const softAuth = new SoftAuthenticator();
    const credData = {
      id: softAuth.credId.toString("base64url"),
      publicKey: softAuth.getCosePublicKey().toString("base64url"),
      counter: 0,
      transports: ["internal"],
    };
    await idpStore.set(`webauthn/alice/${aliceDevId}`, {
      user_id: "alice",
      device_id: aliceDevId,
      credential: credData,
    });

    // Start PAR
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

    const nRes = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: aliceDevId }),
    });
    const { nonceId, nonce } = await nRes.json();
    const appRes = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: aliceDevId,
        nonceId,
        quote: await aliceTpm.quote(aliceAk.handle, nonce),
        eventLog: await aliceTpm.readEventLog(),
      }),
    });
    const { ar } = await appRes.json();

    const parRes = await fetch(`${idpUrl}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: "zta-agent",
        response_type: "code",
        redirect_uri: "http://127.0.0.1:7000/callback",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        dpop_jkt: aliceJkt,
        attestation_result: ar,
      }),
    });
    const { request_uri } = await parRes.json();

    const authRes = await fetch(`${idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(request_uri)}`);
    const cookie = extractCookie(authRes);

    // Login from Sydney (198.51.100.20) via X-ZTA-Sim-IP
    const loginRes = await fetch(`${idpUrl}/oauth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-ZTA-Sim-IP": "198.51.100.20", // Sydney
        Cookie: cookie,
      },
      body: JSON.stringify({ username: "alice", password: "alice-pass" }),
    });

    assert.equal(loginRes.status, 200);
    const loginData = await loginRes.json();
    assert.equal(loginData.redirect, "/stepup.html", "Should redirect to stepup due to rho >= 0.5");
    assert(loginData.risk >= 0.5, `Risk score should be >= 0.5, got ${loginData.risk}`);
  });

  it("Failures plus impossible travel plus new ASN give rho >= 0.85 and deny (403)", async () => {
    // Reset Alice's history in PIP: prior login on a different device in Berlin
    await pipStore.set("history/alice", [
      {
        sub: "alice",
        dev: "old-berlin-device",
        ip: "192.0.2.10", // Berlin (AS6805)
        t: nowMs - 1800 * 1000,
        success: true,
      },
    ]);

    // Set attestation age >= 600s so f4 = 1
    await fetch(`${pipUrl}/pip/device/${aliceDevId}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ZTA-Internal": testCfg.ztaInternalToken,
      },
      body: JSON.stringify({
        last_good_attestation: nowMs - 601 * 1000,
        attestation_age_s: 601,
      }),
    });

    // Add 5 failed login events in the last 15 minutes (f5 = 1)
    for (let i = 0; i < 5; i++) {
      await fetch(`${pipUrl}/pip/login-event`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ZTA-Internal": testCfg.ztaInternalToken,
        },
        body: JSON.stringify({
          sub: "alice",
          dev: aliceDevId,
          ip: "198.51.100.20",
          t: nowMs - 60 * 1000 * (i + 1),
          success: false,
        }),
      });
    }

    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

    const nRes = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: aliceDevId }),
    });
    const { nonceId, nonce } = await nRes.json();
    const appRes = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: aliceDevId,
        nonceId,
        quote: await aliceTpm.quote(aliceAk.handle, nonce),
        eventLog: await aliceTpm.readEventLog(),
      }),
    });
    const { ar } = await appRes.json();

    const parRes = await fetch(`${idpUrl}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: "zta-agent",
        response_type: "code",
        redirect_uri: "http://127.0.0.1:7000/callback",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        dpop_jkt: aliceJkt,
        attestation_result: ar,
      }),
    });
    const { request_uri } = await parRes.json();

    // Re-set attestation age >= 600s after appraise so f4 = 1 during login
    await fetch(`${pipUrl}/pip/device/${aliceDevId}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ZTA-Internal": testCfg.ztaInternalToken,
      },
      body: JSON.stringify({
        last_good_attestation: nowMs - 601 * 1000,
        attestation_age_s: 601,
      }),
    });

    const authRes = await fetch(`${idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(request_uri)}`);
    const cookie = extractCookie(authRes);

    // Login from Sydney (198.51.100.20): travel(w2=0.25) + new ASN(w1=0.25) + 5 fails(w5=0.15) + f4(0.15) + f6(0.10) = 0.90 >= 0.85
    const loginRes = await fetch(`${idpUrl}/oauth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ZTA-Sim-IP": "198.51.100.20",
        Cookie: cookie,
      },
      body: JSON.stringify({ username: "alice", password: "alice-pass" }),
    });

    assert.equal(loginRes.status, 403, "Risk >= 0.85 must deny with 403");
    const data = await loginRes.json();
    assert.equal(data.error, "access_denied");
    assert(data.risk >= 0.85, `Risk score should be >= 0.85, got ${data.risk}`);
  });

  it("WebAuthn step-up path: assertion elevates session to acr = 'mfa'", async () => {
    // 1. Fresh PAR for bob with acr_values="mfa" explicitly requested
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

    const nRes = await fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: bobDevId }),
    });
    const { nonceId, nonce } = await nRes.json();
    const appRes = await fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: bobDevId,
        nonceId,
        quote: await bobTpm.quote(bobAk.handle, nonce),
        eventLog: await bobTpm.readEventLog(),
      }),
    });
    const { ar } = await appRes.json();

    const parRes = await fetch(`${idpUrl}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: "zta-agent",
        response_type: "code",
        redirect_uri: "http://127.0.0.1:7000/callback",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        dpop_jkt: bobJkt,
        attestation_result: ar,
        acr_values: "mfa", // Request step-up
      }),
    });
    const { request_uri } = await parRes.json();

    const authRes = await fetch(`${idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(request_uri)}`);
    const cookie = extractCookie(authRes);

    // Register Bob's WebAuthn credential in store using SoftAuthenticator
    const bobSoftAuth = new SoftAuthenticator();
    const bobCredData = {
      id: bobSoftAuth.credId.toString("base64url"),
      publicKey: bobSoftAuth.getCosePublicKey().toString("base64url"),
      counter: 0,
      transports: ["internal"],
    };
    await idpStore.set(`webauthn/bob/${bobDevId}`, {
      user_id: "bob",
      device_id: bobDevId,
      credential: bobCredData,
    });

    // 2. Primary login as Bob
    const loginRes = await fetch(`${idpUrl}/oauth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        Cookie: cookie,
      },
      body: JSON.stringify({ username: "bob", password: "bob-pass" }),
    });

    assert.equal(loginRes.status, 200);
    const loginData = await loginRes.json();
    assert.equal(loginData.redirect, "/stepup.html", "Must redirect to step-up because acr_values=mfa");

    // 3. Step-up WebAuthn authentication
    const authOptsRes = await fetch(`${idpUrl}/mfa/auth/options`, {
      headers: { Cookie: cookie },
    });
    assert.equal(authOptsRes.status, 200);
    const authOpts = await authOptsRes.json();

    const authAssertion = bobSoftAuth.createAuthenticationResponse(authOpts, {
      origin: idpUrl,
      rpID: new URL(idpUrl).hostname,
    });

    const verifyMfaRes = await fetch(`${idpUrl}/mfa/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookie },
      body: JSON.stringify(authAssertion),
    });

    assert.equal(verifyMfaRes.status, 200);
    const mfaData = await verifyMfaRes.json();
    assert.equal(mfaData.success, true);
    assert.equal(mfaData.acr, "mfa");
    assert.ok(mfaData.code);

    // 4. Token exchange with authorization code from step-up
    const tokenUrl = `${idpUrl}/oauth/token`;
    const noncePre = (await (await fetch(tokenUrl, { method: "POST", body: "{}" })).headers.get("DPoP-Nonce"));

    const bobProof = await signProof({
      signer: (data) => bobTpm.sign(bobKb.handle, data),
      publicJwk: jwkOf(bobKb.publicArea),
      htm: "POST",
      htu: tokenUrl,
      nonce: noncePre,
      clock,
    });

    const tokenRes = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", DPoP: bobProof },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code: mfaData.code,
        code_verifier: codeVerifier,
      }),
    });

    assert.equal(tokenRes.status, 200);
    const tokens = await tokenRes.json();
    assert.ok(tokens.access_token);

    const atParts = tokens.access_token.split(".");
    const atPayload = JSON.parse(Buffer.from(atParts[1], "base64url").toString("utf8"));
    assert.equal(atPayload.sub, "bob");
    assert.equal(atPayload.acr, "mfa", "AT must have acr=mfa after WebAuthn step-up");
    assert.equal(atPayload.role, "employee");
    assert.equal(atPayload.cnf?.jkt, bobJkt);
  });

  it("Metadata and JWKS endpoints return valid discovery info", async () => {
    const metaRes = await fetch(`${idpUrl}/.well-known/oauth-authorization-server`);
    assert.equal(metaRes.status, 200);
    const meta = await metaRes.json();
    assert.equal(meta.issuer, idpUrl);
    assert.equal(meta.require_pushed_authorization_requests, true);
    assert.deepEqual(meta.dpop_signing_alg_values_supported, ["ES256"]);

    const jwksRes = await fetch(`${idpUrl}/oauth/jwks`);
    assert.equal(jwksRes.status, 200);
    const jwks = await jwksRes.json();
    assert.ok(Array.isArray(jwks.keys));
    assert.equal(jwks.keys.length, 1);
    assert.equal(jwks.keys[0].kty, "EC");
    assert.equal(jwks.keys[0].crv, "P-256");
  });

  it("Auth check endpoint (/api/auth/check) reflects IdP session state", async () => {
    const unauthRes = await fetch(`${idpUrl}/api/auth/check`);
    assert.equal(unauthRes.status, 200);
    const unauthData = await unauthRes.json();
    assert.equal(unauthData.authenticated, false);
  });

  it("Devices endpoint (/api/devices) requires auth (401 unauth) and renders with admin token", async () => {
    // Unauthenticated request -> 401
    const unauthRes = await fetch(`${idpUrl}/api/devices`);
    assert.equal(unauthRes.status, 401);

    // Authenticated request with admin token -> 200
    const devRes = await fetch(`${idpUrl}/api/devices`, {
      headers: { Authorization: `Bearer ${testCfg.adminToken}` },
    });
    assert.equal(devRes.status, 200);
    const html = await devRes.text();
    assert(html.includes("TPM Device Registry"), "Should contain registry title");
    assert(html.includes(aliceDevId), "Should contain Alice's devId");
    assert(html.includes("Verification:</b> TPM quote + credential activation"), "Should contain verified status text");
    assert(!html.includes("created_at"), "Should not have created_at bug");
  });

  it("Regression F1: WebAuthn registration rejected during pending oauthTxn, requires completed idpUser, and replacement requires assertion", async () => {
    // Reset Alice's history and device status in PIP
    await pipStore.set("history/alice", []);
    await fetch(`${pipUrl}/pip/device/${aliceDevId}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ZTA-Internal": testCfg.ztaInternalToken,
      },
      body: JSON.stringify({
        status: "active",
        last_good_attestation: nowMs,
        attestation_age_s: 0,
      }),
    });

    const freshAr = await freshArAlice();

    // 1. Initiate PAR + authorize to get a session with pending oauthTxn
    const parRes = await fetch(`${idpUrl}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "zta-agent",
        response_type: "code",
        code_challenge: "challenge-f1",
        code_challenge_method: "S256",
        redirect_uri: "http://127.0.0.1:7000/callback",
        dpop_jkt: aliceJkt,
        attestation_result: freshAr,
      }),
    });
    assert.equal(parRes.status, 201);
    const { request_uri } = await parRes.json();

    const authRes = await fetch(`${idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(request_uri)}`);
    assert.equal(authRes.status, 200);
    const oauthCookie = extractCookie(authRes);

    // Ungated pending oauthTxn without a completed idpUser: registration still refused (401, N2)
    const regOptsPendingRes = await fetch(`${idpUrl}/mfa/register/options`, {
      headers: { Cookie: oauthCookie },
    });
    assert.equal(regOptsPendingRes.status, 401);

    const regVerifyPendingRes = await fetch(`${idpUrl}/mfa/register/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: oauthCookie },
      body: JSON.stringify({}),
    });
    assert.equal(regVerifyPendingRes.status, 401);

    // 2. Unauthenticated session (no idpUser) -> 401
    const unauthOptsRes = await fetch(`${idpUrl}/mfa/register/options`);
    assert.equal(unauthOptsRes.status, 401);

    // 3. Complete login as alice to obtain genuine idpUser session
    const loginRes = await fetch(`${idpUrl}/oauth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Cookie: oauthCookie,
      },
      body: JSON.stringify({ username: "alice", password: "alice-pass" }),
    });
    assert.equal(loginRes.status, 200);

    // Clean existing credential for alice to test first enrolment
    await idpStore.del(`webauthn/alice/${aliceDevId}`);

    // First enrolment from completed idpUser session succeeds
    const regOptsRes = await fetch(`${idpUrl}/mfa/register/options`, {
      headers: { Cookie: oauthCookie },
    });
    assert.equal(regOptsRes.status, 200);
    const regOpts = await regOptsRes.json();

    const softAuth1 = new SoftAuthenticator();
    const regResp1 = softAuth1.createRegistrationResponse(regOpts, {
      expectedOrigin: idpUrl,
      rpID: new URL(idpUrl).hostname,
    });

    const regVerifyRes = await fetch(`${idpUrl}/mfa/register/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: oauthCookie },
      body: JSON.stringify(regResp1),
    });
    assert.equal(regVerifyRes.status, 200);

    // 4. Attempting to register again WITHOUT prior assertion -> 403 credential_exists
    const regOptsAgainRes = await fetch(`${idpUrl}/mfa/register/options`, {
      headers: { Cookie: oauthCookie },
    });
    assert.equal(regOptsAgainRes.status, 403);
    const regOptsAgainBody = await regOptsAgainRes.json();
    assert.equal(regOptsAgainBody.error, "credential_exists");

    // 5. A gated step-up in progress (oauthTxn.gated) blocks registration: 403 registration_forbidden
    const stepUpAr = await freshArAlice();
    const stepUpParRes = await fetch(`${idpUrl}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: "zta-agent",
        response_type: "code",
        code_challenge: "challenge-f1-stepup",
        code_challenge_method: "S256",
        redirect_uri: "http://127.0.0.1:7000/callback",
        dpop_jkt: aliceJkt,
        attestation_result: stepUpAr,
        acr_values: "mfa",
      }),
    });
    assert.equal(stepUpParRes.status, 201);
    const { request_uri: stepUpUri } = await stepUpParRes.json();
    const stepUpAuthRes = await fetch(`${idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(stepUpUri)}`, {
      headers: { Cookie: oauthCookie },
    });
    assert.equal(stepUpAuthRes.status, 200);
    const stepUpLoginRes = await fetch(`${idpUrl}/oauth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json", Cookie: oauthCookie },
      body: JSON.stringify({ username: "alice", password: "alice-pass" }),
    });
    assert.equal(stepUpLoginRes.status, 200);
    assert.equal((await stepUpLoginRes.json()).redirect, "/stepup.html");

    const regOptsGatedRes = await fetch(`${idpUrl}/mfa/register/options`, {
      headers: { Cookie: oauthCookie },
    });
    assert.equal(regOptsGatedRes.status, 403);
    assert.equal((await regOptsGatedRes.json()).error, "registration_forbidden");
    const regVerifyGatedRes = await fetch(`${idpUrl}/mfa/register/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: oauthCookie },
      body: JSON.stringify({}),
    });
    assert.equal(regVerifyGatedRes.status, 403);
    assert.equal((await regVerifyGatedRes.json()).error, "registration_forbidden");

    // 6. Performing an assertion with the enrolled credential (completing the step-up) unlocks replacement
    const authOptsRes = await fetch(`${idpUrl}/mfa/auth/options`, {
      headers: { Cookie: oauthCookie },
    });
    assert.equal(authOptsRes.status, 200);
    const authOpts = await authOptsRes.json();

    const authAssertion = softAuth1.createAuthenticationResponse(authOpts, {
      expectedOrigin: idpUrl,
      rpID: new URL(idpUrl).hostname,
    });

    const verifyAssertionRes = await fetch(`${idpUrl}/mfa/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: oauthCookie },
      body: JSON.stringify(authAssertion),
    });
    assert.equal(verifyAssertionRes.status, 200);

    // Now replacement options and verify should succeed with authenticator 2
    const replaceOptsRes = await fetch(`${idpUrl}/mfa/register/options`, {
      headers: { Cookie: oauthCookie },
    });
    assert.equal(replaceOptsRes.status, 200);
    const replaceOpts = await replaceOptsRes.json();

    const softAuth2 = new SoftAuthenticator();
    const regResp2 = softAuth2.createRegistrationResponse(replaceOpts, {
      expectedOrigin: idpUrl,
      rpID: new URL(idpUrl).hostname,
    });

    const replaceVerifyRes = await fetch(`${idpUrl}/mfa/register/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: oauthCookie },
      body: JSON.stringify(regResp2),
    });
    assert.equal(replaceVerifyRes.status, 200);
  });

  // Helper for N2/N3: PAR (+ optional acr_values) and authorize, reusing a session cookie if given
  async function parAuthorizeAlice({ cookie, acrValues } = {}) {
    const ar = await freshArAlice();
    const parRes = await fetch(`${idpUrl}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: "zta-agent",
        response_type: "code",
        code_challenge: "challenge-n",
        code_challenge_method: "S256",
        redirect_uri: "http://127.0.0.1:7000/callback",
        dpop_jkt: aliceJkt,
        attestation_result: ar,
        ...(acrValues ? { acr_values: acrValues } : {}),
      }),
    });
    assert.equal(parRes.status, 201);
    const { request_uri } = await parRes.json();
    const authRes = await fetch(`${idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(request_uri)}`, {
      headers: cookie ? { Cookie: cookie } : {},
    });
    assert.equal(authRes.status, 200);
    return cookie || extractCookie(authRes);
  }

  async function loginAlice(cookie) {
    return fetch(`${idpUrl}/oauth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json", Cookie: cookie },
      body: JSON.stringify({ username: "alice", password: "alice-pass" }),
    });
  }

  async function resetAliceInPip() {
    await pipStore.set("history/alice", []);
    await fetch(`${pipUrl}/pip/device/${aliceDevId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-ZTA-Internal": testCfg.ztaInternalToken },
      body: JSON.stringify({ status: "active", last_good_attestation: nowMs, attestation_age_s: 0 }),
    });
  }

  it("Regression N2: terminal gate failure clears oauthTxn; abandoned/ungated txn does not block WebAuthn enrolment", async () => {
    await resetAliceInPip();
    await idpStore.del(`webauthn/alice/${aliceDevId}`);

    // pwd login -> completed idpUser session
    const cookie = await parAuthorizeAlice();
    assert.equal((await loginAlice(cookie)).status, 200);

    // "VERIFY IDENTITY" without an enrolled credential -> 403 mfa_not_enrolled (terminal gate failure)
    await parAuthorizeAlice({ cookie, acrValues: "mfa" });
    const stepUpRes = await loginAlice(cookie);
    assert.equal(stepUpRes.status, 403);
    assert.equal((await stepUpRes.json()).error, "mfa_not_enrolled");

    // The failed txn is gone: a second /oauth/login finds no transaction
    const retryRes = await loginAlice(cookie);
    assert.equal(retryRes.status, 400);
    assert.equal((await retryRes.json()).error, "invalid_request");

    // Enrolment is now possible from the same browser session
    const regOptsRes = await fetch(`${idpUrl}/mfa/register/options`, { headers: { Cookie: cookie } });
    assert.equal(regOptsRes.status, 200);

    // An abandoned (ungated) /oauth/authorize also does not block enrolment
    await parAuthorizeAlice({ cookie });
    const regOptsRes2 = await fetch(`${idpUrl}/mfa/register/options`, { headers: { Cookie: cookie } });
    assert.equal(regOptsRes2.status, 200);
    const softAuth = new SoftAuthenticator();
    const regResp = softAuth.createRegistrationResponse(await regOptsRes2.json(), {
      expectedOrigin: idpUrl,
      rpID: new URL(idpUrl).hostname,
    });
    const regVerifyRes = await fetch(`${idpUrl}/mfa/register/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookie },
      body: JSON.stringify(regResp),
    });
    assert.equal(regVerifyRes.status, 200);
  });

  it("Regression N3/N4: replacement grant expires after 120 s; expired gated txn rejected at /mfa/verify", async () => {
    await resetAliceInPip();
    await idpStore.del(`webauthn/alice/${aliceDevId}`);
    const savedTime = nowMs;
    try {
      const cookie = await parAuthorizeAlice();
      assert.equal((await loginAlice(cookie)).status, 200);

      // Enrol credential A
      const softA = new SoftAuthenticator();
      const optsA = await (await fetch(`${idpUrl}/mfa/register/options`, { headers: { Cookie: cookie } })).json();
      const regA = softA.createRegistrationResponse(optsA, { expectedOrigin: idpUrl, rpID: new URL(idpUrl).hostname });
      const regARes = await fetch(`${idpUrl}/mfa/register/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: cookie },
        body: JSON.stringify(regA),
      });
      assert.equal(regARes.status, 200);

      // Standalone assertion with A -> replacement grant
      const assertA = async () => {
        const authOpts = await (await fetch(`${idpUrl}/mfa/auth/options`, { headers: { Cookie: cookie } })).json();
        const assertion = softA.createAuthenticationResponse(authOpts, { expectedOrigin: idpUrl, rpID: new URL(idpUrl).hostname });
        const res = await fetch(`${idpUrl}/mfa/verify`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Cookie: cookie },
          body: JSON.stringify(assertion),
        });
        assert.equal(res.status, 200);
      };
      await assertA();

      // N3: 121 s later the grant has expired in both register handlers
      nowMs += 121 * 1000;
      const lateOpts = await fetch(`${idpUrl}/mfa/register/options`, { headers: { Cookie: cookie } });
      assert.equal(lateOpts.status, 403);
      assert.equal((await lateOpts.json()).error, "credential_exists");
      const lateVerify = await fetch(`${idpUrl}/mfa/register/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: cookie },
        body: JSON.stringify({}),
      });
      assert.equal(lateVerify.status, 403);
      assert.equal((await lateVerify.json()).error, "credential_exists");

      // A fresh assertion within 120 s re-grants replacement
      await assertA();
      nowMs += 60 * 1000;
      const inWindowOpts = await fetch(`${idpUrl}/mfa/register/options`, { headers: { Cookie: cookie } });
      assert.equal(inWindowOpts.status, 200);

      // N4: a gated step-up txn past its PAR lifetime is rejected at /mfa/verify
      await resetAliceInPip();
      await parAuthorizeAlice({ cookie, acrValues: "mfa" });
      const stepUpRes = await loginAlice(cookie);
      assert.equal(stepUpRes.status, 200);
      assert.equal((await stepUpRes.json()).redirect, "/stepup.html");
      const authOpts = await (await fetch(`${idpUrl}/mfa/auth/options`, { headers: { Cookie: cookie } })).json();
      const assertion = softA.createAuthenticationResponse(authOpts, { expectedOrigin: idpUrl, rpID: new URL(idpUrl).hostname });
      nowMs += 61 * 1000;
      const expiredRes = await fetch(`${idpUrl}/mfa/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: cookie },
        body: JSON.stringify(assertion),
      });
      assert.equal(expiredRes.status, 400);
      const expiredBody = await expiredRes.json();
      assert.equal(expiredBody.error, "invalid_request");
      assert.ok(!expiredBody.code, "No authorization code for an expired txn");
    } finally {
      nowMs = savedTime;
    }
  });

  it("Regression F2: /mfa/auth/options and /mfa/verify reject ungated oauthTxn and never fall back to idpUser for code issuance", async () => {
    // Reset Alice's history in PIP
    await pipStore.set("history/alice", []);
    await fetch(`${pipUrl}/pip/device/${aliceDevId}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ZTA-Internal": testCfg.ztaInternalToken,
      },
      body: JSON.stringify({
        status: "active",
        last_good_attestation: nowMs,
        attestation_age_s: 0,
      }),
    });

    const freshArA = await freshArAlice();

    // 1. Establish an idpUser session for alice
    const parRes1 = await fetch(`${idpUrl}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "zta-agent",
        response_type: "code",
        code_challenge: "challenge-f2-1",
        code_challenge_method: "S256",
        redirect_uri: "http://127.0.0.1:7000/callback",
        dpop_jkt: aliceJkt,
        attestation_result: freshArA,
      }),
    });
    assert.equal(parRes1.status, 201);
    const { request_uri: reqUri1 } = await parRes1.json();
    const authRes1 = await fetch(`${idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(reqUri1)}`);
    const sessionCookie = extractCookie(authRes1);

    const loginRes = await fetch(`${idpUrl}/oauth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json", Cookie: sessionCookie },
      body: JSON.stringify({ username: "alice", password: "alice-pass" }),
    });
    assert.equal(loginRes.status, 200);

    // Ensure bob is enrolled with a WebAuthn credential
    const bobSoftAuth = new SoftAuthenticator();
    await bobSoftAuth.registerInStore(idpStore, "bob", bobDevId);

    // Reset Bob's history in PIP
    await pipStore.set("history/bob", []);
    await fetch(`${pipUrl}/pip/device/${bobDevId}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ZTA-Internal": testCfg.ztaInternalToken,
      },
      body: JSON.stringify({
        status: "active",
        last_good_attestation: nowMs,
        attestation_age_s: 0,
      }),
    });

    const freshArB = await freshArBob();

    // 2. Start a new transaction as Bob (dev: bobDevId) using the SAME browser session cookie
    const parRes2 = await fetch(`${idpUrl}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "zta-agent",
        response_type: "code",
        code_challenge: "challenge-f2-2",
        code_challenge_method: "S256",
        redirect_uri: "http://127.0.0.1:7000/callback",
        dpop_jkt: bobJkt,
        attestation_result: freshArB,
        acr_values: "mfa",
      }),
    });
    assert.equal(parRes2.status, 201);
    const { request_uri: reqUri2 } = await parRes2.json();

    // Browser navigates to authorize
    const authRes2 = await fetch(`${idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(reqUri2)}`, {
      headers: { Cookie: sessionCookie },
    });
    assert.equal(authRes2.status, 200);

    // Transaction is now in session, but has NOT passed gateAfterPrimaryAuth (/oauth/login)
    // Attempting /mfa/auth/options directly MUST be rejected (403 unauthorized_transaction)
    const mfaOptsRes = await fetch(`${idpUrl}/mfa/auth/options`, {
      headers: { Cookie: sessionCookie },
    });
    assert.equal(mfaOptsRes.status, 403);
    const mfaOptsBody = await mfaOptsRes.json();
    assert.equal(mfaOptsBody.error, "unauthorized_transaction");

    // Attempting /mfa/verify directly MUST also be rejected (403)
    const mfaVerifyRes = await fetch(`${idpUrl}/mfa/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: sessionCookie },
      body: JSON.stringify({}),
    });
    assert.equal(mfaVerifyRes.status, 403);
    const mfaVerifyBody = await mfaVerifyRes.json();
    assert.equal(mfaVerifyBody.error, "unauthorized_transaction");
  });

  it("Regression F5: PAR request_uri is single-use and /oauth/login re-checks txn expiry", async () => {
    const freshAr = await freshArAlice();

    // 1. Create PAR transaction
    const parRes = await fetch(`${idpUrl}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "zta-agent",
        response_type: "code",
        code_challenge: "challenge-f5",
        code_challenge_method: "S256",
        redirect_uri: "http://127.0.0.1:7000/callback",
        dpop_jkt: aliceJkt,
        attestation_result: freshAr,
      }),
    });
    assert.equal(parRes.status, 201);
    const { request_uri } = await parRes.json();

    // 2. First authorize succeeds
    const authRes1 = await fetch(`${idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(request_uri)}`);
    assert.equal(authRes1.status, 200);
    const cookie = extractCookie(authRes1);

    // 3. Second authorize with SAME request_uri MUST fail (400 single-use)
    const authRes2 = await fetch(`${idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(request_uri)}`);
    assert.equal(authRes2.status, 400);
    const authBody2 = await authRes2.json();
    assert.equal(authBody2.error, "invalid_request");
    assert(authBody2.error_description.includes("Unknown or expired"));

    // 4. Test expired transaction in /oauth/login
    // Advance clock past txn expiry (60 s lifetime)
    nowMs += 65000;
    const loginExpiredRes = await fetch(`${idpUrl}/oauth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: cookie,
      },
      body: JSON.stringify({ username: "alice", password: "alice-pass" }),
    });
    assert.equal(loginExpiredRes.status, 400);
    const loginExpiredBody = await loginExpiredRes.json();
    assert.equal(loginExpiredBody.error, "invalid_request");
    assert(loginExpiredBody.error_description.includes("expired"));

    // Restore clock
    nowMs -= 65000;
  });
});
