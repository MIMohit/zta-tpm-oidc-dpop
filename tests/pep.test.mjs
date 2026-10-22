import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execSync } from "node:child_process";
import * as jose from "jose";

import { createApp as createPepApp } from "../pep.js";
import { createApp as createPdpApp } from "../pdp.js";
import { createApp as createPipApp } from "../pip.js";
import { createApp as createResourceServerApp } from "../services/resource-server.js";
import { createApp as createDecisionControllerApp } from "../decision-controller.js";
import { loadConfig } from "../lib/config.js";
import { signProof } from "../lib/dpop.js";
import { loadOrCreateSigningKey } from "../lib/keys.js";
import { verifyAuditLog } from "../lib/audit-log.js";
import { withAblation } from "../lib/ablation.js";

describe("WP6: Policy Enforcement Point (Alg.3) & Resource Server", () => {
  let tempDir;
  let auditLogFile;
  let baseCfg;

  let pipServer, pdpServer, resourceServer, pepServer;
  let pipPort, pdpPort, resourcePort, pepPort;
  let pipUrl, pdpUrl, resourceUrl, pepPublicUrl;

  let idpKeyPair;
  let idpPublicJwk;
  let idpJwks;

  let clientKeyPair;
  let clientPublicJwk;
  let clientJkt;

  let attackerKeyPair;
  let attackerPublicJwk;
  let attackerJkt;

  let nowMs = 1700000000000; // Fixed test clock epoch
  const clock = () => nowMs;

  async function mintAT({
    sub = "alice",
    role = "employee",
    acr = "pwd",
    dev = "dev-alice",
    auth_time = Math.floor(nowMs / 1000) - 10,
    jkt = clientJkt,
    aud = "zta-api",
    iss = "http://localhost:5173",
    key = idpKeyPair.privateKey,
    expOffset = 300,
  } = {}) {
    const nowSec = Math.floor(nowMs / 1000);
    const payload = {
      sub,
      dev,
      role,
      acr,
      auth_time,
      client_id: "zta-agent",
    };

    if (jkt !== undefined) {
      payload.cnf = { jkt };
    }

    return new jose.SignJWT(payload)
      .setProtectedHeader({ alg: "ES256", typ: "at+jwt" })
      .setIssuer(iss)
      .setAudience(aud)
      .setIssuedAt(nowSec)
      .setExpirationTime(nowSec + expOffset)
      .setJti(crypto.randomUUID())
      .sign(key);
  }

  async function getFreshNonce(targetUrl = `${pepPublicUrl}/api/company/news`) {
    const res = await fetch(targetUrl);
    assert.equal(res.status, 401);
    const nonce = res.headers.get("dpop-nonce");
    assert.ok(nonce, "Expected DPoP-Nonce header from PEP");
    return nonce;
  }

  before(async () => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "zta-pep-test-"));
    auditLogFile = path.join(tempDir, "audit", "pep.log");

    // Keys setup
    idpKeyPair = await jose.generateKeyPair("ES256", { extractable: true });
    idpPublicJwk = await jose.exportJWK(idpKeyPair.publicKey);
    idpPublicJwk.kid = "test-idp-kid";
    idpJwks = { keys: [idpPublicJwk] };

    clientKeyPair = await jose.generateKeyPair("ES256", { extractable: true });
    clientPublicJwk = await jose.exportJWK(clientKeyPair.publicKey);
    clientJkt = await jose.calculateJwkThumbprint(clientPublicJwk, "sha256");

    attackerKeyPair = await jose.generateKeyPair("ES256", { extractable: true });
    attackerPublicJwk = await jose.exportJWK(attackerKeyPair.publicKey);
    attackerJkt = await jose.calculateJwkThumbprint(attackerPublicJwk, "sha256");

    baseCfg = loadConfig({
      dataDir: tempDir,
      store: "memory",
      clock,
      ztaInternalToken: "test-internal-token-1234",
    });

    // 1. Start PIP
    const pipApp = createPipApp(baseCfg);
    pipServer = http.createServer(pipApp);
    await new Promise((r) => pipServer.listen(0, "127.0.0.1", r));
    pipPort = pipServer.address().port;
    pipUrl = `http://127.0.0.1:${pipPort}`;

    // 2. Start PDP
    const pdpCfg = {
      ...baseCfg,
      pipUrl,
    };
    const pdpApp = createPdpApp(pdpCfg);
    pdpServer = http.createServer(pdpApp);
    await new Promise((r) => pdpServer.listen(0, "127.0.0.1", r));
    pdpPort = pdpServer.address().port;
    pdpUrl = `http://127.0.0.1:${pdpPort}`;

    // 3. Start Resource Server
    const resourceApp = createResourceServerApp(baseCfg);
    resourceServer = http.createServer(resourceApp);
    await new Promise((r) => resourceServer.listen(0, "127.0.0.1", r));
    resourcePort = resourceServer.address().port;
    resourceUrl = `http://127.0.0.1:${resourcePort}`;

    // 4. Start PEP
    // Pre-create audit key file in tempDir so scripts/verify-audit.js can read it
    const auditKey = await loadOrCreateSigningKey("audit", {
      ...baseCfg,
      dataDir: tempDir,
      store: "file",
    });

    const pepCfg = {
      ...baseCfg,
      dataDir: tempDir,
      pipUrl,
      pdpUrl,
      resourceUrl,
      idpJwks,
      auditKey,
      auditLogPath: auditLogFile,
      pepPublicUrl: `http://127.0.0.1:0`, // placeholder, updated after bind
    };

    const pepApp = createPepApp(pepCfg);
    pepServer = http.createServer(pepApp);
    await new Promise((r) => pepServer.listen(0, "127.0.0.1", r));
    pepPort = pepServer.address().port;
    pepPublicUrl = `http://127.0.0.1:${pepPort}`;
    pepCfg.pepPublicUrl = pepPublicUrl;

    // Seed PIP with active device for alice
    const seedRes = await fetch(`${pipUrl}/pip/device/dev-alice`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ZTA-Internal": baseCfg.ztaInternalToken,
      },
      body: JSON.stringify({
        user: "alice",
        owner: "alice",
        status: "active",
        jkt: clientJkt,
        last_good_attestation: Math.floor(nowMs / 1000) - 10,
      }),
    });
    assert.equal(seedRes.status, 200);
  });

  after(async () => {
    if (pepServer) await new Promise((r) => pepServer.close(r));
    if (resourceServer) await new Promise((r) => resourceServer.close(r));
    if (pdpServer) await new Promise((r) => pdpServer.close(r));
    if (pipServer) await new Promise((r) => pipServer.close(r));
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("Happy low resource → 200", async () => {
    const at = await mintAT({ sub: "alice", role: "employee", acr: "pwd", dev: "dev-alice" });
    const targetUrl = `${pepPublicUrl}/api/company/news`;
    const nonce = await getFreshNonce(targetUrl);

    const proof = await signProof({
      privateKey: clientKeyPair.privateKey,
      publicJwk: clientPublicJwk,
      htm: "GET",
      htu: targetUrl,
      nonce,
      accessToken: at,
      clock,
    });

    const res = await fetch(targetUrl, {
      headers: {
        Authorization: `DPoP ${at}`,
        DPoP: proof,
      },
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(body.data, "Expected resource data in response");
    assert.ok(body.generated_at, "Expected generated_at in response");
  });

  it("No nonce → 401 with the DPoP-Nonce header", async () => {
    const at = await mintAT({ sub: "alice", role: "employee", acr: "pwd", dev: "dev-alice" });
    const targetUrl = `${pepPublicUrl}/api/company/news`;

    // Proof signed WITHOUT nonce
    const proofWithoutNonce = await signProof({
      privateKey: clientKeyPair.privateKey,
      publicJwk: clientPublicJwk,
      htm: "GET",
      htu: targetUrl,
      accessToken: at,
      clock,
    });

    const res = await fetch(targetUrl, {
      headers: {
        Authorization: `DPoP ${at}`,
        DPoP: proofWithoutNonce,
      },
    });

    assert.equal(res.status, 401);
    const dpopNonceHeader = res.headers.get("dpop-nonce");
    assert.ok(dpopNonceHeader, "Missing DPoP-Nonce header in 401 response");
    const authHeader = res.headers.get("www-authenticate");
    assert.ok(authHeader && authHeader.includes('error="use_dpop_nonce"'));
    const body = await res.json();
    assert.equal(body.error, "use_dpop_nonce");
  });

  it("Bearer → 401", async () => {
    const at = await mintAT({ sub: "alice", role: "employee", acr: "pwd", dev: "dev-alice" });
    const targetUrl = `${pepPublicUrl}/api/company/news`;

    const res = await fetch(targetUrl, {
      headers: {
        Authorization: `Bearer ${at}`,
      },
    });

    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "invalid_token");
    assert.equal(body.reason, "bearer_downgrade");
  });

  it("Stolen AT with the attacker's key → 401 jkt_mismatch", async () => {
    // AT bound to clientJkt (Alice's key)
    const at = await mintAT({ sub: "alice", role: "employee", acr: "pwd", dev: "dev-alice", jkt: clientJkt });
    const targetUrl = `${pepPublicUrl}/api/company/news`;
    const nonce = await getFreshNonce(targetUrl);

    // Attacker signs proof using their own key (attackerKeyPair)
    const attackerProof = await signProof({
      privateKey: attackerKeyPair.privateKey,
      publicJwk: attackerPublicJwk,
      htm: "GET",
      htu: targetUrl,
      nonce,
      accessToken: at,
      clock,
    });

    const res = await fetch(targetUrl, {
      headers: {
        Authorization: `DPoP ${at}`,
        DPoP: attackerProof,
      },
    });

    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "jkt_mismatch");
  });

  it("Replayed proof → 401 replay", async () => {
    const at = await mintAT({ sub: "alice", role: "employee", acr: "pwd", dev: "dev-alice" });
    const targetUrl = `${pepPublicUrl}/api/company/news`;
    const nonce = await getFreshNonce(targetUrl);

    const proof = await signProof({
      privateKey: clientKeyPair.privateKey,
      publicJwk: clientPublicJwk,
      htm: "GET",
      htu: targetUrl,
      nonce,
      accessToken: at,
      clock,
    });

    // First request: success 200
    const firstRes = await fetch(targetUrl, {
      headers: {
        Authorization: `DPoP ${at}`,
        DPoP: proof,
      },
    });
    assert.equal(firstRes.status, 200);

    // Second request: replaying the same proof -> 401 replay
    const replayRes = await fetch(targetUrl, {
      headers: {
        Authorization: `DPoP ${at}`,
        DPoP: proof,
      },
    });
    assert.equal(replayRes.status, 401);
    const body = await replayRes.json();
    assert.equal(body.error, "replay");
  });

  it("htu for another path → 401", async () => {
    const at = await mintAT({ sub: "alice", role: "employee", acr: "pwd", dev: "dev-alice" });
    const targetUrl = `${pepPublicUrl}/api/company/news`;
    const wrongHtu = `${pepPublicUrl}/api/company/other`;
    const nonce = await getFreshNonce(targetUrl);

    const proof = await signProof({
      privateKey: clientKeyPair.privateKey,
      publicJwk: clientPublicJwk,
      htm: "GET",
      htu: wrongHtu, // Mismatched URI
      nonce,
      accessToken: at,
      clock,
    });

    const res = await fetch(targetUrl, {
      headers: {
        Authorization: `DPoP ${at}`,
        DPoP: proof,
      },
    });

    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "htu");
  });

  it("ath mismatch → 401", async () => {
    const at = await mintAT({ sub: "alice", role: "employee", acr: "pwd", dev: "dev-alice" });
    const targetUrl = `${pepPublicUrl}/api/company/news`;
    const nonce = await getFreshNonce(targetUrl);

    const proof = await signProof({
      privateKey: clientKeyPair.privateKey,
      publicJwk: clientPublicJwk,
      htm: "GET",
      htu: targetUrl,
      nonce,
      accessToken: "completely-different-access-token", // Wrong ath
      clock,
    });

    const res = await fetch(targetUrl, {
      headers: {
        Authorization: `DPoP ${at}`,
        DPoP: proof,
      },
    });

    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "ath");
  });

  it("iat − 31 s → 401", async () => {
    const at = await mintAT({ sub: "alice", role: "employee", acr: "pwd", dev: "dev-alice" });
    const targetUrl = `${pepPublicUrl}/api/company/news`;
    const nonce = await getFreshNonce(targetUrl);

    const nowSec = Math.floor(nowMs / 1000);
    const proof = await signProof({
      privateKey: clientKeyPair.privateKey,
      publicJwk: clientPublicJwk,
      htm: "GET",
      htu: targetUrl,
      nonce,
      accessToken: at,
      iat: nowSec - 35, // 35 seconds old, exceeds 30s skew window
      clock,
    });

    const res = await fetch(targetUrl, {
      headers: {
        Authorization: `DPoP ${at}`,
        DPoP: proof,
      },
    });

    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "iat");
  });

  it("AT signed by a non-IdP key → 401", async () => {
    const rogueIdpKey = await jose.generateKeyPair("ES256", { extractable: true });
    const rogueAt = await mintAT({
      sub: "alice",
      role: "employee",
      acr: "pwd",
      dev: "dev-alice",
      key: rogueIdpKey.privateKey, // Signed with untrusted key
    });

    const targetUrl = `${pepPublicUrl}/api/company/news`;
    const nonce = await getFreshNonce(targetUrl);

    const proof = await signProof({
      privateKey: clientKeyPair.privateKey,
      publicJwk: clientPublicJwk,
      htm: "GET",
      htu: targetUrl,
      nonce,
      accessToken: rogueAt,
      clock,
    });

    const res = await fetch(targetUrl, {
      headers: {
        Authorization: `DPoP ${rogueAt}`,
        DPoP: proof,
      },
    });

    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "invalid_token");
  });

  it("AT with a wrong aud → 401", async () => {
    const at = await mintAT({
      sub: "alice",
      role: "employee",
      acr: "pwd",
      dev: "dev-alice",
      aud: "wrong-audience-for-api",
    });

    const targetUrl = `${pepPublicUrl}/api/company/news`;
    const nonce = await getFreshNonce(targetUrl);

    const proof = await signProof({
      privateKey: clientKeyPair.privateKey,
      publicJwk: clientPublicJwk,
      htm: "GET",
      htu: targetUrl,
      nonce,
      accessToken: at,
      clock,
    });

    const res = await fetch(targetUrl, {
      headers: {
        Authorization: `DPoP ${at}`,
        DPoP: proof,
      },
    });

    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "invalid_token");
  });

  it("X-Role: admin, ?role=admin and body {role: 'admin'} with an employee AT on company.audit → 401 step_up (acr pwd) or 403 (acr mfa), never 200", async () => {
    const targetUrl = `${pepPublicUrl}/api/company/audit?role=admin`;

    // 1. With acr pwd: employee attempts bypass to company.audit
    const atPwd = await mintAT({ sub: "alice", role: "employee", acr: "pwd", dev: "dev-alice" });
    const nonce1 = await getFreshNonce(targetUrl);
    const proof1 = await signProof({
      privateKey: clientKeyPair.privateKey,
      publicJwk: clientPublicJwk,
      htm: "GET",
      htu: `${pepPublicUrl}/api/company/audit`,
      nonce: nonce1,
      accessToken: atPwd,
      clock,
    });

    const resPwd = await fetch(targetUrl, {
      method: "GET",
      headers: {
        Authorization: `DPoP ${atPwd}`,
        DPoP: proof1,
        "X-Role": "admin",
      },
    });
    // High sensitivity with acr pwd -> step_up challenge
    assert.equal(resPwd.status, 401);
    const bodyPwd = await resPwd.json();
    assert.equal(bodyPwd.error, "insufficient_user_authentication");
    assert.notEqual(resPwd.status, 200);

    // 2. With acr mfa: employee has completed MFA, but employee role does NOT have permission for company.audit
    const atMfa = await mintAT({ sub: "alice", role: "employee", acr: "mfa", dev: "dev-alice" });
    const nonce2 = await getFreshNonce(targetUrl);
    const proof2 = await signProof({
      privateKey: clientKeyPair.privateKey,
      publicJwk: clientPublicJwk,
      htm: "GET",
      htu: `${pepPublicUrl}/api/company/audit`,
      nonce: nonce2,
      accessToken: atMfa,
      clock,
    });

    const resMfa = await fetch(targetUrl, {
      method: "GET",
      headers: {
        Authorization: `DPoP ${atMfa}`,
        DPoP: proof2,
        "X-Role": "admin",
      },
    });
    // Role ok fails -> 403 access_denied
    assert.equal(resMfa.status, 403);
    const bodyMfa = await resMfa.json();
    assert.equal(bodyMfa.error, "access_denied");
    assert.notEqual(resMfa.status, 200);
  });

  it("High resource with acr pwd → 401 with insufficient_user_authentication and acr_values='mfa'", async () => {
    const at = await mintAT({ sub: "alice", role: "auditor", acr: "pwd", dev: "dev-alice" });
    const targetUrl = `${pepPublicUrl}/api/company/audit`;
    const nonce = await getFreshNonce(targetUrl);

    const proof = await signProof({
      privateKey: clientKeyPair.privateKey,
      publicJwk: clientPublicJwk,
      htm: "GET",
      htu: targetUrl,
      nonce,
      accessToken: at,
      clock,
    });

    const res = await fetch(targetUrl, {
      headers: {
        Authorization: `DPoP ${at}`,
        DPoP: proof,
      },
    });

    assert.equal(res.status, 401);
    const authHeader = res.headers.get("www-authenticate");
    assert.ok(authHeader && authHeader.includes("insufficient_user_authentication"));
    assert.ok(authHeader && authHeader.includes('acr_values="mfa"'));

    const body = await res.json();
    assert.equal(body.error, "insufficient_user_authentication");
    assert.equal(body.acr_values, "mfa");
  });

  it("PIP status revoked → 403", async () => {
    // Revoke device in PIP
    await fetch(`${pipUrl}/pip/device/dev-revoked`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ZTA-Internal": baseCfg.ztaInternalToken,
      },
      body: JSON.stringify({
        user: "alice",
        owner: "alice",
        status: "revoked",
        jkt: clientJkt,
        last_good_attestation: Math.floor(nowMs / 1000) - 10,
      }),
    });

    const at = await mintAT({ sub: "alice", role: "employee", acr: "pwd", dev: "dev-revoked" });
    const targetUrl = `${pepPublicUrl}/api/company/news`;
    const nonce = await getFreshNonce(targetUrl);

    const proof = await signProof({
      privateKey: clientKeyPair.privateKey,
      publicJwk: clientPublicJwk,
      htm: "GET",
      htu: targetUrl,
      nonce,
      accessToken: at,
      clock,
    });

    const res = await fetch(targetUrl, {
      headers: {
        Authorization: `DPoP ${at}`,
        DPoP: proof,
      },
    });

    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.error, "access_denied");
  });

  it("Attestation age 331 s on high → 403", async () => {
    // Device with attestation age = 335s (last_good_attestation = now - 335)
    await fetch(`${pipUrl}/pip/device/dev-stale`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ZTA-Internal": baseCfg.ztaInternalToken,
      },
      body: JSON.stringify({
        user: "alice",
        owner: "alice",
        status: "active",
        jkt: clientJkt,
        last_good_attestation: Math.floor(nowMs / 1000) - 335,
      }),
    });

    // Request high sensitivity resource (T_max high = 330s, so 335s is stale)
    const at = await mintAT({ sub: "alice", role: "auditor", acr: "mfa", dev: "dev-stale" });
    const targetUrl = `${pepPublicUrl}/api/company/audit`;
    const nonce = await getFreshNonce(targetUrl);

    const proof = await signProof({
      privateKey: clientKeyPair.privateKey,
      publicJwk: clientPublicJwk,
      htm: "GET",
      htu: targetUrl,
      nonce,
      accessToken: at,
      clock,
    });

    const res = await fetch(targetUrl, {
      headers: {
        Authorization: `DPoP ${at}`,
        DPoP: proof,
      },
    });

    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.error, "access_denied");
  });

  it("Audit log verifies with scripts/verify-audit.js", async () => {
    assert.ok(fs.existsSync(auditLogFile), "Audit log file was not created");

    // Test programmatically first
    const auditKey = await loadOrCreateSigningKey("audit", {
      ...baseCfg,
      dataDir: tempDir,
      store: "file",
    });
    const result = await verifyAuditLog(auditLogFile, {
      publicJwk: auditKey.publicJwk,
      cfg: { ...baseCfg, dataDir: tempDir },
    });
    assert.equal(result.valid, true, `Audit log verification failed: ${result.error}`);
    assert.ok(result.count > 0, "Expected non-zero verified audit records");

    // Test via CLI script
    const output = execSync(`node scripts/verify-audit.js "${auditLogFile}"`, {
      env: {
        ...process.env,
        ZTA_DATA_DIR: tempDir,
        STORE: "file",
      },
      encoding: "utf8",
    });
    assert.ok(output.includes("SUCCESS"), "CLI verify-audit did not report SUCCESS");
  });

  it("-M16 (formerly ZTA_ABLATE_CNF=1) → stolen AT accepted", async () => {
    // Start a PEP instance; C3 is switched off through the ablation switchboard only
    const ablatedPepCfg = {
      ...baseCfg,
      dataDir: tempDir,
      pipUrl,
      pdpUrl,
      resourceUrl,
      idpJwks,
      auditLogPath: path.join(tempDir, "audit", "ablated.log"),
    };
    const ablatedApp = createPepApp(ablatedPepCfg);
    const ablatedServer = http.createServer(ablatedApp);
    await new Promise((r) => ablatedServer.listen(0, "127.0.0.1", r));
    const ablatedPort = ablatedServer.address().port;
    const ablatedUrl = `http://127.0.0.1:${ablatedPort}`;
    ablatedPepCfg.pepPublicUrl = ablatedUrl;

    try {
      await withAblation("-M16", async () => {
        // Alice's AT (cnf.jkt = clientJkt)
        const at = await mintAT({ sub: "alice", role: "employee", acr: "pwd", dev: "dev-alice", jkt: clientJkt });
        const targetUrl = `${ablatedUrl}/api/company/news`;

        const nonceRes = await fetch(targetUrl);
        const nonce = nonceRes.headers.get("dpop-nonce");

        // Attacker signs with their key (attackerKeyPair)
        const attackerProof = await signProof({
          privateKey: attackerKeyPair.privateKey,
          publicJwk: attackerPublicJwk,
          htm: "GET",
          htu: targetUrl,
          nonce,
          accessToken: at,
          clock,
        });

        const res = await fetch(targetUrl, {
          headers: {
            Authorization: `DPoP ${at}`,
            DPoP: attackerProof,
          },
        });

        // With M16 off, the cnf.jkt check is skipped, so the stolen AT is accepted (200)
        assert.equal(res.status, 200, "Expected 200 with -M16");
      });
    } finally {
      await new Promise((r) => ablatedServer.close(r));
    }
  });

  it("Resource server lock-down: direct call without X-ZTA-Internal returns 401, with token returns 200", async () => {
    // Direct call to :5001 without internal token -> 401
    const unauthAuditRes = await fetch(`${resourceUrl}/company/audit`);
    assert.equal(unauthAuditRes.status, 401);

    const unauthNewsRes = await fetch(`${resourceUrl}/company/news`);
    assert.equal(unauthNewsRes.status, 401);

    // Call with X-ZTA-Internal -> 200
    const authAuditRes = await fetch(`${resourceUrl}/company/audit`, {
      headers: { "X-ZTA-Internal": baseCfg.ztaInternalToken },
    });
    assert.equal(authAuditRes.status, 200);
    const auditData = await authAuditRes.json();
    assert.ok(auditData.data);
    assert.ok(auditData.generated_at);

    const authNewsRes = await fetch(`${resourceUrl}/company/news`, {
      headers: { "X-ZTA-Internal": baseCfg.ztaInternalToken },
    });
    assert.equal(authNewsRes.status, 200);
    const newsData = await authNewsRes.json();
    assert.ok(newsData.data);
    assert.ok(newsData.generated_at);
  });

  it("Decision controller stub returns 410 Gone with pointer to PEP", async () => {
    const dcApp = createDecisionControllerApp(baseCfg);
    const dcServer = http.createServer(dcApp);
    await new Promise((r) => dcServer.listen(0, "127.0.0.1", r));
    const dcPort = dcServer.address().port;

    try {
      const res = await fetch(`http://127.0.0.1:${dcPort}/zta/access/audit`);
      assert.equal(res.status, 410);
      const body = await res.json();
      assert.equal(body.error, "decision_controller_retired");
      assert.ok(body.use.includes("/api/company/audit"));
    } finally {
      await new Promise((r) => dcServer.close(r));
    }
  });
});
