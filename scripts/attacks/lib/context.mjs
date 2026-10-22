/**
 * @file scripts/attacks/lib/context.mjs
 * Execution context for attacks in inproc and live testbed modes.
 * Provides stack lifecycle management and helpers for device enrolment, login,
 * AR forgery, proof generation, and device revocation.
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import * as jose from "jose";

import { startStack } from "../../../tests/helpers/harness.js";
import { signProof } from "../../../lib/dpop.js";
import { jwkOf } from "../../../lib/sim-tpm/public-area.js";
import { state } from "../../../lib/ablation.js";
import { createStore } from "../../../lib/store.js";
import { SimTpm } from "../../../lib/sim-tpm/tpm.js";
import { createVendorCa } from "../../../lib/sim-tpm/vendor-ca.js";
import { ZtaClient } from "../../../lib/agent-client.js";
import { loadConfig } from "../../../lib/config.js";

/**
 * Creates an execution context for an attack trial.
 *
 * @param {Object} options
 * @param {"inproc" | "live"} [options.mode="inproc"]
 * @param {string} [options.config="full"]
 * @param {string} [options.testbedPath]
 * @returns {Promise<Object>}
 */
export async function createContext({ mode = "inproc", config = "full", testbedPath } = {}) {
  if (mode === "live") {
    return createLiveContext({ config, testbedPath });
  }

  return createInprocContext({ config });
}

async function createInprocContext({ config }) {
  const tmpRootsDir = path.join(os.tmpdir(), "zta-ek-roots");
  fs.mkdirSync(tmpRootsDir, { recursive: true });
  const swtpmRoot = path.resolve("tests/fixtures/swtpm/swtpm-localca-root.pem");
  if (fs.existsSync(swtpmRoot)) {
    fs.copyFileSync(swtpmRoot, path.join(tmpRootsDir, "swtpm-localca-root.pem"));
  }

  const stack = await startStack({ ablation: config, initialTime: Date.now(), ekRootsDir: tmpRootsDir });

  const urls = {
    pepUrl: stack.urls.pepPublicUrl,
    idpUrl: stack.urls.idpIssuer,
    verifierUrl: stack.urls.verifierUrl,
    registryUrl: stack.urls.registryUrl,
    resourceUrl: stack.urls.resourceUrl,
  };

  /**
   * Enrols a client device with an inventory code.
   */
  async function enrolDevice(client, code) {
    return await client.enrol(code);
  }

  /**
   * Logs in a user from a given client device.
   */
  async function loginWithDevice(client, options) {
    return await stack.loginUser(client, options);
  }

  /**
   * Forges or signs an Attestation Result (AR) token.
   */
  async function forgeAr({
    devId = "alice-laptop",
    jkt,
    status = "pass",
    iat = Math.floor(stack.clock() / 1000),
    exp = Math.floor(stack.clock() / 1000) + 120,
    signWithKey = null,
  } = {}) {
    const payload = {
      iss: urls.verifierUrl,
      sub: devId,
      dev: devId,
      jkt,
      status,
      iat,
      exp,
      jti: crypto.randomUUID(),
    };

    const header = {
      alg: "ES256",
      typ: "ar+jwt",
    };

    if (signWithKey) {
      if (signWithKey.kid) header.kid = signWithKey.kid;
      else header.kid = "attacker-key-1";
      const jwt = await new jose.SignJWT(payload)
        .setProtectedHeader(header)
        .sign(signWithKey);
      return jwt;
    }

    // Sign with legitimate verifier key
    const verifierKey = stack.keys.verifier || stack.keys.verifierKey;
    if (verifierKey.kid || verifierKey.publicJwk?.kid) {
      header.kid = verifierKey.kid || verifierKey.publicJwk?.kid;
    }
    const jwt = await new jose.SignJWT(payload)
      .setProtectedHeader(header)
      .sign(verifierKey.privateKey);
    return jwt;
  }

  /**
   * Captures a fresh (accessToken, DPoP proof) pair for a client and target URL.
   */
  async function captureProofPair({ client, targetUrl, method = "GET" }) {
    const pubJwk = jwkOf(client.kbPublicArea);
    const preRes = await fetch(targetUrl);
    const nonce = preRes.headers.get("DPoP-Nonce") || undefined;

    const proof = await signProof({
      signer: (data) => client.tpm.sign(client.kbHandle, data),
      publicJwk: pubJwk,
      htm: method,
      htu: targetUrl,
      nonce,
      accessToken: client.accessToken,
      clock: stack.clock,
    });

    return {
      accessToken: client.accessToken,
      proof,
      nonce,
      pubJwk,
    };
  }

  /**
   * Revokes a device in the registry.
   */
  async function revoke(devId) {
    const res = await fetch(`${urls.registryUrl}/registry/${devId}/revoke`, {
      method: "POST",
      headers: { Authorization: `Bearer ${stack.cfg.adminToken}` },
    });
    return res;
  }

  async function cleanup() {
    if (stack) {
      await stack.stop();
    }
  }

  return {
    mode: "inproc",
    config,
    ablation: state(),
    stack,
    urls,
    clients: stack.clients,
    codes: stack.codes,
    stores: stack.stores,
    tpms: stack.tpms,
    clock: stack.clock,
    cfg: stack.cfg,
    adminToken: stack.cfg.adminToken,
    ztaInternalToken: stack.cfg.ztaInternalToken,
    enrolDevice,
    loginWithDevice,
    forgeAr,
    captureProofPair,
    revoke,
    cleanup,
  };
}

async function createLiveContext({ config, testbedPath }) {
  const filePath = testbedPath || path.resolve("testbed/attack-targets.json");
  let target;
  if (fs.existsSync(filePath)) {
    const raw = fs.readFileSync(filePath, "utf8");
    target = JSON.parse(raw);
  } else {
    // Default fallback to local start-zta.sh layout
    target = {
      pepUrl: "http://localhost:4001",
      idpUrl: "http://localhost:5173",
      verifierUrl: "http://localhost:4005",
      registryUrl: "http://localhost:4004",
      resourceUrl: "http://localhost:5001",
      adminToken: "5a18b69f19a9cbe151b7e700e44d82b87426f2250c84944ed772d9930092e200",
    };
    if (fs.existsSync(path.resolve("data/secrets.json"))) {
      try {
        const sec = JSON.parse(fs.readFileSync(path.resolve("data/secrets.json"), "utf8"));
        if (sec.ADMIN_TOKEN) target.adminToken = sec.ADMIN_TOKEN;
        if (sec.ZTA_INTERNAL_TOKEN) target.ztaInternalToken = sec.ZTA_INTERNAL_TOKEN;
      } catch {}
    }
  }

  const requiredFields = ["pepUrl", "idpUrl", "verifierUrl", "registryUrl", "resourceUrl"];
  for (const f of requiredFields) {
    if (!target[f]) {
      throw new Error(`Invalid testbed config: missing '${f}' in ${filePath}`);
    }
  }

  // Refuse to run when any service lacks /health or reports a different ablation state
  const servicesToCheck = [
    { name: "pep", url: `${target.pepUrl}/health` },
    { name: "idp", url: `${target.idpUrl}/health` },
    { name: "verifier", url: `${target.verifierUrl}/health` },
    { name: "registry", url: `${target.registryUrl}/health` },
  ];

  let targetAblation = null;
  for (const s of servicesToCheck) {
    let healthRes;
    try {
      healthRes = await fetch(s.url, { signal: AbortSignal.timeout(3000) });
    } catch (err) {
      throw new Error(`Remote service '${s.name}' health check failed: ${err.message}`);
    }
    if (!healthRes.ok) {
      throw new Error(`Remote service '${s.name}' lacks /health or returned status ${healthRes.status}`);
    }
    const healthData = await healthRes.json().catch(() => ({}));
    if (!healthData.ablation || typeof healthData.ablation !== "object") {
      throw new Error(`Remote service '${s.name}' /health does not report ablation state`);
    }
    if (healthData.ablation.label !== config) {
      throw new Error(
        `Remote ablation label mismatch on service '${s.name}': expected '${config}', but remote service reported '${healthData.ablation.label}'`
      );
    }
    targetAblation = healthData.ablation;
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "zta-live-agent-"));
  const vendorCaDir = path.join(tempDir, "vendor-ca");
  const defaultCaDir = path.resolve("data/vendor-ca");
  if (fs.existsSync(path.join(defaultCaDir, "sim-vendor.jwk"))) {
    fs.mkdirSync(vendorCaDir, { recursive: true, mode: 0o700 });
    fs.copyFileSync(path.join(defaultCaDir, "sim-vendor.jwk"), path.join(vendorCaDir, "sim-vendor.jwk"));
    fs.copyFileSync(path.join(defaultCaDir, "sim-vendor.pub.jwk"), path.join(vendorCaDir, "sim-vendor.pub.jwk"));
  }
  const simVendorCa = await createVendorCa(vendorCaDir, "sim-vendor", "SimTPM Vendor CA");
  const evilCa = await createVendorCa(path.join(vendorCaDir, "evil"), "evil", "Untrusted Evil Vendor CA");

  async function provisionTpm(name, caKey) {
    const dir = path.join(tempDir, "agent", name);
    const preSeeded = path.resolve("data/agent", name);
    if (fs.existsSync(preSeeded)) {
      fs.mkdirSync(dir, { recursive: true });
      fs.cpSync(preSeeded, dir, { recursive: true });
    }
    const tpm = new SimTpm({ caKey });
    tpm.dir = dir;
    tpm._loadFromDisk();
    await tpm.init();
    return tpm;
  }

  const aliceTpm = await provisionTpm("alice-laptop", simVendorCa);
  const bobTpm = await provisionTpm("bob-laptop", simVendorCa);
  const rogueTpm = await provisionTpm("rogue", simVendorCa);
  const evilTpm = await provisionTpm("evil", evilCa);

  const tpms = {
    alice: aliceTpm,
    bob: bobTpm,
    rogue: rogueTpm,
    evil: evilTpm,
  };

  const clientCfg = loadConfig({
    pepPublicUrl: target.pepUrl,
    idpIssuer: target.idpUrl,
    verifierUrl: target.verifierUrl,
    resourceUrl: target.resourceUrl,
  });

  const clients = {
    alice: new ZtaClient({ tpm: aliceTpm, cfg: clientCfg }),
    bob: new ZtaClient({ tpm: bobTpm, cfg: clientCfg }),
    rogue: new ZtaClient({ tpm: rogueTpm, cfg: clientCfg }),
    evil: new ZtaClient({ tpm: evilTpm, cfg: clientCfg }),
  };

  let codes = {};
  if (fs.existsSync(path.resolve("data/dev-enrolment-codes.json"))) {
    try {
      codes = JSON.parse(fs.readFileSync(path.resolve("data/dev-enrolment-codes.json"), "utf8"));
    } catch {}
  }
  codes.alice = codes["alice-laptop"] || codes.alice;
  codes.bob = codes["bob-laptop"] || codes.bob;

  const urls = {
    pepUrl: target.pepUrl,
    idpUrl: target.idpUrl,
    verifierUrl: target.verifierUrl,
    registryUrl: target.registryUrl,
    resourceUrl: target.resourceUrl,
  };

  try {
    const { devIdOf } = await import("../../../lib/sim-tpm/public-area.js");
    const aliceDevId = await devIdOf(aliceTpm.ek.publicArea);
    const freshAliceCode = crypto.randomBytes(16).toString("hex");
    const invRes = await fetch(`${urls.verifierUrl}/v/inventory`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ZTA-Internal": target.ztaInternalToken || target.adminToken,
        Authorization: `Bearer ${target.adminToken}`,
      },
      body: JSON.stringify({ devId: aliceDevId, user: "alice", code: freshAliceCode }),
    });
    if (invRes.ok) {
      codes["alice-laptop"] = freshAliceCode;
      codes.alice = freshAliceCode;
    }
  } catch {}

  async function loginWithDevice(client, { username, password, acrValues, simIp, softAuth } = {}) {
    const loginStart = await client.startLogin({ acrValues });
    const authRes = await fetch(loginStart.authorizeUrl);
    const cookie = (authRes.headers.get("set-cookie") || "").split(";")[0];

    const loginHeaders = {
      "Content-Type": "application/json",
      Accept: "application/json",
      Cookie: cookie,
    };
    if (simIp) {
      loginHeaders["X-ZTA-Sim-IP"] = simIp;
    }

    const loginRes = await fetch(`${urls.idpUrl}/oauth/login`, {
      method: "POST",
      headers: loginHeaders,
      body: JSON.stringify({ username, password }),
    });

    const loginData = await loginRes.json().catch(() => ({}));
    if (!loginRes.ok) {
      const err = new Error(loginData.reason || loginData.error || `Login failed (${loginRes.status})`);
      err.status = loginRes.status;
      err.body = loginData;
      throw err;
    }

    let code = loginData.code;
    if (loginData.redirect === "/stepup.html" || loginData.redirect?.includes("stepup")) {
      if (!softAuth) {
        const err = new Error("Step-up required but no soft-authenticator provided");
        err.stepUpRequired = true;
        err.risk = loginData.risk;
        throw err;
      }
      const authOptsRes = await fetch(`${urls.idpUrl}/mfa/auth/options`, {
        headers: { Cookie: cookie },
      });
      const authOpts = await authOptsRes.json();
      const assertion = softAuth.createAuthenticationResponse(authOpts, {
        origin: urls.idpUrl,
        rpID: new URL(urls.idpUrl).hostname,
      });
      const verifyRes = await fetch(`${urls.idpUrl}/mfa/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: cookie },
        body: JSON.stringify(assertion),
      });
      const verifyData = await verifyRes.json();
      if (!verifyRes.ok) {
        throw new Error(verifyData.error || "MFA step-up verification failed");
      }
      code = verifyData.code;
    }

    if (code) {
      await client.finishLogin(code);
    }
    return { code, res: loginRes };
  }

  async function forgeAr({
    devId = "alice-laptop",
    jkt,
    status = "pass",
    iat = Math.floor(Date.now() / 1000),
    exp = Math.floor(Date.now() / 1000) + 120,
    signWithKey = null,
  } = {}) {
    const payload = {
      iss: urls.verifierUrl,
      sub: devId,
      dev: devId,
      jkt,
      status,
      iat,
      exp,
      jti: crypto.randomUUID(),
    };
    const header = { alg: "ES256", typ: "ar+jwt" };
    if (signWithKey) {
      header.kid = signWithKey.kid || "attacker-key-1";
      return await new jose.SignJWT(payload).setProtectedHeader(header).sign(signWithKey);
    }
    const key = await jose.generateKeyPair("ES256");
    header.kid = "verifier-live-1";
    return await new jose.SignJWT(payload).setProtectedHeader(header).sign(key.privateKey);
  }

  async function captureProofPair({ client, targetUrl, method = "GET" }) {
    const pubJwk = jwkOf(client.kbPublicArea);
    const preRes = await fetch(targetUrl);
    const nonce = preRes.headers.get("DPoP-Nonce") || undefined;

    const proof = await signProof({
      signer: (data) => client.tpm.sign(client.kbHandle, data),
      publicJwk: pubJwk,
      htm: method,
      htu: targetUrl,
      nonce,
      accessToken: client.accessToken,
    });

    return {
      accessToken: client.accessToken,
      proof,
      nonce,
      pubJwk,
    };
  }

  async function revoke(devId) {
    return await fetch(`${urls.registryUrl}/registry/${devId}/revoke`, {
      method: "POST",
      headers: { Authorization: `Bearer ${target.adminToken}` },
    });
  }

  let stores = {};
  try {
    stores = {
      idp: createStore("idp"),
      verifier: createStore("verifier"),
    };
  } catch {}

  return {
    mode: "live",
    config,
    ablation: targetAblation,
    urls,
    target,
    adminToken: target.adminToken,
    ztaInternalToken: target.ztaInternalToken || process.env.ZTA_INTERNAL_TOKEN,
    clients,
    tpms,
    codes,
    stores,
    clock: () => Date.now(),
    loginWithDevice,
    enrolDevice: async (c, code) => c.enrol(code),
    forgeAr,
    captureProofPair,
    revoke,
    async cleanup() {},
  };
}
