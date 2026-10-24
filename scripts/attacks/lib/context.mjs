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
import { addToInventory } from "../../../lib/verifier/inventory.js";
import { loadOrCreateSigningKey } from "../../../lib/keys.js";
import { SimTpm } from "../../../lib/sim-tpm/tpm.js";
import { createVendorCa } from "../../../lib/sim-tpm/vendor-ca.js";
import { ZtaClient } from "../../../lib/agent-client.js";
import { loadConfig } from "../../../lib/config.js";
import { RealTpm } from "../../../lib/tpm-real/index.js";
import { prepareSwtpmFleet, startSwtpmFleet } from "./swtpm-fleet.mjs";
import { keycloakBrowserLogin } from "./keycloak-login.mjs";
import { loginFlow } from "./login-flow.mjs";

/**
 * Creates an execution context for an attack trial.
 *
 * @param {Object} options
 * @param {"inproc" | "live"} [options.mode="inproc"]
 * @param {string} [options.config="full"]
 * @param {string} [options.testbedPath]
 * @param {"sim" | "swtpm"} [options.tpm="sim"] - inproc only: simulated TPMs, or one real
 *   swtpm (TCG reference TPM 2.0) per device with X.509 EK certificates
 * @returns {Promise<Object>}
 */
export async function createContext({ mode = "inproc", config = "full", testbedPath, tpm = "sim", targets, orchestrate = false, idp = "keycloak" } = {}) {
  if (mode === "live") {
    return createLiveContext({ config, testbedPath, targets, tpm, orchestrate, idp });
  }

  return createInprocContext({ config, tpm });
}

async function createInprocContext({ config, tpm = "sim" }) {
  let fleet = null;
  let workDir = null;
  let tmpRootsDir;
  let tpmFactory;
  if (tpm === "swtpm") {
    // Trust only the lab CA: "evil" carries a genuine EK certificate from a foreign CA
    const prepared = prepareSwtpmFleet(process.env.ZTA_SWTPM_FLEET_DIR || undefined);
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), "zta-swtpm-trial-"));
    tmpRootsDir = path.join(workDir, "ek-roots");
    fs.mkdirSync(tmpRootsDir, { recursive: true });
    fs.copyFileSync(prepared.labRootPem, path.join(tmpRootsDir, "lab-root.pem"));
    fleet = await startSwtpmFleet(prepared, workDir);
    tpmFactory = async ({ name, dir }) => {
      const dev = fleet.devices[name];
      if (!dev) throw new Error(`No swtpm for harness device ${name}`);
      const real = new RealTpm({ device: "swtpm", host: "127.0.0.1", port: dev.port, dir, ekType: "ecc384", ekCertChain: [dev.chain] });
      await real.init();
      return real;
    };
  } else if (tpm === "sim") {
    tmpRootsDir = path.join(os.tmpdir(), "zta-ek-roots");
    fs.mkdirSync(tmpRootsDir, { recursive: true });
    const swtpmRoot = path.resolve("tests/fixtures/swtpm/swtpm-localca-root.pem");
    if (fs.existsSync(swtpmRoot)) {
      fs.copyFileSync(swtpmRoot, path.join(tmpRootsDir, "swtpm-localca-root.pem"));
    }
  } else {
    throw new Error(`Unknown tpm backend for attacks: ${tpm} (expected sim or swtpm)`);
  }

  let stack;
  try {
    stack = await startStack({ ablation: config, initialTime: Date.now(), ekRootsDir: tmpRootsDir, tpmFactory });
  } catch (err) {
    if (fleet) await fleet.stop();
    if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
    throw err;
  }

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

  /** Adds a device to the verifier inventory (in-process: the verifier's own store). */
  async function seedInventory({ devId, user, code = crypto.randomBytes(16).toString("hex"), rvProfile }) {
    await addToInventory(stack.stores.verifier, { devId, user, code, rvProfile, clock: stack.clock });
    return code;
  }

  /** Registers a WebAuthn credential for (user, device) (in-process: the IdP's own store). */
  async function seedWebauthn(softAuth, { user, client }) {
    await softAuth.registerInStore(stack.stores.idp, user, client.devId);
  }

  async function cleanup() {
    if (stack) {
      await stack.stop();
    }
    if (fleet) await fleet.stop();
    if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
  }

  return {
    mode: "inproc",
    tpm,
    // What ran (recorded per row); not "stack", which is the harness's own stack object
    stackInfo: { idp: "local", hsm: false, timeScale: 1, processes: "in-process", tls: false },
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
    seedInventory,
    seedWebauthn,
    advance: async (seconds) => stack.clock.advance(seconds),
    ...loginFlow({ idpUrl: urls.idpUrl, idpMode: "local" }),
    passwords: { alice: "alice-pass", bob: "bob-pass" },
    forgeAr,
    captureProofPair,
    revoke,
    cleanup,
  };
}

async function createLiveContext({ config, testbedPath, targets, tpm = "sim", orchestrate = false, idp = "keycloak" }) {
  // Resources this context owns, released in reverse order by cleanup()
  const cleanups = [];
  const releaseAll = async () => {
    for (const fn of cleanups.reverse()) await fn().catch(() => {});
  };

  try {
    const prepared = tpm === "swtpm" ? prepareSwtpmFleet(process.env.ZTA_SWTPM_FLEET_DIR || undefined) : null;

    let target;
    let filePath = testbedPath || path.resolve("testbed/attack-targets.json");
    if (orchestrate) {
      // A fresh stack (separate processes) for this trial only, so no state crosses trials
      const { startLiveStack } = await import("../../stack.mjs");
      const timeScale = Number(process.env.ZTA_LIVE_TIME_SCALE || 0.1);
      const stack = await startLiveStack({ config, idp, timeScale, ekRootDirs: prepared ? [prepared.trustDir] : [] });
      cleanups.push(() => stack.stop());
      target = stack.targets;
      filePath = "(orchestrated stack)";
    } else if (targets) {
      target = targets;
      filePath = "(targets object)";
    } else if (fs.existsSync(filePath)) {
      target = JSON.parse(fs.readFileSync(filePath, "utf8"));
    } else {
      // Local start-zta.sh layout; tokens only from data/secrets.json (never hard-coded)
      target = {
        pepUrl: "http://localhost:4001",
        idpUrl: "http://localhost:5173",
        verifierUrl: "http://localhost:4005",
        registryUrl: "http://localhost:4004",
        resourceUrl: "http://localhost:5001",
      };
      if (fs.existsSync(path.resolve("data/secrets.json"))) {
        const sec = JSON.parse(fs.readFileSync(path.resolve("data/secrets.json"), "utf8"));
        target.adminToken = sec.ADMIN_TOKEN;
        target.ztaInternalToken = sec.ZTA_INTERNAL_TOKEN;
      }
    }
    if (!target.adminToken || !target.ztaInternalToken) {
      throw new Error(`Live target ${filePath} lacks adminToken/ztaInternalToken`);
    }

    const ctx = await buildLiveContext({ config, target, filePath, tpm, prepared, cleanups });
    ctx.cleanup = releaseAll;
    return ctx;
  } catch (err) {
    await releaseAll();
    throw err;
  }
}

async function buildLiveContext({ config, target, filePath, tpm, prepared, cleanups }) {
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
  cleanups.push(async () => fs.rmSync(tempDir, { recursive: true, force: true }));

  let tpms;
  if (tpm === "swtpm") {
    // Real TPM 2.0 devices; the stack's verifier trusts only the lab root (prepared.trustDir)
    const fleet = await startSwtpmFleet(prepared, tempDir);
    cleanups.push(() => fleet.stop());
    const make = async (name) => {
      const dev = fleet.devices[name];
      const real = new RealTpm({ device: "swtpm", host: "127.0.0.1", port: dev.port, dir: path.join(tempDir, "agent", name), ekType: "ecc384", ekCertChain: [dev.chain] });
      await real.init();
      cleanups.push(() => real.close());
      return real;
    };
    tpms = { alice: await make("alice-laptop"), bob: await make("bob-laptop"), rogue: await make("rogue"), evil: await make("evil") };
  } else {
    tpms = await provisionSimTpms(tempDir);
  }

  const clientCfg = loadConfig({
    pepPublicUrl: target.pepUrl,
    idpIssuer: target.idpUrl,
    verifierUrl: target.verifierUrl,
    resourceUrl: target.resourceUrl,
  });

  const clients = {
    alice: new ZtaClient({ tpm: tpms.alice, cfg: clientCfg }),
    bob: new ZtaClient({ tpm: tpms.bob, cfg: clientCfg }),
    rogue: new ZtaClient({ tpm: tpms.rogue, cfg: clientCfg }),
    evil: new ZtaClient({ tpm: tpms.evil, cfg: clientCfg }),
  };

  const urls = {
    pepUrl: target.pepUrl,
    idpUrl: target.idpUrl,
    verifierUrl: target.verifierUrl,
    registryUrl: target.registryUrl,
    resourceUrl: target.resourceUrl,
  };

  /** Adds a device to the verifier inventory through its internal endpoint, as an operator would. */
  async function seedInventory({ devId, user, code = crypto.randomBytes(16).toString("hex"), rvProfile }) {
    const res = await fetch(`${urls.verifierUrl}/v/inventory`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ZTA-Internal": target.ztaInternalToken,
        Authorization: `Bearer ${target.adminToken}`,
      },
      body: JSON.stringify({ devId, user, code, ...(rvProfile ? { rvProfile } : {}) }),
    });
    if (!res.ok) throw new Error(`Inventory add failed for ${devId} (${res.status})`);
    return code;
  }

  // Alice's and Bob's devices are in the inventory with fresh one-time codes; rogue and evil are not
  const { devIdOf } = await import("../../../lib/sim-tpm/public-area.js");
  const codes = {};
  for (const [user, name, tpmKey] of [["alice", "alice-laptop", "alice"], ["bob", "bob-laptop", "bob"]]) {
    const devId = await devIdOf((await tpms[tpmKey].getEk()).publicArea);
    const code = await seedInventory({ devId, user });
    codes[name] = code;
    codes[user] = code;
  }

  async function loginWithDevice(client, { username, password, acrValues, simIp, softAuth } = {}) {
    // The client keeps its simulated location for the requests that follow the login
    if (simIp) client.simIp = simIp;
    const loginStart = await client.startLogin({ acrValues });
    let cookie;
    let loginRes;
    let loginData;

    if (target.idpMode === "keycloak") {
      // Keycloak is the main IdP: log in through its real login form, as a browser would
      try {
        const kc = await keycloakBrowserLogin({ authorizeUrl: loginStart.authorizeUrl, username, password, simIp });
        cookie = kc.gateCookie;
        loginRes = { ok: kc.status >= 200 && kc.status < 300, status: kc.status };
        loginData = kc.data;
      } catch (err) {
        // An HTTP refusal is an outcome; a failure to reach Keycloak or the gate is not, and
        // must surface as an execution error rather than look like the system rejecting the attack
        if (!err.status) throw err;
        loginRes = { ok: false, status: err.status };
        loginData = err.body || { error: err.message };
      }
    } else {
      const authRes = await fetch(loginStart.authorizeUrl);
      cookie = (authRes.headers.get("set-cookie") || "").split(";")[0];

      const loginHeaders = {
        "Content-Type": "application/json",
        Accept: "application/json",
        Cookie: cookie,
      };
      if (simIp) {
        loginHeaders["X-ZTA-Sim-IP"] = simIp;
      }

      loginRes = await fetch(`${urls.idpUrl}/oauth/login`, {
        method: "POST",
        headers: loginHeaders,
        body: JSON.stringify({ username, password }),
      });
      loginData = await loginRes.json().catch(() => ({}));
    }

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
    return { code, res: loginRes, cookie };
  }

  /**
   * Registers a WebAuthn credential for (user, device) the way a user does: a normal login
   * on the enrolled device, then /mfa/register through the gate.
   */
  async function seedWebauthn(softAuth, { user, client, password }) {
    const { cookie } = await loginWithDevice(client, { username: user, password });
    const optsRes = await fetch(`${urls.idpUrl}/mfa/register/options`, { headers: { Cookie: cookie } });
    if (!optsRes.ok) throw new Error(`WebAuthn registration options failed (${optsRes.status})`);
    const options = await optsRes.json();
    const attestation = softAuth.createRegistrationResponse(options, {
      origin: urls.idpUrl,
      rpID: new URL(urls.idpUrl).hostname,
    });
    const verifyRes = await fetch(`${urls.idpUrl}/mfa/register/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookie },
      body: JSON.stringify(attestation),
    });
    if (!verifyRes.ok) throw new Error(`WebAuthn registration failed (${verifyRes.status})`);
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
    if (target.hsm) {
      // The verifier's key is in the stack's HSM token: the token signs (test oracle), in a
      // helper process because a PKCS#11 library is initialised once per process
      const { execFileSync } = await import("node:child_process");
      return execFileSync(process.execPath, [path.resolve("scripts/hsm-sign.mjs")], {
        input: JSON.stringify({ key: "verifier", header, payload }),
        env: { ...process.env, ...target.hsm },
        encoding: "utf8",
      }).trim();
    }
    if (target.dataDir) {
      // The harness owns this stack: sign with the verifier's own key (test oracle), so the
      // expiry and status checks are what is tested, not the signature check. Fetching the
      // JWKS first makes the verifier create and persist its key before we read it.
      await fetch(`${urls.verifierUrl}/v/jwks`);
      const verifierKey = await loadOrCreateSigningKey("verifier", { dataDir: target.dataDir, store: "file" });
      header.kid = verifierKey.kid;
      return await new jose.SignJWT(payload).setProtectedHeader(header).sign(verifierKey.privateKey);
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

  return {
    mode: "live",
    tpm,
    stackInfo: {
      idp: target.idpMode || "local",
      hsm: Boolean(target.hsm),
      timeScale: target.timeScale ?? 1,
      processes: target.dataDir ? "orchestrated" : "external",
      tls: String(target.pepUrl || "").startsWith("https://"),
    },
    config,
    ablation: targetAblation,
    urls,
    target,
    adminToken: target.adminToken,
    ztaInternalToken: target.ztaInternalToken || process.env.ZTA_INTERNAL_TOKEN,
    clients,
    tpms,
    codes,
    // No store handles in live mode: the services own their stores; use the seed helpers
    stores: null,
    passwords: { alice: process.env.ZTA_ALICE_PASSWORD || "alice-pass", bob: process.env.ZTA_BOB_PASSWORD || "bob-pass" },
    clock: () => Date.now(),
    loginWithDevice,
    seedInventory,
    seedWebauthn,
    // Real waiting, scaled like the stack's protocol times (target.timeScale)
    advance: (seconds) => new Promise((r) => setTimeout(r, seconds * (target.timeScale ?? 1) * 1000)),
    ...loginFlow({ idpUrl: urls.idpUrl, idpMode: target.idpMode || "local" }),
    enrolDevice: async (c, code) => c.enrol(code),
    forgeAr,
    captureProofPair,
    revoke,
  };
}

/** Simulated TPMs for live runs without --tpm swtpm (development only). */
async function provisionSimTpms(tempDir) {
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

  return {
    alice: aliceTpm,
    bob: bobTpm,
    rogue: rogueTpm,
    evil: evilTpm,
  };

}
