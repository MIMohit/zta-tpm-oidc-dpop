/**
 * @file tests/helpers/harness.js
 * In-process full ZTA stack test harness.
 *
 * Boots all 7 backend services on port 0 with STORE=memory, an isolated fake clock,
 * in-memory keys, and wires all inter-service URLs and internal tokens.
 * Provisions SimTPM instances (alice-laptop, bob-laptop, rogue, evil), seeds
 * verifier inventory and IdP directory, and returns pre-configured ZtaClient instances.
 */

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import * as jose from "jose";

import { createApp as createPipApp } from "../../pip.js";
import { createApp as createPdpApp } from "../../pdp.js";
import { createApp as createVerifierApp } from "../../services/attestation-service.js";
import { createApp as createRegistryApp } from "../../services/device-registry.js";
import { createApp as createResourceServerApp } from "../../services/resource-server.js";
import { createApp as createServerApp } from "../../server.js";
import { createApp as createPepApp } from "../../pep.js";

import { loadConfig } from "../../lib/config.js";
import { loadOrCreateSigningKey, publicJwks } from "../../lib/keys.js";
import { SimTpm } from "../../lib/sim-tpm/tpm.js";
import { createVendorCa } from "../../lib/sim-tpm/vendor-ca.js";
import { devIdOf } from "../../lib/sim-tpm/public-area.js";
import { addToInventory } from "../../lib/verifier/inventory.js";
import { setUser } from "../../lib/idp/directory.js";
import { ZtaClient } from "../../lib/agent-client.js";
import { configureAblation, parseConfigLabel, resetAblation } from "../../lib/ablation.js";

/**
 * Creates an isolated in-memory store matching the store.js interface.
 * Ensures zero cross-test state leakage.
 */
export function createIsolatedMemoryStore() {
  const data = {};

  function parsePath(p) {
    if (!p) return [];
    if (Array.isArray(p)) return p;
    return String(p).split("/").filter(Boolean);
  }

  function getByPath(root, parts) {
    if (parts.length === 0) return root;
    let curr = root;
    for (const part of parts) {
      if (curr == null || typeof curr !== "object") return undefined;
      curr = curr[part];
    }
    return curr;
  }

  function setByPath(root, parts, val) {
    if (parts.length === 0) {
      if (val && typeof val === "object" && !Array.isArray(val)) {
        for (const k of Object.keys(root)) delete root[k];
        Object.assign(root, val);
      }
      return root;
    }
    let curr = root;
    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (curr[part] == null || typeof curr[part] !== "object") {
        curr[part] = {};
      }
      curr = curr[part];
    }
    curr[parts[parts.length - 1]] = val;
    return root;
  }

  function updateByPath(root, parts, obj) {
    if (parts.length === 0) {
      Object.assign(root, obj);
      return root;
    }
    let curr = root;
    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (curr[part] == null || typeof curr[part] !== "object") {
        curr[part] = {};
      }
      curr = curr[part];
    }
    const last = parts[parts.length - 1];
    if (curr[last] == null || typeof curr[last] !== "object") {
      curr[last] = {};
    }
    Object.assign(curr[last], obj);
    return root;
  }

  function delByPath(root, parts) {
    if (parts.length === 0) {
      for (const k of Object.keys(root)) delete root[k];
      return true;
    }
    let curr = root;
    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (curr == null || typeof curr !== "object") return false;
      curr = curr[part];
    }
    if (curr && typeof curr === "object") {
      delete curr[parts[parts.length - 1]];
      return true;
    }
    return false;
  }

  function formatList(node) {
    if (node == null || typeof node !== "object") return [];
    const result = [];
    for (const [k, v] of Object.entries(node)) {
      if (v != null && typeof v === "object" && !Array.isArray(v)) {
        const item = { ...v };
        if (item.key === undefined) item.key = k;
        if (item.id === undefined) item.id = k;
        Object.defineProperty(item, "value", { value: v, enumerable: false, writable: true });
        item[Symbol.iterator] = function* () {
          yield k;
          yield v;
        };
        result.push(item);
      } else {
        const item = {
          key: k,
          id: k,
          value: v,
          [Symbol.iterator]: function* () {
            yield k;
            yield v;
          },
        };
        result.push(item);
      }
    }
    return result;
  }

  return {
    async get(pathStr) {
      return getByPath(data, parsePath(pathStr));
    },
    async set(pathStr, v) {
      setByPath(data, parsePath(pathStr), v);
      return v;
    },
    async update(pathStr, obj) {
      updateByPath(data, parsePath(pathStr), obj);
      return getByPath(data, parsePath(pathStr));
    },
    async del(pathStr) {
      return delByPath(data, parsePath(pathStr));
    },
    async list(prefix) {
      return formatList(getByPath(data, parsePath(prefix)));
    },
    _raw: data,
  };
}

/**
 * Creates a shared mutable fake clock.
 * @param {number} [initialTime=1700000000000]
 */
export function createFakeClock(initialTime = 1700000000000) {
  let nowMs = initialTime;
  const clock = () => nowMs;
  clock.now = () => nowMs;
  clock.advance = (seconds) => {
    nowMs += Number(seconds) * 1000;
    return nowMs;
  };
  clock.advanceMs = (ms) => {
    nowMs += Number(ms);
    return nowMs;
  };
  clock.set = (target) => {
    nowMs = target < 1e11 ? target * 1000 : target;
    return nowMs;
  };
  return clock;
}

/**
 * Starts an in-process full ZTA stack on port 0.
 *
 * @param {Object} [overrides={}]
 * @returns {Promise<{
 *   urls: Record<string, string>,
 *   cfg: Record<string, any>,
 *   clock: Function,
 *   clients: { alice: ZtaClient, bob: ZtaClient, rogue: ZtaClient, evil: ZtaClient },
 *   codes: Record<string, string>,
 *   stores: Record<string, any>,
 *   tpms: Record<string, any>,
 *   keys: Record<string, any>,
 *   auditLogFile: string,
 *   tempDir: string,
 *   loginUser: Function,
 *   stop: Function
 * }>}
 */
export async function startStack(overrides = {}) {
  const tempDir = overrides.dataDir || fs.mkdtempSync(path.join(os.tmpdir(), "zta-harness-"));
  const auditLogFile = overrides.auditLogPath || path.join(tempDir, "audit", "pep.log");
  fs.mkdirSync(path.dirname(auditLogFile), { recursive: true });

  const clock = overrides.clock || createFakeClock(overrides.initialTime || 1700000000000);

  const ztaInternalToken = overrides.ztaInternalToken || `internal-${crypto.randomUUID()}`;
  const adminToken = overrides.adminToken || `admin-${crypto.randomUUID()}`;
  const sessionSecret = overrides.sessionSecret || `session-${crypto.randomUUID()}`;

  // 1. Signing keys (in-memory for speed and isolation)
  const verifierKey = overrides.verifierKey || (await loadOrCreateSigningKey("verifier", { store: "memory", clock, dataDir: tempDir }));
  const idpKey = overrides.idpKey || (await loadOrCreateSigningKey("idp", { store: "memory", clock, dataDir: tempDir }));
  const auditKey = overrides.auditKey || (await loadOrCreateSigningKey("audit", { store: "memory", clock, dataDir: tempDir }));

  // 2. Vendor CAs and SimTPM provision
  const vendorCaDir = path.join(tempDir, "vendor-ca");
  const simVendorCa = await createVendorCa(vendorCaDir, "sim-vendor", "SimTPM Vendor CA");
  const evilCa = await createVendorCa(path.join(vendorCaDir, "evil"), "evil", "Untrusted Evil Vendor CA");

  // Optional overrides.tpmFactory({ name, dir, tempDir }) -> backend | null lets a test put a
  // device on another TpmBackend (e.g. RealTpm on the software TPM). Default: SimTpm for all.
  const factoryTpms = [];
  async function provisionTpm(name, caKey) {
    const dir = path.join(tempDir, "agent", name);
    if (typeof overrides.tpmFactory === "function") {
      const custom = await overrides.tpmFactory({ name, dir, tempDir });
      if (custom) {
        factoryTpms.push(custom);
        return custom;
      }
    }
    const tpm = new SimTpm({ dir, caKey });
    await tpm.init();
    return tpm;
  }

  // Alice TPM
  const aliceTpm = await provisionTpm("alice-laptop", simVendorCa);
  const aliceEk = await aliceTpm.getEk();
  const aliceDevId = await devIdOf(aliceEk.publicArea);

  // Bob TPM
  const bobTpm = await provisionTpm("bob-laptop", simVendorCa);
  const bobEk = await bobTpm.getEk();
  const bobDevId = await devIdOf(bobEk.publicArea);

  // Rogue TPM (genuine vendor cert, but omitted from inventory)
  const rogueTpm = await provisionTpm("rogue", simVendorCa);
  const rogueEk = await rogueTpm.getEk();
  const rogueDevId = await devIdOf(rogueEk.publicArea);

  // Evil TPM (cert signed by untrusted Evil CA)
  const evilTpm = await provisionTpm("evil", evilCa);
  const evilEk = await evilTpm.getEk();
  const evilDevId = await devIdOf(evilEk.publicArea);

  // 3. Isolated in-memory stores
  const pipStore = overrides.pipStore || createIsolatedMemoryStore();
  const verifierStore = overrides.verifierStore || createIsolatedMemoryStore();
  const idpStore = overrides.idpStore || createIsolatedMemoryStore();
  const resourceStore = overrides.resourceStore || createIsolatedMemoryStore();

  // 4. Seed verifier inventory
  const aliceInv = await addToInventory(verifierStore, {
    devId: aliceDevId,
    user: "alice",
    ttlMs: 365 * 24 * 3600 * 1000,
    clock,
  });

  const bobInv = await addToInventory(verifierStore, {
    devId: bobDevId,
    user: "bob",
    ttlMs: 365 * 24 * 3600 * 1000,
    clock,
  });

  const codes = {
    "alice-laptop": aliceInv.code,
    "bob-laptop": bobInv.code,
    alice: aliceInv.code,
    bob: bobInv.code,
  };

  // 5. Seed IdP users
  await setUser("alice", { password: "alice-pass", role: "auditor" }, idpStore);
  await setUser("bob", { password: "bob-pass", role: "employee" }, idpStore);

  // 6. Base configuration object
  const baseCfg = loadConfig({
    store: "memory",
    dataDir: tempDir,
    idpMode: "local",
    clock,
    ztaInternalToken,
    adminToken,
    sessionSecret,
    simIpHeader: true, // Allow X-ZTA-Sim-IP in tests / eval
    tauAR: 120,
    tAT: 300,
    tRA: 300,
    tNonce: 60,
    wJti: 120,
    skew: 30,
    thetaLogin: 0.5,
    thetaDeny: 0.85,
    ...overrides,
  });

  // Every ablation goes through the switchboard so state(), banner and manifest see it.
  // Legacy ablateCnf/ablateNonce overrides map to -M16/-M17 (VERIFY4 H4).
  const raw = overrides.ablation ?? overrides.ZTA_ABLATE ?? overrides.ZTA_BASELINE;
  const legacyOff = [];
  if (overrides.ablateCnf) legacyOff.push("M16");
  if (overrides.ablateNonce) legacyOff.push("M17");
  if (raw !== undefined || legacyOff.length > 0) {
    let parsed = { off: [], baseline: null };
    if (typeof raw === "string") {
      parsed = parseConfigLabel(raw);
    } else if (raw && typeof raw === "object") {
      parsed = { off: raw.off ?? [], baseline: raw.baseline ?? null };
    }
    configureAblation({ off: [...parsed.off, ...legacyOff], baseline: parsed.baseline, source: "harness" });
  }

  // Track all running HTTP servers
  const servers = [];

  // Helper to start an Express app on port 0
  async function listenApp(app) {
    const s = http.createServer(app);
    await new Promise((resolve) => s.listen(0, "127.0.0.1", resolve));
    servers.push(s);
    const port = s.address().port;
    return `http://127.0.0.1:${port}`;
  }

  // 7. Start PIP (Policy Information Point)
  const pipCfg = {
    ...baseCfg,
    storeInstance: pipStore,
  };
  const pipApp = createPipApp(pipCfg);
  const pipUrl = await listenApp(pipApp);
  baseCfg.pipUrl = pipUrl;

  // 8. Start PDP (Policy Decision Point)
  const pdpCfg = {
    ...baseCfg,
    pipUrl,
  };
  const pdpApp = createPdpApp(pdpCfg);
  const pdpUrl = await listenApp(pdpApp);
  baseCfg.pdpUrl = pdpUrl;

  // 9. Start Verifier
  const verifierCfg = {
    ...baseCfg,
    storeInstance: verifierStore,
    pipUrl,
    verifierKey,
    trustAnchors: [simVendorCa.publicJwk],
  };
  const verifierApp = createVerifierApp(verifierCfg);
  const verifierUrl = await listenApp(verifierApp);
  baseCfg.verifierUrl = verifierUrl;

  // 10. Start Device Registry Admin
  const registryCfg = {
    ...baseCfg,
    verifierUrl,
  };
  const registryApp = createRegistryApp(registryCfg);
  const registryUrl = await listenApp(registryApp);

  // 11. Start Resource Server
  const resourceCfg = {
    ...baseCfg,
    storeInstance: resourceStore,
  };
  const resourceApp = createResourceServerApp(resourceCfg);
  const resourceUrl = await listenApp(resourceApp);
  baseCfg.resourceUrl = resourceUrl;

  // 12. Start IdP Gate / Server
  const idpCfg = {
    ...baseCfg,
    storeInstance: idpStore,
    pipUrl,
    verifierUrl,
    idpKey,
    verifierJwks: publicJwks(verifierKey),
  };
  const idpApp = createServerApp(idpCfg);
  const idpIssuer = await listenApp(idpApp);
  idpCfg.idpIssuer = idpIssuer;
  baseCfg.idpIssuer = idpIssuer;

  // 13. Start PEP (Policy Enforcement Point)
  const pepCfg = {
    ...baseCfg,
    pdpUrl,
    resourceUrl,
    idpIssuer,
    idpJwks: publicJwks(idpKey),
    auditKey,
    auditLogPath: auditLogFile,
  };
  const pepApp = createPepApp(pepCfg);
  const pepPublicUrl = await listenApp(pepApp);
  pepCfg.pepPublicUrl = pepPublicUrl;
  baseCfg.pepPublicUrl = pepPublicUrl;

  const urls = {
    pipUrl,
    pdpUrl,
    verifierUrl,
    registryUrl,
    resourceUrl,
    idpIssuer,
    pepPublicUrl,
    // Aliases
    idpUrl: idpIssuer,
    pepUrl: pepPublicUrl,
    PIP_URL: pipUrl,
    PDP_URL: pdpUrl,
    VERIFIER_URL: verifierUrl,
    REGISTRY_URL: registryUrl,
    RESOURCE_URL: resourceUrl,
    IDP_ISSUER: idpIssuer,
    PEP_PUBLIC_URL: pepPublicUrl,
  };

  // 14. Initialize client instances
  const clientCfg = {
    ...baseCfg,
    ...urls,
    clock,
  };

  const clients = {
    alice: new ZtaClient({ tpm: aliceTpm, cfg: clientCfg, clock }),
    bob: new ZtaClient({ tpm: bobTpm, cfg: clientCfg, clock }),
    rogue: new ZtaClient({ tpm: rogueTpm, cfg: clientCfg, clock }),
    evil: new ZtaClient({ tpm: evilTpm, cfg: clientCfg, clock }),
  };

  /**
   * Helper to execute complete user login transaction against the stack.
   *
   * @param {ZtaClient} client
   * @param {Object} options
   * @param {string} options.username
   * @param {string} options.password
   * @param {string} [options.acrValues]
   * @param {string} [options.simIp]
   * @param {import('./soft-webauthn.js').SoftAuthenticator} [options.softAuth]
   * @returns {Promise<{ tokens: any, code: string, res: Response }>}
   */
  async function loginUser(client, { username, password, acrValues, simIp, softAuth }) {
    // The client keeps its simulated location for the requests that follow the login
    if (simIp) client.simIp = simIp;
    const loginStart = await client.startLogin({ acrValues });
    const authRes = await fetch(loginStart.authorizeUrl);
    const rawCookie = authRes.headers.get("set-cookie") || "";
    const cookie = rawCookie.split(";")[0];

    const loginHeaders = {
      "Content-Type": "application/json",
      Accept: "application/json",
      Cookie: cookie,
    };
    if (simIp) {
      loginHeaders["X-ZTA-Sim-IP"] = simIp;
    }

    const loginRes = await fetch(`${idpIssuer}/oauth/login`, {
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

    // Handle step-up authentication if redirected to stepup.html
    if (loginData.redirect === "/stepup.html" || loginData.redirect?.includes("stepup")) {
      if (!softAuth) {
        const err = new Error("Step-up required but no soft-authenticator provided");
        err.stepUpRequired = true;
        err.risk = loginData.risk;
        throw err;
      }

      // Fetch authentication options
      const authOptsRes = await fetch(`${idpIssuer}/mfa/auth/options`, {
        headers: { Cookie: cookie },
      });
      const authOpts = await authOptsRes.json();

      const assertion = softAuth.createAuthenticationResponse(authOpts, {
        origin: idpIssuer,
        rpID: new URL(idpIssuer).hostname,
      });

      const verifyRes = await fetch(`${idpIssuer}/mfa/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: cookie },
        body: JSON.stringify(assertion),
      });

      const verifyData = await verifyRes.json();
      if (!verifyRes.ok || !verifyData.code) {
        throw new Error(verifyData.error || "WebAuthn step-up failed");
      }
      code = verifyData.code;
    }

    const tokens = await client.finishLogin(code, loginStart.state);
    return { tokens, code, res: loginRes };
  }

  /**
   * Gracefully tears down the stack and removes temp data directory.
   */
  async function stop() {
    for (const client of Object.values(clients)) {
      if (client.stopReattestation) {
        client.stopReattestation();
      }
    }
    for (const s of servers) {
      if (s && s.listening) {
        await new Promise((res) => s.close(res));
      }
    }
    for (const tpm of factoryTpms) {
      if (typeof tpm.close === "function") {
        await Promise.resolve(tpm.close()).catch(() => {});
      }
    }
    if (!overrides.keepTempDir) {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {}
    }
    resetAblation();
  }

  return {
    urls,
    cfg: baseCfg,
    clock,
    clients,
    codes,
    stores: {
      pip: pipStore,
      verifier: verifierStore,
      idp: idpStore,
      resource: resourceStore,
    },
    tpms: {
      alice: aliceTpm,
      bob: bobTpm,
      rogue: rogueTpm,
      evil: evilTpm,
    },
    ca: {
      simVendorCa,
      evilCa,
    },
    keys: {
      verifier: verifierKey,
      idp: idpKey,
      audit: auditKey,
    },
    auditLogFile,
    tempDir,
    loginUser,
    stop,
  };
}

export default { startStack, createFakeClock, createIsolatedMemoryStore };
