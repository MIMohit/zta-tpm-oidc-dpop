/**
 * @file backend.js
 * Real TPM 2.0 backend implementing TpmBackend contract.
 * Powered by tss.js with crash-safe devices and robust handle lifecycle management.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import tss from "tss.js";

import { TpmBackend } from "../sim-tpm/backend.js";
import { selectDevice } from "./devices.js";
import { TpmConn, TpmError, isTpmUnavailable, isHandleError } from "./tpm-conn.js";
import {
  ekRsaTemplate,
  ekEccTemplate,
  ekEccP384HighTemplate,
  srkTemplate,
  akTemplate,
  kbTemplate,
} from "./templates.js";
import { MeasuredBootManager } from "./measured-boot.js";
import { readEkCert, detectEkType } from "./ek-cert.js";
import {
  nameOfTpmt,
  publicAreaFromTpmt,
  isStandardEk,
  classifyEkTemplate,
  parsePublic,
} from "../tpm2/index.js";

export const PERSISTENT_EK_HANDLES = {
  rsa: 0x81010001,
  ecc: 0x81010002,
  ecc384: 0x81010016,
};

export function parseSrkHandle(val) {
  let h;
  if (typeof val === "number") {
    h = val;
  } else if (typeof val === "string") {
    h = val.startsWith("0x") || val.startsWith("0X") ? parseInt(val, 16) : Number(val);
  } else {
    h = 0x81000001;
  }
  if (isNaN(h) || h < 0x81000000 || h > 0x817fffff) {
    throw new Error(`Invalid SRK handle 0x${(h >>> 0).toString(16)}: must be in persistent range 0x81000000-0x817FFFFF`);
  }
  return h;
}

export function loadEkCertChain(stateDir, explicitChain) {
  if (Array.isArray(explicitChain) && explicitChain.length > 0) {
    return explicitChain;
  }
  const chain = [];
  if (process.env.TPM_EK_CHAIN_FILES) {
    const paths = process.env.TPM_EK_CHAIN_FILES.split(",").map((s) => s.trim()).filter(Boolean);
    for (const p of paths) {
      if (fs.existsSync(p)) {
        try {
          const content = fs.readFileSync(p);
          const str = content.toString("utf8");
          if (str.includes("-----BEGIN CERTIFICATE-----")) {
            chain.push(str);
          } else {
            chain.push(content);
          }
        } catch {}
      }
    }
    return chain;
  }

  if (stateDir) {
    const chainDir = path.join(stateDir, "ek-chain");
    if (fs.existsSync(chainDir) && fs.statSync(chainDir).isDirectory()) {
      try {
        const files = fs.readdirSync(chainDir).filter((f) => f.endsWith(".pem") || f.endsWith(".crt") || f.endsWith(".der"));
        for (const file of files) {
          const p = path.join(chainDir, file);
          const content = fs.readFileSync(p);
          const str = content.toString("utf8");
          if (str.includes("-----BEGIN CERTIFICATE-----")) {
            chain.push(str);
          } else {
            chain.push(content);
          }
        }
      } catch {}
    }
  }

  return chain;
}

function matchesEkType(classified, requestedType) {
  if (!classified) return false;
  if (requestedType === "ecc384") {
    return classified.id === "H-3" || classified.curve === "P-384";
  }
  if (requestedType === "ecc") {
    return classified.id === "L-2" || classified.curve === "P-256";
  }
  if (requestedType === "rsa") {
    return classified.id === "L-1" || classified.keyBits === 2048;
  }
  return false;
}

const {
  TPM_HANDLE,
  TPM_RH,
  TPM_SE,
  TPM_ALG_ID,
  TPMA_OBJECT,
  TPMS_PCR_SELECTION,
  TPMS_SENSITIVE_CREATE,
  TPMS_ID_OBJECT,
  TPMS_NULL_SIG_SCHEME,
  TPMT_SYM_DEF,
  TPMT_TK_HASHCHECK,
  Session,
  TPM2B_PRIVATE,
  TPMT_PUBLIC,
} = tss;

function toBuf(val) {
  if (Buffer.isBuffer(val)) return val;
  if (val instanceof Uint8Array) return Buffer.from(val);
  if (typeof val === "string") {
    // Hex string
    if (/^[0-9a-fA-F]+$/.test(val) && val.length % 2 === 0) {
      return Buffer.from(val, "hex");
    }
    // Base64url or utf8
    try {
      return Buffer.from(val, "base64url");
    } catch {
      return Buffer.from(val, "utf8");
    }
  }
  throw new Error("Cannot convert value to buffer");
}

function p1363(sig) {
  const s = sig?.signature || sig;
  const r = Buffer.from(s.signatureR).toString("hex").padStart(64, "0");
  const sPart = Buffer.from(s.signatureS).toString("hex").padStart(64, "0");
  return Buffer.concat([Buffer.from(r, "hex"), Buffer.from(sPart, "hex")]);
}

export class RealTpm extends TpmBackend {
  /**
   * @param {Object} [options]
   * @param {string} [options.device] - auto | tcp | linux | tbs
   * @param {string} [options.host] - Default 127.0.0.1
   * @param {number} [options.port] - Default 2321
   * @param {boolean} [options.powerOn] - Default true
   * @param {number} [options.timeoutMs] - Default 3000
   * @param {string} [options.dir] - State directory for tpm-real.json
   * @param {string} [options.agentDir] - Agent base dir fallback
   * @param {string} [options.ekType] - auto | rsa | ecc
   * @param {number} [options.srkHandle] - Default 0x81000001
   * @param {number} [options.persistKb] - Optional persistent handle for K_B
   * @param {string} [options.goldenBootPath]
   */
  constructor(options = {}) {
    super();
    this.options = options;
    this.deviceType = (options.device || process.env.TPM_DEVICE || "auto").toLowerCase();
    this.dir = options.dir
      ? path.resolve(options.dir)
      : options.agentDir
      ? path.resolve(options.agentDir, "tpm")
      : process.env.TPM_STATE_DIR
      ? path.resolve(process.env.TPM_STATE_DIR)
      : path.resolve("data/agent/tpm");

    this.ekType = options.ekType || process.env.TPM_EK_TYPE || "auto";
    this.srkHandle = parseSrkHandle(options.srkHandle || process.env.TPM_SRK_HANDLE || 0x81000001);
    this.persistKbHandle = options.persistKb || (process.env.TPM_PERSIST_KB ? Number(process.env.TPM_PERSIST_KB) : null);

    this.device = selectDevice({
      device: this.deviceType,
      host: options.host,
      port: options.port,
      powerOn: options.powerOn,
      timeoutMs: options.timeoutMs,
    });

    this.conn = new TpmConn(this.device, { device: this.deviceType });

    this.keys = new Map(); // handle -> { handle, publicArea, name }
    this._keyBlobs = new Map(); // handle -> { pub: Buffer, priv: Buffer }
    this._loadedHandles = new Map(); // handle -> transient uint32 handle

    this.srk = { mode: "primary" };
    this.measuredBoot = null;
    this._isOpen = false;
    this._reopening = null;
  }

  /**
   * Connects to the TPM, initializes device, measured boot, and loads persistent state.
   * @returns {Promise<RealTpm>}
   */
  async open() {
    if (this._isOpen) return this;

    await this.conn.open();
    console.log(`[RealTpm] SRK handle: 0x${this.srkHandle.toString(16)}`);

    // Load existing state from disk if present
    const savedState = this._loadFromDisk();

    // Detect EK type
    this.ekType = await detectEkType(this.conn, this.dir, this.ekType);

    // Initialize measured boot manager
    this.measuredBoot = new MeasuredBootManager({
      conn: this.conn,
      deviceType: this.deviceType,
      goldenBootPath: this.options.goldenBootPath,
      savedEventLog: savedState?.eventLog,
    });
    await this.measuredBoot.init();

    // Check SRK: use persistent SRK if present and valid
    try {
      const srkPub = await this.conn.call("ReadPublic", new TPM_HANDLE(this.srkHandle));
      const attrs = srkPub?.outPublic?.objectAttributes || 0;
      if ((attrs & TPMA_OBJECT.restricted) && (attrs & TPMA_OBJECT.decrypt)) {
        this.srk = {
          mode: "persistent",
          handle: this.srkHandle,
          publicArea: publicAreaFromTpmt(srkPub.outPublic.toBytes()),
        };
      } else {
        this.srk = { mode: "primary" };
      }
    } catch {
      this.srk = { mode: "primary" };
    }

    this._isOpen = true;
    return this;
  }

  /**
   * Runs a TPM operation; if the TPM was lost mid-run (socket closed, or TPM reset ->
   * TPM_RC_INITIALIZE) reconnects once (Startup, flush, reload keys, replay measured
   * boot) and retries. Throws a TpmError with code TPM_UNAVAILABLE if it stays unreachable.
   * @private
   */
  async _withReconnect(fn) {
    try {
      if (!this._isOpen) await this.open();
      return await fn();
    } catch (err) {
      if (!isTpmUnavailable(err)) throw err;
      await this._reopen();
      return fn();
    }
  }

  /**
   * Drops the connection and all transient handles, then opens again. Concurrent callers share one attempt.
   * @private
   */
  _reopen() {
    if (!this._reopening) {
      this._reopening = (async () => {
        this._isOpen = false;
        this._loadedHandles.clear();
        await this.conn.close();
        try {
          await this.open();
        } catch (e) {
          await this.conn.close();
          this._isOpen = false;
          throw new TpmError(`TPM unavailable: ${e.message}`, 0, { unavailable: true });
        }
        console.log("✅ [RealTpm] Reconnected to the TPM (keys reloaded, measured boot replayed if the TPM was reset)");
      })().finally(() => {
        this._reopening = null;
      });
    }
    return this._reopening;
  }

  /**
   * Cheap liveness probe (GetRandom); reconnects if the TPM came back after a loss.
   * @returns {Promise<boolean>}
   */
  async ping() {
    await this.conn.call("GetRandom", 1);
    return true;
  }

  /**
   * Alias for open() to conform to SimTpm.init()
   */
  async init() {
    return this.open();
  }

  /**
   * Loads state from <dir>/tpm-real.json.
   * @private
   */
  _loadFromDisk() {
    if (!this.dir) return null;
    const stateFile = path.join(this.dir, "tpm-real.json");
    if (!fs.existsSync(stateFile)) return null;

    try {
      const data = JSON.parse(fs.readFileSync(stateFile, "utf8"));
      if (data.ekType) this.ekType = data.ekType;
      if (data.srk) this.srk = data.srk;

      if (data.keys) {
        for (const [id, k] of Object.entries(data.keys)) {
          this.keys.set(id, {
            handle: id,
            publicArea: k.publicArea,
            name: Buffer.from(k.name, "hex"),
          });
          this._keyBlobs.set(id, {
            pub: Buffer.from(k.pub, "hex"),
            priv: Buffer.from(k.priv, "hex"),
          });
        }
      }
      return data;
    } catch (err) {
      console.warn("⚠️ [RealTpm] Error loading tpm-real.json:", err.message);
      return null;
    }
  }

  /**
   * Persists state to <dir>/tpm-real.json with mode 0600.
   * @private
   */
  _saveToDisk() {
    if (!this.dir) return;
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const stateFile = path.join(this.dir, "tpm-real.json");

    const keysObj = {};
    for (const [id, k] of this.keys.entries()) {
      const blob = this._keyBlobs.get(id);
      keysObj[id] = {
        name: k.name.toString("hex"),
        publicArea: k.publicArea,
        pub: blob?.pub ? blob.pub.toString("hex") : "",
        priv: blob?.priv ? blob.priv.toString("hex") : "",
      };
    }

    const state = {
      v: 1,
      device: this.deviceType,
      ekType: this.ekType,
      srk: this.srk,
      keys: keysObj,
      eventLog: this.measuredBoot?.readEventLog() || [],
    };

    fs.writeFileSync(stateFile, JSON.stringify(state, null, 2), {
      encoding: "utf8",
      mode: 0o600,
    });
    try {
      fs.chmodSync(stateFile, 0o600);
    } catch {}
  }

  /**
   * Ensures the logical key ('ak' or 'kb') is loaded in the TPM and returns its transient handle.
   * @private
   */
  async _ensureLoaded(id) {
    if (this._loadedHandles.has(id)) {
      return this._loadedHandles.get(id);
    }

    const blob = this._keyBlobs.get(id);
    if (!blob) {
      const err = new Error(`TPM_RC_HANDLE: key handle '${id}' not loaded and not in state`);
      err.code = "TPM_RC_HANDLE";
      throw err;
    }

    const priv = TPM2B_PRIVATE.fromBytes(blob.priv);
    const pub = TPMT_PUBLIC.fromBytes(blob.pub);

    let loadedHandle;

    if (this.srk.mode === "persistent") {
      const res = await this.conn.call("Load", new TPM_HANDLE(this.srk.handle), priv, pub);
      loadedHandle = typeof res.handle === "number" ? res.handle >>> 0 : res.handle.handle >>> 0;
    } else {
      // Primary SRK (deterministic)
      const srk = await this.conn.call("CreatePrimary", new TPM_HANDLE(TPM_RH.OWNER), new TPMS_SENSITIVE_CREATE(), srkTemplate, Buffer.alloc(0), []);
      try {
        const res = await this.conn.call("Load", srk.handle, priv, pub);
        loadedHandle = typeof res.handle === "number" ? res.handle >>> 0 : res.handle.handle >>> 0;
      } finally {
        await this.conn.call("FlushContext", srk.handle).catch(() => {});
      }
    }

    this._loadedHandles.set(id, loadedHandle);
    return loadedHandle;
  }

  /**
   * Obtains public area for SRK.
   */
  async getSrkPublic() {
    if (this.srk.mode === "persistent") {
      const r = await this.conn.call("ReadPublic", new TPM_HANDLE(this.srk.handle));
      return publicAreaFromTpmt(r.outPublic.toBytes());
    }
    const srk = await this.conn.call("CreatePrimary", new TPM_HANDLE(TPM_RH.OWNER), new TPMS_SENSITIVE_CREATE(), srkTemplate, Buffer.alloc(0), []);
    try {
      return publicAreaFromTpmt(srk.outPublic.toBytes());
    } finally {
      await this.conn.call("FlushContext", srk.handle).catch(() => {});
    }
  }

  /**
   * Returns Endorsement Key (EK) public area and certificate.
   * @returns {Promise<{ publicArea: Record<string, any>, cert: string, chain: Array }>}
   */
  async getEk() {
    if (!this._isOpen) await this.open();

    let ekPubBytes;
    const persistentEkHandle = PERSISTENT_EK_HANDLES[this.ekType];

    if (persistentEkHandle) {
      try {
        const r = await this.conn.call("ReadPublic", new TPM_HANDLE(persistentEkHandle));
        const pub = r.outPublic.toBytes();
        const classified = classifyEkTemplate(pub);
        if (matchesEkType(classified, this.ekType)) {
          ekPubBytes = pub;
        }
      } catch {}
    }

    if (!ekPubBytes) {
      const tmpl =
        this.ekType === "ecc384"
          ? ekEccP384HighTemplate
          : this.ekType === "ecc"
          ? ekEccTemplate
          : ekRsaTemplate;
      const ek = await this.conn.call("CreatePrimary", new TPM_HANDLE(TPM_RH.ENDORSEMENT), new TPMS_SENSITIVE_CREATE(), tmpl, Buffer.alloc(0), []);
      try {
        ekPubBytes = ek.outPublic.toBytes();
      } finally {
        await this.conn.call("FlushContext", ek.handle).catch(() => {});
      }
    }

    const publicArea = publicAreaFromTpmt(ekPubBytes);
    const certBuf = await readEkCert(this.conn, this.ekType, this.dir);
    const certStr = certBuf ? certBuf.toString("base64") : "";
    const chain = loadEkCertChain(this.dir, this.options.ekCertChain || this.options.chain);

    return {
      publicArea,
      cert: certStr,
      nvIndex: certBuf?.nvIndex,
      chain,
      ekCertChain: chain,
    };
  }

  /**
   * Returns extras required for enrolment of a real TPM.
   * @returns {Promise<{ ekPublic: Record<string, any>, srkPublic: Record<string, any>, ekCertChain: Array }>}
   */
  async getEnrolExtras() {
    const ek = await this.getEk();
    const srkPub = await this.getSrkPublic();
    return {
      ekPublic: ek.publicArea,
      srkPublic: srkPub,
      ekCertChain: ek.chain,
    };
  }

  /**
   * Creates an Attestation Key (AK).
   * @returns {Promise<{ handle: string, publicArea: Record<string, any>, name: Buffer }>}
   */
  async createAk() {
    return this._createKey("ak", akTemplate);
  }

  /**
   * Creates a Binding Key (K_B).
   * @returns {Promise<{ handle: string, publicArea: Record<string, any>, name: Buffer }>}
   */
  async createKb() {
    return this._createKey("kb", kbTemplate);
  }

  /**
   * Helper to create and load a child key under SRK.
   * @private
   */
  async _createKey(id, template) {
    if (!this._isOpen) await this.open();

    let srkHandleToUse;
    let srkPrimaryHandle = null;

    if (this.srk.mode === "persistent") {
      srkHandleToUse = new TPM_HANDLE(this.srk.handle);
    } else {
      const srk = await this.conn.call("CreatePrimary", new TPM_HANDLE(TPM_RH.OWNER), new TPMS_SENSITIVE_CREATE(), srkTemplate, Buffer.alloc(0), []);
      srkPrimaryHandle = srk.handle;
      srkHandleToUse = srk.handle;
    }

    let created, loaded;
    try {
      created = await this.conn.call("Create", srkHandleToUse, new TPMS_SENSITIVE_CREATE(), template, Buffer.alloc(0), []);
      loaded = await this.conn.call("Load", srkHandleToUse, created.outPrivate, created.outPublic);
    } finally {
      if (srkPrimaryHandle) {
        await this.conn.call("FlushContext", srkPrimaryHandle).catch(() => {});
      }
    }

    // Flush previous loaded handle if any
    if (this._loadedHandles.has(id)) {
      const prevH = this._loadedHandles.get(id);
      await this.conn.call("FlushContext", new TPM_HANDLE(prevH)).catch(() => {});
    }

    const loadedUint = typeof loaded.handle === "number" ? loaded.handle >>> 0 : loaded.handle.handle >>> 0;
    this._loadedHandles.set(id, loadedUint);

    const pubBytes = created.outPublic.toBytes();
    const privBytes = created.outPrivate.toBytes();
    const name = nameOfTpmt(pubBytes);
    const publicArea = publicAreaFromTpmt(pubBytes);

    this.keys.set(id, { handle: id, publicArea, name });
    this._keyBlobs.set(id, { pub: pubBytes, priv: privBytes });

    this._saveToDisk();

    return { handle: id, publicArea, name };
  }

  /**
   * Activates credential blob for the AK.
   *
   * @param {string} akHandle
   * @param {Object} blob - { format: "tpm2", credentialBlob, secret }
   * @returns {Promise<Buffer>} Recovered secret s
   */
  async activateCredential(akHandle, blob) {
    if (!this._isOpen) await this.open();

    if (!blob || blob.format !== "tpm2" || !blob.credentialBlob || !blob.secret) {
      const err = new Error("TPM_RC_INTEGRITY: invalid or incompatible credential blob format");
      err.code = "TPM_RC_INTEGRITY";
      throw err;
    }

    const idObjectBuf = Buffer.from(blob.credentialBlob, "base64url");
    const encSecretBuf = Buffer.from(blob.secret, "base64url");

    if (idObjectBuf.length < 4) {
      const err = new Error("TPM_RC_INTEGRITY: credential blob too short");
      err.code = "TPM_RC_INTEGRITY";
      throw err;
    }

    const integrityLen = idObjectBuf.readUInt16BE(0);
    const integrity = idObjectBuf.subarray(2, 2 + integrityLen);
    const encIdentity = idObjectBuf.subarray(2 + integrityLen);
    const idObject = new TPMS_ID_OBJECT(integrity, encIdentity);

    const akH = await this._ensureLoaded("ak");

    // Load EK via persistent handle if it exists and matches, else CreatePrimary
    let ekHandleToUse = null;
    let ekPrimaryToFlush = null;
    let ekTemplateClass = null;

    const persistentEkHandle = PERSISTENT_EK_HANDLES[this.ekType];
    if (persistentEkHandle) {
      try {
        const r = await this.conn.call("ReadPublic", new TPM_HANDLE(persistentEkHandle));
        const pub = r.outPublic.toBytes();
        const classified = classifyEkTemplate(pub);
        if (matchesEkType(classified, this.ekType)) {
          ekHandleToUse = new TPM_HANDLE(persistentEkHandle);
          ekTemplateClass = classified;
        }
      } catch {}
    }

    if (!ekHandleToUse) {
      const tmpl =
        this.ekType === "ecc384"
          ? ekEccP384HighTemplate
          : this.ekType === "ecc"
          ? ekEccTemplate
          : ekRsaTemplate;
      const ek = await this.conn.call("CreatePrimary", new TPM_HANDLE(TPM_RH.ENDORSEMENT), new TPMS_SENSITIVE_CREATE(), tmpl, Buffer.alloc(0), []);
      ekHandleToUse = ek.handle;
      ekPrimaryToFlush = ek.handle;
      ekTemplateClass = classifyEkTemplate(ek.outPublic.toBytes());
    }

    // If EK template has userWithAuth (H template), authorize with empty password session
    if (ekTemplateClass?.userWithAuth) {
      try {
        this.conn.withSessions(Session.Pw(), Session.Pw());
        const secret = await this.conn.call(
          "ActivateCredential",
          new TPM_HANDLE(akH),
          ekHandleToUse,
          idObject,
          encSecretBuf
        );
        return Buffer.from(secret);
      } finally {
        if (ekPrimaryToFlush) {
          await this.conn.call("FlushContext", ekPrimaryToFlush).catch(() => {});
        }
      }
    }

    let polSession = null;
    try {
      polSession = await this.conn.call(
        "StartAuthSession",
        null,
        null,
        crypto.randomBytes(32),
        Buffer.alloc(0),
        TPM_SE.POLICY,
        new TPMT_SYM_DEF(TPM_ALG_ID.NULL, 0, TPM_ALG_ID.NULL),
        TPM_ALG_ID.SHA256
      );

      await this.conn.call(
        "PolicySecret",
        new TPM_HANDLE(TPM_RH.ENDORSEMENT),
        polSession.handle,
        Buffer.alloc(0),
        Buffer.alloc(0),
        Buffer.alloc(0),
        0
      );

      this.conn.withSessions(Session.Pw(), new Session(polSession.handle));

      const secret = await this.conn.call(
        "ActivateCredential",
        new TPM_HANDLE(akH),
        ekHandleToUse,
        idObject,
        encSecretBuf
      );

      return Buffer.from(secret);
    } finally {
      // Failed command does not consume policy session (G6); always flush in finally
      if (polSession) {
        await this.conn.call("FlushContext", polSession.handle).catch(() => {});
      }
      if (ekPrimaryToFlush) {
        await this.conn.call("FlushContext", ekPrimaryToFlush).catch(() => {});
      }
    }
  }

  /**
   * Produces a TPM2_Quote over selected PCRs signed by AK.
   *
   * @param {string} akHandle
   * @param {Buffer|string} nonce
   * @param {number[]} [pcrSel=[0,1,2,3,4,5,6,7]]
   * @returns {Promise<{ attest: Buffer, sig: string, pcrs: string[] }>}
   */
  async quote(akHandle, nonce, pcrSel = [0, 1, 2, 3, 4, 5, 6, 7]) {
    if (!this._isOpen) await this.open();

    const akH = await this._ensureLoaded("ak");
    const nonceBuf = toBuf(nonce);

    let mask = 0;
    for (const p of pcrSel) mask |= 1 << p;
    const pcrSelectBuf = Buffer.from([mask & 0xff, (mask >> 8) & 0xff, (mask >> 16) & 0xff]);
    const pcrSelection = [new TPMS_PCR_SELECTION(TPM_ALG_ID.SHA256, pcrSelectBuf)];

    let q;
    try {
      q = await this.conn.call("Quote", new TPM_HANDLE(akH), nonceBuf, new TPMS_NULL_SIG_SCHEME(), pcrSelection);
    } catch (err) {
      // Reload on handle loss and retry once
      if (isHandleError(err)) {
        this._loadedHandles.delete("ak");
        const freshAkH = await this._ensureLoaded("ak");
        q = await this.conn.call("Quote", new TPM_HANDLE(freshAkH), nonceBuf, new TPMS_NULL_SIG_SCHEME(), pcrSelection);
      } else {
        throw err;
      }
    }

    const attest = this.conn.rawAttest();
    const sig = p1363(q.signature).toString("base64url");

    // Read current PCR values
    const pr = await this.conn.call("PCR_Read", pcrSelection);
    const pcrs = (pr.pcrValues || []).map((d) => Buffer.from(d.buffer).toString("hex"));

    return { attest, sig, pcrs };
  }

  /**
   * Produces a TPM2_Certify of an object (K_B) by the AK.
   *
   * @param {string} objHandle
   * @param {string} akHandle
   * @param {Buffer|string} nonce
   * @returns {Promise<{ attest: Buffer, sig: string }>}
   */
  async certify(objHandle, akHandle, nonce) {
    if (!this._isOpen) await this.open();

    const kbH = await this._ensureLoaded("kb");
    const akH = await this._ensureLoaded("ak");
    const nonceBuf = toBuf(nonce);

    let c;
    try {
      c = await this.conn.call("Certify", new TPM_HANDLE(kbH), new TPM_HANDLE(akH), nonceBuf, new TPMS_NULL_SIG_SCHEME());
    } catch (err) {
      if (isHandleError(err)) {
        this._loadedHandles.delete("ak");
        this._loadedHandles.delete("kb");
        const freshKbH = await this._ensureLoaded("kb");
        const freshAkH = await this._ensureLoaded("ak");
        c = await this.conn.call("Certify", new TPM_HANDLE(freshKbH), new TPM_HANDLE(freshAkH), nonceBuf, new TPMS_NULL_SIG_SCHEME());
      } else {
        throw err;
      }
    }

    const attest = this.conn.rawAttest();
    const sig = p1363(c.signature).toString("base64url");

    return { attest, sig };
  }

  /**
   * Signs data with K_B (ES256 P1363).
   * Refuses restricted keys before calling the TPM.
   *
   * @param {string} kbHandle
   * @param {Buffer|Uint8Array|string} data
   * @returns {Promise<Buffer>} 64-byte IEEE-P1363 signature (r || s)
   */
  async sign(kbHandle, data) {
    if (!this._isOpen) await this.open();

    const keyInfo = this.keys.get(kbHandle) || this.keys.get("kb");
    if (!keyInfo) {
      const err = new Error(`TPM_RC_HANDLE: key handle '${kbHandle}' not loaded`);
      err.code = "TPM_RC_HANDLE";
      throw err;
    }

    const attrs = keyInfo.publicArea.objectAttributes;
    if (attrs & TPMA_OBJECT.restricted) {
      const err = new Error("TPM_RC_ATTRIBUTES: restricted key cannot be used with sign()");
      err.code = "TPM_RC_ATTRIBUTES";
      throw err;
    }
    if (!(attrs & TPMA_OBJECT.sign)) {
      const err = new Error("TPM_RC_ATTRIBUTES: key does not have signing attribute");
      err.code = "TPM_RC_ATTRIBUTES";
      throw err;
    }

    const kbH = await this._ensureLoaded("kb");
    const dataBuf = Buffer.isBuffer(data)
      ? data
      : data instanceof Uint8Array
      ? Buffer.from(data)
      : Buffer.from(String(data), "utf8");

    const digest = crypto.createHash("sha256").update(dataBuf).digest();

    let sg;
    try {
      sg = await this.conn.call("Sign", new TPM_HANDLE(kbH), digest, new TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK.nullTicket());
    } catch (err) {
      if (isHandleError(err)) {
        this._loadedHandles.delete("kb");
        const freshKbH = await this._ensureLoaded("kb");
        sg = await this.conn.call("Sign", new TPM_HANDLE(freshKbH), digest, new TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK.nullTicket());
      } else {
        throw err;
      }
    }

    return p1363(sg);
  }

  /**
   * Reads measured boot event log.
   * @returns {Array|null}
   */
  readEventLog() {
    return this.measuredBoot ? this.measuredBoot.readEventLog() : null;
  }

  /**
   * Extends PCR measurement.
   *
   * @param {number} pcr
   * @param {Buffer|string} digest
   * @param {string} [desc=""]
   */
  async extendPcr(pcr, digest, desc = "") {
    if (!this._isOpen) await this.open();
    await this.measuredBoot.extendPcr(pcr, digest, desc);
    this._saveToDisk();
  }

  /**
   * Tamper helper: extends PCR4 with rogue measurement (TCP devices only).
   *
   * @param {string} [desc="rogue measurement"]
   */
  async tamper(desc = "rogue measurement") {
    if (!this._isOpen) await this.open();
    await this.measuredBoot.tamper(desc);
    this._saveToDisk();
  }

  /**
   * Closes the backend and connection.
   */
  async close() {
    this._isOpen = false;
    for (const [id, h] of this._loadedHandles.entries()) {
      try {
        await this.conn.call("FlushContext", new TPM_HANDLE(h));
      } catch {}
    }
    this._loadedHandles.clear();
    await this.conn.close();
  }
}

// Every TPM-touching operation survives a TPM restart/power-cycle mid-run (VERIFY3 V4).
for (const method of [
  "ping",
  "getSrkPublic",
  "getEk",
  "getEnrolExtras",
  "createAk",
  "createKb",
  "activateCredential",
  "quote",
  "certify",
  "sign",
  "extendPcr",
  "tamper",
]) {
  const op = RealTpm.prototype[method];
  RealTpm.prototype[method] = function (...args) {
    return this._withReconnect(() => op.apply(this, args));
  };
}

export default RealTpm;
