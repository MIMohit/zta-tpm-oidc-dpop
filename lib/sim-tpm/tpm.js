/**
 * @file tpm.js
 * Simulated TPM (Software TPM 2.0 subset).
 * Implements TpmBackend interface.
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import * as jose from "jose";

import { TpmBackend } from "./backend.js";
import {
  TPMA_OBJECT,
  makePublicArea,
  nameOf,
  jwkOf,
} from "./public-area.js";
import {
  marshalAttest,
  pcrDigest,
  replayEventLog,
  TPM_ST_ATTEST_QUOTE,
  TPM_ST_ATTEST_CERTIFY,
} from "./attest.js";
import { activate } from "./credential.js";
import { issueEkCert } from "./vendor-ca.js";
import {
  parseTcgEventLog,
  replayTcgEventLog,
  toAppraisalEvents,
} from "../verifier/tcg-eventlog.js";

/**
 * Loads golden boot fixture from disk or fallback array.
 * @param {string} [fixturePath]
 * @returns {Array<{ pcr: number, digest: string, desc: string }>}
 */
function loadGoldenBoot(fixturePath) {
  const p = fixturePath || path.resolve(import.meta.dirname, "../../fixtures/golden-boot.json");
  if (fs.existsSync(p)) {
    try {
      return JSON.parse(fs.readFileSync(p, "utf8"));
    } catch {
      // Fallback
    }
  }
  // Built-in fallback
  return [
    { pcr: 0, desc: "CRTM: Core Root of Trust for Measurement", digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    { pcr: 0, desc: "UEFI: Base Firmware Code", digest: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3" },
    { pcr: 1, desc: "UEFI: Host Platform Configuration", digest: "b5a2c96250612366ea8c2c10df6be08602df3649022e497220c8b7b05ff161ac" },
    { pcr: 2, desc: "UEFI: Option ROM and Device Drivers", digest: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592" },
    { pcr: 3, desc: "UEFI: Option ROM Configuration and Data", digest: "044852b2a6703b057691660ab9ec41300f7457704772048d70f552e8290cb733" },
    { pcr: 4, desc: "UEFI: Bootloader Executable (shim/GRUB)", digest: "7d793037a0760186574b0282f2f435e708170e62ffc672111225f4859a7a49b6" },
    { pcr: 4, desc: "OS: Kernel Image and Initramfs", digest: "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d" },
    { pcr: 5, desc: "GPT: Partition Table and Boot Config", digest: "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a" },
    { pcr: 6, desc: "State: Resume from S4/S5 and Power State", digest: "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c" },
    { pcr: 7, desc: "SecureBoot: Policy (PK, KEK, db, dbx) - SecureBoot=on", digest: "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918" },
  ];
}

export class SimTpm extends TpmBackend {
  /**
   * @param {Object} [options]
   * @param {string} [options.dir] - Storage directory for tpm.json
   * @param {Object} [options.caKey] - Vendor CA key used to issue EK cert if needed
   * @param {string} [options.goldenBootPath] - Path to golden-boot.json
   * @param {Buffer} [options.bootLog] - Raw TCG binary event log to replay into PCR0..7
   * @param {Function} [options.clock] - Custom clock function
   */
  constructor(options = {}) {
    super();
    this.dir = options.dir ? path.resolve(options.dir) : null;
    this.caKey = options.caKey || null;
    this.goldenBootPath = options.goldenBootPath || null;
    this.bootLog = options.bootLog ? Buffer.from(options.bootLog) : null;
    this.clock = options.clock || (() => Date.now());

    this.ek = null;
    this.keys = new Map(); // handle -> { handle, privateJwk, publicArea, name, isAk, isKb }

    this.resetCount = 1;
    this.restartCount = 0;
    this.firmwareVersion = 1n;

    this.pcrs = Array.from({ length: 8 }, () => Buffer.alloc(32, 0));
    this.eventLog = [];

    // Boot: replay boot measurements
    this._boot();

    // If dir is specified, attempt to load state
    if (this.dir) {
      this._loadFromDisk();
    }
  }

  /**
   * Resets PCRs to 0 and replays boot events into PCR0..7.
   * @private
   */
  _boot() {
    this.pcrs = Array.from({ length: 8 }, () => Buffer.alloc(32, 0));
    this.eventLog = [];
    if (this.bootLog) {
      const parsed = parseTcgEventLog(this.bootLog);
      const { pcrs } = replayTcgEventLog(parsed, { bank: "sha256", pcrs: [0, 1, 2, 3, 4, 5, 6, 7] });
      for (let i = 0; i < 8; i++) {
        this.pcrs[i] = pcrs[i] || Buffer.alloc(32, 0);
      }
      this.eventLog = toAppraisalEvents(parsed, { bank: "sha256", pcrs: [0, 1, 2, 3, 4, 5, 6, 7] });
      return;
    }
    const goldenEvents = loadGoldenBoot(this.goldenBootPath);
    for (const evt of goldenEvents) {
      this.extendPcr(evt.pcr, evt.digest, evt.desc);
    }
  }

  /**
   * Reads state from <dir>/tpm.json if present.
   * @private
   */
  _loadFromDisk() {
    if (!this.dir) return;
    const filePath = path.join(this.dir, "tpm.json");
    if (!fs.existsSync(filePath)) return;

    try {
      const data = JSON.parse(fs.readFileSync(filePath, "utf8"));
      if (data.ek) {
        this.ek = data.ek;
      }
      if (data.keys) {
        for (const [handle, k] of Object.entries(data.keys)) {
          this.keys.set(handle, {
            ...k,
            name: Buffer.from(k.name, "hex"),
          });
        }
      }
      if (typeof data.resetCount === "number") {
        this.resetCount = data.resetCount;
      }
      if (typeof data.restartCount === "number") {
        this.restartCount = data.restartCount;
      }
      if (Array.isArray(data.eventLog) && data.eventLog.length > 0) {
        this.eventLog = data.eventLog;
        const replayed = replayEventLog(this.eventLog);
        this.pcrs = replayed.pcrs;
      }
    } catch (err) {
      console.warn("⚠️ [SimTpm] Error loading tpm.json:", err.message);
    }
  }

  /**
   * Persists current state to <dir>/tpm.json with mode 0600.
   * @private
   */
  _saveToDisk() {
    if (!this.dir) return;
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const filePath = path.join(this.dir, "tpm.json");

    const keysObj = {};
    for (const [h, k] of this.keys.entries()) {
      keysObj[h] = {
        ...k,
        name: k.name.toString("hex"),
      };
    }

    const state = {
      ek: this.ek,
      keys: keysObj,
      resetCount: this.resetCount,
      restartCount: this.restartCount,
      firmwareVersion: this.firmwareVersion.toString(),
      eventLog: this.eventLog,
      pcrs: this.pcrs.map((p) => p.toString("hex")),
    };

    fs.writeFileSync(filePath, JSON.stringify(state, null, 2), {
      encoding: "utf8",
      mode: 0o600,
    });
    try {
      fs.chmodSync(filePath, 0o600);
    } catch {
      // Ignore on non-POSIX
    }
  }

  /**
   * Initializes the TPM, generating EK and EK certificate if not already present.
   * @returns {Promise<SimTpm>}
   */
  async init() {
    if (!this.ek) {
      // Generate EK keypair: ECC P-256 restricted-decrypt
      const { privateKey, publicKey } = await jose.generateKeyPair("ES256", { extractable: true });
      const privateJwk = await jose.exportJWK(privateKey);
      const publicJwk = await jose.exportJWK(publicKey);

      const attrs =
        TPMA_OBJECT.fixedTPM |
        TPMA_OBJECT.fixedParent |
        TPMA_OBJECT.sensitiveDataOrigin |
        TPMA_OBJECT.userWithAuth |
        TPMA_OBJECT.restricted |
        TPMA_OBJECT.decrypt;

      const publicArea = makePublicArea(publicJwk, attrs);

      // Issue EK cert if CA is provided
      let cert = "";
      if (this.caKey) {
        cert = await issueEkCert(this.caKey, publicArea);
      }

      this.ek = {
        privateJwk,
        publicArea,
        cert,
      };

      this._saveToDisk();
    }

    return this;
  }

  /**
   * Sets or updates the EK certificate issued by vendor CA.
   * @param {string} cert - Compact JWS EK certificate
   */
  setEkCert(cert) {
    if (!this.ek) {
      throw new Error("Cannot set EK cert before EK is initialized");
    }
    this.ek.cert = cert;
    this._saveToDisk();
  }

  /**
   * Returns EK publicArea and vendor certificate.
   * @returns {Promise<{ publicArea: Record<string, any>, cert: string }>}
   */
  async getEk() {
    if (!this.ek) {
      await this.init();
    }
    return {
      publicArea: this.ek.publicArea,
      cert: this.ek.cert,
    };
  }

  /**
   * Creates an Attestation Key (AK).
   * Attributes: restricted | sign | fixedTPM | fixedParent | sensitiveDataOrigin
   * @returns {Promise<{ handle: string, publicArea: Record<string, any>, name: Buffer }>}
   */
  async createAk() {
    const { privateKey, publicKey } = await jose.generateKeyPair("ES256", { extractable: true });
    const privateJwk = await jose.exportJWK(privateKey);
    const publicJwk = await jose.exportJWK(publicKey);

    const attrs =
      TPMA_OBJECT.restricted |
      TPMA_OBJECT.sign |
      TPMA_OBJECT.fixedTPM |
      TPMA_OBJECT.fixedParent |
      TPMA_OBJECT.sensitiveDataOrigin;

    const publicArea = makePublicArea(publicJwk, attrs);
    const name = nameOf(publicArea);
    this.akSeq = (this.akSeq || 0) + 1;
    const handle = this.akSeq === 1 ? "ak" : `ak_${this.akSeq}`;

    const keyInfo = {
      handle,
      privateJwk,
      publicArea,
      name,
      isAk: true,
      isKb: false,
    };

    this.keys.set(handle, keyInfo);
    // Keep default 'ak' pointer if not already set
    if (!this.keys.has("ak")) {
      this.keys.set("ak", keyInfo);
    }
    this._saveToDisk();

    return { handle, publicArea, name };
  }

  /**
   * Creates a Binding Key (K_B).
   * Attributes: sign | fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth (not restricted, not decrypt).
   * @returns {Promise<{ handle: string, publicArea: Record<string, any>, name: Buffer }>}
   */
  async createKb() {
    const { privateKey, publicKey } = await jose.generateKeyPair("ES256", { extractable: true });
    const privateJwk = await jose.exportJWK(privateKey);
    const publicJwk = await jose.exportJWK(publicKey);

    const attrs =
      TPMA_OBJECT.sign |
      TPMA_OBJECT.fixedTPM |
      TPMA_OBJECT.fixedParent |
      TPMA_OBJECT.sensitiveDataOrigin |
      TPMA_OBJECT.userWithAuth;

    const publicArea = makePublicArea(publicJwk, attrs);
    const name = nameOf(publicArea);
    this.kbSeq = (this.kbSeq || 0) + 1;
    const handle = this.kbSeq === 1 ? "kb" : `kb_${this.kbSeq}`;

    const keyInfo = {
      handle,
      privateJwk,
      publicArea,
      name,
      isAk: false,
      isKb: true,
    };

    this.keys.set(handle, keyInfo);
    if (!this.keys.has("kb")) {
      this.keys.set("kb", keyInfo);
    }
    this._saveToDisk();

    return { handle, publicArea, name };
  }

  /**
   * Activates credential for the loaded AK handle using the EK private key.
   * Throws TPM_RC_INTEGRITY if HMAC or Name check fails.
   *
   * @param {string|number} akHandle
   * @param {{ credentialBlob: string, secret: string }} blob
   * @returns {Promise<Buffer>} The decrypted secret s
   */
  async activateCredential(akHandle, blob) {
    if (!this.ek) {
      await this.init();
    }
    const ak = this.keys.get(akHandle);
    if (!ak) {
      const err = new Error(`TPM_RC_HANDLE: key handle '${akHandle}' not loaded in TPM`);
      err.code = "TPM_RC_HANDLE";
      throw err;
    }

    return activate(this.ek.privateJwk, ak.name, blob);
  }

  /**
   * Produces a TPM2_Quote over selected PCRs and qualifying data (nonce), signed by AK.
   *
   * @param {string|number} akHandle
   * @param {Buffer|string} nonce
   * @param {number[]} [pcrSel=[0, 1, 2, 3, 4, 5, 6, 7]]
   * @returns {Promise<{ attest: Buffer, sig: string, pcrs: string[] }>}
   */
  async quote(akHandle, nonce, pcrSel = [0, 1, 2, 3, 4, 5, 6, 7]) {
    const ak = this.keys.get(akHandle);
    if (!ak) {
      const err = new Error(`TPM_RC_HANDLE: AK handle '${akHandle}' not loaded`);
      err.code = "TPM_RC_HANDLE";
      throw err;
    }
    if (!(ak.publicArea.objectAttributes & TPMA_OBJECT.restricted) || !(ak.publicArea.objectAttributes & TPMA_OBJECT.sign)) {
      const err = new Error("TPM_RC_ATTRIBUTES: quote requires restricted signing key (AK)");
      err.code = "TPM_RC_ATTRIBUTES";
      throw err;
    }

    const currentPcrDigest = pcrDigest(this.pcrs);

    const attest = marshalAttest({
      type: TPM_ST_ATTEST_QUOTE,
      signerName: ak.name,
      extraData: nonce,
      clockInfo: {
        clock: this.clock(),
        resetCount: this.resetCount,
        restartCount: this.restartCount,
        safe: 1,
      },
      firmwareVersion: this.firmwareVersion,
      attested: {
        pcrSelect: {
          count: 1,
          hash: 0x000b,
          sizeofSelect: 3,
          pcrSelect: Buffer.from([0xff, 0x00, 0x00]),
        },
        pcrDigest: currentPcrDigest,
      },
    });

    const keyObj = crypto.createPrivateKey({
      key: {
        kty: "EC",
        crv: "P-256",
        x: ak.privateJwk.x,
        y: ak.privateJwk.y,
        d: ak.privateJwk.d,
      },
      format: "jwk",
    });

    const sigBuf = crypto.sign("sha256", attest, {
      key: keyObj,
      dsaEncoding: "ieee-p1363",
    });

    return {
      attest,
      sig: sigBuf.toString("base64url"),
      pcrs: this.pcrs.map((p) => p.toString("hex")),
    };
  }

  /**
   * Produces a TPM2_Certify certifying an object (K_B) using AK over qualifying data (nonce).
   *
   * @param {string|number} objHandle
   * @param {string|number} akHandle
   * @param {Buffer|string} nonce
   * @returns {Promise<{ attest: Buffer, sig: string }>}
   */
  async certify(objHandle, akHandle, nonce) {
    const ak = this.keys.get(akHandle);
    if (!ak) {
      const err = new Error(`TPM_RC_HANDLE: AK handle '${akHandle}' not loaded`);
      err.code = "TPM_RC_HANDLE";
      throw err;
    }
    const obj = this.keys.get(objHandle);
    if (!obj) {
      const err = new Error(`TPM_RC_HANDLE: Object handle '${objHandle}' not loaded`);
      err.code = "TPM_RC_HANDLE";
      throw err;
    }

    const attest = marshalAttest({
      type: TPM_ST_ATTEST_CERTIFY,
      signerName: ak.name,
      extraData: nonce,
      clockInfo: {
        clock: this.clock(),
        resetCount: this.resetCount,
        restartCount: this.restartCount,
        safe: 1,
      },
      firmwareVersion: this.firmwareVersion,
      attested: {
        name: obj.name,
        qualifiedName: obj.name,
      },
    });

    const keyObj = crypto.createPrivateKey({
      key: {
        kty: "EC",
        crv: "P-256",
        x: ak.privateJwk.x,
        y: ak.privateJwk.y,
        d: ak.privateJwk.d,
      },
      format: "jwk",
    });

    const sigBuf = crypto.sign("sha256", attest, {
      key: keyObj,
      dsaEncoding: "ieee-p1363",
    });

    return {
      attest,
      sig: sigBuf.toString("base64url"),
    };
  }

  /**
   * Signs data with K_B key (ES256 IEEE-P1363).
   * Refuses AK or any restricted key to enforce TPM restricted key modeling.
   *
   * @param {string|number} kbHandle
   * @param {Buffer|Uint8Array|string} data
   * @returns {Promise<Buffer>} 64-byte IEEE-P1363 signature (r || s)
   */
  async sign(kbHandle, data) {
    const key = this.keys.get(kbHandle);
    if (!key) {
      const err = new Error(`TPM_RC_HANDLE: key handle '${kbHandle}' not loaded`);
      err.code = "TPM_RC_HANDLE";
      throw err;
    }

    // Refuse AK or any restricted key
    if (key.publicArea.objectAttributes & TPMA_OBJECT.restricted) {
      const err = new Error("TPM_RC_ATTRIBUTES: restricted key cannot be used with sign()");
      err.code = "TPM_RC_ATTRIBUTES";
      throw err;
    }

    if (!(key.publicArea.objectAttributes & TPMA_OBJECT.sign)) {
      const err = new Error("TPM_RC_ATTRIBUTES: key does not have signing attribute");
      err.code = "TPM_RC_ATTRIBUTES";
      throw err;
    }

    const dataBuf = Buffer.isBuffer(data)
      ? data
      : (data instanceof Uint8Array ? Buffer.from(data) : Buffer.from(String(data), "utf8"));

    const keyObj = crypto.createPrivateKey({
      key: {
        kty: "EC",
        crv: "P-256",
        x: key.privateJwk.x,
        y: key.privateJwk.y,
        d: key.privateJwk.d,
      },
      format: "jwk",
    });

    return crypto.sign("sha256", dataBuf, {
      key: keyObj,
      dsaEncoding: "ieee-p1363",
    });
  }

  /**
   * Reads measured boot event log.
   * Returns { format: "tcg2-binary", data } if bootLog is set, else legacy JSON array.
   * @returns {Array<{ pcr: number, digest: string, desc: string }>|{ format: string, data: string }}
   */
  readEventLog() {
    if (this.bootLog) {
      return {
        format: "tcg2-binary",
        data: this.bootLog.toString("base64url"),
      };
    }
    return JSON.parse(JSON.stringify(this.eventLog));
  }

  /**
   * Extends PCR measurement and updates event log.
   * @param {number} pcr
   * @param {Buffer|string} digest
   * @param {string} [desc=""]
   */
  extendPcr(pcr, digest, desc = "") {
    if (pcr < 0 || pcr > 7) {
      throw new Error(`Invalid PCR index: ${pcr} (expected 0..7)`);
    }
    const dBuf = typeof digest === "string" ? Buffer.from(digest, "hex") : Buffer.from(digest);
    this.pcrs[pcr] = crypto.createHash("sha256").update(this.pcrs[pcr]).update(dBuf).digest();
    this.eventLog.push({
      pcr,
      digest: dBuf.toString("hex"),
      desc: String(desc),
    });
    if (this.bootLog) {
      const eventData = Buffer.from(String(desc || ""), "utf8");
      const header = Buffer.alloc(12 + 2 + 32 + 4);
      header.writeUInt32LE(pcr, 0);
      header.writeUInt32LE(0x06, 4); // EV_EVENT_TAG
      header.writeUInt32LE(1, 8); // 1 digest
      header.writeUInt16LE(0x000b, 12); // SHA-256
      dBuf.copy(header, 14);
      header.writeUInt32LE(eventData.length, 14 + 32);
      this.bootLog = Buffer.concat([this.bootLog, header, eventData]);
    }
    this._saveToDisk();
  }

  /**
   * Tamper helper: extends PCR4 with a rogue measurement digest.
   * Causes quote pcrDigest to deviate from the reference values.
   * @param {string} [desc="rogue measurement"]
   */
  tamper(desc = "rogue measurement") {
    const rogueDigest = crypto.createHash("sha256").update(desc).digest();
    if (this.bootLog) {
      this.pcrs[4] = crypto.createHash("sha256").update(this.pcrs[4]).update(rogueDigest).digest();
      const eventData = Buffer.from(desc, "utf8");
      const header = Buffer.alloc(12 + 2 + 32 + 4);
      header.writeUInt32LE(4, 0); // PCR4
      header.writeUInt32LE(0x80000003, 4); // EV_EFI_BOOT_SERVICES_APPLICATION
      header.writeUInt32LE(1, 8); // 1 digest
      header.writeUInt16LE(0x000b, 12); // SHA-256
      rogueDigest.copy(header, 14);
      header.writeUInt32LE(eventData.length, 14 + 32);
      this.bootLog = Buffer.concat([this.bootLog, header, eventData]);
      this.eventLog.push({
        pcr: 4,
        digest: rogueDigest.toString("hex"),
        desc: String(desc),
      });
      this._saveToDisk();
      return;
    }
    this.extendPcr(4, rogueDigest, desc);
  }
}

export default SimTpm;
