import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonical, sha256 } from "./canonical.js";
import { loadOrCreateSigningKey } from "./keys.js";

const GENESIS_PREV = "0".repeat(64);

/**
 * Normalises a private key into a Node KeyObject.
 * @param {any} key
 * @returns {crypto.KeyObject}
 */
function toPrivateKeyObject(key) {
  let priv = key?.privateKey || key;
  if (!priv) {
    throw new Error("Missing private key for audit signing");
  }
  if (priv instanceof crypto.KeyObject) {
    return priv;
  }
  if (priv.type === "private" || priv.type === "secret") {
    return crypto.KeyObject.from(priv);
  }
  if (typeof priv === "object" && priv.kty) {
    return crypto.createPrivateKey({ key: priv, format: "jwk" });
  }
  return priv;
}

/**
 * Normalises a public key into a Node KeyObject.
 * @param {any} key
 * @returns {crypto.KeyObject}
 */
function toPublicKeyObject(key) {
  let pub = key?.publicJwk || key?.publicKey || key;
  if (!pub) {
    throw new Error("Missing public key for audit verification");
  }
  if (pub instanceof crypto.KeyObject) {
    return pub;
  }
  if (pub.type === "public") {
    return crypto.KeyObject.from(pub);
  }
  if (typeof pub === "object" && pub.kty) {
    return crypto.createPublicKey({ key: pub, format: "jwk" });
  }
  return pub;
}

/**
 * Signs a hash string using ECDSA-P256-SHA256 (IEEE P1363 format).
 * @param {string} hash
 * @param {any} key
 * @returns {string} base64url-encoded signature
 */
export function signAuditHash(hash, key) {
  const privKeyObj = toPrivateKeyObject(key);
  const sigBuf = crypto.sign("sha256", Buffer.from(hash, "utf8"), {
    key: privKeyObj,
    dsaEncoding: "ieee-p1363",
  });
  return sigBuf.toString("base64url");
}

/**
 * Verifies an audit log signature.
 * @param {string} hash
 * @param {string} sig
 * @param {any} key
 * @returns {boolean}
 */
export function verifyAuditSig(hash, sig, key) {
  try {
    const pubKeyObj = toPublicKeyObject(key);
    const sigBuf = Buffer.isBuffer(sig) ? sig : Buffer.from(sig, "base64url");
    return crypto.verify(
      "sha256",
      Buffer.from(hash, "utf8"),
      {
        key: pubKeyObj,
        dsaEncoding: "ieee-p1363",
      },
      sigBuf
    );
  } catch {
    return false;
  }
}

/**
 * Creates an append-only, tamper-evident signed audit log.
 * Entries follow the hash-chain structure:
 *   entry = { seq, ts, prev, ...record }
 *   hash = sha256(canonical(entry))
 *   sig = ES256(hash)
 *
 * Sequence number and previous hash are recovered from the last line on start.
 *
 * @param {object} params
 * @param {string} params.file - Absolute or relative path to log file
 * @param {any} params.key - Signing key object (from loadOrCreateSigningKey) or KeyObject
 * @param {() => number} [params.clock] - Clock returning ms epoch
 * @returns {{ append: (record: Record<string, any>) => Record<string, any>, getFile: () => string, getSeq: () => number, getPrev: () => string }}
 */
export function createAuditLog(params = {}) {
  const { file, key, clock = () => Date.now() } = params;

  if (!file) {
    throw new Error("createAuditLog requires a 'file' parameter");
  }
  if (!key) {
    throw new Error("createAuditLog requires a 'key' parameter");
  }

  const resolvedFile = path.resolve(file);
  fs.mkdirSync(path.dirname(resolvedFile), { recursive: true });

  let seq = 0;
  let prev = GENESIS_PREV;

  // Recover state from last line if file exists
  if (fs.existsSync(resolvedFile)) {
    try {
      const content = fs.readFileSync(resolvedFile, "utf8").trim();
      if (content.length > 0) {
        const lines = content.split("\n");
        for (let i = lines.length - 1; i >= 0; i--) {
          const line = lines[i].trim();
          if (line) {
            const parsed = JSON.parse(line);
            if (typeof parsed.seq === "number") seq = parsed.seq;
            if (typeof parsed.hash === "string") prev = parsed.hash;
            break;
          }
        }
      }
    } catch (err) {
      console.warn(`[AUDIT] Could not read existing log for recovery: ${err.message}`);
    }
  }

  return {
    /**
     * Appends a new audit record to the log.
     * @param {Record<string, any>} record
     * @returns {Record<string, any>} Appended record including seq, ts, prev, hash, sig
     */
    append(record) {
      seq += 1;
      const ts = clock();
      const entry = {
        seq,
        ts,
        prev,
        ...record,
      };

      const canon = canonical(entry);
      const hash = sha256(canon, "hex");
      const sig = signAuditHash(hash, key);

      const logLineObj = { ...entry, hash, sig };
      fs.appendFileSync(resolvedFile, JSON.stringify(logLineObj) + "\n", {
        encoding: "utf8",
      });

      prev = hash;
      return logLineObj;
    },

    getFile() {
      return resolvedFile;
    },

    getSeq() {
      return seq;
    },

    getPrev() {
      return prev;
    },
  };
}

/**
 * Verifies an audit log file or array of line strings.
 * Checks hash integrity, sequential numbering, previous-hash chaining,
 * and cryptographic signatures under publicJwk.
 *
 * @param {string|string[]} fileOrLines - File path or array of JSON line strings
 * @param {object} [options={}]
 * @param {any} [options.publicJwk] - Public JWK or KeyObject for the audit signing key
 * @param {Record<string, any>} [options.cfg] - Optional configuration overrides
 * @returns {Promise<{ valid: boolean, count: number, error?: string, lineNum?: number, badLine?: string }>}
 */
export async function verifyAuditLog(fileOrLines, options = {}) {
  let lines = [];
  if (Array.isArray(fileOrLines)) {
    lines = fileOrLines;
  } else if (typeof fileOrLines === "string") {
    const resolvedPath = path.resolve(fileOrLines);
    if (!fs.existsSync(resolvedPath)) {
      return {
        valid: false,
        count: 0,
        error: `File not found: ${resolvedPath}`,
      };
    }
    const content = fs.readFileSync(resolvedPath, "utf8").trim();
    if (!content) {
      return { valid: true, count: 0 };
    }
    lines = content.split("\n").filter((l) => l.trim().length > 0);
  } else {
    throw new Error("verifyAuditLog requires a file path string or an array of lines");
  }

  let publicJwk = options.publicJwk;
  if (!publicJwk) {
    const auditKey = await loadOrCreateSigningKey("audit", options.cfg);
    publicJwk = auditKey.publicJwk;
  }

  let expectedSeq = 1;
  let previousHash = GENESIS_PREV;

  for (let idx = 0; idx < lines.length; idx++) {
    const lineNum = idx + 1;
    const rawLine = lines[idx].trim();
    if (!rawLine) continue;

    let parsed;
    try {
      parsed = JSON.parse(rawLine);
    } catch (err) {
      return {
        valid: false,
        count: idx,
        lineNum,
        badLine: rawLine,
        error: `Malformed JSON on line ${lineNum}: ${err.message}`,
      };
    }

    const { seq, ts, prev, hash, sig, ...record } = parsed;

    // Check sequence number
    if (seq !== expectedSeq) {
      return {
        valid: false,
        count: idx,
        lineNum,
        badLine: rawLine,
        error: `Sequence mismatch on line ${lineNum}: expected ${expectedSeq}, got ${seq}`,
      };
    }

    // Check prev link
    if (idx === 0) {
      if (prev !== GENESIS_PREV && prev !== null && prev !== "0") {
        return {
          valid: false,
          count: idx,
          lineNum,
          badLine: rawLine,
          error: `Genesis prev hash invalid on line 1: got ${prev}`,
        };
      }
    } else {
      if (prev !== previousHash) {
        return {
          valid: false,
          count: idx,
          lineNum,
          badLine: rawLine,
          error: `Hash chain broken on line ${lineNum}: expected prev ${previousHash}, got ${prev}`,
        };
      }
    }

    // Recompute canonical entry and hash
    const rawEntry = { seq, ts, prev, ...record };
    const expectedHash = sha256(canonical(rawEntry), "hex");
    if (hash !== expectedHash) {
      return {
        valid: false,
        count: idx,
        lineNum,
        badLine: rawLine,
        error: `Hash tampering detected on line ${lineNum}: expected ${expectedHash}, recorded ${hash}`,
      };
    }

    // Verify signature
    const sigValid = verifyAuditSig(hash, sig, publicJwk);
    if (!sigValid) {
      return {
        valid: false,
        count: idx,
        lineNum,
        badLine: rawLine,
        error: `Signature verification failed on line ${lineNum}`,
      };
    }

    expectedSeq = seq + 1;
    previousHash = hash;
  }

  return { valid: true, count: lines.length };
}

export default {
  createAuditLog,
  signAuditHash,
  verifyAuditSig,
  verifyAuditLog,
};
