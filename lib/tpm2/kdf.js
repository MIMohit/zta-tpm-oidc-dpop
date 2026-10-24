/**
 * @file kdf.js
 * TPM 2.0 Part 1 KDF implementations (pure software, node:crypto only).
 */
import crypto from "node:crypto";

const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
};

const toBuf = (v) => {
  if (!v) return Buffer.alloc(0);
  if (Buffer.isBuffer(v)) return v;
  if (typeof v === "string") return Buffer.from(v, "utf8");
  return Buffer.from(v);
};

const lbl = (s) => Buffer.concat([Buffer.from(s, "ascii"), Buffer.from([0])]); // label incl. trailing NUL

/**
 * TPM 2.0 Part 1 §11.4.10.2 KDFa (SP800-108 counter mode, HMAC)
 *
 * @param {string} hash - hash algorithm, e.g. "sha256"
 * @param {Buffer|string} key - HMAC key
 * @param {string} label - ASCII label (NUL terminator is appended automatically)
 * @param {Buffer|string} ctxU - context U (e.g. key Name)
 * @param {Buffer|string} ctxV - context V
 * @param {number} bits - required output bits (e.g. 128, 256)
 * @returns {Buffer} output key bytes (bits / 8)
 */
export function kdfa(hash, key, label, ctxU, ctxV, bits) {
  const cU = toBuf(ctxU);
  const cV = toBuf(ctxV);
  const k = toBuf(key);
  const out = [];
  let len = 0;
  for (let i = 1; len * 8 < bits; i++) {
    const h = crypto
      .createHmac(hash, k)
      .update(Buffer.concat([u32(i), lbl(label), cU, cV, u32(bits)]))
      .digest();
    out.push(h);
    len += h.length;
  }
  return Buffer.concat(out).subarray(0, bits / 8);
}

/**
 * TPM 2.0 Part 1 §11.4.10.3 KDFe (SP800-56A concat KDF)
 *
 * @param {string} hash - hash algorithm, e.g. "sha256"
 * @param {Buffer|string} z - shared secret (e.g. ECDH x-coordinate)
 * @param {string} label - ASCII label (NUL terminator is appended automatically)
 * @param {Buffer|string} partyU - party U (e.g. ephemeral public x)
 * @param {Buffer|string} partyV - party V (e.g. EK public x)
 * @param {number} bits - required output bits (e.g. 256)
 * @returns {Buffer} output key bytes (bits / 8)
 */
export function kdfe(hash, z, label, partyU, partyV, bits) {
  const pU = toBuf(partyU);
  const pV = toBuf(partyV);
  const zBuf = toBuf(z);
  const out = [];
  let len = 0;
  for (let i = 1; len * 8 < bits; i++) {
    const h = crypto
      .createHash(hash)
      .update(Buffer.concat([u32(i), zBuf, lbl(label), pU, pV]))
      .digest();
    out.push(h);
    len += h.length;
  }
  return Buffer.concat(out).subarray(0, bits / 8);
}

export default { kdfa, kdfe };
