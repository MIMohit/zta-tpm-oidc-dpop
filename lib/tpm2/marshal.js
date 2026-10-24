/**
 * @file marshal.js
 * Pure-software TPM 2.0 structure parsing and marshalling (node:crypto only, no tss.js).
 */
import crypto from "node:crypto";

export const TPM_RH_OWNER = 0x40000001;
export const TPM_RH_ENDORSEMENT = 0x4000000b;
export const TPM_ALG_RSA = 0x0001;
export const TPM_ALG_SHA256 = 0x000b;
export const TPM_ALG_SHA384 = 0x000c;
export const TPM_ALG_NULL = 0x0010;
export const TPM_ALG_ECC = 0x0023;
export const TPM_ECC_NIST_P256 = 0x0003;
export const TPM_ECC_NIST_P384 = 0x0004;

export const HASH = {
  0x000b: { name: "sha256", size: 32 },
  0x000c: { name: "sha384", size: 48 },
};

/**
 * Computes TPM 2.0 Name of raw TPMT_PUBLIC bytes.
 * Name = nameAlg (2 bytes) || HASH(tpmtPublicBytes)
 *
 * @param {Buffer|string|Record<string, any>} buf - raw TPMT_PUBLIC bytes or object with tpmtPublic
 * @returns {Buffer} 34-byte (SHA-256) or 50-byte (SHA-384) TPM Name buffer
 */
export function nameOfTpmt(buf) {
  let raw;
  if (Buffer.isBuffer(buf)) {
    raw = buf;
  } else if (typeof buf === "string") {
    raw =
      /^[0-9a-fA-F]+$/.test(buf) && buf.length % 2 === 0
        ? Buffer.from(buf, "hex")
        : Buffer.from(buf, "base64url");
  } else if (buf && typeof buf.tpmtPublic === "string") {
    raw = Buffer.from(buf.tpmtPublic, "base64url");
  } else {
    throw new Error("Invalid buffer passed to nameOfTpmt");
  }
  if (raw.length < 4) {
    throw new Error("TPMT_PUBLIC buffer too short to extract nameAlg");
  }
  const nameAlg = raw.readUInt16BE(2);
  const hashInfo = HASH[nameAlg];
  if (!hashInfo) {
    const prefix = Buffer.from([0x00, 0x0b]);
    const hash = crypto.createHash("sha256").update(raw).digest();
    return Buffer.concat([prefix, hash]);
  }
  const prefix = Buffer.alloc(2);
  prefix.writeUInt16BE(nameAlg);
  const hash = crypto.createHash(hashInfo.name).update(raw).digest();
  return Buffer.concat([prefix, hash]);
}

/**
 * Parses TPMT_PUBLIC bytes into structured fields.
 * Supports RSA (0x0001) and ECC (0x0023). Enforces strict length with no trailing bytes.
 *
 * @param {Buffer|string} buf - TPMT_PUBLIC bytes
 * @returns {Record<string, any>} Parsed public structure
 */
export function parsePublic(buf) {
  if (!buf || (!Buffer.isBuffer(buf) && typeof buf !== "string")) {
    throw new Error("Invalid buffer passed to parsePublic");
  }
  const raw = Buffer.isBuffer(buf)
    ? buf
    : /^[0-9a-fA-F]+$/.test(buf) && buf.length % 2 === 0
    ? Buffer.from(buf, "hex")
    : Buffer.from(buf, "base64url");
  if (raw.length < 14) {
    throw new Error(`TPMT_PUBLIC buffer too short (${raw.length} bytes)`);
  }

  let o = 0;
  const r16 = () => {
    if (o + 2 > raw.length) throw new Error(`TPMT_PUBLIC truncated reading uint16 at offset ${o}`);
    const v = raw.readUInt16BE(o);
    o += 2;
    return v;
  };
  const r32 = () => {
    if (o + 4 > raw.length) throw new Error(`TPMT_PUBLIC truncated reading uint32 at offset ${o}`);
    const v = raw.readUInt32BE(o);
    o += 4;
    return v;
  };
  const rb = () => {
    const n = r16();
    if (o + n > raw.length) throw new Error(`TPMT_PUBLIC truncated reading bytes of length ${n} at offset ${o}`);
    const v = raw.subarray(o, o + n);
    o += n;
    return v;
  };

  const type = r16();
  const nameAlg = r16();
  const objectAttributes = r32();
  const authPolicy = rb();

  const sym = r16();
  let symKeyBits, symMode;
  if (sym !== TPM_ALG_NULL) {
    symKeyBits = r16();
    symMode = r16();
  }

  const scheme = r16();
  let schemeHash;
  if (scheme !== TPM_ALG_NULL) {
    schemeHash = r16();
  }

  const out = {
    type,
    nameAlg,
    objectAttributes,
    authPolicy,
    sym,
    symKeyBits,
    symMode,
    scheme,
    schemeHash,
    raw,
  };

  if (type === TPM_ALG_RSA) {
    out.keyBits = r16();
    out.exponent = r32() || 65537;
    out.n = rb();
  } else if (type === TPM_ALG_ECC) {
    out.curveID = r16();
    const kdf = r16();
    let kdfHash;
    if (kdf !== TPM_ALG_NULL) {
      kdfHash = r16();
    }
    out.kdf = kdf;
    out.kdfHash = kdfHash;
    out.x = rb();
    out.y = rb();
  } else {
    throw new Error(`unsupported TPMT_PUBLIC type 0x${type.toString(16)}`);
  }

  if (o !== raw.length) {
    throw new Error(`trailing bytes in TPMT_PUBLIC (${raw.length - o})`);
  }

  return out;
}

/**
 * Extracts a KeyObject (public key) from parsed TPMT_PUBLIC structure or raw bytes.
 *
 * @param {Record<string, any>|Buffer} p - parsed public structure or TPMT_PUBLIC bytes
 * @returns {crypto.KeyObject}
 */
export function publicKeyOf(p) {
  let parsed;
  if (Buffer.isBuffer(p)) {
    parsed = parsePublic(p);
  } else if (typeof p === "string") {
    const buf =
      /^[0-9a-fA-F]+$/.test(p) && p.length % 2 === 0
        ? Buffer.from(p, "hex")
        : Buffer.from(p, "base64url");
    parsed = parsePublic(buf);
  } else if (p && typeof p.tpmtPublic === "string") {
    const buf =
      /^[0-9a-fA-F]+$/.test(p.tpmtPublic) && p.tpmtPublic.length % 2 === 0
        ? Buffer.from(p.tpmtPublic, "hex")
        : Buffer.from(p.tpmtPublic, "base64url");
    parsed = parsePublic(buf);
  } else {
    parsed = p;
  }

  if (!parsed || typeof parsed !== "object") {
    throw new Error("Invalid structure passed to publicKeyOf");
  }

  if (parsed.type === TPM_ALG_RSA || parsed.type === "rsa") {
    const e = Buffer.alloc(4);
    e.writeUInt32BE(parsed.exponent || 65537);
    const nonZero = e.findIndex((x) => x !== 0);
    const eTrimmed = e.subarray(nonZero >= 0 ? nonZero : 3);
    const nB64u = Buffer.isBuffer(parsed.n) ? parsed.n.toString("base64url") : parsed.n;
    const eB64u = Buffer.isBuffer(parsed.e) ? parsed.e.toString("base64url") : (parsed.e || eTrimmed.toString("base64url"));
    return crypto.createPublicKey({
      key: {
        kty: "RSA",
        n: nB64u,
        e: eB64u,
      },
      format: "jwk",
    });
  }

  if (parsed.type === TPM_ALG_ECC || parsed.type === "ecc") {
    const xB64u = Buffer.isBuffer(parsed.x) ? parsed.x.toString("base64url") : parsed.x;
    const yB64u = Buffer.isBuffer(parsed.y) ? parsed.y.toString("base64url") : parsed.y;
    let crv = "P-256";
    if (parsed.curveID === TPM_ECC_NIST_P384 || parsed.curve === "P-384") {
      crv = "P-384";
    } else if (parsed.curveID === TPM_ECC_NIST_P256 || parsed.curve === "P-256") {
      crv = "P-256";
    } else if (parsed.curve) {
      crv = parsed.curve;
    }
    return crypto.createPublicKey({
      key: {
        kty: "EC",
        crv,
        x: xB64u,
        y: yB64u,
      },
      format: "jwk",
    });
  }

  throw new Error(`Cannot derive public key for type ${parsed.type}`);
}

/**
 * Converts raw TPMT_PUBLIC bytes into the canonical JSON publicArea shape
 * with added { format: "tpm2", tpmtPublic }.
 *
 * @param {Buffer|string|Record<string, any>} buf - TPMT_PUBLIC buffer or object
 * @returns {Record<string, any>} publicArea object
 */
export function publicAreaFromTpmt(buf) {
  let rawBuf;
  if (Buffer.isBuffer(buf)) {
    rawBuf = buf;
  } else if (typeof buf === "string") {
    rawBuf =
      /^[0-9a-fA-F]+$/.test(buf) && buf.length % 2 === 0
        ? Buffer.from(buf, "hex")
        : Buffer.from(buf, "base64url");
  } else if (buf && typeof buf.tpmtPublic === "string") {
    rawBuf = Buffer.from(buf.tpmtPublic, "base64url");
  } else {
    throw new Error("Invalid TPMT_PUBLIC input provided to publicAreaFromTpmt");
  }

  const p = parsePublic(rawBuf);
  const base = {
    format: "tpm2",
    tpmtPublic: rawBuf.toString("base64url"),
    objectAttributes: p.objectAttributes,
  };

  const nameAlgStr = HASH[p.nameAlg]?.name || (p.nameAlg === TPM_ALG_SHA384 ? "sha384" : "sha256");

  if (p.type === TPM_ALG_RSA) {
    const e = Buffer.alloc(4);
    e.writeUInt32BE(p.exponent || 65537);
    const nonZero = e.findIndex((x) => x !== 0);
    const eTrimmed = e.subarray(nonZero >= 0 ? nonZero : 3);
    return {
      ...base,
      type: "rsa",
      kty: "RSA",
      nameAlg: nameAlgStr,
      n: p.n.toString("base64url"),
      e: eTrimmed.toString("base64url"),
      keyBits: p.keyBits,
      exponent: p.exponent || 65537,
    };
  }

  if (p.type === TPM_ALG_ECC) {
    const curveStr =
      p.curveID === TPM_ECC_NIST_P256
        ? "P-256"
        : p.curveID === TPM_ECC_NIST_P384
        ? "P-384"
        : `curve_${p.curveID}`;
    return {
      ...base,
      type: "ecc",
      nameAlg: nameAlgStr,
      curve: curveStr,
      x: p.x.toString("base64url"),
      y: p.y.toString("base64url"),
    };
  }

  throw new Error(`Unsupported public area type 0x${p.type.toString(16)}`);
}

/**
 * Computes the Qualified Name of a child entity given parent QN and child Name.
 * QN(child) = 0x000B || SHA256(QN(parent) || Name(child))
 *
 * @param {Buffer|string} parentQn - parent Qualified Name (or handle buffer for primary)
 * @param {Buffer|string} name - entity Name
 * @returns {Buffer} 34-byte Qualified Name buffer
 */
export function qualifiedName(parentQn, name) {
  const pQn = Buffer.isBuffer(parentQn)
    ? parentQn
    : typeof parentQn === "string"
    ? Buffer.from(parentQn, "hex")
    : Buffer.alloc(0);
  const n = Buffer.isBuffer(name)
    ? name
    : typeof name === "string"
    ? Buffer.from(name, "hex")
    : Buffer.alloc(0);
  const prefix = Buffer.from([0x00, 0x0b]);
  const hash = crypto.createHash("sha256").update(Buffer.concat([pQn, n])).digest();
  return Buffer.concat([prefix, hash]);
}

/**
 * Computes the Qualified Name of a primary key created under Owner hierarchy.
 * QN(SRK) = 0x000B || SHA256( 0x40000001 || Name(SRK) )
 *
 * @param {Buffer|string} nameOfPrimary - Name of the primary key
 * @returns {Buffer} 34-byte Qualified Name buffer
 */
export function ownerQn(nameOfPrimary) {
  const u32 = Buffer.alloc(4);
  u32.writeUInt32BE(TPM_RH_OWNER);
  return qualifiedName(u32, nameOfPrimary);
}

/**
 * Verifies that the JSON fields in a publicArea match the raw TPMT_PUBLIC bytes.
 * Rejects any mismatch.
 *
 * @param {Record<string, any>} pa - publicArea object with tpmtPublic
 * @returns {Record<string, any>} canonical publicArea object derived from raw bytes
 */
export function verifyPublicArea(pa) {
  if (!pa || typeof pa !== "object") {
    throw new Error("Invalid publicArea object");
  }
  if (!pa.tpmtPublic) {
    throw new Error("publicArea missing tpmtPublic");
  }
  const parsed = publicAreaFromTpmt(pa.tpmtPublic);

  // Compare all relevant JSON fields present in pa
  if (pa.type && pa.type !== parsed.type) {
    throw new Error(`publicArea type mismatch: claimed ${pa.type}, parsed ${parsed.type}`);
  }
  if (pa.nameAlg && pa.nameAlg !== parsed.nameAlg) {
    throw new Error(`publicArea nameAlg mismatch: claimed ${pa.nameAlg}, parsed ${parsed.nameAlg}`);
  }
  if (pa.objectAttributes !== undefined && (pa.objectAttributes >>> 0) !== (parsed.objectAttributes >>> 0)) {
    throw new Error(
      `publicArea objectAttributes mismatch: claimed 0x${(pa.objectAttributes >>> 0).toString(16)}, parsed 0x${(parsed.objectAttributes >>> 0).toString(16)}`
    );
  }
  if (parsed.type === "ecc") {
    if (pa.curve && pa.curve !== parsed.curve) {
      throw new Error(`publicArea curve mismatch: claimed ${pa.curve}, parsed ${parsed.curve}`);
    }
    if (pa.x && pa.x !== parsed.x) {
      throw new Error(`publicArea x coordinate mismatch`);
    }
    if (pa.y && pa.y !== parsed.y) {
      throw new Error(`publicArea y coordinate mismatch`);
    }
  } else if (parsed.type === "rsa") {
    if (pa.n && pa.n !== parsed.n) {
      throw new Error(`publicArea RSA n mismatch`);
    }
    if (pa.e && pa.e !== parsed.e) {
      throw new Error(`publicArea RSA e mismatch`);
    }
    if (pa.keyBits !== undefined && pa.keyBits !== parsed.keyBits) {
      throw new Error(`publicArea RSA keyBits mismatch`);
    }
  }
  return parsed;
}

export default {
  TPM_RH_OWNER,
  TPM_RH_ENDORSEMENT,
  TPM_ALG_RSA,
  TPM_ALG_SHA256,
  TPM_ALG_SHA384,
  TPM_ALG_NULL,
  TPM_ALG_ECC,
  TPM_ECC_NIST_P256,
  TPM_ECC_NIST_P384,
  HASH,
  nameOfTpmt,
  parsePublic,
  publicKeyOf,
  publicAreaFromTpmt,
  qualifiedName,
  ownerQn,
  verifyPublicArea,
};
