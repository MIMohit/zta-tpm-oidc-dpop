/**
 * @file public-area.js
 * TPM 2.0 Public Area and Name manipulation for ECC P-256 keys.
 */

import * as jose from "jose";
import { canonicalJson, sha256Buf } from "../canonical.js";

/**
 * TPM 2.0 TPMA_OBJECT attribute bit definitions.
 */
export const TPMA_OBJECT = {
  fixedTPM: 0x00000002,
  fixedParent: 0x00000010,
  sensitiveDataOrigin: 0x00000020,
  userWithAuth: 0x00000040,
  adminWithPolicy: 0x00000080,
  noDA: 0x00000400,
  encryptedDuplication: 0x00002000,
  restricted: 0x00010000,
  decrypt: 0x00020000,
  sign: 0x00040000,
};

export const fixedTPM = TPMA_OBJECT.fixedTPM;
export const fixedParent = TPMA_OBJECT.fixedParent;
export const sensitiveDataOrigin = TPMA_OBJECT.sensitiveDataOrigin;
export const userWithAuth = TPMA_OBJECT.userWithAuth;
export const adminWithPolicy = TPMA_OBJECT.adminWithPolicy;
export const restricted = TPMA_OBJECT.restricted;
export const decrypt = TPMA_OBJECT.decrypt;
export const sign = TPMA_OBJECT.sign;

/**
 * Normalizes attributes parameter to a 32-bit unsigned integer bitmask.
 * @param {number|string[]|Record<string, boolean>} attrs
 * @returns {number}
 */
export function normalizeAttributes(attrs) {
  if (typeof attrs === "number") {
    return attrs >>> 0;
  }
  let mask = 0;
  if (Array.isArray(attrs)) {
    for (const item of attrs) {
      if (typeof item === "number") {
        mask |= item;
      } else if (typeof item === "string" && TPMA_OBJECT[item] !== undefined) {
        mask |= TPMA_OBJECT[item];
      }
    }
    return mask >>> 0;
  }
  if (attrs && typeof attrs === "object") {
    for (const [key, val] of Object.entries(attrs)) {
      if (val && TPMA_OBJECT[key] !== undefined) {
        mask |= TPMA_OBJECT[key];
      }
    }
    return mask >>> 0;
  }
  return 0;
}

/**
 * Constructs a TPM 2.0 public area for an ECC P-256 key from its JWK and attribute bits.
 * Format per PLAN.md §2.4:
 * { type: "ecc", nameAlg: "sha256", objectAttributes: <u32>, curve: "P-256", x, y }
 *
 * @param {Record<string, any>} jwk - JWK containing x and y coordinates
 * @param {number|string[]|Record<string, boolean>} attrs - TPMA_OBJECT attributes
 * @returns {Record<string, any>} publicArea object
 */
export function makePublicArea(jwk, attrs) {
  if (!jwk || !jwk.x || !jwk.y) {
    throw new Error("JWK must include x and y coordinates");
  }
  const objectAttributes = normalizeAttributes(attrs);
  return {
    type: "ecc",
    nameAlg: "sha256",
    objectAttributes,
    curve: jwk.crv || "P-256",
    x: jwk.x,
    y: jwk.y,
  };
}

/**
 * Computes the TPM Name of a publicArea object.
 * Name = 0x000B || SHA256(canonicalJSON(publicArea))
 * Returns a 34-byte Buffer.
 *
 * @param {Record<string, any>|Buffer} publicArea
 * @returns {Buffer}
 */
export function nameOf(publicArea) {
  if (Buffer.isBuffer(publicArea)) {
    if (publicArea.length === 34 && publicArea.readUInt16BE(0) === 0x000b) {
      return publicArea;
    }
  }
  if (!publicArea || typeof publicArea !== "object") {
    throw new Error("Invalid publicArea passed to nameOf");
  }
  const canonical = canonicalJson(publicArea);
  const hash = sha256Buf(canonical);
  const prefix = Buffer.from([0x00, 0x0b]);
  return Buffer.concat([prefix, hash]);
}

/**
 * Extracts a public JWK representation from a publicArea object.
 * @param {Record<string, any>} publicArea
 * @returns {Record<string, any>} JWK
 */
export function jwkOf(publicArea) {
  if (!publicArea || typeof publicArea !== "object") {
    throw new Error("Invalid publicArea object for jwkOf");
  }
  const toB64u = (val) => (Buffer.isBuffer(val) ? val.toString("base64url") : val);
  if (publicArea.kty) {
    return publicArea;
  }
  if (publicArea.type === "rsa" || publicArea.kty === "RSA" || (publicArea.n && (publicArea.e || publicArea.exponent))) {
    const e = publicArea.e
      ? toB64u(publicArea.e)
      : typeof publicArea.exponent === "number"
      ? Buffer.from([0x01, 0x00, 0x01]).toString("base64url")
      : "AQAB";
    return {
      kty: "RSA",
      n: toB64u(publicArea.n),
      e,
    };
  }
  if (!publicArea.x || !publicArea.y) {
    throw new Error("Invalid publicArea object for jwkOf");
  }
  let crv = publicArea.curve || "P-256";
  if (crv === "curve_4" || publicArea.curveID === 4 || publicArea.curveID === 0x0004) {
    crv = "P-384";
  }
  const jwk = {
    kty: "EC",
    crv,
    x: toB64u(publicArea.x),
    y: toB64u(publicArea.y),
  };
  return jwk;
}

/**
 * Computes RFC 7638 SHA-256 thumbprint of an EC JWK or publicArea.
 * @param {Record<string, any>} jwkOrPublicArea
 * @returns {Promise<string>} Base64url thumbprint
 */
export async function thumbprintOf(jwkOrPublicArea) {
  const jwk = jwkOrPublicArea.kty ? jwkOrPublicArea : jwkOf(jwkOrPublicArea);
  return jose.calculateJwkThumbprint(jwk, "sha256");
}

/**
 * Alias for thumbprint of EKpub (devId).
 */
export const devIdOf = thumbprintOf;

export default {
  TPMA_OBJECT,
  fixedTPM,
  fixedParent,
  sensitiveDataOrigin,
  userWithAuth,
  adminWithPolicy,
  restricted,
  decrypt,
  sign,
  normalizeAttributes,
  makePublicArea,
  nameOf,
  jwkOf,
  thumbprintOf,
  devIdOf,
};
