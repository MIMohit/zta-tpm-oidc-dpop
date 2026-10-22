/**
 * @file credential.js
 * TPM 2.0 MakeCredential and ActivateCredential emulation.
 * Uses ECC P-256 restricted-decrypt EK and HKDF-SHA256 (in place of TPM KDFa/KDFe).
 */

import crypto from "node:crypto";
import { b64u } from "../canonical.js";
import { nameOf, jwkOf } from "./public-area.js";

/**
 * Extracts a 65-byte uncompressed EC P-256 public point (0x04 || x || y) from
 * a publicArea object, a JWK, or an existing buffer.
 *
 * @param {Record<string, any>|Buffer} pub
 * @returns {Buffer} 65-byte uncompressed EC point
 */
function extractEcPoint(pub) {
  if (Buffer.isBuffer(pub)) {
    if (pub.length === 65 && pub[0] === 0x04) return pub;
    if (pub.length === 64) return Buffer.concat([Buffer.from([0x04]), pub]);
  }
  const jwk = pub?.kty ? pub : (pub?.x ? jwkOf(pub) : null);
  if (jwk?.x && jwk?.y) {
    const xBuf = b64u.decode(jwk.x);
    const yBuf = b64u.decode(jwk.y);
    return Buffer.concat([Buffer.from([0x04]), xBuf, yBuf]);
  }
  throw new Error("Unable to extract EC P-256 public point from input");
}

/**
 * Normalizes an AK name to a 34-byte Buffer.
 * @param {Buffer|Object|string} akName
 * @returns {Buffer}
 */
function normalizeAkName(akName) {
  if (Buffer.isBuffer(akName)) {
    return akName;
  }
  if (akName && typeof akName === "object") {
    return nameOf(akName);
  }
  if (typeof akName === "string") {
    if (/^[0-9a-fA-F]{68}$/.test(akName)) {
      return Buffer.from(akName, "hex");
    }
    return Buffer.from(akName, "base64url");
  }
  throw new Error("Invalid akName format");
}

/**
 * Simulates TPM2_MakeCredential on the verifier side.
 *
 * Verifier draws an ephemeral ECDH key, then:
 * seed = ECDH(eph, EKpub)
 * symKey = HKDF-SHA256(seed, info = "STORAGE" || Name(AK), 16)
 * hmacKey = HKDF-SHA256(seed, info = "INTEGRITY", 32)
 * encIdentity = AES-128-CFB(symKey, iv = 0, TPM2B(s))
 * integrity = HMAC(hmacKey, encIdentity || Name(AK))
 * Returns { credentialBlob: b64u(integrity || encIdentity), secret: b64u(ephPub) }
 *
 * @param {Record<string, any>} ekPublicArea - Public area or JWK of the EK
 * @param {Buffer|Record<string, any>} akName - Name of the AK to be activated
 * @param {Buffer|string} secret - Secret s to be protected
 * @returns {{ credentialBlob: string, secret: string }}
 */
export function makeCredential(ekPublicArea, akName, secret) {
  const ekRawPub = extractEcPoint(ekPublicArea);
  const akNameBuf = normalizeAkName(akName);
  const sBuf = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, "utf8");

  // Generate ephemeral ECDH key on P-256
  const eph = crypto.createECDH("prime256v1");
  eph.generateKeys();
  const ephPub = eph.getPublicKey(); // 65 bytes uncompressed point

  // Compute shared secret seed
  const seed = eph.computeSecret(ekRawPub);

  // Derive symmetric encryption key and integrity key via HKDF
  const symKey = crypto.hkdfSync(
    "sha256",
    seed,
    Buffer.alloc(0),
    Buffer.concat([Buffer.from("STORAGE", "utf8"), akNameBuf]),
    16
  );

  const hmacKey = crypto.hkdfSync(
    "sha256",
    seed,
    Buffer.alloc(0),
    Buffer.from("INTEGRITY", "utf8"),
    32
  );

  // Wrap secret in TPM2B(s): u16 length || secret bytes
  const sSizeBuf = Buffer.alloc(2);
  sSizeBuf.writeUInt16BE(sBuf.length, 0);
  const tpm2bS = Buffer.concat([sSizeBuf, sBuf]);

  // Encrypt with AES-128-CFB (iv = 0)
  const cipher = crypto.createCipheriv("aes-128-cfb", symKey, Buffer.alloc(16, 0));
  const encIdentity = Buffer.concat([cipher.update(tpm2bS), cipher.final()]);

  // Compute integrity HMAC over (encIdentity || Name(AK))
  const integrity = crypto
    .createHmac("sha256", hmacKey)
    .update(Buffer.concat([encIdentity, akNameBuf]))
    .digest();

  const credentialBlob = b64u.encode(Buffer.concat([integrity, encIdentity]));
  const secretB64u = b64u.encode(ephPub);

  return {
    credentialBlob,
    secret: secretB64u,
  };
}

/**
 * Simulates TPM2_ActivateCredential on the TPM side.
 *
 * Recomputes the keys with the EK private key and the Name of the AK actually loaded,
 * verifies the HMAC, and returns s or throws TPM_RC_INTEGRITY.
 *
 * @param {Record<string, any>|Buffer} ekPrivateKey - Private JWK (with d) or raw private key of EK
 * @param {Buffer|Record<string, any>} loadedAkName - Name of the loaded AK
 * @param {{ credentialBlob: string, secret: string }} blob - Credential blob from verifier
 * @returns {Buffer} The decrypted secret s
 * @throws {Error} With code "TPM_RC_INTEGRITY" on validation failure
 */
export function activate(ekPrivateKey, loadedAkName, blob) {
  if (!blob || !blob.credentialBlob || !blob.secret) {
    const err = new Error("TPM_RC_INTEGRITY: missing credential blob or secret");
    err.code = "TPM_RC_INTEGRITY";
    throw err;
  }

  const credBuf = b64u.decode(blob.credentialBlob);
  if (credBuf.length < 34) {
    const err = new Error("TPM_RC_INTEGRITY: credential blob too short");
    err.code = "TPM_RC_INTEGRITY";
    throw err;
  }

  const integrity = credBuf.subarray(0, 32);
  const encIdentity = credBuf.subarray(32);

  const ephPubBuf = b64u.decode(blob.secret);
  let ephRawPub;
  try {
    ephRawPub = extractEcPoint(ephPubBuf);
  } catch {
    const err = new Error("TPM_RC_INTEGRITY: invalid ephemeral public key in credential blob");
    err.code = "TPM_RC_INTEGRITY";
    throw err;
  }

  // Extract private key d scalar
  let dBuf;
  if (Buffer.isBuffer(ekPrivateKey)) {
    dBuf = ekPrivateKey;
  } else if (ekPrivateKey?.d) {
    dBuf = b64u.decode(ekPrivateKey.d);
  } else {
    const err = new Error("TPM_RC_INTEGRITY: unable to extract EK private key");
    err.code = "TPM_RC_INTEGRITY";
    throw err;
  }

  let seed;
  try {
    const ecdh = crypto.createECDH("prime256v1");
    ecdh.setPrivateKey(dBuf);
    seed = ecdh.computeSecret(ephRawPub);
  } catch {
    const err = new Error("TPM_RC_INTEGRITY: ECDH key agreement failed");
    err.code = "TPM_RC_INTEGRITY";
    throw err;
  }

  const akNameBuf = normalizeAkName(loadedAkName);

  // Derive symmetric key and integrity key using loaded AK name
  const symKey = crypto.hkdfSync(
    "sha256",
    seed,
    Buffer.alloc(0),
    Buffer.concat([Buffer.from("STORAGE", "utf8"), akNameBuf]),
    16
  );

  const hmacKey = crypto.hkdfSync(
    "sha256",
    seed,
    Buffer.alloc(0),
    Buffer.from("INTEGRITY", "utf8"),
    32
  );

  // Verify HMAC integrity
  const computedIntegrity = crypto
    .createHmac("sha256", hmacKey)
    .update(Buffer.concat([encIdentity, akNameBuf]))
    .digest();

  if (integrity.length !== 32 || !crypto.timingSafeEqual(integrity, computedIntegrity)) {
    const err = new Error("TPM_RC_INTEGRITY: credential activation integrity check failed");
    err.code = "TPM_RC_INTEGRITY";
    throw err;
  }

  // Decrypt encIdentity
  const decipher = crypto.createDecipheriv("aes-128-cfb", symKey, Buffer.alloc(16, 0));
  const tpm2bS = Buffer.concat([decipher.update(encIdentity), decipher.final()]);

  if (tpm2bS.length < 2) {
    const err = new Error("TPM_RC_INTEGRITY: decrypted secret buffer truncated");
    err.code = "TPM_RC_INTEGRITY";
    throw err;
  }

  const sLen = tpm2bS.readUInt16BE(0);
  if (tpm2bS.length < 2 + sLen) {
    const err = new Error("TPM_RC_INTEGRITY: decrypted secret length mismatch");
    err.code = "TPM_RC_INTEGRITY";
    throw err;
  }

  const s = tpm2bS.subarray(2, 2 + sLen);
  return s;
}

export default {
  makeCredential,
  activate,
};
