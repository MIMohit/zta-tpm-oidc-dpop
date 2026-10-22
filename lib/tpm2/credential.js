/**
 * @file credential.js
 * TPM2_MakeCredential pure-software verifier implementation (RSA-OAEP and ECC-ECDH).
 * Generic over the EK's nameAlg (SHA-256, SHA-384) and symmetric cipher (AES-128-CFB, AES-256-CFB).
 */
import crypto from "node:crypto";
import { kdfa, kdfe } from "./kdf.js";
import {
  parsePublic,
  publicKeyOf,
  TPM_ALG_RSA,
  TPM_ALG_ECC,
  TPM_ALG_SHA384,
  TPM_ECC_NIST_P384,
  HASH,
} from "./marshal.js";

const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return b;
};
const tpm2b = (b) => Buffer.concat([u16(b.length), b]);
const lbl = (s) => Buffer.concat([Buffer.from(s, "ascii"), Buffer.from([0])]); // label incl. trailing NUL

/**
 * Low-level TPM2_MakeCredential in software (returns raw Buffer fields).
 *
 * @param {Record<string, any>|Buffer|string} ekPub - parsed public area or TPMT_PUBLIC buffer
 * @param {Buffer|string} akName - 34-byte or 50-byte Name of the target key (e.g. AK)
 * @param {Buffer|string} credential - secret to wrap (e.g. 32-byte auth secret)
 * @param {object} [options] - optional pre-selected seed or ephemeral key for reproducible tests
 * @returns {{ seed: Buffer, integrity: Buffer, encIdentity: Buffer, idObject: Buffer, encSecret: Buffer }}
 */
export function makeCredential(ekPub, akName, credential, options = {}) {
  const p = Buffer.isBuffer(ekPub) || typeof ekPub === "string" ? parsePublic(ekPub) : ekPub;
  const akNameBuf = Buffer.isBuffer(akName)
    ? akName
    : typeof akName === "string"
    ? Buffer.from(akName, "hex")
    : null;
  if (!akNameBuf) throw new Error("Invalid akName passed to makeCredential");

  const credBuf = Buffer.isBuffer(credential)
    ? credential
    : typeof credential === "string"
    ? Buffer.from(credential, /^[0-9a-fA-F]+$/.test(credential) && credential.length % 2 === 0 ? "hex" : "utf8")
    : Buffer.from(credential);

  // Hash h from EK nameAlg
  let h = "sha256";
  let hashSize = 32;
  if (p.nameAlg === TPM_ALG_SHA384 || p.nameAlg === 0x000c || p.nameAlg === "sha384") {
    h = "sha384";
    hashSize = 48;
  } else if (HASH[p.nameAlg]) {
    h = HASH[p.nameAlg].name;
    hashSize = HASH[p.nameAlg].size;
  }

  // Symmetric cipher key bits (default 128, or 256 for H-3)
  const symKeyBits = p.symKeyBits || (p.sym === 0x0006 && p.symKeyBits ? p.symKeyBits : 128);
  const cipherAlg = symKeyBits === 256 ? "aes-256-cfb" : "aes-128-cfb";

  let seed, encSecret;

  if (p.type === TPM_ALG_RSA || p.type === "rsa") {
    seed = options.seed || crypto.randomBytes(hashSize);
    encSecret = crypto.publicEncrypt(
      {
        key: publicKeyOf(p),
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: h,
        oaepLabel: lbl("IDENTITY"),
      },
      seed
    );
  } else if (p.type === TPM_ALG_ECC || p.type === "ecc") {
    const isP384 = p.curveID === TPM_ECC_NIST_P384 || p.curve === "P-384";
    const curveName = isP384 ? "secp384r1" : "prime256v1";
    const coordLen = isP384 ? 48 : 32;

    const eph = options.eph || crypto.createECDH(curveName);
    if (!options.eph) {
      eph.generateKeys();
    }
    const ephPt = eph.getPublicKey();
    let ex = ephPt.subarray(1, 1 + coordLen);
    let ey = ephPt.subarray(1 + coordLen, 1 + 2 * coordLen);
    if (ex.length < coordLen) {
      ex = Buffer.concat([Buffer.alloc(coordLen - ex.length), ex]);
    }
    if (ey.length < coordLen) {
      ey = Buffer.concat([Buffer.alloc(coordLen - ey.length), ey]);
    }

    let ekX = p.x;
    let ekY = p.y;
    if (Buffer.isBuffer(ekX) && ekX.length < coordLen) {
      ekX = Buffer.concat([Buffer.alloc(coordLen - ekX.length), ekX]);
    }
    if (Buffer.isBuffer(ekY) && ekY.length < coordLen) {
      ekY = Buffer.concat([Buffer.alloc(coordLen - ekY.length), ekY]);
    }

    const peerPoint = Buffer.concat([Buffer.from([4]), ekX, ekY]);
    let z = eph.computeSecret(peerPoint); // shared x-coordinate
    if (z.length < coordLen) {
      z = Buffer.concat([Buffer.alloc(coordLen - z.length), z]);
    }

    seed = kdfe(h, z, "IDENTITY", ex, ekX, hashSize * 8);
    encSecret = Buffer.concat([tpm2b(ex), tpm2b(ey)]); // TPMS_ECC_POINT
  } else {
    throw new Error(`Unsupported EK type 0x${p.type.toString(16)} for MakeCredential`);
  }

  const symKey = kdfa(h, seed, "STORAGE", akNameBuf, Buffer.alloc(0), symKeyBits);
  const c = crypto.createCipheriv(cipherAlg, symKey, Buffer.alloc(16));
  const encIdentity = Buffer.concat([c.update(tpm2b(credBuf)), c.final()]);
  const hmacKey = kdfa(h, seed, "INTEGRITY", Buffer.alloc(0), Buffer.alloc(0), hashSize * 8);
  const integrity = crypto
    .createHmac(h, hmacKey)
    .update(Buffer.concat([encIdentity, akNameBuf]))
    .digest();

  const idObject = Buffer.concat([tpm2b(integrity), encIdentity]);

  return {
    seed,
    integrity,
    encIdentity,
    idObject,
    encSecret,
  };
}

/**
 * Standard MakeCredential for TPM 2.0 (returns base64url JSON format).
 *
 * @param {Record<string, any>|Buffer} ekPublicArea - EK public area (object or buffer)
 * @param {Buffer|string} akName - AK Name
 * @param {Buffer|string} secret - Secret to envelop
 * @param {object} [options]
 * @returns {{ format: "tpm2", credentialBlob: string, secret: string }}
 */
export function makeCredentialTpm2(ekPublicArea, akName, secret, options = {}) {
  let ekPub = ekPublicArea;
  if (ekPublicArea && typeof ekPublicArea.tpmtPublic === "string") {
    ekPub = parsePublic(Buffer.from(ekPublicArea.tpmtPublic, "base64url"));
  }
  const res = makeCredential(ekPub, akName, secret, options);
  return {
    format: "tpm2",
    credentialBlob: res.idObject.toString("base64url"),
    secret: res.encSecret.toString("base64url"),
  };
}

export default { makeCredential, makeCredentialTpm2 };
