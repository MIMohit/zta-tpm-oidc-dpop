/**
 * @file evidence.js
 * Evidence format dispatch and validation for real TPM 2.0 and simulated TPM evidence.
 * Pure software (node:crypto only, no tss.js).
 */
import {
  nameOfTpmt,
  parsePublic,
  publicAreaFromTpmt,
  verifyPublicArea,
  qualifiedName,
  ownerQn,
  TPM_ALG_ECC,
  TPM_ALG_SHA256,
  TPM_ECC_NIST_P256,
} from "../tpm2/marshal.js";
import { makeCredentialTpm2 } from "../tpm2/credential.js";
import { isStandardEk } from "../tpm2/ek-template.js";
import { nameOf, normalizeAttributes, TPMA_OBJECT } from "../sim-tpm/public-area.js";
import { makeCredential as makeCredentialSim } from "../sim-tpm/credential.js";

/**
 * Expected attribute bitmasks.
 */
export const AK_REQUIRED_ATTRS =
  TPMA_OBJECT.fixedTPM |
  TPMA_OBJECT.fixedParent |
  TPMA_OBJECT.sensitiveDataOrigin |
  TPMA_OBJECT.restricted |
  TPMA_OBJECT.sign; // 0x00050072

export const SRK_REQUIRED_ATTRS =
  TPMA_OBJECT.fixedTPM |
  TPMA_OBJECT.restricted |
  TPMA_OBJECT.decrypt; // 0x00030002

/**
 * Resolves and validates a publicArea structure.
 * If tpmtPublic is present, verifies strict agreement between JSON fields and raw bytes.
 * Returns the canonical publicArea with Name attached.
 *
 * @param {Record<string, any>} pa
 * @returns {Record<string, any>}
 */
export function resolvePublic(pa) {
  if (!pa || typeof pa !== "object") {
    throw new Error("Invalid public area structure");
  }

  if (pa.tpmtPublic) {
    return verifyPublicArea(pa);
  }

  // Simulated TPM format: return unmodified so canonicalJson(pa) is preserved
  return pa;
}

/**
 * Computes or retrieves the TPM Name of any publicArea or Name representation.
 * Supports both raw TPMT_PUBLIC (tpm2) and canonical JSON (sim).
 *
 * @param {Buffer|string|Record<string, any>} pa
 * @returns {Buffer} 34-byte TPM Name buffer
 */
export function nameOfAny(pa) {
  if (Buffer.isBuffer(pa)) {
    if (pa.length === 34 && pa.readUInt16BE(0) === 0x000b) {
      return pa;
    }
    if (pa.length === 50 && pa.readUInt16BE(0) === 0x000c) {
      return pa;
    }
  }
  if (typeof pa === "string") {
    if (/^[0-9a-fA-F]{68}$/.test(pa) || /^[0-9a-fA-F]{100}$/.test(pa)) {
      return Buffer.from(pa, "hex");
    }
    if (/^[A-Za-z0-9_-]{46}$/.test(pa) || /^[A-Za-z0-9_-]{67}$/.test(pa)) {
      return Buffer.from(pa, "base64url");
    }
  }
  if (pa && typeof pa === "object") {
    if (pa.tpmtPublic || pa.format === "tpm2") {
      return nameOfTpmt(pa.tpmtPublic || pa);
    }
    return nameOf(pa);
  }
  throw new Error("Unable to determine TPM Name from provided object");
}

/**
 * Verifies that the AK public area satisfies the ZTA constraints:
 * ECC P-256 with ECDSA-SHA256 and restricted|sign|fixedTPM|fixedParent|sensitiveDataOrigin.
 *
 * @param {Record<string, any>} akPa
 */
export function verifyAkAttributes(akPa) {
  if (akPa.tpmtPublic) {
    const parsed = parsePublic(Buffer.from(akPa.tpmtPublic, "base64url"));
    if (parsed.type !== TPM_ALG_ECC || parsed.curveID !== TPM_ECC_NIST_P256) {
      throw new Error("AK must be ECC NIST P-256");
    }
    if ((parsed.objectAttributes & AK_REQUIRED_ATTRS) !== AK_REQUIRED_ATTRS) {
      throw new Error("AK missing required attributes (fixedTPM|fixedParent|sensitiveDataOrigin|restricted|sign)");
    }
    return true;
  }

  // SimTPM path
  const attrs = normalizeAttributes(akPa.objectAttributes ?? akPa);
  if ((attrs & AK_REQUIRED_ATTRS) !== AK_REQUIRED_ATTRS) {
    throw new Error("AK missing required attributes (restricted and sign)");
  }
  return true;
}

/**
 * Verifies that the K_B public area satisfies ZTA constraints:
 * fixedTPM, fixedParent, sign; must exclude restricted, decrypt.
 * For real TPM evidence, checks directly from parsed bytes.
 *
 * @param {Record<string, any>} kbPa
 */
export function verifyKbAttributes(kbPa) {
  let attrs;
  if (kbPa.tpmtPublic) {
    const parsed = parsePublic(Buffer.from(kbPa.tpmtPublic, "base64url"));
    attrs = parsed.objectAttributes >>> 0;
  } else {
    attrs = normalizeAttributes(kbPa.objectAttributes ?? kbPa);
  }

  if (!(attrs & TPMA_OBJECT.fixedTPM)) {
    throw new Error("K_B publicArea missing fixedTPM attribute");
  }
  if (!(attrs & TPMA_OBJECT.fixedParent)) {
    throw new Error("K_B publicArea missing fixedParent attribute");
  }
  if (!(attrs & TPMA_OBJECT.sign)) {
    throw new Error("K_B publicArea missing sign attribute");
  }
  if (attrs & TPMA_OBJECT.restricted) {
    throw new Error("K_B publicArea must not have restricted attribute");
  }
  if (attrs & TPMA_OBJECT.decrypt) {
    throw new Error("K_B publicArea must not have decrypt attribute");
  }
  return true;
}

/**
 * Computes the expected Qualified Name of a child entity (e.g. AK or K_B)
 * given child publicArea and SRK publicArea.
 *
 * QN(SRK) = 0x000B || SHA256( 0x40000001 || Name(SRK) )
 * QN(child) = 0x000B || SHA256( QN(SRK) || Name(child) )
 *
 * @param {Record<string, any>|Buffer} childPa - child publicArea or Name
 * @param {Record<string, any>|Buffer} [srkPa] - SRK publicArea (if real TPM with SRK)
 * @returns {Buffer|null} 34-byte Qualified Name buffer, or null if no SRK
 */
export function expectedQn(childPa, srkPa) {
  if (!srkPa) return null;

  if (srkPa.tpmtPublic) {
    const parsedSrk = parsePublic(Buffer.from(srkPa.tpmtPublic, "base64url"));
    const attrs = parsedSrk.objectAttributes >>> 0;
    if ((attrs & SRK_REQUIRED_ATTRS) !== SRK_REQUIRED_ATTRS) {
      throw new Error("SRK must have fixedTPM, restricted, and decrypt attributes");
    }
  }

  const srkName = nameOfAny(srkPa);
  const srkQn = ownerQn(srkName);
  const childName = nameOfAny(childPa);
  return qualifiedName(srkQn, childName);
}

/**
 * Dispatches MakeCredential to real TPM 2.0 (tpm2) or simulated TPM (sim).
 *
 * @param {Record<string, any>} ekPublicArea
 * @param {Buffer|string} akName
 * @param {Buffer|string} secret
 * @returns {{ format: string, credentialBlob: string, secret: string }}
 */
export function makeCredentialAny(ekPublicArea, akName, secret) {
  if (ekPublicArea?.format === "tpm2" || ekPublicArea?.tpmtPublic) {
    if (!isStandardEk(ekPublicArea)) {
      throw new Error("Non-standard EK template: attributes, policy, or cipher do not match TCG EK profile");
    }
    return makeCredentialTpm2(ekPublicArea, akName, secret);
  }

  // SimTPM path
  const simBlob = makeCredentialSim(ekPublicArea, akName, secret);
  return {
    format: "sim",
    ...simBlob,
  };
}

export default {
  resolvePublic,
  nameOfAny,
  verifyAkAttributes,
  verifyKbAttributes,
  expectedQn,
  makeCredentialAny,
  AK_REQUIRED_ATTRS,
  SRK_REQUIRED_ATTRS,
};
