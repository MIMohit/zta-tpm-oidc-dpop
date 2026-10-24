/**
 * @file ek-template.js
 * Verification and classification of standard TCG EK templates:
 *  - Low Range: L-1 RSA-2048 and L-2 ECC P-256 (TCG EK Credential Profile 2.0 / 2.5)
 *  - High Range: H-3 ECC NIST P-384 (TCG EK Credential Profile 2.5 Annex B / measured from swtpm 0.10.2)
 *
 * Note on H-1 and H-2:
 * TCG EK Credential Profile v2.5 Annex B defines H-1 (RSA 2048, SHA-256 PolicyB) and H-2
 * (ECC P-256, SHA-256 PolicyB). PolicyB requires a TPM2_PolicyOR with PolicyAuthorizeNV.
 * Per PLAN-MAC.md §1.2 / §3.1 item 2 / §8 R4, we ship verified L-1, L-2, and H-3 templates.
 */
import {
  parsePublic,
  TPM_ALG_RSA,
  TPM_ALG_SHA256,
  TPM_ALG_SHA384,
  TPM_ALG_NULL,
  TPM_ALG_ECC,
  TPM_ECC_NIST_P256,
  TPM_ECC_NIST_P384,
} from "./marshal.js";

// L-1 and L-2 authPolicy: PolicySecret(TPM_RH_ENDORSEMENT) (SHA-256, 32 bytes)
export const EK_AUTH_POLICY = Buffer.from(
  "837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa",
  "hex"
);
export const EK_OBJECT_ATTRIBUTES = 0x000300b2;

// H-3 authPolicy: PolicyB (SHA-384, 48 bytes, measured from swtpm 0.10.2 per PLAN-MAC.md §0 X7)
export const EK_H3_AUTH_POLICY = Buffer.from(
  "b26e7d28d11a50bc53d882bcf5fd3a1a074148bb35d3b4e4cb1c0ad9bde419cacb47ba09699646150f9fc000f3f80e12",
  "hex"
);
export const EK_H_OBJECT_ATTRIBUTES = 0x000300f2;

/**
 * Classifies whether the given public area represents a standard TCG EK template.
 *
 * @param {Buffer|string|Record<string, any>} input - TPMT_PUBLIC buffer/string or a publicArea carrying tpmtPublic
 * @returns {{ id: "L-1"|"L-2"|"H-1"|"H-2"|"H-3", nameAlg: string, symKeyBits: number, curve?: string, keyBits?: number, userWithAuth: boolean } | null}
 */
export function classifyEkTemplate(input) {
  try {
    let p;
    if (Buffer.isBuffer(input) || typeof input === "string") {
      p = parsePublic(input);
    } else if (input && typeof input.tpmtPublic === "string") {
      p = parsePublic(Buffer.from(input.tpmtPublic, "base64url"));
    } else {
      // Only raw TPMT_PUBLIC bytes are trusted (V2): a plain JSON object carrying
      // authPolicy/type fields says nothing about the key it is paired with.
      return null;
    }

    const attrs = p.objectAttributes >>> 0;
    const policyBuf = Buffer.isBuffer(p.authPolicy)
      ? p.authPolicy
      : typeof p.authPolicy === "string"
      ? Buffer.from(p.authPolicy, "hex")
      : null;
    if (!policyBuf) return null;

    // Common template requirements:
    // Symmetric cipher must be AES-CFB, Scheme must be NULL (0x0010)
    if (p.sym !== 0x0006 || p.symMode !== 0x0043 || p.scheme !== TPM_ALG_NULL) {
      return null;
    }

    // 1. Check Low-Range templates (L-1, L-2)
    // Attributes: 0x000300B2 (fixedTPM | fixedParent | sensitiveDataOrigin | adminWithPolicy | restricted | decrypt)
    // AuthPolicy: EK_AUTH_POLICY (32 bytes SHA-256)
    // Cipher: AES-128-CFB
    // NameAlg: SHA-256
    if (
      attrs === EK_OBJECT_ATTRIBUTES &&
      policyBuf.equals(EK_AUTH_POLICY) &&
      p.nameAlg === TPM_ALG_SHA256 &&
      p.symKeyBits === 128
    ) {
      if (p.type === TPM_ALG_RSA) {
        // L-1 RSA-2048
        if (p.keyBits !== 2048) return null;
        if (p.exponent !== 0 && p.exponent !== 65537) return null;
        return {
          id: "L-1",
          nameAlg: "sha256",
          symKeyBits: 128,
          keyBits: 2048,
          userWithAuth: false,
        };
      }

      if (p.type === TPM_ALG_ECC) {
        // L-2 ECC NIST P-256
        if (p.curveID !== TPM_ECC_NIST_P256) return null;
        return {
          id: "L-2",
          nameAlg: "sha256",
          symKeyBits: 128,
          curve: "P-256",
          userWithAuth: false,
        };
      }
    }

    // 2. Check High-Range template H-3
    // Attributes: 0x000300F2 (userWithAuth added)
    // AuthPolicy: EK_H3_AUTH_POLICY (48 bytes SHA-384)
    // Cipher: AES-256-CFB
    // NameAlg: SHA-384
    // Curve: NIST P-384 (curveID 0x0004)
    if (
      attrs === EK_H_OBJECT_ATTRIBUTES &&
      policyBuf.equals(EK_H3_AUTH_POLICY) &&
      p.nameAlg === TPM_ALG_SHA384 &&
      p.symKeyBits === 256 &&
      p.type === TPM_ALG_ECC &&
      p.curveID === TPM_ECC_NIST_P384
    ) {
      return {
        id: "H-3",
        nameAlg: "sha384",
        symKeyBits: 256,
        curve: "P-384",
        userWithAuth: true,
      };
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Checks whether the given public area or parsed TPMT_PUBLIC represents a standard
 * TCG EK template (L-1, L-2, or H-3).
 *
 * @param {Buffer|string|Record<string, any>} input - TPMT_PUBLIC buffer/string or a publicArea carrying tpmtPublic
 * @returns {boolean}
 */
export function isStandardEk(input) {
  return classifyEkTemplate(input) !== null;
}

export default {
  isStandardEk,
  classifyEkTemplate,
  EK_AUTH_POLICY,
  EK_OBJECT_ATTRIBUTES,
  EK_H3_AUTH_POLICY,
  EK_H_OBJECT_ATTRIBUTES,
};
