/**
 * @file templates.js
 * Standard TPM 2.0 public templates (TCG EK Credential Profile L-1/L-2, SRK, AK, K_B).
 * Conforms to PLAN-TPM.md Snippet S1.
 */
import tss from "tss.js";

const {
  TPM_ALG_ID,
  TPM_ECC_CURVE,
  TPMA_OBJECT,
  TPMT_PUBLIC,
  TPMS_RSA_PARMS,
  TPMS_ECC_PARMS,
  TPMT_SYM_DEF_OBJECT,
  TPMS_NULL_ASYM_SCHEME,
  TPMS_SIG_SCHEME_ECDSA,
  TPMS_NULL_KDF_SCHEME,
  TPM2B_PUBLIC_KEY_RSA,
  TPMS_ECC_POINT,
} = tss;

// TCG EK Policy: PolicySecret(TPM_RH_ENDORSEMENT)
export const EK_POLICY = Buffer.from(
  "837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa",
  "hex"
);

// TCG H-3 EK Policy: PolicyB SHA-384
export const EK_H3_POLICY = Buffer.from(
  "b26e7d28d11a50bc53d882bcf5fd3a1a074148bb35d3b4e4cb1c0ad9bde419cacb47ba09699646150f9fc000f3f80e12",
  "hex"
);

// EK attributes: fixedTPM | fixedParent | sensitiveDataOrigin | adminWithPolicy | restricted | decrypt (0x000300B2)
export const EK_ATTRS =
  TPMA_OBJECT.fixedTPM |
  TPMA_OBJECT.fixedParent |
  TPMA_OBJECT.sensitiveDataOrigin |
  TPMA_OBJECT.adminWithPolicy |
  TPMA_OBJECT.restricted |
  TPMA_OBJECT.decrypt;

// High-range EK attributes: adds userWithAuth (0x000300F2)
export const EK_H_ATTRS = EK_ATTRS | TPMA_OBJECT.userWithAuth;

// Symmetric cipher for parameter encryption: AES-128-CFB
export const AES128CFB = new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 128, TPM_ALG_ID.CFB);

// SRK attributes: owner hierarchy, ECC P-256 storage key
export const SRK_ATTRS =
  TPMA_OBJECT.fixedTPM |
  TPMA_OBJECT.fixedParent |
  TPMA_OBJECT.sensitiveDataOrigin |
  TPMA_OBJECT.userWithAuth |
  TPMA_OBJECT.noDA |
  TPMA_OBJECT.restricted |
  TPMA_OBJECT.decrypt;

// AK attributes: restricted | sign | fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth (0x00050072)
export const AK_ATTRS =
  TPMA_OBJECT.fixedTPM |
  TPMA_OBJECT.fixedParent |
  TPMA_OBJECT.sensitiveDataOrigin |
  TPMA_OBJECT.userWithAuth |
  TPMA_OBJECT.restricted |
  TPMA_OBJECT.sign;

// K_B attributes: sign | fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth (0x00040072)
export const KB_ATTRS =
  TPMA_OBJECT.fixedTPM |
  TPMA_OBJECT.fixedParent |
  TPMA_OBJECT.sensitiveDataOrigin |
  TPMA_OBJECT.userWithAuth |
  TPMA_OBJECT.sign;

export const NULL_SYM = new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.NULL, 0, TPM_ALG_ID.NULL);

export function createEkRsaTemplate() {
  return new TPMT_PUBLIC(
    TPM_ALG_ID.SHA256,
    EK_ATTRS,
    EK_POLICY,
    new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 128, TPM_ALG_ID.CFB), new TPMS_NULL_ASYM_SCHEME(), 2048, 0),
    new TPM2B_PUBLIC_KEY_RSA(Buffer.alloc(256))
  );
}

export function createEkEccTemplate() {
  return new TPMT_PUBLIC(
    TPM_ALG_ID.SHA256,
    EK_ATTRS,
    EK_POLICY,
    new TPMS_ECC_PARMS(
      new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 128, TPM_ALG_ID.CFB),
      new TPMS_NULL_ASYM_SCHEME(),
      TPM_ECC_CURVE.NIST_P256,
      new TPMS_NULL_KDF_SCHEME()
    ),
    new TPMS_ECC_POINT(Buffer.alloc(32), Buffer.alloc(32))
  );
}

export function createSrkTemplate() {
  return new TPMT_PUBLIC(
    TPM_ALG_ID.SHA256,
    SRK_ATTRS,
    Buffer.alloc(0),
    new TPMS_ECC_PARMS(
      new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 128, TPM_ALG_ID.CFB),
      new TPMS_NULL_ASYM_SCHEME(),
      TPM_ECC_CURVE.NIST_P256,
      new TPMS_NULL_KDF_SCHEME()
    ),
    new TPMS_ECC_POINT(Buffer.alloc(0), Buffer.alloc(0))
  );
}

export function createEccSignTemplate(attrs) {
  return new TPMT_PUBLIC(
    TPM_ALG_ID.SHA256,
    attrs,
    Buffer.alloc(0),
    new TPMS_ECC_PARMS(
      new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.NULL, 0, TPM_ALG_ID.NULL),
      new TPMS_SIG_SCHEME_ECDSA(TPM_ALG_ID.SHA256),
      TPM_ECC_CURVE.NIST_P256,
      new TPMS_NULL_KDF_SCHEME()
    ),
    new TPMS_ECC_POINT(Buffer.alloc(0), Buffer.alloc(0))
  );
}

export function createEkEccP384HighTemplate() {
  return new TPMT_PUBLIC(
    TPM_ALG_ID.SHA384,
    EK_H_ATTRS,
    EK_H3_POLICY,
    new TPMS_ECC_PARMS(
      new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 256, TPM_ALG_ID.CFB),
      new TPMS_NULL_ASYM_SCHEME(),
      TPM_ECC_CURVE.NIST_P384,
      new TPMS_NULL_KDF_SCHEME()
    ),
    new TPMS_ECC_POINT(Buffer.alloc(0), Buffer.alloc(0))
  );
}

export function createAkTemplate() {
  return createEccSignTemplate(AK_ATTRS);
}

export function createKbTemplate() {
  return createEccSignTemplate(KB_ATTRS);
}

export const ekRsaTemplate = createEkRsaTemplate();
export const ekEccTemplate = createEkEccTemplate();
export const ekEccP384HighTemplate = createEkEccP384HighTemplate();
export const srkTemplate = createSrkTemplate();
export const akTemplate = createAkTemplate();
export const kbTemplate = createKbTemplate();

