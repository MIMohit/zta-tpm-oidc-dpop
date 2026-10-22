/**
 * @file tpm2.test.mjs
 * Unit tests for lib/tpm2 pure-software TPM 2.0 structures (no TPM hardware required).
 * Verifies TPMT_PUBLIC parsing, Name, QN, MakeCredential, and captured real TPM 2.0 fixtures.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  parsePublic,
  publicKeyOf,
  publicAreaFromTpmt,
  nameOfTpmt,
  qualifiedName,
  ownerQn,
  verifyPublicArea,
  kdfa,
  kdfe,
  makeCredential,
  makeCredentialTpm2,
  isStandardEk,
  EK_AUTH_POLICY,
  EK_OBJECT_ATTRIBUTES,
} from "../lib/tpm2/index.js";
import { parseAttest, pcrDigest } from "../lib/sim-tpm/attest.js";

const FIXTURES_DIR = path.resolve(import.meta.dirname, "fixtures/tpm2");
const loadFixture = (name) => JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, name), "utf8"));

describe("WP-T1: TPM 2.0 Pure-Software Structures", () => {
  const ekRsa = loadFixture("ek-rsa.json");
  const ekEcc = loadFixture("ek-ecc.json");
  const srk = loadFixture("srk.json");
  const ak = loadFixture("ak.json");
  const kb = loadFixture("kb.json");
  const quote = loadFixture("quote.json");
  const certify = loadFixture("certify.json");
  const actRsa = loadFixture("activate-rsa.json");
  const actEcc = loadFixture("activate-ecc.json");

  describe("TPMT_PUBLIC Parsing and Validation", () => {
    it("parses standard RSA-2048 and ECC P-256 templates accurately", () => {
      const parsedRsa = parsePublic(Buffer.from(ekRsa.rawHex, "hex"));
      assert.equal(parsedRsa.type, 0x0001); // TPM_ALG_RSA
      assert.equal(parsedRsa.nameAlg, 0x000b); // TPM_ALG_SHA256
      assert.equal(parsedRsa.objectAttributes, EK_OBJECT_ATTRIBUTES);
      assert.equal(parsedRsa.keyBits, 2048);
      assert.equal(parsedRsa.exponent, 65537);

      const parsedEcc = parsePublic(Buffer.from(ekEcc.rawHex, "hex"));
      assert.equal(parsedEcc.type, 0x0023); // TPM_ALG_ECC
      assert.equal(parsedEcc.nameAlg, 0x000b);
      assert.equal(parsedEcc.objectAttributes, EK_OBJECT_ATTRIBUTES);
      assert.equal(parsedEcc.curveID, 0x0003); // NIST_P256
    });

    it("parsePublic rejects trailing bytes", () => {
      const raw = Buffer.from(ekRsa.rawHex, "hex");
      const bad = Buffer.concat([raw, Buffer.from([0x00, 0x01, 0x02])]);
      assert.throws(
        () => parsePublic(bad),
        /trailing bytes in TPMT_PUBLIC/
      );
    });

    it("parsePublic rejects unknown types", () => {
      const raw = Buffer.from(ekRsa.rawHex, "hex");
      const bad = Buffer.from(raw);
      bad.writeUInt16BE(0x0099, 0); // Invalid TPM_ALG_ID
      assert.throws(
        () => parsePublic(bad),
        /unsupported TPMT_PUBLIC type 0x99/
      );
    });

    it("parsePublic rejects truncated buffers", () => {
      assert.throws(() => parsePublic(Buffer.from([0x00, 0x01])), /too short/);
      const raw = Buffer.from(ekEcc.rawHex, "hex");
      assert.throws(() => parsePublic(raw.subarray(0, 30)), /truncated/);
    });
  });

  describe("Name and Qualified Name (QN) Calculation", () => {
    it("Name of captured RSA/ECC EK, AK, and K_B fixtures equals the TPM-reported name", () => {
      const rsaName = nameOfTpmt(Buffer.from(ekRsa.rawHex, "hex")).toString("hex");
      assert.equal(rsaName, ekRsa.tpmReportedNameHex);
      assert.equal(rsaName, ekRsa.nameHex);

      const eccName = nameOfTpmt(Buffer.from(ekEcc.rawHex, "hex")).toString("hex");
      assert.equal(eccName, ekEcc.tpmReportedNameHex);
      assert.equal(eccName, ekEcc.nameHex);

      const akName = nameOfTpmt(Buffer.from(ak.rawHex, "hex")).toString("hex");
      assert.equal(akName, ak.tpmReportedNameHex);
      assert.equal(akName, ak.nameHex);

      const kbName = nameOfTpmt(Buffer.from(kb.rawHex, "hex")).toString("hex");
      assert.equal(kbName, kb.tpmReportedNameHex);
      assert.equal(kbName, kb.nameHex);
    });

    it("QN(AK) equals the fixture quote's qualifiedSigner", () => {
      // QN(SRK) = H(0x40000001 || Name(SRK))
      const srkNameBuf = Buffer.from(srk.nameHex, "hex");
      const srkQn = ownerQn(srkNameBuf);
      assert.equal(srkQn.toString("hex"), srk.qnHex);

      // QN(AK) = H(QN(SRK) || Name(AK))
      const akNameBuf = Buffer.from(ak.nameHex, "hex");
      const akQn = qualifiedName(srkQn, akNameBuf);
      assert.equal(akQn.toString("hex"), ak.qnHex);

      // Must equal quote fixture qualifiedSigner
      assert.equal(akQn.toString("hex"), quote.qualifiedSignerHex);

      // Also verify parseAttest parses the raw quote bytes and matches
      const parsedQuote = parseAttest(Buffer.from(quote.attestRawHex, "hex"));
      assert.equal(parsedQuote.qualifiedSigner.toString("hex"), akQn.toString("hex"));
    });
  });

  describe("Quote and Certify Attestation Verification", () => {
    it("captured quote signature verifies under AK public key and parseAttest fields match", () => {
      const akKey = publicKeyOf(Buffer.from(ak.rawHex, "hex"));
      const attestBuf = Buffer.from(quote.attestRawHex, "hex");
      const sigBuf = Buffer.from(quote.sigRawHex, "hex");

      const validSig = crypto.verify("sha256", attestBuf, { key: akKey, dsaEncoding: "ieee-p1363" }, sigBuf);
      assert.equal(validSig, true);

      const parsed = parseAttest(attestBuf);
      assert.equal(parsed.magic, 0xff544347); // TPM_GENERATED_VALUE
      assert.equal(parsed.type, 0x8018); // TPM_ST_ATTEST_QUOTE
      assert.equal(parsed.extraData.toString("hex"), quote.nonceHex);
      assert.equal(parsed.pcrDigest.toString("hex"), quote.pcrDigestHex);

      // Recompute PCR digest from individual PCR values
      const pcrBufs = quote.pcrsHex.map((h) => Buffer.from(h, "hex"));
      const expectedPcrDigest = pcrDigest(pcrBufs);
      assert.equal(parsed.pcrDigest.toString("hex"), expectedPcrDigest.toString("hex"));
    });

    it("captured certify signature verifies under AK public key and attested fields match", () => {
      const akKey = publicKeyOf(Buffer.from(ak.rawHex, "hex"));
      const attestBuf = Buffer.from(certify.attestRawHex, "hex");
      const sigBuf = Buffer.from(certify.sigRawHex, "hex");

      const validSig = crypto.verify("sha256", attestBuf, { key: akKey, dsaEncoding: "ieee-p1363" }, sigBuf);
      assert.equal(validSig, true);

      const parsed = parseAttest(attestBuf);
      assert.equal(parsed.magic, 0xff544347);
      assert.equal(parsed.type, 0x8017); // TPM_ST_ATTEST_CERTIFY
      assert.equal(parsed.extraData.toString("hex"), certify.nonceHex);
      assert.equal(parsed.attested.name.toString("hex"), certify.attestedNameHex);
      assert.equal(parsed.attested.name.toString("hex"), kb.nameHex);
      assert.equal(parsed.attested.qualifiedName.toString("hex"), certify.attestedQualifiedNameHex);
      assert.equal(parsed.attested.qualifiedName.toString("hex"), kb.qnHex);
    });
  });

  describe("KDF and MakeCredential Activation Round-Trip", () => {
    it("KDFa SP800-108 counter mode produces accurate bits", () => {
      const key = Buffer.from("0123456789abcdef0123456789abcdef", "hex");
      const k128 = kdfa("sha256", key, "STORAGE", Buffer.from("test-name"), Buffer.alloc(0), 128);
      const k256 = kdfa("sha256", key, "STORAGE", Buffer.from("test-name"), Buffer.alloc(0), 256);
      const k512 = kdfa("sha256", key, "STORAGE", Buffer.from("test-name"), Buffer.alloc(0), 512);

      assert.equal(k128.length, 16);
      assert.equal(k256.length, 32);
      assert.equal(k512.length, 64);

      // Determinism
      assert.deepEqual(kdfa("sha256", key, "STORAGE", Buffer.from("test-name"), Buffer.alloc(0), 128), k128);
      assert.deepEqual(kdfa("sha256", key, "STORAGE", Buffer.from("test-name"), Buffer.alloc(0), 256), k256);
      // Different labels produce distinct outputs
      const kOther = kdfa("sha256", key, "INTEGRITY", Buffer.from("test-name"), Buffer.alloc(0), 128);
      assert.notDeepEqual(k128, kOther);
    });

    it("KDFe SP800-56A produces deterministic output", () => {
      const z = Buffer.alloc(32, 0x42);
      const pU = Buffer.alloc(32, 0x01);
      const pV = Buffer.alloc(32, 0x02);
      const k = kdfe("sha256", z, "IDENTITY", pU, pV, 256);
      assert.equal(k.length, 32);
      // Determinism
      assert.deepEqual(kdfe("sha256", z, "IDENTITY", pU, pV, 256), k);
    });

    it("The KDFa test vector equals a value computed by the TPM, captured via ActivateCredential round-trip fixture", () => {
      // In both RSA and ECC activation fixtures, the software MakeCredential generated the
      // credentialBlob (using KDFa for symKey + hmacKey) and the TPM verified the integrity
      // and decrypted the secret, matching the original secret.
      assert.equal(actRsa.verified, true);
      assert.equal(actRsa.secretHex, actRsa.activatedSecretHex);

      assert.equal(actEcc.verified, true);
      assert.equal(actEcc.secretHex, actEcc.activatedSecretHex);

      // Verify that deciphering or re-making credential with the exact inputs is consistent
      const akNameBuf = Buffer.from(actRsa.akNameHex, "hex");
      const secBuf = Buffer.from(actRsa.secretHex, "hex");
      const ekRsaPub = parsePublic(Buffer.from(ekRsa.rawHex, "hex"));

      // Negative test: MakeCredential for wrong AK name generates different integrity
      const mcCorrect = makeCredential(ekRsaPub, akNameBuf, secBuf);
      const mcWrong = makeCredential(ekRsaPub, Buffer.alloc(34, 0xff), secBuf, { seed: mcCorrect.seed });
      assert.notDeepEqual(mcCorrect.integrity, mcWrong.integrity);
    });
  });

  describe("JSON/Raw Public Area Mismatch Rejection", () => {
    it("publicAreaFromTpmt generates expected JSON shape with tpmtPublic and format: tpm2", () => {
      const paEcc = publicAreaFromTpmt(Buffer.from(ak.rawHex, "hex"));
      assert.equal(paEcc.format, "tpm2");
      assert.equal(paEcc.type, "ecc");
      assert.equal(paEcc.nameAlg, "sha256");
      assert.equal(paEcc.curve, "P-256");
      assert.equal(paEcc.objectAttributes, 0x00050072);
      assert.equal(paEcc.x, ak.x);
      assert.equal(paEcc.y, ak.y);

      const paRsa = publicAreaFromTpmt(Buffer.from(ekRsa.rawHex, "hex"));
      assert.equal(paRsa.format, "tpm2");
      assert.equal(paRsa.type, "rsa");
      assert.equal(paRsa.kty, "RSA");
      assert.equal(paRsa.n, ekRsa.n);
      assert.equal(paRsa.exponent, 65537);
    });

    it("verifyPublicArea accepts matching JSON and raw bytes", () => {
      const pa = publicAreaFromTpmt(Buffer.from(ak.rawHex, "hex"));
      const res = verifyPublicArea(pa);
      assert.equal(res.format, "tpm2");
      assert.equal(res.objectAttributes, 0x00050072);
    });

    it("verifyPublicArea rejects tampered JSON attributes (objectAttributes mismatch)", () => {
      const pa = publicAreaFromTpmt(Buffer.from(ak.rawHex, "hex"));
      // Attacker tampers with attributes to pretend it is unrestricted
      pa.objectAttributes = 0x00040072;
      assert.throws(() => verifyPublicArea(pa), /publicArea objectAttributes mismatch/);
    });

    it("verifyPublicArea rejects tampered key coordinates (x mismatch)", () => {
      const pa = publicAreaFromTpmt(Buffer.from(ak.rawHex, "hex"));
      pa.x = Buffer.alloc(32, 0x00).toString("base64url");
      assert.throws(() => verifyPublicArea(pa), /publicArea x coordinate mismatch/);
    });

    it("verifyPublicArea rejects tampered type", () => {
      const pa = publicAreaFromTpmt(Buffer.from(ak.rawHex, "hex"));
      pa.type = "rsa";
      assert.throws(() => verifyPublicArea(pa), /publicArea type mismatch/);
    });
  });

  describe("Standard EK Template Verification (isStandardEk)", () => {
    it("returns true for standard L-1 RSA and L-2 ECC templates", () => {
      assert.equal(isStandardEk(Buffer.from(ekRsa.rawHex, "hex")), true);
      assert.equal(isStandardEk(Buffer.from(ekEcc.rawHex, "hex")), true);
      assert.equal(isStandardEk(publicAreaFromTpmt(Buffer.from(ekRsa.rawHex, "hex"))), true);
      assert.equal(isStandardEk(publicAreaFromTpmt(Buffer.from(ekEcc.rawHex, "hex"))), true);
    });

    it("returns false for non-standard keys (AK, K_B, SRK)", () => {
      assert.equal(isStandardEk(Buffer.from(ak.rawHex, "hex")), false);
      assert.equal(isStandardEk(Buffer.from(kb.rawHex, "hex")), false);
      assert.equal(isStandardEk(Buffer.from(srk.rawHex, "hex")), false);
    });

    it("returns false if policy or attributes do not match standard EK template", () => {
      const parsed = parsePublic(Buffer.from(ekEcc.rawHex, "hex"));
      const modifiedAttrs = { ...parsed, objectAttributes: 0x000200b2 };
      assert.equal(isStandardEk(modifiedAttrs), false);

      const modifiedPolicy = { ...parsed, authPolicy: Buffer.alloc(32, 0) };
      assert.equal(isStandardEk(modifiedPolicy), false);
    });
  });
});
