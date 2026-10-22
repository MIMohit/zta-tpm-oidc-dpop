/**
 * @file tests/ek-p384.test.mjs
 * Unit tests for WP-B: P-384 EK, H-3 template classification, Name derivation,
 * multi-dir trust anchors, X9 regression (chain alias), MakeCredential P-384,
 * DER trim, and SRK handle validation.
 */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";

import {
  nameOfTpmt,
  parsePublic,
  publicKeyOf,
  publicAreaFromTpmt,
  classifyEkTemplate,
  isStandardEk,
  makeCredential,
  makeCredentialTpm2,
  kdfa,
  kdfe,
} from "../lib/tpm2/index.js";
import { verifyX509EkCert } from "../lib/verifier/ek-cert-x509.js";
import { trimDer } from "../lib/tpm-real/ek-cert.js";
import { parseSrkHandle } from "../lib/tpm-real/backend.js";

const fixturesDir = path.resolve("tests/fixtures/swtpm");
const p384H3Tpmt = fs.readFileSync(path.join(fixturesDir, "ek-p384-H3.tpmt"));
const rsa2048L1Tpmt = fs.readFileSync(path.join(fixturesDir, "ek-rsa2048-L1.tpmt"));
const p384CertDer = fs.readFileSync(path.join(fixturesDir, "ekcert-p384-nv01c00016.der"));
const rsaCertDer = fs.readFileSync(path.join(fixturesDir, "ekcert-rsa2048-nv01c00002.der"));
const issuerPem = fs.readFileSync(path.join(fixturesDir, "swtpm-localca-issuer.pem"), "utf8");
const rootPem = fs.readFileSync(path.join(fixturesDir, "swtpm-localca-root.pem"), "utf8");
const eccL2Json = JSON.parse(fs.readFileSync(path.resolve("tests/fixtures/tpm2/ek-ecc.json"), "utf8"));

test("WP-B: Template Classification (classifyEkTemplate & isStandardEk)", () => {
  // H-3 template classification
  const h3Class = classifyEkTemplate(p384H3Tpmt);
  assert.ok(h3Class, "H-3 template must be recognized");
  assert.equal(h3Class.id, "H-3");
  assert.equal(h3Class.nameAlg, "sha384");
  assert.equal(h3Class.symKeyBits, 256);
  assert.equal(h3Class.curve, "P-384");
  assert.equal(h3Class.userWithAuth, true);
  assert.equal(isStandardEk(p384H3Tpmt), true);

  // L-1 template classification
  const l1Class = classifyEkTemplate(rsa2048L1Tpmt);
  assert.ok(l1Class, "L-1 template must be recognized");
  assert.equal(l1Class.id, "L-1");
  assert.equal(l1Class.nameAlg, "sha256");
  assert.equal(l1Class.symKeyBits, 128);
  assert.equal(l1Class.keyBits, 2048);
  assert.equal(l1Class.userWithAuth, false);
  assert.equal(isStandardEk(rsa2048L1Tpmt), true);

  // L-2 template classification from fixture
  const l2Class = classifyEkTemplate(eccL2Json.tpmtPublic);
  assert.ok(l2Class, "L-2 template must be recognized");
  assert.equal(l2Class.id, "L-2");
  assert.equal(l2Class.nameAlg, "sha256");
  assert.equal(l2Class.symKeyBits, 128);
  assert.equal(l2Class.curve, "P-256");
  assert.equal(l2Class.userWithAuth, false);
  assert.equal(isStandardEk(eccL2Json.tpmtPublic), true);
});

test("WP-B: Template Negatives (flipping attribute bit, authPolicy byte, symKeyBits, or curveID)", () => {
  // 1. Flip one attribute bit (offset 6 in TPMT_PUBLIC)
  const badAttrs = Buffer.from(p384H3Tpmt);
  badAttrs[7] ^= 0x01; // flip 1 bit in attributes
  assert.equal(classifyEkTemplate(badAttrs), null, "flipped attribute bit must reject");

  // 2. Flip one byte of authPolicy (offset 10 in H-3)
  const badPolicy = Buffer.from(p384H3Tpmt);
  badPolicy[12] ^= 0xff;
  assert.equal(classifyEkTemplate(badPolicy), null, "flipped authPolicy byte must reject");

  // 3. Change symKeyBits 256 -> 128 on H-3
  // Look for symKeyBits in H-3
  // H-3 has type(2B)=0x0023, nameAlg(2B)=0x000c, attrs(4B)=0x000300f2, policyLen(2B)=0x0030, policy(48B), sym(2B)=0x0006, symKeyBits(2B)=0x0100 (256)
  const badSym = Buffer.from(p384H3Tpmt);
  const symOffset = 2 + 2 + 4 + 2 + 48; // 58
  assert.equal(badSym.readUInt16BE(symOffset), 0x0006, "check sym is AES");
  assert.equal(badSym.readUInt16BE(symOffset + 2), 256, "check symKeyBits is 256");
  badSym.writeUInt16BE(128, symOffset + 2);
  assert.equal(classifyEkTemplate(badSym), null, "symKeyBits 128 on H-3 must reject");

  // 4. Change curve P-384 -> P-256 with SHA-384 nameAlg
  const badCurve = Buffer.from(p384H3Tpmt);
  const curveOffset = symOffset + 2 + 2 + 2 + 2; // sym(2) + keyBits(2) + mode(2) + scheme(2) -> curveID
  assert.equal(badCurve.readUInt16BE(curveOffset), 0x0004, "check curveID is P-384 (4)");
  badCurve.writeUInt16BE(0x0003, curveOffset); // curveID = 3 (P-256)
  assert.equal(classifyEkTemplate(badCurve), null, "curve P-256 with SHA-384 nameAlg must reject");
});

test("WP-B: nameOfTpmt and publicAreaFromTpmt on H-3", () => {
  const name = nameOfTpmt(p384H3Tpmt);
  assert.equal(name.length, 50, "Name of H-3 must be exactly 50 bytes");
  assert.equal(name.readUInt16BE(0), 0x000c, "Name must start with TPM_ALG_SHA384 (0x000C)");

  const pa = publicAreaFromTpmt(p384H3Tpmt);
  assert.equal(pa.nameAlg, "sha384", "publicArea nameAlg must be sha384");
  assert.equal(pa.curve, "P-384", "publicArea curve must be P-384");
  assert.equal(pa.type, "ecc");
  assert.ok(pa.x && pa.y, "coordinates x and y must be present");
});

test("WP-B: verifyX509EkCert with P-384 and RSA EK certs and X9 regression", async () => {
  const tmpRootsDir = fs.mkdtempSync(path.join(os.tmpdir(), "zta-roots-"));
  try {
    fs.writeFileSync(path.join(tmpRootsDir, "root.pem"), rootPem);

    const h3Pa = publicAreaFromTpmt(p384H3Tpmt);
    const rsaPa = publicAreaFromTpmt(rsa2048L1Tpmt);

    // 1. P-384 cert + H-3 public area + intermediate in ekCertChain
    const resP384 = await verifyX509EkCert(
      {
        cert: p384CertDer,
        ekCertChain: [issuerPem],
        ekPublicArea: h3Pa,
      },
      tmpRootsDir,
      { ztaEnv: "development" }
    );
    assert.ok(resP384, "P-384 EK verification must succeed");
    assert.equal(resP384.curve, "P-384");

    // 2. X9 Regression: intermediate passed only via `chain` alias
    const resX9 = await verifyX509EkCert(
      {
        cert: p384CertDer,
        chain: [issuerPem],
        ekPublicArea: h3Pa,
      },
      tmpRootsDir,
      { ztaEnv: "development" }
    );
    assert.ok(resX9, "Intermediate passed via 'chain' must be used and succeed (X9 fix)");

    // 3. RSA cert + RSA L-1 public area
    const resRsa = await verifyX509EkCert(
      {
        cert: rsaCertDer,
        chain: [issuerPem],
        ekPublicArea: rsaPa,
      },
      tmpRootsDir,
      { ztaEnv: "development" }
    );
    assert.ok(resRsa, "RSA EK verification must succeed");
    assert.equal(resRsa.type, "rsa");

    // 4. Cross-binding (P-1): P-384 cert with RSA EK public area -> reject
    await assert.rejects(
      async () => {
        await verifyX509EkCert(
          {
            cert: p384CertDer,
            chain: [issuerPem],
            ekPublicArea: rsaPa,
          },
          tmpRootsDir,
          { ztaEnv: "development" }
        );
      },
      /Certificate public key does not match EK public area|SPKI mismatch|ek_template_invalid/i
    );

    // 5. Cross-binding (P-1): RSA cert with H-3 EK public area -> reject
    await assert.rejects(
      async () => {
        await verifyX509EkCert(
          {
            cert: rsaCertDer,
            chain: [issuerPem],
            ekPublicArea: h3Pa,
          },
          tmpRootsDir,
          { ztaEnv: "development" }
        );
      },
      /Certificate public key does not match EK public area|SPKI mismatch/i
    );
  } finally {
    fs.rmSync(tmpRootsDir, { recursive: true, force: true });
  }
});

test("WP-B: Multi-directory trust anchors and Untrusted Root", async () => {
  const dir1 = fs.mkdtempSync(path.join(os.tmpdir(), "zta-roots-empty-"));
  const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), "zta-roots-good-"));

  try {
    fs.writeFileSync(path.join(dir2, "root.pem"), rootPem);
    const h3Pa = publicAreaFromTpmt(p384H3Tpmt);

    // 1. Untrusted root: only dir1 (which lacks the root CA)
    await assert.rejects(
      async () => {
        await verifyX509EkCert(
          {
            cert: p384CertDer,
            chain: [issuerPem],
            ekPublicArea: h3Pa,
          },
          dir1,
          { ztaEnv: "development" }
        );
      },
      /Untrusted root CA|No trusted EK root/i
    );

    // 2. Multi-dir list [dir1, dir2] where only dir2 has the root -> ok
    const twoDirList = `${dir1}${path.delimiter}${dir2}`;
    const res = await verifyX509EkCert(
      {
        cert: p384CertDer,
        chain: [issuerPem],
        ekPublicArea: h3Pa,
      },
      twoDirList,
      { ztaEnv: "development" }
    );
    assert.ok(res, "Multi-directory anchor list containing root CA in second entry must succeed");
  } finally {
    fs.rmSync(dir1, { recursive: true, force: true });
    fs.rmSync(dir2, { recursive: true, force: true });
  }
});

test("WP-B: MakeCredential P-384 self-consistency round-trip", () => {
  // Generate a real P-384 key pair
  const ecdh = crypto.createECDH("secp384r1");
  ecdh.generateKeys();
  const pubPt = ecdh.getPublicKey();
  const ekX = pubPt.subarray(1, 49);
  const ekY = pubPt.subarray(49, 97);

  // Build an H-3-shaped TPMT_PUBLIC around this P-384 key
  // Header: type(2B)=0x0023, nameAlg(2B)=0x000c, attrs(4B)=0x000300f2, policyLen(2B)=48, policy(48B)
  // sym(2B)=0x0006, symKeyBits(2B)=256, symMode(2B)=0x0043, scheme(2B)=0x0010
  // curveID(2B)=0x0004, kdf(2B)=0x0010, xLen(2B)=48, x(48B), yLen(2B)=48, y(48B)
  const authPolicy = Buffer.from(
    "b26e7d28d11a50bc53d882bcf5fd3a1a074148bb35d3b4e4cb1c0ad9bde419cacb47ba09699646150f9fc000f3f80e12",
    "hex"
  );
  const hdr = Buffer.alloc(10);
  hdr.writeUInt16BE(0x0023, 0); // TPM_ALG_ECC
  hdr.writeUInt16BE(0x000c, 2); // TPM_ALG_SHA384
  hdr.writeUInt32BE(0x000300f2, 4); // TPMA_OBJECT
  hdr.writeUInt16BE(authPolicy.length, 8);

  const parms = Buffer.alloc(12);
  parms.writeUInt16BE(0x0006, 0); // AES
  parms.writeUInt16BE(256, 2); // 256 bits
  parms.writeUInt16BE(0x0043, 4); // CFB
  parms.writeUInt16BE(0x0010, 6); // NULL scheme
  parms.writeUInt16BE(0x0004, 8); // NIST P-384
  parms.writeUInt16BE(0x0010, 10); // NULL kdf

  const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(n);
    return b;
  };
  const tpmtPub = Buffer.concat([
    hdr,
    authPolicy,
    parms,
    u16(ekX.length),
    ekX,
    u16(ekY.length),
    ekY,
  ]);

  assert.equal(classifyEkTemplate(tpmtPub)?.id, "H-3", "Generated template must classify as H-3");

  const akName = crypto.randomBytes(34);
  const secret = crypto.randomBytes(32);

  const cred = makeCredential(tpmtPub, akName, secret);
  assert.ok(cred.idObject);
  assert.ok(cred.encSecret);

  // Reference activation in test:
  // encSecret is TPMS_ECC_POINT: 2B xLen || ephX || 2B yLen || ephY
  const ephXLen = cred.encSecret.readUInt16BE(0);
  const ephX = cred.encSecret.subarray(2, 2 + ephXLen);
  const ephYLen = cred.encSecret.readUInt16BE(2 + ephXLen);
  const ephY = cred.encSecret.subarray(4 + ephXLen, 4 + ephXLen + ephYLen);

  const ephPtRaw = Buffer.concat([Buffer.from([4]), ephX, ephY]);
  const z = ecdh.computeSecret(ephPtRaw); // ECDH with EK private key
  const recoveredSeed = kdfe("sha384", z, "IDENTITY", ephX, ekX, 48 * 8);

  const recoveredSymKey = kdfa("sha384", recoveredSeed, "STORAGE", akName, Buffer.alloc(0), 256);
  const recoveredHmacKey = kdfa("sha384", recoveredSeed, "INTEGRITY", Buffer.alloc(0), Buffer.alloc(0), 48 * 8);

  // Verify integrity
  const integrityLen = cred.idObject.readUInt16BE(0);
  const integrity = cred.idObject.subarray(2, 2 + integrityLen);
  const encIdentity = cred.idObject.subarray(2 + integrityLen);

  const expectedIntegrity = crypto
    .createHmac("sha384", recoveredHmacKey)
    .update(Buffer.concat([encIdentity, akName]))
    .digest();
  assert.deepEqual(integrity, expectedIntegrity, "HMAC-SHA-384 integrity must match");

  // Decrypt encIdentity using AES-256-CFB
  const decipher = crypto.createDecipheriv("aes-256-cfb", recoveredSymKey, Buffer.alloc(16));
  const decIdentity = Buffer.concat([decipher.update(encIdentity), decipher.final()]);
  const credLen = decIdentity.readUInt16BE(0);
  const recoveredSecret = decIdentity.subarray(2, 2 + credLen);

  assert.deepEqual(recoveredSecret, secret, "Recovered secret must equal original secret");
});

test("WP-B: readEkCert DER trim handles 0xFF padding", () => {
  // Take real cert DER and append 200 x 0xFF padding bytes
  const padding = Buffer.alloc(200, 0xff);
  const padded = Buffer.concat([p384CertDer, padding]);

  const trimmed = trimDer(padded);
  assert.equal(trimmed.length, p384CertDer.length, "trimDer must strip all trailing padding");
  assert.deepEqual(trimmed, p384CertDer, "trimDer must return exact DER bytes");
});

test("WP-B: TPM_SRK_HANDLE validation", () => {
  assert.equal(parseSrkHandle(0x81000101), 0x81000101);
  assert.equal(parseSrkHandle("0x81000101"), 0x81000101);
  assert.equal(parseSrkHandle("0x817FFFFF"), 0x817fffff);
  assert.equal(parseSrkHandle(0x81000000), 0x81000000);

  // Out of range handles must throw
  assert.throws(() => parseSrkHandle(0x01000000), /persistent range 0x81000000-0x817FFFFF/);
  assert.throws(() => parseSrkHandle("0x01000000"), /persistent range 0x81000000-0x817FFFFF/);
  assert.throws(() => parseSrkHandle(0x82000000), /persistent range 0x81000000-0x817FFFFF/);
  assert.throws(() => parseSrkHandle("not_a_handle"), /persistent range/);
});
