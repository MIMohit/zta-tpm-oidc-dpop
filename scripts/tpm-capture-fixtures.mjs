#!/usr/bin/env node
/**
 * @file tpm-capture-fixtures.mjs
 * Captures real TPM 2.0 evidence fixtures from the IBM tpm_server for static unit tests.
 * Outputs are committed to tests/fixtures/tpm2/*.json.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import tss from "tss.js";
import { parsePublic, publicKeyOf, nameOfTpmt, qualifiedName, ownerQn, isStandardEk } from "../lib/tpm2/index.js";
import { makeCredential, makeCredentialTpm2 } from "../lib/tpm2/credential.js";
import { parseAttest } from "../lib/sim-tpm/attest.js";

const {
  Tpm,
  TPM_HANDLE,
  TPM_ALG_ID,
  TPM_RH,
  TPM_SE,
  TPM_ECC_CURVE,
  TPMA_OBJECT,
  TPMT_PUBLIC,
  TPMS_RSA_PARMS,
  TPMS_ECC_PARMS,
  TPMT_SYM_DEF_OBJECT,
  TPMT_SYM_DEF,
  TPMS_NULL_ASYM_SCHEME,
  TPMS_SIG_SCHEME_ECDSA,
  TPMS_NULL_SIG_SCHEME,
  TPMS_NULL_KDF_SCHEME,
  TPM2B_PUBLIC_KEY_RSA,
  TPMS_ECC_POINT,
  TPMS_SENSITIVE_CREATE,
  TPMS_PCR_SELECTION,
  TPMS_ID_OBJECT,
  TPMT_HA,
  Session,
} = tss;

const HOST = process.env.TPM_TCP_HOST || "127.0.0.1";
const PORT = +(process.env.TPM_TCP_PORT || 2321);

const hex = (b) => Buffer.from(b).toString("hex");
const b64u = (b) => Buffer.from(b).toString("base64url");
const p1363 = (sig) =>
  Buffer.concat([
    Buffer.from(Buffer.from(sig.signatureR).toString("hex").padStart(64, "0"), "hex"),
    Buffer.from(Buffer.from(sig.signatureS).toString("hex").padStart(64, "0"), "hex"),
  ]);

// Standard templates
const EK_POLICY = Buffer.from("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa", "hex");
const EK_ATTRS =
  TPMA_OBJECT.fixedTPM |
  TPMA_OBJECT.fixedParent |
  TPMA_OBJECT.sensitiveDataOrigin |
  TPMA_OBJECT.adminWithPolicy |
  TPMA_OBJECT.restricted |
  TPMA_OBJECT.decrypt; // 0x000300B2
const AES128CFB = new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 128, TPM_ALG_ID.CFB);

const ekRsaTemplate = new TPMT_PUBLIC(
  TPM_ALG_ID.SHA256,
  EK_ATTRS,
  EK_POLICY,
  new TPMS_RSA_PARMS(AES128CFB, new TPMS_NULL_ASYM_SCHEME(), 2048, 0),
  new TPM2B_PUBLIC_KEY_RSA(Buffer.alloc(256))
);

const ekEccTemplate = new TPMT_PUBLIC(
  TPM_ALG_ID.SHA256,
  EK_ATTRS,
  EK_POLICY,
  new TPMS_ECC_PARMS(AES128CFB, new TPMS_NULL_ASYM_SCHEME(), TPM_ECC_CURVE.NIST_P256, new TPMS_NULL_KDF_SCHEME()),
  new TPMS_ECC_POINT(Buffer.alloc(32), Buffer.alloc(32))
);

const SRK_ATTRS =
  TPMA_OBJECT.fixedTPM |
  TPMA_OBJECT.fixedParent |
  TPMA_OBJECT.sensitiveDataOrigin |
  TPMA_OBJECT.userWithAuth |
  TPMA_OBJECT.noDA |
  TPMA_OBJECT.restricted |
  TPMA_OBJECT.decrypt;

const srkTemplate = new TPMT_PUBLIC(
  TPM_ALG_ID.SHA256,
  SRK_ATTRS,
  Buffer.alloc(0),
  new TPMS_ECC_PARMS(AES128CFB, new TPMS_NULL_ASYM_SCHEME(), TPM_ECC_CURVE.NIST_P256, new TPMS_NULL_KDF_SCHEME()),
  new TPMS_ECC_POINT(Buffer.alloc(0), Buffer.alloc(0))
);

const NULL_SYM = new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.NULL, 0, TPM_ALG_ID.NULL);

const AK_ATTRS =
  TPMA_OBJECT.fixedTPM |
  TPMA_OBJECT.fixedParent |
  TPMA_OBJECT.sensitiveDataOrigin |
  TPMA_OBJECT.userWithAuth |
  TPMA_OBJECT.restricted |
  TPMA_OBJECT.sign;

const akTemplate = new TPMT_PUBLIC(
  TPM_ALG_ID.SHA256,
  AK_ATTRS,
  Buffer.alloc(0),
  new TPMS_ECC_PARMS(NULL_SYM, new TPMS_SIG_SCHEME_ECDSA(TPM_ALG_ID.SHA256), TPM_ECC_CURVE.NIST_P256, new TPMS_NULL_KDF_SCHEME()),
  new TPMS_ECC_POINT(Buffer.alloc(0), Buffer.alloc(0))
);

const KB_ATTRS =
  TPMA_OBJECT.fixedTPM |
  TPMA_OBJECT.fixedParent |
  TPMA_OBJECT.sensitiveDataOrigin |
  TPMA_OBJECT.userWithAuth |
  TPMA_OBJECT.sign;

const kbTemplate = new TPMT_PUBLIC(
  TPM_ALG_ID.SHA256,
  KB_ATTRS,
  Buffer.alloc(0),
  new TPMS_ECC_PARMS(NULL_SYM, new TPMS_SIG_SCHEME_ECDSA(TPM_ALG_ID.SHA256), TPM_ECC_CURVE.NIST_P256, new TPMS_NULL_KDF_SCHEME()),
  new TPMS_ECC_POINT(Buffer.alloc(0), Buffer.alloc(0))
);

const PCR0_7 = [new TPMS_PCR_SELECTION(TPM_ALG_ID.SHA256, Buffer.from([0xff, 0x00, 0x00]))];

async function capture() {
  console.log(`[capture] Connecting to TPM on ${HOST}:${PORT}...`);
  const tpm = new Tpm(true, HOST, PORT);
  const call = (fn, ...args) =>
    new Promise((resolve, reject) => {
      tpm[fn](...args, (err, res) => (err ? reject(Object.assign(new Error(`${fn}: ${err.message || err}`), { rc: tpm.lastResponseCode })) : resolve(res)));
    });

  await new Promise((resolve, reject) => {
    tpm.connect((err) => (err ? reject(err) : resolve()));
  });

  // Raw response interceptor to bypass tss.js uint64 bug (Gotcha G2)
  let lastResp = null;
  const dev = tpm.device;
  const origDispatch = dev.dispatchCommand.bind(dev);
  dev.dispatchCommand = (cmd, cb) =>
    origDispatch(cmd, (err, resp) => {
      lastResp = resp ? Buffer.from(resp) : null;
      cb(err, resp);
    });

  const rawAttest = () => {
    const n = lastResp.readUInt16BE(14);
    return lastResp.subarray(16, 16 + n);
  };

  const flushHandles = async (handleType) => {
    const cap = await call("GetCapability", tss.TPM_CAP.HANDLES, handleType, 32);
    const handles = cap?.capabilityData?.handle || [];
    for (const h of handles) {
      await call("FlushContext", h);
    }
  };

  await flushHandles(0x80000000);
  await flushHandles(0x02000000);
  await flushHandles(0x03000000);

  const outDir = path.resolve(import.meta.dirname, "../tests/fixtures/tpm2");
  fs.mkdirSync(outDir, { recursive: true });

  // 1. RSA EK
  console.log("[capture] Creating RSA-2048 EK...");
  const ekRsa = await call("CreatePrimary", new TPM_HANDLE(TPM_RH.ENDORSEMENT), new TPMS_SENSITIVE_CREATE(), ekRsaTemplate, Buffer.alloc(0), []);
  const ekRsaPubBytes = ekRsa.outPublic.toBytes();
  const ekRsaName = nameOfTpmt(ekRsaPubBytes);
  const ekRsaParsed = parsePublic(ekRsaPubBytes);
  const ekRsaFixture = {
    tpmtPublic: b64u(ekRsaPubBytes),
    rawHex: hex(ekRsaPubBytes),
    nameHex: hex(ekRsaName),
    tpmReportedNameHex: hex(ekRsa.name),
    type: "rsa",
    keyBits: ekRsaParsed.keyBits,
    exponent: ekRsaParsed.exponent,
    n: b64u(ekRsaParsed.n),
    objectAttributes: ekRsaParsed.objectAttributes,
    isStandardEk: isStandardEk(ekRsaPubBytes),
  };
  fs.writeFileSync(path.join(outDir, "ek-rsa.json"), JSON.stringify(ekRsaFixture, null, 2));
  await call("FlushContext", ekRsa.handle);

  // 2. ECC EK
  console.log("[capture] Creating ECC-P256 EK...");
  const ekEcc = await call("CreatePrimary", new TPM_HANDLE(TPM_RH.ENDORSEMENT), new TPMS_SENSITIVE_CREATE(), ekEccTemplate, Buffer.alloc(0), []);
  const ekEccPubBytes = ekEcc.outPublic.toBytes();
  const ekEccName = nameOfTpmt(ekEccPubBytes);
  const ekEccParsed = parsePublic(ekEccPubBytes);
  const ekEccFixture = {
    tpmtPublic: b64u(ekEccPubBytes),
    rawHex: hex(ekEccPubBytes),
    nameHex: hex(ekEccName),
    tpmReportedNameHex: hex(ekEcc.name),
    type: "ecc",
    curveID: ekEccParsed.curveID,
    x: b64u(ekEccParsed.x),
    y: b64u(ekEccParsed.y),
    objectAttributes: ekEccParsed.objectAttributes,
    isStandardEk: isStandardEk(ekEccPubBytes),
  };
  fs.writeFileSync(path.join(outDir, "ek-ecc.json"), JSON.stringify(ekEccFixture, null, 2));
  await call("FlushContext", ekEcc.handle);

  // 3. SRK
  console.log("[capture] Creating SRK...");
  const srk = await call("CreatePrimary", new TPM_HANDLE(TPM_RH.OWNER), new TPMS_SENSITIVE_CREATE(), srkTemplate, Buffer.alloc(0), []);
  const srkPubBytes = srk.outPublic.toBytes();
  const srkName = nameOfTpmt(srkPubBytes);
  const srkQn = ownerQn(srkName);
  const srkFixture = {
    tpmtPublic: b64u(srkPubBytes),
    rawHex: hex(srkPubBytes),
    nameHex: hex(srkName),
    qnHex: hex(srkQn),
    type: "ecc",
  };
  fs.writeFileSync(path.join(outDir, "srk.json"), JSON.stringify(srkFixture, null, 2));

  // 4. AK
  console.log("[capture] Creating AK...");
  const akCreate = await call("Create", srk.handle, new TPMS_SENSITIVE_CREATE(), akTemplate, Buffer.alloc(0), []);
  const akLoad = await call("Load", srk.handle, akCreate.outPrivate, akCreate.outPublic);
  const akPubBytes = akCreate.outPublic.toBytes();
  const akName = nameOfTpmt(akPubBytes);
  const akQn = qualifiedName(srkQn, akName);
  const akParsed = parsePublic(akPubBytes);
  const akFixture = {
    tpmtPublic: b64u(akPubBytes),
    rawHex: hex(akPubBytes),
    privateBlob: b64u(akCreate.outPrivate.toBytes()),
    nameHex: hex(akName),
    tpmReportedNameHex: hex(akCreate.outPublic.getName()),
    qnHex: hex(akQn),
    objectAttributes: akParsed.objectAttributes,
    x: b64u(akParsed.x),
    y: b64u(akParsed.y),
  };
  fs.writeFileSync(path.join(outDir, "ak.json"), JSON.stringify(akFixture, null, 2));

  // 5. K_B
  console.log("[capture] Creating K_B...");
  const kbCreate = await call("Create", srk.handle, new TPMS_SENSITIVE_CREATE(), kbTemplate, Buffer.alloc(0), []);
  const kbLoad = await call("Load", srk.handle, kbCreate.outPrivate, kbCreate.outPublic);
  const kbPubBytes = kbCreate.outPublic.toBytes();
  const kbName = nameOfTpmt(kbPubBytes);
  const kbQn = qualifiedName(srkQn, kbName);
  const kbParsed = parsePublic(kbPubBytes);
  const kbFixture = {
    tpmtPublic: b64u(kbPubBytes),
    rawHex: hex(kbPubBytes),
    privateBlob: b64u(kbCreate.outPrivate.toBytes()),
    nameHex: hex(kbName),
    tpmReportedNameHex: hex(kbCreate.outPublic.getName()),
    qnHex: hex(kbQn),
    objectAttributes: kbParsed.objectAttributes,
    x: b64u(kbParsed.x),
    y: b64u(kbParsed.y),
  };
  fs.writeFileSync(path.join(outDir, "kb.json"), JSON.stringify(kbFixture, null, 2));

  // Flush SRK to free a transient slot (G5)
  await call("FlushContext", srk.handle);

  // Helper for EK Policy Secret session
  const startEkPolicy = async () => {
    const s = await call("StartAuthSession", null, null, crypto.randomBytes(32), Buffer.alloc(0), TPM_SE.POLICY, new TPMT_SYM_DEF(TPM_ALG_ID.NULL, 0, TPM_ALG_ID.NULL), TPM_ALG_ID.SHA256);
    await call("PolicySecret", new TPM_HANDLE(TPM_RH.ENDORSEMENT), s.handle, Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0), 0);
    return s.handle;
  };

  // 6. MakeCredential / ActivateCredential round trips
  console.log("[capture] Testing MakeCredential / ActivateCredential with RSA EK...");
  const ekRsaLive = await call("CreatePrimary", new TPM_HANDLE(TPM_RH.ENDORSEMENT), new TPMS_SENSITIVE_CREATE(), ekRsaTemplate, Buffer.alloc(0), []);
  const rsaSecret = crypto.randomBytes(32);
  const rsaMc = makeCredential(parsePublic(ekRsaPubBytes), akName, rsaSecret);
  const rsaPol = await startEkPolicy();
  tpm.withSessions(Session.Pw(), new Session(rsaPol));
  const rsaActivated = await call("ActivateCredential", akLoad, ekRsaLive.handle, new TPMS_ID_OBJECT(rsaMc.integrity, rsaMc.encIdentity), rsaMc.encSecret);
  if (!Buffer.from(rsaActivated).equals(rsaSecret)) {
    throw new Error("RSA ActivateCredential secret mismatch!");
  }
  const rsaActFixture = {
    ekType: "rsa",
    akNameHex: hex(akName),
    secretHex: hex(rsaSecret),
    credentialBlob: b64u(rsaMc.idObject),
    encSecret: b64u(rsaMc.encSecret),
    activatedSecretHex: hex(rsaActivated),
    verified: true,
  };
  fs.writeFileSync(path.join(outDir, "activate-rsa.json"), JSON.stringify(rsaActFixture, null, 2));
  await call("FlushContext", ekRsaLive.handle);

  console.log("[capture] Testing MakeCredential / ActivateCredential with ECC EK...");
  const ekEccLive = await call("CreatePrimary", new TPM_HANDLE(TPM_RH.ENDORSEMENT), new TPMS_SENSITIVE_CREATE(), ekEccTemplate, Buffer.alloc(0), []);
  const eccSecret = crypto.randomBytes(32);
  const eccMc = makeCredential(parsePublic(ekEccPubBytes), akName, eccSecret);
  const eccPol = await startEkPolicy();
  tpm.withSessions(Session.Pw(), new Session(eccPol));
  const eccActivated = await call("ActivateCredential", akLoad, ekEccLive.handle, new TPMS_ID_OBJECT(eccMc.integrity, eccMc.encIdentity), eccMc.encSecret);
  if (!Buffer.from(eccActivated).equals(eccSecret)) {
    throw new Error("ECC ActivateCredential secret mismatch!");
  }
  const eccActFixture = {
    ekType: "ecc",
    akNameHex: hex(akName),
    secretHex: hex(eccSecret),
    credentialBlob: b64u(eccMc.idObject),
    encSecret: b64u(eccMc.encSecret),
    activatedSecretHex: hex(eccActivated),
    verified: true,
  };
  fs.writeFileSync(path.join(outDir, "activate-ecc.json"), JSON.stringify(eccActFixture, null, 2));
  await call("FlushContext", ekEccLive.handle);

  // 7. Quote
  console.log("[capture] Quoting with AK...");
  const meas = crypto.createHash("sha256").update("measured-boot-v1").digest();
  await call("PCR_Extend", TPM_HANDLE.pcr(4), [new TPMT_HA(TPM_ALG_ID.SHA256, meas)]);
  const pr = await call("PCR_Read", PCR0_7);
  const pcrs = pr.pcrValues.map((d) => Buffer.from(d.buffer));
  const pcrDigest = crypto.createHash("sha256").update(Buffer.concat(pcrs)).digest();
  const quoteNonce = crypto.randomBytes(32);
  const q = await call("Quote", akLoad, quoteNonce, new TPMS_NULL_SIG_SCHEME(), PCR0_7);
  const quoteAttestBytes = rawAttest();
  const quoteSig = p1363(q.signature);

  // Verify quote against AK public key
  const akKey = publicKeyOf(parsePublic(akPubBytes));
  const qVerified = crypto.verify("sha256", quoteAttestBytes, { key: akKey, dsaEncoding: "ieee-p1363" }, quoteSig);
  const parsedQuote = parseAttest(quoteAttestBytes);
  if (!qVerified) throw new Error("Quote signature verification failed!");
  if (!parsedQuote.qualifiedSigner.equals(akQn)) throw new Error("Quote qualifiedSigner != akQn!");

  const quoteFixture = {
    nonceHex: hex(quoteNonce),
    attestB64u: b64u(quoteAttestBytes),
    attestRawHex: hex(quoteAttestBytes),
    sigB64u: b64u(quoteSig),
    sigRawHex: hex(quoteSig),
    pcrsHex: pcrs.map((p) => hex(p)),
    pcrDigestHex: hex(pcrDigest),
    qualifiedSignerHex: hex(parsedQuote.qualifiedSigner),
    clockInfo: {
      safe: parsedQuote.clockInfo.safe,
      resetCount: parsedQuote.clockInfo.resetCount,
      restartCount: parsedQuote.clockInfo.restartCount,
    },
    firmwareVersionHex: parsedQuote.firmwareVersion.toString(16),
  };
  fs.writeFileSync(path.join(outDir, "quote.json"), JSON.stringify(quoteFixture, null, 2));

  // 8. Certify
  console.log("[capture] Certifying K_B with AK...");
  const certifyNonce = crypto.randomBytes(32);
  const cert = await call("Certify", kbLoad, akLoad, certifyNonce, new TPMS_NULL_SIG_SCHEME());
  const certifyAttestBytes = rawAttest();
  const certifySig = p1363(cert.signature);
  const cVerified = crypto.verify("sha256", certifyAttestBytes, { key: akKey, dsaEncoding: "ieee-p1363" }, certifySig);
  const parsedCertify = parseAttest(certifyAttestBytes);
  if (!cVerified) throw new Error("Certify signature verification failed!");
  if (!parsedCertify.attested.name.equals(kbName)) throw new Error("Certify attested name != kbName!");
  if (!parsedCertify.attested.qualifiedName.equals(kbQn)) throw new Error("Certify attested qualifiedName != kbQn!");

  const certifyFixture = {
    nonceHex: hex(certifyNonce),
    attestB64u: b64u(certifyAttestBytes),
    attestRawHex: hex(certifyAttestBytes),
    sigB64u: b64u(certifySig),
    sigRawHex: hex(certifySig),
    attestedNameHex: hex(parsedCertify.attested.name),
    attestedQualifiedNameHex: hex(parsedCertify.attested.qualifiedName),
    qualifiedSignerHex: hex(parsedCertify.qualifiedSigner),
  };
  fs.writeFileSync(path.join(outDir, "certify.json"), JSON.stringify(certifyFixture, null, 2));

  // Clean up
  await call("FlushContext", akLoad);
  await call("FlushContext", kbLoad);
  tpm.close();
  console.log(`[capture] Successfully wrote all fixtures to ${outDir}`);
}

capture().catch((err) => {
  console.error("[capture] Error:", err);
  process.exit(1);
});
