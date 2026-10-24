/**
 * @file verifier-tpm2.test.mjs
 * Pure-software unit tests for WP-T3 verifier upgrades with real TPM 2.0 evidence.
 * Covers X.509 EK verification, dev CA, Qualified Names, golden PCRs, and format dispatch.
 * Always-on suite (runs without real TPM hardware, using committed fixtures).
 */

import "reflect-metadata";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import assert from "node:assert/strict";
import { describe, it, before, after } from "node:test";
import * as x509 from "@peculiar/x509";

import { createStore } from "../lib/store.js";
import { addToInventory, getInventory } from "../lib/verifier/inventory.js";
import { startEnrol, finishEnrol, verifyQuote, verifyCertify } from "../lib/verifier/enrol.js";
import { requestAppraiseNonce, appraiseDevice } from "../lib/verifier/appraise.js";
import { verifyGoldenPcr, loadGoldenPcrs } from "../lib/verifier/reference-values.js";
import { verifyX509EkCert, parseTcgSan } from "../lib/verifier/ek-cert-x509.js";
import {
  resolvePublic,
  expectedQn,
  nameOfAny,
  makeCredentialAny,
  verifyAkAttributes,
  verifyKbAttributes,
} from "../lib/verifier/evidence.js";
import { parsePublic, publicKeyOf, publicAreaFromTpmt, nameOfTpmt } from "../lib/tpm2/index.js";
import { devIdOf, thumbprintOf } from "../lib/sim-tpm/public-area.js";
import { loadOrCreateSigningKey, publicJwks } from "../lib/keys.js";
import { verifyAttestationResult } from "../lib/verifier/ar.js";

x509.cryptoProvider.set(crypto.webcrypto);

const FIXTURES_DIR = path.resolve(import.meta.dirname, "fixtures/tpm2");
const loadFixture = (name) => JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, name), "utf8"));

async function createDevCa(name = "CN=ZTA Dev TPM Manufacturer Root CA, O=ZTA Lab") {
  const caAlg = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
  const caKeys = await crypto.webcrypto.subtle.generateKey(caAlg, true, ["sign", "verify"]);
  const caCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name,
    keys: caKeys,
    signingAlgorithm: caAlg,
    notBefore: new Date(Date.now() - 60000),
    notAfter: new Date(Date.now() + 10 * 365 * 864e5),
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });
  return { caKeys, caCert, caAlg };
}

async function issueDevEkCert(ca, ekSpkiDer, options = {}) {
  const ekCert = await x509.X509CertificateGenerator.create({
    serialNumber: crypto.randomBytes(8).toString("hex"),
    subject: "",
    issuer: ca.caCert.subject,
    publicKey: new x509.PublicKey(ekSpkiDer),
    signingKey: ca.caKeys.privateKey,
    signingAlgorithm: ca.caAlg,
    notBefore: options.notBefore || new Date(Date.now() - 60000),
    notAfter: options.notAfter || new Date(Date.now() + 10 * 365 * 864e5),
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyEncipherment, true),
      new x509.ExtendedKeyUsageExtension(["2.23.133.8.1"]),
      new x509.SubjectAlternativeNameExtension(
        [{ type: "dn", value: "2.23.133.2.1=id:49424D20+2.23.133.2.2=SW TPM+2.23.133.2.3=id:00020000" }],
        true
      ),
    ],
  });
  return Buffer.from(ekCert.rawData).toString("base64");
}

describe("WP-T3: Verifier Upgrades for Real Evidence", () => {
  const ekRsa = loadFixture("ek-rsa.json");
  const ekEcc = loadFixture("ek-ecc.json");
  const srk = loadFixture("srk.json");
  const ak = loadFixture("ak.json");
  const kb = loadFixture("kb.json");
  const quote = loadFixture("quote.json");
  const certify = loadFixture("certify.json");

  let tmpRootsDir;
  let devCa;
  let evilCa;
  let rsaEkCertB64;
  let eccEkCertB64;
  let verifierKey;

  before(async () => {
    tmpRootsDir = fs.mkdtempSync(path.join(os.tmpdir(), "ek-roots-test-"));
    devCa = await createDevCa();
    evilCa = await createDevCa("CN=Evil Root CA, O=Attacker");

    // Write trusted root PEM to tmpRootsDir
    fs.writeFileSync(path.join(tmpRootsDir, "dev-root.pem"), devCa.caCert.toString("pem"));

    const rsaParsed = parsePublic(Buffer.from(ekRsa.rawHex, "hex"));
    const rsaSpki = publicKeyOf(rsaParsed).export({ type: "spki", format: "der" });
    rsaEkCertB64 = await issueDevEkCert(devCa, rsaSpki);

    const eccParsed = parsePublic(Buffer.from(ekEcc.rawHex, "hex"));
    const eccSpki = publicKeyOf(eccParsed).export({ type: "spki", format: "der" });
    eccEkCertB64 = await issueDevEkCert(devCa, eccSpki);

    verifierKey = await loadOrCreateSigningKey("verifier", { store: "memory" });
  });

  after(() => {
    if (tmpRootsDir && fs.existsSync(tmpRootsDir)) {
      fs.rmSync(tmpRootsDir, { recursive: true, force: true });
    }
  });

  describe("Enrolment with Real TPM 2.0 Evidence", () => {
    it("enrol start/finish with fixture evidence and a dev-CA X.509 cert generated in the test -> active registry", async () => {
      const store = createStore("verifier", { store: "memory" });
      const ekPa = publicAreaFromTpmt(ekRsa.rawHex);
      const akPa = publicAreaFromTpmt(ak.rawHex);
      const kbPa = publicAreaFromTpmt(kb.rawHex);
      const srkPa = publicAreaFromTpmt(srk.rawHex);

      const devId = await devIdOf(ekPa);
      const code = "real-tpm-enrol-code-1";
      await addToInventory(store, {
        devId,
        user: "alice",
        code,
        goldenPcrDigests: [quote.pcrDigestHex],
      });

      const secret = crypto.randomBytes(32);
      const startRes = await startEnrol({
        code,
        ekCert: rsaEkCertB64,
        akPublic: akPa,
        kbPublic: kbPa,
        ekPublic: ekPa,
        srkPublic: srkPa,
        store,
        ekRootsDir: tmpRootsDir,
        secret,
        nonce: Buffer.from(quote.nonceHex, "hex"),
        certifyNonce: Buffer.from(certify.nonceHex, "hex"),
      });

      assert.equal(startRes.ok, true);
      assert.ok(startRes.sessionId);
      assert.ok(startRes.blob);
      assert.equal(startRes.blob.format, "tpm2");
      assert.ok(startRes.blob.credentialBlob);
      assert.ok(startRes.blob.secret);

      // Finish enrolment with real quote and certify fixtures (golden PCR mode: eventLog = null)
      const finishRes = await finishEnrol({
        sessionId: startRes.sessionId,
        secret,
        quote: { attest: quote.attestRawHex, sig: quote.sigRawHex },
        certify: { attest: certify.attestRawHex, sig: certify.sigRawHex },
        eventLog: null,
        store,
      });

      assert.equal(finishRes.ok, true);
      assert.equal(finishRes.devId, devId);
      assert.ok(finishRes.jkt);

      // Verify active device in registry
      const reg = await store.get(`registry/${devId}`);
      assert.ok(reg);
      assert.equal(reg.status, "active");
      assert.equal(reg.akQn, ak.qnHex);
      assert.equal(reg.ekTrust, "cert");
      assert.equal(reg.user, "alice");
    });

    it("wrong root -> ek_cert_invalid", async () => {
      const store = createStore("verifier", { store: "memory" });
      const ekPa = publicAreaFromTpmt(ekRsa.rawHex);
      const akPa = publicAreaFromTpmt(ak.rawHex);
      const kbPa = publicAreaFromTpmt(kb.rawHex);

      const rsaParsed = parsePublic(Buffer.from(ekRsa.rawHex, "hex"));
      const rsaSpki = publicKeyOf(rsaParsed).export({ type: "spki", format: "der" });
      const evilCertB64 = await issueDevEkCert(evilCa, rsaSpki);

      const devId = await devIdOf(ekPa);
      const code = "wrong-root-code";
      await addToInventory(store, { devId, user: "alice", code });

      const startRes = await startEnrol({
        code,
        ekCert: evilCertB64,
        akPublic: akPa,
        kbPublic: kbPa,
        ekPublic: ekPa,
        store,
        ekRootsDir: tmpRootsDir, // Only trusts devCa, not evilCa
      });

      assert.equal(startRes.ok, false);
      assert.equal(startRes.status, 403);
      assert.equal(startRes.error, "ek_cert_invalid");
    });

    it("SPKI != ekPublic -> reject", async () => {
      const store = createStore("verifier", { store: "memory" });
      const ekPaRsa = publicAreaFromTpmt(ekRsa.rawHex);
      const ekPaEcc = publicAreaFromTpmt(ekEcc.rawHex);
      const akPa = publicAreaFromTpmt(ak.rawHex);
      const kbPa = publicAreaFromTpmt(kb.rawHex);

      const devId = await devIdOf(ekPaRsa);
      const code = "spki-mismatch-code";
      await addToInventory(store, { devId, user: "alice", code });

      // Provide RSA cert, but claim ECC ekPublic
      const startRes = await startEnrol({
        code,
        ekCert: rsaEkCertB64,
        akPublic: akPa,
        kbPublic: kbPa,
        ekPublic: ekPaEcc, // Mismatched key!
        store,
        ekRootsDir: tmpRootsDir,
      });

      assert.equal(startRes.ok, false);
      assert.equal(startRes.status, 403);
      assert.equal(startRes.error, "ek_cert_invalid");
      assert.match(startRes.message, /Certificate public key does not match EK public area/);
    });

    it("non-standard EK template -> reject", async () => {
      const store = createStore("verifier", { store: "memory" });
      // AK as EK has wrong attributes (missing restricted/decrypt, wrong policy)
      const badEkPa = publicAreaFromTpmt(ak.rawHex);
      const akPa = publicAreaFromTpmt(ak.rawHex);
      const kbPa = publicAreaFromTpmt(kb.rawHex);

      const devId = await devIdOf(badEkPa);
      const code = "non-std-ek-code";
      await addToInventory(store, { devId, user: "alice", code });

      const startRes = await startEnrol({
        code,
        ekCert: rsaEkCertB64,
        akPublic: akPa,
        kbPublic: kbPa,
        ekPublic: badEkPa,
        store,
        ekRootsDir: tmpRootsDir,
      });

      assert.equal(startRes.ok, false);
      assert.equal(startRes.status, 403);
      assert.equal(startRes.error, "ek_template_invalid");
    });

    it("JSON/raw mismatch -> reject", async () => {
      const store = createStore("verifier", { store: "memory" });
      const ekPa = publicAreaFromTpmt(ekRsa.rawHex);
      const akPa = publicAreaFromTpmt(ak.rawHex);
      const kbPa = publicAreaFromTpmt(kb.rawHex);

      // Tamper with AK JSON attributes (claims 0x00040072 unrestricted instead of 0x00050072)
      const tamperedAk = { ...akPa, objectAttributes: 0x00040072 };

      const devId = await devIdOf(ekPa);
      const code = "json-raw-mismatch-code";
      await addToInventory(store, { devId, user: "alice", code });

      const startRes = await startEnrol({
        code,
        ekCert: rsaEkCertB64,
        akPublic: tamperedAk,
        kbPublic: kbPa,
        ekPublic: ekPa,
        store,
        ekRootsDir: tmpRootsDir,
      });

      assert.equal(startRes.ok, false);
      assert.equal(startRes.status, 403);
      assert.equal(startRes.error, "ak_attributes_invalid");
      assert.match(startRes.message, /publicArea objectAttributes mismatch/);
    });

    it("qualifiedSigner != QN -> quote_invalid", async () => {
      const akPa = publicAreaFromTpmt(ak.rawHex);

      // 1. With correct QN, quote is valid
      const validRes = verifyQuote({
        quote: { attest: quote.attestRawHex, sig: quote.sigRawHex },
        akPublic: akPa,
        expectedNonce: quote.nonceHex,
        eventLog: null,
        devRecord: { goldenPcrDigests: [quote.pcrDigestHex] },
        akQn: quote.qualifiedSignerHex,
      });
      assert.equal(validRes.valid, true);

      // 2. With wrong QN, quote fails qualifiedSigner check
      const wrongQn = "000b" + "99".repeat(32);
      const invalidRes = verifyQuote({
        quote: { attest: quote.attestRawHex, sig: quote.sigRawHex },
        akPublic: akPa,
        expectedNonce: quote.nonceHex,
        eventLog: null,
        devRecord: { goldenPcrDigests: [quote.pcrDigestHex] },
        akQn: wrongQn,
      });
      assert.equal(invalidRes.valid, false);
      assert.match(invalidRes.error, /qualifiedSigner does not match/);
    });
  });

  describe("Golden PCR Verification", () => {
    const validDigest = quote.pcrDigestHex;
    const invalidDigest = "00".repeat(32);

    it("matching digest OK from inventory", () => {
      const res = verifyGoldenPcr({
        pcrDigest: validDigest,
        devRecord: { goldenPcrDigests: [validDigest] },
      });
      assert.equal(res.valid, true);
      assert.equal(res.source, "inventory");
    });

    it("other digest rejected", () => {
      const res = verifyGoldenPcr({
        pcrDigest: invalidDigest,
        devRecord: { goldenPcrDigests: [validDigest] },
      });
      assert.equal(res.valid, false);
      assert.match(res.error, /does not match inventory golden PCRs/);
    });

    it("no RV -> reject with 'no reference values'", () => {
      const res = verifyGoldenPcr({
        pcrDigest: validDigest,
        devRecord: {},
        allowTofu: false,
      });
      assert.equal(res.valid, false);
      assert.equal(res.error, "no reference values");
    });

    it("TOFU only when the flag is set", () => {
      // Flag false -> rejected
      const disabledRes = verifyGoldenPcr({
        pcrDigest: validDigest,
        devRecord: {},
        allowTofu: false,
      });
      assert.equal(disabledRes.valid, false);
      assert.equal(disabledRes.error, "no reference values");

      // Flag true -> accepted and captured
      const enabledRes = verifyGoldenPcr({
        pcrDigest: validDigest,
        devRecord: {},
        allowTofu: true,
      });
      assert.equal(enabledRes.valid, true);
      assert.equal(enabledRes.source, "tofu");
      assert.equal(enabledRes.tofuCaptured, true);
      assert.equal(enabledRes.digest, validDigest.toLowerCase());
    });
  });

  describe("EK Pinned Policy (EK_CERT_POLICY=pinned-ok)", () => {
    it("EK_CERT_POLICY=pinned-ok accepts an inventory-pinned EK without certificate", async () => {
      const store = createStore("verifier", { store: "memory" });
      const ekPa = publicAreaFromTpmt(ekRsa.rawHex);
      const akPa = publicAreaFromTpmt(ak.rawHex);
      const kbPa = publicAreaFromTpmt(kb.rawHex);
      const srkPa = publicAreaFromTpmt(srk.rawHex);

      const devId = await devIdOf(ekPa);
      const code = "pinned-ek-code";
      await addToInventory(store, {
        devId,
        user: "bob",
        code,
        ekTrust: "pinned",
        ekPublic: ekPa,
        goldenPcrDigests: [quote.pcrDigestHex],
      });

      const startRes = await startEnrol({
        code,
        ekCert: null, // No EK certificate provided
        akPublic: akPa,
        kbPublic: kbPa,
        ekPublic: ekPa,
        srkPublic: srkPa,
        store,
        cfg: { ekCertPolicy: "pinned-ok" },
      });

      assert.equal(startRes.ok, true);
      assert.ok(startRes.sessionId);
      assert.ok(startRes.blob);
      assert.equal(startRes.blob.format, "tpm2");
    });

    it("EK_CERT_POLICY=require rejects missing EK certificate even if pinned", async () => {
      const store = createStore("verifier", { store: "memory" });
      const ekPa = publicAreaFromTpmt(ekRsa.rawHex);
      const akPa = publicAreaFromTpmt(ak.rawHex);
      const kbPa = publicAreaFromTpmt(kb.rawHex);

      const devId = await devIdOf(ekPa);
      const code = "require-ek-code";
      await addToInventory(store, {
        devId,
        user: "bob",
        code,
        ekTrust: "pinned",
        ekPublic: ekPa,
      });

      const startRes = await startEnrol({
        code,
        ekCert: null,
        akPublic: akPa,
        kbPublic: kbPa,
        ekPublic: ekPa,
        store,
        cfg: { ekCertPolicy: "require" },
      });

      assert.equal(startRes.ok, false);
      assert.equal(startRes.status, 403);
      assert.equal(startRes.error, "ek_cert_invalid");
    });
  });

  describe("Appraisal with Real TPM State and Attestation Result (AR)", () => {
    it("appraiseDevice succeeds with golden PCRs and issues valid AR", async () => {
      const store = createStore("verifier", { store: "memory" });
      const ekPa = publicAreaFromTpmt(ekRsa.rawHex);
      const akPa = publicAreaFromTpmt(ak.rawHex);
      const kbPa = publicAreaFromTpmt(kb.rawHex);
      const devId = await devIdOf(ekPa);
      const jkt = await thumbprintOf(kbPa);

      // Pre-seed active registry record with real TPM attributes and akQn
      const regRecord = {
        devId,
        akPub: akPa,
        kbPub: kbPa,
        jkt,
        user: "alice",
        status: "active",
        akQn: ak.qnHex,
        goldenPcrDigests: [quote.pcrDigestHex],
        enrolledAt: Date.now(),
        last: Date.now(),
      };
      await store.set(`registry/${devId}`, regRecord);

      // Request appraisal nonce
      const nonceRecord = {
        nonceId: "appraise-nonce-id-1",
        devId,
        nonce: quote.nonceHex,
        expiresAt: Date.now() + 60000,
        used: false,
      };
      await store.set(`nonces/appraise-nonce-id-1`, nonceRecord);

      const appraiseRes = await appraiseDevice({
        devId,
        nonceId: "appraise-nonce-id-1",
        quote: { attest: quote.attestRawHex, sig: quote.sigRawHex },
        eventLog: null,
        store,
        verifierKey,
      });

      assert.equal(appraiseRes.ok, true);
      assert.ok(appraiseRes.ar);

      // Verify Attestation Result (AR) JWT
      const jwks = publicJwks(verifierKey);
      const { payload } = await verifyAttestationResult(appraiseRes.ar, jwks);
      assert.equal(payload.sub, devId);
      assert.equal(payload.jkt, jkt);
      assert.equal(payload.status, "pass");
    });
  });
});
