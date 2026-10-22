#!/usr/bin/env node
/**
 * @file scripts/tpm-provision-ek-cert.mjs
 * Dev Manufacturer CA tool to issue an X.509 EK Certificate and write it
 * into the software TPM's NV storage (0x01C00002 for RSA / 0x01C0000A for ECC)
 * and place the trusted dev root into data/ek-roots-dev/.
 *
 * Idempotent: reuses data/ek-ca-dev/ and replaces the NV index with a freshly issued cert.
 *
 * Usage:
 *   node scripts/tpm-provision-ek-cert.mjs [--type rsa|ecc|all] [--dir data/agent/alice-laptop]
 */

import "reflect-metadata"; // GOTCHA G13: @peculiar/x509 v2 (tsyringe) requires reflect polyfill first
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import * as x509 from "@peculiar/x509";
import tss from "tss.js";

import { loadConfig } from "../lib/config.js";
import { isMain } from "../lib/main.js";
import { RealTpm, readEkCertFromNv, NV_INDEX_EK_CERT_RSA, NV_INDEX_EK_CERT_ECC } from "../lib/tpm-real/index.js";
import { realTpmOptions } from "../lib/tpm-factory.js";
import { parsePublic, publicKeyOf } from "../lib/tpm2/index.js";

x509.cryptoProvider.set(crypto.webcrypto);

const {
  TPM_HANDLE,
  TPM_RH,
  TPM_ALG_ID,
  TPMA_NV,
  TPMS_NV_PUBLIC,
} = tss;

export function parseArgs(args = process.argv.slice(2)) {
  const options = {
    type: "rsa",
    dir: null,
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if ((a === "--type" || a === "-t") && i + 1 < args.length) {
      options.type = args[++i];
    } else if (a.startsWith("--type=")) {
      options.type = a.slice(7);
    } else if ((a === "--dir" || a === "-d") && i + 1 < args.length) {
      options.dir = args[++i];
    } else if (a.startsWith("--dir=")) {
      options.dir = a.slice(6);
    }
  }
  return options;
}

const DEV_CA_SUBJECT = "CN=ZTA Dev TPM Manufacturer Root CA, O=ZTA Lab";
const CA_ALG = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };

/**
 * Loads the dev manufacturer CA from caDir, creating it on first use.
 * @param {string} caDir
 * @returns {Promise<{ keys: CryptoKeyPair, certPem: string }>}
 */
export async function loadOrCreateDevCa(caDir) {
  fs.mkdirSync(caDir, { recursive: true, mode: 0o700 });
  const caKeyFile = path.join(caDir, "ca-key.json");
  const caCertFile = path.join(caDir, "ca-cert.pem");

  if (fs.existsSync(caKeyFile) && fs.existsSync(caCertFile)) {
    try {
      const jwk = JSON.parse(fs.readFileSync(caKeyFile, "utf8"));
      const privateKey = await crypto.webcrypto.subtle.importKey("jwk", jwk, CA_ALG, true, ["sign"]);
      const { d, ...pubJwk } = jwk;
      const publicKey = await crypto.webcrypto.subtle.importKey("jwk", { ...pubJwk, key_ops: ["verify"] }, CA_ALG, true, ["verify"]);
      console.log(`[prov] Loaded existing dev manufacturer CA from ${caCertFile}`);
      return { keys: { privateKey, publicKey }, certPem: fs.readFileSync(caCertFile, "utf8") };
    } catch (err) {
      console.warn(`[prov] Warning loading CA, regenerating: ${err.message}`);
    }
  }

  const keys = await crypto.webcrypto.subtle.generateKey(CA_ALG, true, ["sign", "verify"]);
  const selfSigned = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: DEV_CA_SUBJECT,
    keys,
    signingAlgorithm: CA_ALG,
    notBefore: new Date(Date.now() - 3600 * 1000),
    notAfter: new Date(Date.now() + 10 * 365 * 864e5),
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });
  const certPem = selfSigned.toString("pem");
  const privJwk = await crypto.webcrypto.subtle.exportKey("jwk", keys.privateKey);
  fs.writeFileSync(caKeyFile, JSON.stringify(privJwk, null, 2), { mode: 0o600 });
  fs.writeFileSync(caCertFile, certPem, { mode: 0o644 });
  console.log(`[prov] Generated dev manufacturer CA: ${DEV_CA_SUBJECT}`);
  return { keys, certPem };
}

/**
 * Issues an X.509 EK certificate (TCG EK Credential Profile shape) for a real EK public area.
 * @param {{ keys: CryptoKeyPair }} ca
 * @param {Record<string, any>} ekPublicArea - publicArea with tpmtPublic (from RealTpm.getEk())
 * @returns {Promise<Buffer>} DER
 */
export async function issueEkCertDer(ca, ekPublicArea) {
  const parsedEk = parsePublic(Buffer.from(ekPublicArea.tpmtPublic, "base64url"));
  const ekSpki = publicKeyOf(parsedEk).export({ type: "spki", format: "der" });
  const ekCert = await x509.X509CertificateGenerator.create({
    serialNumber: crypto.randomBytes(8).toString("hex"),
    subject: "",
    issuer: DEV_CA_SUBJECT,
    publicKey: new x509.PublicKey(ekSpki),
    signingKey: ca.keys.privateKey,
    signingAlgorithm: CA_ALG,
    notBefore: new Date(Date.now() - 3600 * 1000),
    notAfter: new Date(Date.now() + 10 * 365 * 864e5),
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyEncipherment, true),
      new x509.ExtendedKeyUsageExtension(["2.23.133.8.1"]), // tcg-kp-EKCertificate
      new x509.SubjectAlternativeNameExtension([
        { type: "dn", value: "2.23.133.2.1=id:49424D20+2.23.133.2.2=SW TPM+2.23.133.2.3=id:00020000" },
      ], true),
    ],
  });
  return Buffer.from(ekCert.rawData);
}

/**
 * Writes (or replaces) the EK certificate NV index under platform auth (software TPM only),
 * in chunks of at most 1024 bytes, and reads it back.
 * @param {import("../lib/tpm-real/backend.js").RealTpm} tpm - open RealTpm
 * @param {"rsa"|"ecc"} ekType
 * @param {Buffer} certDer
 * @returns {Promise<boolean>} true when the read-back equals certDer
 */
export async function writeEkCertToNv(tpm, ekType, certDer) {
  const nvIndex = ekType === "ecc" ? NV_INDEX_EK_CERT_ECC : NV_INDEX_EK_CERT_RSA;
  const nvHandle = new TPM_HANDLE(nvIndex);
  const platform = new TPM_HANDLE(TPM_RH.PLATFORM);

  try {
    tpm.conn.tpm.allowErrors();
    await tpm.conn.call("NV_UndefineSpace", platform, nvHandle);
  } catch {}

  const nvAttrs =
    TPMA_NV.PPWRITE |
    TPMA_NV.WRITEDEFINE |
    TPMA_NV.PPREAD |
    TPMA_NV.OWNERREAD |
    TPMA_NV.AUTHREAD |
    TPMA_NV.NO_DA |
    TPMA_NV.PLATFORMCREATE;

  await tpm.conn.call(
    "NV_DefineSpace",
    platform,
    Buffer.alloc(0),
    new TPMS_NV_PUBLIC(nvHandle, TPM_ALG_ID.SHA256, nvAttrs, Buffer.alloc(0), certDer.length)
  );
  for (let off = 0; off < certDer.length; off += 1024) {
    const chunk = certDer.subarray(off, Math.min(off + 1024, certDer.length));
    await tpm.conn.call("NV_Write", platform, nvHandle, chunk, off);
  }
  const back = await readEkCertFromNv(tpm.conn, ekType);
  return Boolean(back && back.equals(certDer));
}

/**
 * Removes the EK certificate NV index (software TPM only). Ignores "not defined".
 * @param {import("../lib/tpm-real/backend.js").RealTpm} tpm
 * @param {"rsa"|"ecc"} ekType
 */
export async function removeEkCertFromNv(tpm, ekType) {
  const nvIndex = ekType === "ecc" ? NV_INDEX_EK_CERT_ECC : NV_INDEX_EK_CERT_RSA;
  try {
    tpm.conn.tpm.allowErrors();
    await tpm.conn.call("NV_UndefineSpace", new TPM_HANDLE(TPM_RH.PLATFORM), new TPM_HANDLE(nvIndex));
  } catch {}
}

export async function provisionEkCert(options = {}, cfg = loadConfig()) {
  const dataDir = path.resolve(cfg.dataDir || cfg.ZTA_DATA_DIR || "./data");
  const caDir = path.join(dataDir, "ek-ca-dev");
  const rootsDevDir = path.join(dataDir, "ek-roots-dev");
  const targetDir = options.dir
    ? path.resolve(options.dir)
    : path.join(dataDir, "agent", "alice-laptop");

  // 1. Dev Manufacturer CA (load or create); its root goes to data/ek-roots-dev/ (trusted only when ZTA_ENV != production)
  const ca = await loadOrCreateDevCa(caDir);
  fs.mkdirSync(rootsDevDir, { recursive: true, mode: 0o755 });
  const devRootDest = path.join(rootsDevDir, "dev-root-ca.pem");
  fs.writeFileSync(devRootDest, ca.certPem, { mode: 0o644 });
  console.log(`[prov] Installed dev root certificate into ${devRootDest}`);

  // 2. Connect to the TPM
  const tpmOpts = realTpmOptions(cfg, targetDir);
  const tpm = new RealTpm(tpmOpts);
  await tpm.open();
  console.log(`[prov] Connected to TPM (${tpmOpts.device}${tpmOpts.device === "tcp" ? ` ${tpmOpts.host}:${tpmOpts.port}` : ""})`);
  if (tpmOpts.device !== "tcp") {
    console.warn("[prov] ⚠️ Writing EK certs into NV under platform auth is meant for the software TPM (TPM_DEVICE=tcp); real TPMs ship a vendor EK cert");
  }

  const results = [];
  try {
    const typesToProvision = options.type === "all" ? ["rsa", "ecc"] : [options.type || "rsa"];
    for (const ekType of typesToProvision) {
      tpm.ekType = ekType;
      const ek = await tpm.getEk();
      const nvIndex = ekType === "ecc" ? NV_INDEX_EK_CERT_ECC : NV_INDEX_EK_CERT_RSA;
      console.log(`[prov] Issuing X.509 EK Certificate for ${ekType.toUpperCase()} EK (NV index 0x${nvIndex.toString(16)})...`);

      // 3. Issue the X.509 leaf and 4. write it into TPM NV (+ file fallback in the agent's TPM state dir)
      const certDer = await issueEkCertDer(ca, ek.publicArea);
      const matched = await writeEkCertToNv(tpm, ekType, certDer);
      console.log(`[prov] ✅ Wrote ${certDer.length} bytes to NV 0x${nvIndex.toString(16)}. Verified: ${matched}`);

      fs.mkdirSync(tpmOpts.dir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(path.join(tpmOpts.dir, `ek-cert-${ekType}.der`), certDer);
      results.push({ ekType, nvIndex, bytes: certDer.length, verified: matched });
    }
  } finally {
    await tpm.close();
  }
  console.log(`[prov] ✅ Provisioning complete.`);
  return results;
}

if (isMain(import.meta.url)) {
  const opts = parseArgs();
  provisionEkCert(opts)
    .catch((err) => {
      console.error(`❌ [prov] Error:`, err.message || err);
      process.exit(1);
    });
}

export default { provisionEkCert, parseArgs, loadOrCreateDevCa, issueEkCertDer, writeEkCertToNv, removeEkCertFromNv };
