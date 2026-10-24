#!/usr/bin/env node
/**
 * @file scripts/tpm-probe.mjs
 * Comprehensive diagnostic and step-by-step capability report for any TPM device:
 *  1. Startup & Manufacturer probe
 *  2. EK RSA-2048 & ECC P-256 inspection
 *  3. EK certificate check in NV
 *  4. SRK inspection / deterministic generation
 *  5. AK and K_B creation and attribute validation
 *  6. Self-made credential activation (MakeCredential / ActivateCredential)
 *  7. Quote attestation & verification
 *  8. Certify attestation & verification
 *  9. Sign with K_B & crypto.verify check
 * 10. PCR 0..7 readout and golden PCR digest calculation
 *
 * Usage:
 *   node scripts/tpm-probe.mjs [--device auto|tcp|linux|tbs] [--host 127.0.0.1] [--port 2321]
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import tss from "tss.js";

import { loadConfig } from "../lib/config.js";
import { isMain } from "../lib/main.js";
import { RealTpm } from "../lib/tpm-real/index.js";
import { realTpmOptions } from "../lib/tpm-factory.js";
import { devIdOf } from "../lib/sim-tpm/public-area.js";
import { parseAttest } from "../lib/sim-tpm/attest.js";
import {
  nameOfTpmt,
  makeCredentialTpm2,
  publicKeyOf,
  parsePublic,
} from "../lib/tpm2/index.js";

const {
  TPM_CAP,
  TPM_PT,
  TPM_HANDLE,
  TPM_ALG_ID,
  TPMS_PCR_SELECTION,
} = tss;

export function parseArgs(args = process.argv.slice(2)) {
  const options = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--device" && i + 1 < args.length) options.device = args[++i];
    else if (a.startsWith("--device=")) options.device = a.slice(9);
    else if (a === "--host" && i + 1 < args.length) options.host = args[++i];
    else if (a.startsWith("--host=")) options.host = a.slice(7);
    else if (a === "--port" && i + 1 < args.length) options.port = Number(args[++i]);
    else if (a.startsWith("--port=")) options.port = Number(a.slice(7));
  }
  return options;
}

export async function runProbe(options = {}, cfg = loadConfig()) {
  console.log(`\n============================================================`);
  console.log(`🔍 TPM 2.0 CAPABILITY & HEALTH PROBE`);
  console.log(`============================================================\n`);

  // Throwaway state dir: the probe creates its own AK/K_B and must not overwrite an agent's keys
  const probeDir = fs.mkdtempSync(path.join(os.tmpdir(), "zta-tpm-probe-"));
  const tpmOpts = realTpmOptions(
    {
      ...cfg,
      ...(options.device ? { tpmDevice: options.device } : {}),
      ...(options.host ? { tpmTcpHost: options.host } : {}),
      ...(options.port ? { tpmTcpPort: options.port } : {}),
    },
    probeDir
  );
  const tpm = new RealTpm({ ...tpmOpts, dir: probeDir });

  try {
    await tpm.open();
  } catch (err) {
    console.error(`❌ [probe] Could not connect to TPM: ${err.message}`);
    console.error(`Device: ${tpm.deviceType}, Target: ${tpm.options.host || "127.0.0.1"}:${tpm.options.port || 2321}`);
    throw err;
  }

  try {
    // 1. Query TPM Properties
    console.log(`[1] Connection & Manufacturer:`);
    const cap = await tpm.conn.call("GetCapability", TPM_CAP.TPM_PROPERTIES, TPM_PT.MANUFACTURER, 1);
    const mfrProp = cap?.capabilityData?.tpmProperty?.[0];
    const val = mfrProp ? mfrProp.value : 0;
    const hex = val.toString(16).padStart(8, "0");
    const ascii = Buffer.from(hex, "hex").toString("ascii").replace(/[^\x20-\x7E]/g, "");
    console.log(`    Manufacturer: 0x${hex} ('${ascii.trim()}')`);

    const rnd = await tpm.conn.call("GetRandom", 8);
    console.log(`    GetRandom(8): ${Buffer.from(rnd).toString("hex")}`);

    // 2. EK Probe
    console.log(`\n[2] Endorsement Keys (EK):`);
    const detectedEkType = tpm.ekType;

    const nvCheck = async (idx) => {
      try {
        const pub = await tpm.conn.call("NV_ReadPublic", new TPM_HANDLE(idx));
        return pub?.nvPublic?.dataSize || null;
      } catch {
        return null;
      }
    };
    const rsaNv = (await nvCheck(0x01c00002)) ? "0x01C00002" : ((await nvCheck(0x01c00012)) ? "0x01C00012" : "none");
    const eccNv = (await nvCheck(0x01c0000a)) ? "0x01C0000A" : ((await nvCheck(0x01c00014)) ? "0x01C00014" : "none");
    const ecc384Nv = (await nvCheck(0x01c00016)) ? "0x01C00016" : "none";
    console.log(`    NV Cert Indices: RSA=${rsaNv}, ECC=${eccNv}, ECC384=${ecc384Nv}`);

    tpm.ekType = "rsa";
    const ekRsa = await tpm.getEk();
    const rsaDevId = await devIdOf(ekRsa.publicArea);
    const rsaName = nameOfTpmt(Buffer.from(ekRsa.publicArea.tpmtPublic, "base64url")).toString("hex");
    console.log(`    RSA-2048 EK: devId=${rsaDevId}`);
    console.log(`                 Name=${rsaName}`);
    console.log(`                 Cert in NV (${rsaNv}): ${ekRsa.cert ? `${Buffer.from(ekRsa.cert, "base64").length} B` : "absent"} (Chain length: ${ekRsa.chain?.length || 0})`);

    tpm.ekType = "ecc";
    const ekEcc = await tpm.getEk();
    const eccDevId = await devIdOf(ekEcc.publicArea);
    const eccName = nameOfTpmt(Buffer.from(ekEcc.publicArea.tpmtPublic, "base64url")).toString("hex");
    console.log(`    ECC P-256 EK: devId=${eccDevId}`);
    console.log(`                 Name=${eccName}`);
    console.log(`                 Cert in NV (${eccNv}): ${ekEcc.cert ? `${Buffer.from(ekEcc.cert, "base64").length} B` : "absent"} (Chain length: ${ekEcc.chain?.length || 0})`);

    // The P-384 EK template (H-3) needs SHA-384 as nameAlg; some TPMs (e.g. AMD fTPMs) lack SHA-384.
    tpm.ekType = "ecc384";
    let ekEcc384 = null;
    try {
      ekEcc384 = await tpm.getEk();
    } catch (err) {
      console.log(`    ECC P-384 EK: not supported by this TPM (${err.message})`);
    }
    if (ekEcc384) {
      const ecc384DevId = await devIdOf(ekEcc384.publicArea);
      const ecc384Name = nameOfTpmt(Buffer.from(ekEcc384.publicArea.tpmtPublic, "base64url")).toString("hex");
      console.log(`    ECC P-384 EK: devId=${ecc384DevId}`);
      console.log(`                 Name=${ecc384Name}`);
      console.log(`                 Cert in NV (${ecc384Nv}): ${ekEcc384.cert ? `${Buffer.from(ekEcc384.cert, "base64").length} B` : "absent"} (Chain length: ${ekEcc384.chain?.length || 0})`);
    }

    // 3. SRK Probe
    console.log(`\n[3] Storage Root Key (SRK):`);
    const srkPub = await tpm.getSrkPublic();
    const srkName = nameOfTpmt(Buffer.from(srkPub.tpmtPublic, "base64url")).toString("hex");
    console.log(`    SRK handle: 0x${tpm.srkHandle.toString(16)}, mode: ${tpm.srk.mode} (Name=${srkName})`);

    // 4. AK & K_B Creation
    console.log(`\n[4] Attestation Key (AK) & Binding Key (K_B):`);
    const ak = await tpm.createAk();
    const kb = await tpm.createKb();
    console.log(`    AK:  handle=${ak.handle} attrs=0x${ak.publicArea.objectAttributes.toString(16)} Name=${ak.name.toString("hex")}`);
    console.log(`    K_B: handle=${kb.handle} attrs=0x${kb.publicArea.objectAttributes.toString(16)} Name=${kb.name.toString("hex")}`);

    // 5. MakeCredential / ActivateCredential
    console.log(`\n[5] Credential Activation (MakeCredential & ActivateCredential):`);
    const testSecret = crypto.randomBytes(32);
    // Use the active EK
    tpm.ekType = detectedEkType;
    const activeEk = detectedEkType === "ecc384" ? ekEcc384 : (detectedEkType === "ecc" ? ekEcc : ekRsa);
    console.log(`    Active EK type: ${detectedEkType}`);
    console.log(`    Active EK cert source: ${activeEk.cert ? (detectedEkType === "ecc384" ? ecc384Nv : (detectedEkType === "ecc" ? eccNv : rsaNv)) : "none"}`);
    console.log(`    Active EK chain length: ${activeEk.chain?.length || 0}`);
    const credBlob = await makeCredentialTpm2(activeEk.publicArea, ak.name, testSecret);
    const activated = await tpm.activateCredential("ak", credBlob);
    const activatedBuf = Buffer.isBuffer(activated) ? activated : Buffer.from(activated, "hex");
    const actMatch = activatedBuf.equals(testSecret);
    console.log(`    ActivateCredential: ${actMatch ? "SUCCESS (activated secret matches)" : "FAILED"}`);

    // 6. Quote Attestation
    console.log(`\n[6] Attestation Quote:`);
    const nonce = crypto.randomBytes(32);
    const quote = await tpm.quote("ak", nonce);
    const attestBuf = Buffer.isBuffer(quote.attest) ? quote.attest : Buffer.from(quote.attest, "base64url");
    const parsedQuote = parseAttest(attestBuf);
    console.log(`    Attest length: ${attestBuf.length} B, Magic: 0x${parsedQuote.magic.toString(16)}`);
    const quotedDigest = parsedQuote.attested?.pcrDigest ?? parsedQuote.attested?.quote?.pcrDigest;
    console.log(`    PCR Digest:    ${quotedDigest ? Buffer.from(quotedDigest).toString("hex") : "n/a"}`);

    // Verify quote signature with AK public key
    const akParsed = parsePublic(Buffer.from(ak.publicArea.tpmtPublic, "base64url"));
    const akKey = publicKeyOf(akParsed);
    const sigBuf = Buffer.from(quote.sig, "base64url");
    const sigValid = crypto.verify("sha256", attestBuf, { key: akKey, dsaEncoding: "ieee-p1363" }, sigBuf);
    console.log(`    Quote Signature: ${sigValid ? "VALID" : "INVALID"}`);

    // 7. Certify
    console.log(`\n[7] Key Certification (Certify K_B):`);
    const certify = await tpm.certify("kb", "ak", nonce);
    const certAttestBuf = Buffer.isBuffer(certify.attest) ? certify.attest : Buffer.from(certify.attest, "base64url");
    const certSigBuf = Buffer.from(certify.sig, "base64url");
    const certSigValid = crypto.verify("sha256", certAttestBuf, { key: akKey, dsaEncoding: "ieee-p1363" }, certSigBuf);
    console.log(`    Certify Signature: ${certSigValid ? "VALID" : "INVALID"}`);

    // 8. Sign with K_B
    console.log(`\n[8] Data Signing with K_B:`);
    const testData = Buffer.from("ZTA test message for DPoP verification");
    const signature = await tpm.sign("kb", testData);
    const kbParsed = parsePublic(Buffer.from(kb.publicArea.tpmtPublic, "base64url"));
    const kbKey = publicKeyOf(kbParsed);
    const signSigBuf = Buffer.from(signature, "base64url");
    const signValid = crypto.verify("sha256", testData, { key: kbKey, dsaEncoding: "ieee-p1363" }, signSigBuf);
    console.log(`    Sign Signature: ${signValid ? "VALID" : "INVALID"}`);

    // 9. PCRs & Golden PCR
    console.log(`\n[9] Platform Configuration Registers (PCR 0..7):`);
    const pcrRead = await tpm.conn.call("PCR_Read", [
      new TPMS_PCR_SELECTION(TPM_ALG_ID.SHA256, Buffer.from([0xff, 0, 0])),
    ]);
    const pcrValues = pcrRead?.pcrValues || [];
    let pcrConcat = Buffer.alloc(0);
    for (let i = 0; i < 8; i++) {
      const digest = pcrValues[i]?.buffer ? Buffer.from(pcrValues[i].buffer) : Buffer.alloc(32);
      console.log(`    PCR[${i}]: ${digest.toString("hex")}`);
      pcrConcat = Buffer.concat([pcrConcat, digest]);
    }

    const goldenPcrDigest = crypto.createHash("sha256").update(pcrConcat).digest("hex");
    console.log(`\n============================================================`);
    console.log(`🏆 GOLDEN PCR DIGEST:`);
    console.log(`   ${goldenPcrDigest}`);
    console.log(`\n📋 Register this device with:`);
    console.log(`   npm run inventory:add -- --backend tpm --devId ${detectedEkType === "ecc" ? eccDevId : rsaDevId} --golden-pcr ${goldenPcrDigest} --user alice`);
    console.log(`============================================================\n`);

    return {
      success: true,
      manufacturer: ascii.trim(),
      rsaDevId,
      eccDevId,
      goldenPcrDigest,
    };
  } finally {
    await tpm.close();
    fs.rmSync(probeDir, { recursive: true, force: true });
  }
}

if (isMain(import.meta.url)) {
  const options = parseArgs();
  runProbe(options).catch((err) => {
    console.error("❌ Probe failed:", err.message || err);
    process.exit(1);
  });
}

export default { runProbe, parseArgs };
