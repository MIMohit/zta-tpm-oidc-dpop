/**
 * @file enrol.js
 * Algorithm 1: Enrolment verification for TPM-backed Zero Trust architecture.
 * Implements E3-E8 checks, credential activation verification, quote verification,
 * and binding key (K_B) certification verification for real TPM 2.0 and SimTPM.
 */

import crypto from "node:crypto";
import { makeCredential as makeCredentialSim } from "../sim-tpm/credential.js";
import { devIdOf, nameOf, normalizeAttributes, TPMA_OBJECT, thumbprintOf } from "../sim-tpm/public-area.js";
import { verifyEkCert, loadTrustAnchors } from "../sim-tpm/vendor-ca.js";
import { parseAttest, TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE, TPM_ST_ATTEST_CERTIFY, replayEventLog } from "../sim-tpm/attest.js";
import { verifyEventLog, loadReferenceValues, loadReferenceValuesFrom, verifyGoldenPcr } from "./reference-values.js";
import { parseTcgEventLog, replayTcgEventLog, pcrCompositeDigest, toAppraisalEvents, MAX_LOG_BYTES } from "./tcg-eventlog.js";
import { getInventory, verifyCode, markCodeUsed } from "./inventory.js";
import { internalFetch } from "../internal-auth.js";
import {
  resolvePublic,
  nameOfAny,
  verifyAkAttributes,
  verifyKbAttributes,
  expectedQn,
  makeCredentialAny,
} from "./evidence.js";
import { verifyX509EkCert } from "./ek-cert-x509.js";
import { publicKeyOf } from "../tpm2/marshal.js";
import { on } from "../ablation.js";

/**
 * Normalizes a nonce or secret to a Buffer.
 * @param {Buffer|string} val
 * @returns {Buffer}
 */
export function normalizeBuffer(val) {
  if (Buffer.isBuffer(val)) return val;
  if (typeof val === "string") {
    if (/^[0-9a-fA-F]{64}$/.test(val)) {
      return Buffer.from(val, "hex");
    }
    if (/^[A-Za-z0-9_-]{43,44}$/.test(val)) {
      return Buffer.from(val, "base64url");
    }
    return Buffer.from(val, "utf8");
  }
  return Buffer.from(val || "");
}

/**
 * Decodes attestation or signature payload from Buffer, hex string, or base64url string.
 * @param {Buffer|string} val
 * @returns {Buffer}
 */
export function decodePayload(val) {
  if (Buffer.isBuffer(val)) return val;
  if (typeof val === "string") {
    if (/^[0-9a-fA-F]+$/.test(val) && val.length % 2 === 0 && val.length >= 64) {
      return Buffer.from(val, "hex");
    }
    return Buffer.from(val, "base64url");
  }
  return Buffer.from(val || "");
}

/**
 * True when a parsed TPML_PCR_SELECTION is exactly one SHA-256 bank selecting PCR0..7.
 * @param {{ count: number, hash: number, sizeofSelect: number, pcrSelect: Buffer }} [sel]
 * @returns {boolean}
 */
export function isExpectedPcrSelection(sel) {
  return Boolean(
    sel &&
    sel.count === 1 &&
    sel.hash === 0x000b &&
    sel.sizeofSelect === 3 &&
    sel.pcrSelect &&
    sel.pcrSelect.length === 3 &&
    sel.pcrSelect[0] === 0xff &&
    sel.pcrSelect[1] === 0x00 &&
    sel.pcrSelect[2] === 0x00
  );
}

/**
 * Verifies a TPM2_Quote structure (QuoteOK in Algorithm 1).
 *
 * @param {Object} params
 * @param {{ attest: Buffer|string, sig: string|Buffer }} params.quote
 * @param {Record<string, any>} params.akPublic - Public area of AK
 * @param {Buffer|string} params.expectedNonce - Qualifying data n_V
 * @param {Array<any>|null} params.eventLog - Measured boot event log (or null for real TPM golden PCR mode)
 * @param {Record<number, Set<string>>} [params.referenceValues] - Reference values
 * @param {Record<string, any>} [params.devRecord] - Device record for golden PCR lookup
 * @param {Buffer|string} [params.akQn] - Expected Qualified Name of AK (if real TPM with SRK)
 * @param {boolean} [params.allowTofu] - Allow Trust On First Use for golden PCR
 * @returns {{ valid: boolean, error?: string, akSigned: boolean, fresh?: boolean, tofuCaptured?: boolean, pcrDigest?: string }}
 */
export function verifyQuote({
  quote,
  akPublic,
  expectedNonce,
  eventLog,
  referenceValues,
  devRecord,
  akQn,
  allowTofu,
}) {
  if (!quote || !quote.attest || !quote.sig) {
    return { valid: false, error: "Missing quote attest or signature", akSigned: false };
  }
  if (!akPublic) {
    return { valid: false, error: "Missing AK public area", akSigned: false };
  }

  const attestBuf = decodePayload(quote.attest);

  let parsed;
  try {
    parsed = parseAttest(attestBuf);
  } catch (err) {
    return { valid: false, error: `Failed to parse quote TPMS_ATTEST: ${err.message}`, akSigned: false };
  }

  // 1. Magic check
  if (parsed.magic !== TPM_GENERATED_VALUE) {
    return { valid: false, error: `Invalid quote magic: 0x${parsed.magic?.toString(16)}`, akSigned: false };
  }

  // 2. Type check
  if (parsed.type !== TPM_ST_ATTEST_QUOTE) {
    return { valid: false, error: `Invalid quote type: 0x${parsed.type?.toString(16)} (expected 0x8018)`, akSigned: false };
  }

  // 3. Signature verification under AKpub
  if (on("M5")) {
    try {
      let akKeyObj;
      if (akPublic.tpmtPublic) {
        akKeyObj = publicKeyOf(akPublic.tpmtPublic);
      } else {
        akKeyObj = crypto.createPublicKey({
          key: {
            kty: "EC",
            crv: akPublic.curve || "P-256",
            x: akPublic.x,
            y: akPublic.y,
          },
          format: "jwk",
        });
      }

      const sigBuf = decodePayload(quote.sig);

      const validSig = crypto.verify("sha256", attestBuf, {
        key: akKeyObj,
        dsaEncoding: "ieee-p1363",
      }, sigBuf);

      if (!validSig) {
        return { valid: false, error: "Quote signature verification failed under AK", akSigned: false };
      }
    } catch (err) {
      return { valid: false, error: `Quote signature verification error: ${err.message}`, akSigned: false };
    }
  }

  // Evidence is genuinely AK-signed (or M5 is off). A nonce or signer mismatch below means the
  // evidence is stale/replayed (not fresh), so it must not change device state (N1).
  // 4. extraData == n_V
  if (on("M4")) {
    const expectedNonceBuf = normalizeBuffer(expectedNonce);
    if (Buffer.compare(parsed.extraData, expectedNonceBuf) !== 0) {
      return { valid: false, error: "Quote extraData does not match expected nonce", akSigned: true, fresh: false };
    }
  }

  // 5. qualifiedSigner check: compare against akQn (if available) or Name(AK)
  if (on("M5")) {
    const expectedSigner = akQn ? (Buffer.isBuffer(akQn) ? akQn : Buffer.from(akQn, "hex")) : nameOfAny(akPublic);
    if (Buffer.compare(parsed.qualifiedSigner, expectedSigner) !== 0) {
      return { valid: false, error: "Quote qualifiedSigner does not match AK name or Qualified Name", akSigned: true, fresh: false };
    }
  }

  // Evidence is AK-signed AND fresh: failures below are appraisal failures.
  const quotedPcrDigestHex = parsed.pcrDigest ? parsed.pcrDigest.toString("hex") : "";

  // 6. PCR selection (V1): both appraisal modes must quote exactly SHA-256 PCR0..7.
  // Otherwise a host could quote untouched PCRs (e.g. PCR8..15) next to an empty log.
  if (on("M6")) {
    const sel = parsed.attested?.pcrSelect;
    if (!isExpectedPcrSelection(sel)) {
      return {
        valid: false,
        error: "Invalid PCR selection in quote (expected exactly SHA-256 PCR0..7)",
        akSigned: true,
        fresh: true,
      };
    }
  }

  // 7. PCR Verification: Golden-PCR mode if eventLog is null, otherwise replay event log
  if (!on("M7")) {
    return {
      valid: true,
      akSigned: true,
      fresh: true,
      pcrDigest: quotedPcrDigestHex,
    };
  }
  if (eventLog === null) {
    const gCheck = verifyGoldenPcr({
      pcrDigest: parsed.pcrDigest,
      devRecord: devRecord || {},
      // TOFU only when the caller opts in (finishEnrol); never implied by the env flag here (V3)
      allowTofu: Boolean(allowTofu),
    });

    if (!gCheck.valid) {
      return {
        valid: false,
        error: `Golden PCR verification failed: ${gCheck.error}`,
        akSigned: true,
        fresh: true,
      };
    }

    return {
      valid: true,
      akSigned: true,
      fresh: true,
      tofuCaptured: gCheck.tofuCaptured,
      pcrDigest: quotedPcrDigestHex,
    };
  }

  // TCG2 binary event log branch (Linux devices with securityfs event log)
  if (eventLog && typeof eventLog === "object" && eventLog.format === "tcg2-binary") {
    let rawBuf;
    try {
      if (Buffer.isBuffer(eventLog.data)) {
        rawBuf = eventLog.data;
      } else if (typeof eventLog.data === "string") {
        rawBuf = Buffer.from(eventLog.data, "base64url");
      } else {
        throw new Error("Invalid tcg2-binary payload");
      }
      if (rawBuf.length > MAX_LOG_BYTES) {
        throw new Error(`Log exceeds MAX_LOG_BYTES (${rawBuf.length} > ${MAX_LOG_BYTES})`);
      }
      const parsedLog = parseTcgEventLog(rawBuf);
      const { pcrs: replayedPcrs } = replayTcgEventLog(parsedLog, { bank: "sha256", pcrs: [0, 1, 2, 3, 4, 5, 6, 7] });
      const composite = pcrCompositeDigest(replayedPcrs, [0, 1, 2, 3, 4, 5, 6, 7]);
      if (Buffer.compare(composite, parsed.pcrDigest) !== 0) {
        return {
          valid: false,
          akSigned: true,
          fresh: true,
          error: "Replayed TCG event log does not match quoted pcrDigest",
        };
      }
      const events = toAppraisalEvents(parsedLog, { bank: "sha256", pcrs: [0, 1, 2, 3, 4, 5, 6, 7] });
      const rv = referenceValues || loadReferenceValuesFrom();
      const rvCheck = verifyEventLog(events, rv);
      if (!rvCheck.valid) {
        return {
          valid: false,
          error: `Event log verification failed: ${rvCheck.error}`,
          akSigned: true,
          fresh: true,
        };
      }
      // The log must cover the golden boot: every PCR with reference values needs an event.
      const measured = new Set(events.map((e) => e.pcr));
      for (const [pcr, allowed] of Object.entries(rv)) {
        if (allowed && allowed.size > 0 && !measured.has(Number(pcr))) {
          return {
            valid: false,
            error: `Event log has no measurement for PCR ${pcr}`,
            akSigned: true,
            fresh: true,
          };
        }
      }
      return { valid: true, akSigned: true, fresh: true, pcrDigest: quotedPcrDigestHex };
    } catch (err) {
      return {
        valid: false,
        error: `TCG event log appraisal failure: ${err.message}`,
        akSigned: true,
        fresh: true,
      };
    }
  }

  // Simulated TPM / emulated measured boot event log replay
  if (!Array.isArray(eventLog) || eventLog.length === 0) {
    return { valid: false, error: "Event log is missing or empty", akSigned: true, fresh: true };
  }
  const log = eventLog;
  const { digest: replayedDigest } = replayEventLog(log);
  if (!replayedDigest.equals(parsed.pcrDigest)) {
    return { valid: false, error: "Replayed event log PCR digest does not match quoted pcrDigest", akSigned: true, fresh: true };
  }

  // 8. Event log checks against Reference Values (RV)
  const rv = referenceValues || loadReferenceValues();
  const rvCheck = verifyEventLog(log, rv);
  if (!rvCheck.valid) {
    return { valid: false, error: `Event log verification failed: ${rvCheck.error}`, akSigned: true, fresh: true };
  }

  // The log must cover the golden boot: every PCR with reference values needs an event.
  const measured = new Set(log.map((e) => e.pcr));
  for (const [pcr, allowed] of Object.entries(rv)) {
    if (allowed && allowed.size > 0 && !measured.has(Number(pcr))) {
      return { valid: false, error: `Event log has no measurement for PCR ${pcr}`, akSigned: true, fresh: true };
    }
  }

  return { valid: true, akSigned: true, fresh: true, pcrDigest: quotedPcrDigestHex };
}

/**
 * Verifies a TPM2_Certify structure (CertifyOK in Algorithm 1).
 *
 * @param {Object} params
 * @param {{ attest: Buffer|string, sig: string|Buffer }} params.certify
 * @param {Record<string, any>} params.akPublic - Public area of AK
 * @param {Record<string, any>} params.kbPublic - Public area of K_B
 * @param {Buffer|string} params.expectedNonce - Qualifying data n_V
 * @param {Buffer|string} [params.akQn] - Expected Qualified Name of AK
 * @param {Record<string, any>} [params.srkPublic] - SRK public area (for checking K_B Qualified Name)
 * @returns {{ valid: boolean, error?: string }}
 */
export function verifyCertify({ certify, akPublic, kbPublic, expectedNonce, akQn, srkPublic }) {
  if (!certify || !certify.attest || !certify.sig) {
    return { valid: false, error: "Missing certify attest or signature" };
  }
  if (!akPublic || !kbPublic) {
    return { valid: false, error: "Missing AK or K_B public area" };
  }

  const attestBuf = decodePayload(certify.attest);

  let parsed;
  try {
    parsed = parseAttest(attestBuf);
  } catch (err) {
    return { valid: false, error: `Failed to parse certify TPMS_ATTEST: ${err.message}` };
  }

  // 1. Magic check
  if (parsed.magic !== TPM_GENERATED_VALUE) {
    return { valid: false, error: `Invalid certify magic: 0x${parsed.magic?.toString(16)}` };
  }

  // 2. Type check
  if (parsed.type !== TPM_ST_ATTEST_CERTIFY) {
    return { valid: false, error: `Invalid certify type: 0x${parsed.type?.toString(16)} (expected 0x8017)` };
  }

  // 3. extraData == n_V
  if (on("M4")) {
    const expectedNonceBuf = normalizeBuffer(expectedNonce);
    if (Buffer.compare(parsed.extraData, expectedNonceBuf) !== 0) {
      return { valid: false, error: "Certify extraData does not match expected nonce" };
    }
  }

  // 4. qualifiedSigner check: akQn or Name(AK)
  if (on("M8")) {
    const expectedSigner = akQn ? (Buffer.isBuffer(akQn) ? akQn : Buffer.from(akQn, "hex")) : nameOfAny(akPublic);
    if (Buffer.compare(parsed.qualifiedSigner, expectedSigner) !== 0) {
      return { valid: false, error: "Certify qualifiedSigner does not match AK name or Qualified Name" };
    }
  }

  // 5. Signature verification under AK
  if (on("M8")) {
    try {
      let akKeyObj;
      if (akPublic.tpmtPublic) {
        akKeyObj = publicKeyOf(akPublic.tpmtPublic);
      } else {
        akKeyObj = crypto.createPublicKey({
          key: {
            kty: "EC",
            crv: akPublic.curve || "P-256",
            x: akPublic.x,
            y: akPublic.y,
          },
          format: "jwk",
        });
      }

      const sigBuf = decodePayload(certify.sig);

      const validSig = crypto.verify("sha256", attestBuf, {
        key: akKeyObj,
        dsaEncoding: "ieee-p1363",
      }, sigBuf);

      if (!validSig) {
        return { valid: false, error: "Certify signature verification failed under AK" };
      }
    } catch (err) {
      return { valid: false, error: `Certify signature verification error: ${err.message}` };
    }
  }

  // 6. Attested Name matches Name(K_B)
  const expectedKbName = nameOfAny(kbPublic);
  if (!parsed.attested.name || Buffer.compare(parsed.attested.name, expectedKbName) !== 0) {
    return { valid: false, error: "Certify attested name does not match Name(kbPublic)" };
  }

  // 6b. Attested Qualified Name check (if SRK is present)
  if (srkPublic && parsed.attested.qualifiedName) {
    const expKbQn = expectedQn(kbPublic, srkPublic);
    if (expKbQn && Buffer.compare(parsed.attested.qualifiedName, expKbQn) !== 0) {
      return { valid: false, error: "Certify attested qualifiedName does not match expected K_B Qualified Name" };
    }
  }

  // 7. K_B attributes check
  try {
    verifyKbAttributes(kbPublic);
  } catch (err) {
    return { valid: false, error: err.message };
  }

  return { valid: true };
}

/**
 * Executes E3 checks and initiates an enrolment session.
 *
 * @param {Object} params
 * @param {string} params.code - One-time enrolment code
 * @param {string} [params.ekCert] - Compact JWS or X.509 EK certificate
 * @param {Record<string, any>} params.akPublic - AK public area
 * @param {Record<string, any>} params.kbPublic - K_B public area
 * @param {Record<string, any>} [params.ekPublic] - EK public area (real TPM)
 * @param {Record<string, any>} [params.srkPublic] - SRK public area (real TPM)
 * @param {Array<string|Buffer>} [params.ekCertChain] - Optional intermediate EK certificates
 * @param {Object} params.store - Verifier store
 * @param {any} [params.trustAnchors] - Trust anchors for JWS EK cert verification
 * @param {string} [params.ekRootsDir] - Roots directory for X.509 EK cert verification
 * @param {Record<string, any>} [params.cfg] - Verifier config
 * @param {Function} [params.clock] - Clock function
 * @returns {Promise<{ ok: boolean, status?: number, error?: string, message?: string, sessionId?: string, blob?: any, nonce?: string }>}
 */
export async function startEnrol({
  code,
  ekCert,
  akPublic,
  kbPublic,
  ekPublic,
  srkPublic,
  ekCertChain,
  store,
  trustAnchors,
  ekRootsDir,
  cfg,
  secret: customSecret,
  nonce: customNonce,
  certifyNonce: customCertifyNonce,
  clock = () => Date.now(),
  user,
}) {
  if (on("M2") && !code) {
    return { ok: false, status: 403, error: "code_invalid", message: "Missing enrolment code" };
  }
  if (!akPublic) {
    return { ok: false, status: 403, error: "ak_public_invalid", message: "Missing AK public area" };
  }
  if (!kbPublic) {
    return { ok: false, status: 403, error: "kb_public_invalid", message: "Missing K_B public area" };
  }

  // 0. Resolve and validate AK and K_B public areas
  let resolvedAk, resolvedKb;
  try {
    resolvedAk = resolvePublic(akPublic);
    verifyAkAttributes(resolvedAk);
    resolvedKb = resolvePublic(kbPublic);
  } catch (err) {
    return { ok: false, status: 403, error: "ak_attributes_invalid", message: err.message };
  }

  // 1. Verify EK certificate or check pinned EK policy
  let ekPublicArea = null;
  let ekTrust = "cert";
  let san = null;

  const ekPolicy = cfg?.ekCertPolicy || process.env.EK_CERT_POLICY || "require";

  if (!ekCert) {
    // Missing EK cert: check if pinned-ok policy applies or M1 is off
    if (!on("M1") && ekPublic) {
      try {
        ekPublicArea = resolvePublic(ekPublic);
        ekTrust = "unverified";
      } catch (err) {
        return { ok: false, status: 403, error: "ek_public_invalid", message: err.message };
      }
    } else if (ekPolicy === "pinned-ok" && ekPublic) {
      try {
        const resolvedEk = resolvePublic(ekPublic);
        const devId = await devIdOf(resolvedEk);
        const invRecord = await getInventory(store, devId);
        if (!invRecord) {
          return { ok: false, status: 403, error: "ek_not_in_inventory", message: `Device ${devId} not in inventory` };
        }
        const pinnedEk = invRecord.ekPublic || invRecord.pinnedEkPub;
        if (!pinnedEk) {
          return { ok: false, status: 403, error: "ek_cert_invalid", message: "Missing EK certificate and device has no pinned EK" };
        }
        const pinnedResolved = resolvePublic(pinnedEk);
        if (pinnedResolved.tpmtPublic && resolvedEk.tpmtPublic) {
          if (pinnedResolved.tpmtPublic !== resolvedEk.tpmtPublic) {
            return { ok: false, status: 403, error: "ek_pinned_mismatch", message: "Claimed EK does not match pinned EK" };
          }
        }
        ekPublicArea = resolvedEk;
        ekTrust = "pinned";
      } catch (err) {
        return { ok: false, status: 403, error: "ek_public_invalid", message: err.message };
      }
    } else {
      return { ok: false, status: 403, error: "ek_cert_invalid", message: "Missing EK certificate" };
    }
  } else {
    // EK cert is present
    const isJws = typeof ekCert === "string" && ekCert.split(".").length === 3 && !ekCert.includes("-----BEGIN");
    if (isJws) {
      if (on("M1")) {
        try {
          ekPublicArea = await verifyEkCert(ekCert, trustAnchors);
        } catch (err) {
          return { ok: false, status: 403, error: "ek_cert_invalid", message: err.message };
        }
      } else {
        try {
          const parts = ekCert.split(".");
          const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
          if (!payload.ek_pub || typeof payload.ek_pub !== "object") {
            return { ok: false, status: 403, error: "ek_cert_invalid", message: "EK certificate payload missing ek_pub property" };
          }
          ekPublicArea = payload.ek_pub;
          ekTrust = "unverified";
        } catch (err) {
          return { ok: false, status: 403, error: "ek_cert_invalid", message: err.message };
        }
      }
    } else {
      // Real TPM X.509 path
      if (on("M1")) {
        try {
          const rootsDir = ekRootsDir || cfg?.ekRootsDir || process.env.EK_ROOTS_DIR;
          const verifiedEk = await verifyX509EkCert(
            {
              cert: ekCert,
              chain: ekCertChain,
              ekPublicArea: ekPublic,
            },
            rootsDir,
            {
              ignoreExpiry: cfg?.ekCertIgnoreExpiry,
              ztaEnv: cfg?.ztaEnv || process.env.ZTA_ENV,
              clock,
            }
          );
          ekPublicArea = verifiedEk;
          san = verifiedEk.san;
        } catch (err) {
          const errCode = err.message.includes("ek_template_invalid") ? "ek_template_invalid" : "ek_cert_invalid";
          return { ok: false, status: 403, error: errCode, message: err.message };
        }
      } else {
        try {
          ekPublicArea = resolvePublic(ekPublic);
          ekTrust = "unverified";
        } catch (err) {
          return { ok: false, status: 403, error: "ek_public_invalid", message: err.message };
        }
      }
    }
  }

  // 2. Compute devId = H(EKpub) and check inventory
  const devId = await devIdOf(ekPublicArea);
  let invRecord = null;
  if (on("M2")) {
    invRecord = await getInventory(store, devId);
    if (!invRecord) {
      return { ok: false, status: 403, error: "ek_not_in_inventory", message: `Device ${devId} not in inventory` };
    }

    // 3. Verify enrolment code
    const codeResult = verifyCode(invRecord, code, clock);
    if (!codeResult.valid) {
      return {
        ok: false,
        status: 403,
        error: codeResult.error || "code_invalid",
        message: codeResult.reason || "Enrolment code invalid",
      };
    }
  } else {
    try {
      invRecord = await getInventory(store, devId);
    } catch {
      invRecord = null;
    }
  }

  // 4. Resolve SRK and calculate expected Qualified Name (QN) if SRK is provided
  let akQn = null;
  let resolvedSrk = null;
  if (srkPublic) {
    try {
      resolvedSrk = resolvePublic(srkPublic);
      akQn = expectedQn(resolvedAk, resolvedSrk);
    } catch (err) {
      return { ok: false, status: 403, error: "srk_invalid", message: err.message };
    }
  }

  // 5. Draw secret s (32 bytes) and nonce n_V (32 bytes)
  const secret = customSecret ? normalizeBuffer(customSecret) : crypto.randomBytes(32);
  const nonce = customNonce ? normalizeBuffer(customNonce) : crypto.randomBytes(32);
  const nonceB64u = nonce.toString("base64url");
  const certifyNonceB64u = customCertifyNonce
    ? normalizeBuffer(customCertifyNonce).toString("base64url")
    : undefined;

  // 6. MakeCredential blob (format-dispatched via evidence.js)
  const akName = nameOfAny(resolvedAk);
  let blob;
  try {
    blob = makeCredentialAny(ekPublicArea, akName, secret);
  } catch (err) {
    const errCode = err.message.includes("Non-standard EK") ? "ek_template_invalid" : "credential_error";
    return { ok: false, status: 403, error: errCode, message: err.message };
  }

  // 7. Store session (60s lifetime)
  const sessionId = crypto.randomUUID();
  const nowMs = clock ? clock() : Date.now();
  const owner = invRecord?.user ?? user ?? "unknown";
  const session = {
    sessionId,
    devId,
    user: owner,
    akPublic: resolvedAk,
    kbPublic: resolvedKb,
    srkPublic: resolvedSrk,
    akQn: akQn ? akQn.toString("hex") : null,
    ekTrust,
    san,
    secret: secret.toString("hex"),
    nonce: nonceB64u,
    ...(certifyNonceB64u ? { certifyNonce: certifyNonceB64u } : {}),
    expiresAt: nowMs + 60000,
  };

  await store.set(`sessions/${sessionId}`, session);

  return {
    ok: true,
    sessionId,
    blob,
    nonce: nonceB64u,
  };
}

/**
 * Completes enrolment (finishEnrol), verifying s', QuoteOK and CertifyOK.
 *
 * @param {Object} params
 * @param {string} params.sessionId
 * @param {Buffer|string} params.secret - Decrypted secret s' from ActivateCredential
 * @param {{ attest: any, sig: string }} params.quote
 * @param {{ attest: any, sig: string }} params.certify
 * @param {Array<any>|null} params.eventLog
 * @param {Object} params.store - Verifier store
 * @param {Record<string, any>} params.cfg - Verifier config
 * @param {Record<number, Set<string>>} [params.referenceValues]
 * @param {Function} [params.clock]
 * @returns {Promise<{ ok: boolean, status?: number, error?: string, message?: string, devId?: string, jkt?: string }>}
 */
export async function finishEnrol({
  sessionId,
  secret,
  quote,
  certify,
  eventLog,
  store,
  cfg,
  referenceValues,
  clock = () => Date.now(),
}) {
  if (!sessionId) {
    return { ok: false, status: 403, error: "session_invalid", message: "Missing sessionId" };
  }

  const session = await store.get(`sessions/${sessionId}`);
  if (!session) {
    return { ok: false, status: 403, error: "session_invalid", message: "Enrolment session not found or already used" };
  }

  // Delete session to prevent replay
  await store.del(`sessions/${sessionId}`);

  const nowMs = clock ? clock() : Date.now();
  if (nowMs > session.expiresAt) {
    return { ok: false, status: 403, error: "session_expired", message: "Enrolment session expired" };
  }

  // 1. Constant-time secret comparison: s' == s
  if (on("M3")) {
    const clientSecretBuf = normalizeBuffer(secret);
    const expectedSecretBuf = Buffer.from(session.secret, "hex");

    if (
      !clientSecretBuf ||
      clientSecretBuf.length !== expectedSecretBuf.length ||
      !crypto.timingSafeEqual(clientSecretBuf, expectedSecretBuf)
    ) {
      return { ok: false, status: 403, error: "secret_mismatch", message: "Credential activation secret mismatch" };
    }
  }

  // 2. QuoteOK
  const invRecord = await getInventory(store, session.devId);
  const devRecord = {
    devId: session.devId,
    ...(invRecord || {}),
    sanModel: session.san,
  };
  const allowTofu = Boolean(cfg?.verifierGoldenTofu || process.env.VERIFIER_GOLDEN_TOFU === "1");

  const quoteResult = verifyQuote({
    quote,
    akPublic: session.akPublic,
    expectedNonce: session.nonce,
    eventLog,
    referenceValues,
    devRecord,
    akQn: session.akQn ? Buffer.from(session.akQn, "hex") : undefined,
    allowTofu,
  });

  if (!quoteResult.valid) {
    return { ok: false, status: 403, error: "quote_invalid", message: quoteResult.error };
  }

  // 3. CertifyOK
  if (on("M8")) {
    const certifyResult = verifyCertify({
      certify,
      akPublic: session.akPublic,
      kbPublic: session.kbPublic,
      expectedNonce: session.certifyNonce || session.nonce,
      akQn: session.akQn ? Buffer.from(session.akQn, "hex") : undefined,
      srkPublic: session.srkPublic,
    });

    if (!certifyResult.valid) {
      return { ok: false, status: 403, error: "certify_invalid", message: certifyResult.error };
    }
  }

  // 4. Registry update
  const devId = session.devId;
  const jkt = await thumbprintOf(session.kbPublic);
  const nowS = Math.floor(nowMs / 1000);

  const registryRecord = {
    devId,
    akPub: session.akPublic,
    kbPub: session.kbPublic,
    jkt,
    user: session.user,
    status: "active",
    enrolledAt: nowMs,
    last: nowMs,
    ...(session.akQn ? { akQn: session.akQn } : {}),
    ...(session.srkPublic ? { srkPub: session.srkPublic } : {}),
    ...(session.ekTrust ? { ekTrust: session.ekTrust } : {}),
    ...(session.san ? { san: session.san } : {}),
    ...(quoteResult.tofuCaptured
      ? { rvSource: "tofu", goldenPcrDigest: quoteResult.pcrDigest }
      : {}),
  };

  await store.set(`registry/${devId}`, registryRecord);

  // 5. Mark code as used in inventory
  if (on("M2")) {
    await markCodeUsed(store, devId);
  }

  // 6. Push to PIP synchronously
  if (cfg?.pipUrl) {
    try {
      const pipRes = await internalFetch(`${cfg.pipUrl}/pip/device/${devId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user: session.user,
          status: "active",
          jkt,
          last_good_attestation: nowS,
        }),
      }, cfg);

      if (!pipRes.ok) {
        console.warn(`⚠️ [verifier/enrol] PIP push returned ${pipRes.status} for ${devId}`);
      }
    } catch (err) {
      console.warn(`⚠️ [verifier/enrol] PIP push error for ${devId}:`, err.message);
    }
  }

  return {
    ok: true,
    devId,
    jkt,
  };
}

export default {
  verifyQuote,
  verifyCertify,
  startEnrol,
  finishEnrol,
};
