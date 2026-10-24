/**
 * @file appraise.js
 * Algorithm 1: Attestation appraisal at the verifier.
 * Nonce issuance, quote appraisal against reference values, device suspension on failure,
 * PIP status push, and Attestation Result (AR) issuance.
 */

import crypto from "node:crypto";
import { verifyQuote } from "./enrol.js";
import { createAttestationResult } from "./ar.js";
import { internalFetch } from "../internal-auth.js";
import { pcrsOf, profileFor } from "./reference-values.js";
import { on } from "../ablation.js";

/**
 * Issues a single-use appraisal nonce for an active device.
 *
 * @param {Object} params
 * @param {string} params.devId - Device identifier
 * @param {Object} params.store - Verifier store
 * @param {Function} [params.clock] - Clock function
 * @returns {Promise<{ ok: boolean, status?: number, error?: string, message?: string, nonceId?: string, nonce?: string }>}
 */
export async function requestAppraiseNonce({ devId, store, clock = () => Date.now(), referenceValues, rvProfiles }) {
  if (!devId) {
    return { ok: false, status: 400, error: "missing_dev_id", message: "devId is required" };
  }

  const reg = await store.get(`registry/${devId}`);
  if (!reg || reg.status !== "active") {
    return {
      ok: false,
      status: 403,
      error: "device_not_active",
      message: `Device ${devId} is not in active state (current status: ${reg?.status || "unknown"})`,
    };
  }

  // The PCR set to quote, from the profile fixed at enrolment (M6)
  let pcrs;
  try {
    pcrs = pcrsOf(profileFor(reg, { referenceValues, rvProfiles }));
  } catch (err) {
    return { ok: false, status: 500, error: "rv_profile_invalid", message: err.message };
  }

  const nonce = crypto.randomBytes(32).toString("base64url");
  const nonceId = crypto.randomUUID();
  const nowMs = clock ? clock() : Date.now();

  const nonceRecord = {
    nonceId,
    devId,
    nonce,
    expiresAt: nowMs + 60000,
    used: false,
  };

  await store.set(`nonces/${nonceId}`, nonceRecord);

  return {
    ok: true,
    nonceId,
    nonce,
    pcrs,
  };
}

/**
 * Appraises device quote and event log.
 * On failure of fresh AK-signed evidence: marks status as suspended, pushes to PIP, returns 403.
 * Unsigned or stale/replayed evidence: 400 with no state change.
 * On success: updates last timestamp, pushes to PIP, and issues signed AR.
 *
 * @param {Object} params
 * @param {string} params.devId
 * @param {string} params.nonceId
 * @param {{ attest: any, sig: string }} params.quote
 * @param {Array<any>} params.eventLog
 * @param {Object} params.store - Verifier store
 * @param {Record<string, any>} params.cfg - Verifier config
 * @param {Object} params.verifierKey - Signing key { privateKey, kid }
 * @param {Record<number, Set<string>>} [params.referenceValues]
 * @param {Function} [params.clock]
 * @returns {Promise<{ ok: boolean, status?: number, error?: string, reason?: string, ar?: string }>}
 */
export async function appraiseDevice({
  devId,
  nonceId,
  quote,
  eventLog,
  store,
  cfg,
  verifierKey,
  referenceValues,
  rvProfiles,
  clock = () => Date.now(),
}) {
  if (!devId || !nonceId) {
    return {
      ok: false,
      status: 400,
      error: "appraisal_failed",
      reason: "missing_parameters",
    };
  }

  // 1. Look up device in registry
  const reg = await store.get(`registry/${devId}`);
  if (!reg) {
    return {
      ok: false,
      status: 403,
      error: "appraisal_failed",
      reason: "device_not_found",
    };
  }

  if (reg.status !== "active") {
    return {
      ok: false,
      status: 403,
      error: "appraisal_failed",
      reason: `device_${reg.status}`,
    };
  }

  // 2. Validate nonce
  const storedNonce = await store.get(`nonces/${nonceId}`);
  const nowMs = clock ? clock() : Date.now();

  if (on("M4")) {
    if (
      !storedNonce ||
      storedNonce.used ||
      storedNonce.devId !== devId ||
      nowMs > storedNonce.expiresAt
    ) {
      return {
        ok: false,
        status: 403,
        error: "appraisal_failed",
        reason: "invalid_nonce",
      };
    }
  } else {
    // When M4 is OFF: appraise still looks up nonceId->devId but ignores used/expiry
    if (!storedNonce || storedNonce.devId !== devId) {
      return {
        ok: false,
        status: 403,
        error: "appraisal_failed",
        reason: "invalid_nonce",
      };
    }
  }

  // Mark nonce used
  if (storedNonce) {
    storedNonce.used = true;
    await store.set(`nonces/${nonceId}`, storedNonce);
  }

  // 3. Run QuoteOK against the device's profile. A missing profile is a verifier
  // misconfiguration, not device evidence: no state change.
  let rv;
  try {
    rv = profileFor(reg, { referenceValues, rvProfiles });
  } catch (err) {
    return { ok: false, status: 500, error: "appraisal_failed", reason: `rv_profile_invalid: ${err.message}` };
  }
  const akQn = reg.akQn ? Buffer.from(reg.akQn, "hex") : undefined;
  // Golden-PCR reference values provisioned in the inventory still apply at appraisal time.
  const inv = (await store.get(`inventory/${devId}`)) || {};
  const devRecord = {
    ...(inv.goldenPcrDigests ? { goldenPcrDigests: inv.goldenPcrDigests } : {}),
    ...(inv.goldenPcrDigest ? { goldenPcrDigest: inv.goldenPcrDigest } : {}),
    ...(reg.san ? { sanModel: reg.san } : {}),
    ...reg,
  };
  const quoteResult = verifyQuote({
    quote,
    akPublic: reg.akPub,
    expectedNonce: storedNonce.nonce,
    eventLog,
    referenceValues: rv,
    devRecord,
    akQn,
    // V3: TOFU only ever applies at enrolment; appraisal fails closed without a stored golden digest.
    allowTofu: false,
  });

  if (!quoteResult.valid) {
    if (on("M23")) {
      if (!quoteResult.akSigned) {
        // F3: Parse/signature failures return 400 with NO state change
        return {
          ok: false,
          status: 400,
          error: "invalid_quote",
          reason: quoteResult.error || "quote_signature_invalid",
        };
      }

      if (!quoteResult.fresh) {
        // N1: AK-signed but not bound to the current nonce/AK name -> stale or replayed
        // evidence. 400 with NO state change (a sniffed quote must not suspend the device).
        return {
          ok: false,
          status: 400,
          error: "stale_evidence",
          reason: quoteResult.error || "quote_not_fresh",
        };
      }
    }

    // F3/N1: Only AK-signed evidence carrying the current nonce that fails the
    // PCR digest or reference-value check suspends a device (when M23 is on).
    // When M23 is OFF: Suspend on any failed appraisal.
    reg.status = "suspended";
    await store.set(`registry/${devId}`, reg);

    // Push suspended to PIP synchronously
    if (cfg?.pipUrl) {
      try {
        await internalFetch(`${cfg.pipUrl}/pip/device/${devId}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status: "suspended" }),
        }, cfg);
      } catch (err) {
        console.warn(`⚠️ [verifier/appraise] PIP push error for ${devId}:`, err.message);
      }
    }

    return {
      ok: false,
      status: 403,
      error: "appraisal_failed",
      reason: quoteResult.error || "quote_invalid",
    };
  }

  // 4. Success -> update last, push active to PIP, issue AR
  const nowS = Math.floor(nowMs / 1000);
  reg.last = nowMs;
  await store.set(`registry/${devId}`, reg);

  if (cfg?.pipUrl) {
    try {
      await internalFetch(`${cfg.pipUrl}/pip/device/${devId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status: "active",
          last_good_attestation: nowS,
        }),
      }, cfg);
    } catch (err) {
      console.warn(`⚠️ [verifier/appraise] PIP push error for ${devId}:`, err.message);
    }
  }

  // Mint AR
  const issuer = cfg?.verifierUrl || "http://localhost:4005";
  const tauAR = Number(cfg?.tauAR ?? 120);

  const ar = await createAttestationResult({
    devId,
    jkt: reg.jkt,
    nonce: storedNonce.nonce,
    verifierKey,
    issuer,
    tauAR,
    clock,
  });

  return {
    ok: true,
    ar,
  };
}

export default {
  requestAppraiseNonce,
  appraiseDevice,
};
