/**
 * @file inventory.js
 * Device inventory management and one-time enrolment code handling.
 * Store namespace: verifier
 * Path: inventory/<devId> = { user, codeHash, codeExp, codeUsed }
 */

import crypto from "node:crypto";
import { safeEqual } from "../internal-auth.js";

/**
 * Computes SHA-256 hash of a code string as lowercase hex.
 * @param {string} code
 * @returns {string}
 */
export function hashCode(code) {
  return crypto.createHash("sha256").update(String(code).trim(), "utf8").digest("hex");
}

/**
 * Adds or updates a device in inventory with a one-time enrolment code.
 *
 * @param {Object} store - verifier store instance
 * @param {Object} params
 * @param {string} params.devId - Device identifier H(EKpub)
 * @param {string} params.user - Assigned username
 * @param {string} [params.code] - Optional explicit code; generated if omitted
 * @param {number} [params.ttlMs=2592000000] - Code TTL in ms (default 30 days)
 * @param {Function} [params.clock] - Clock function
 * @returns {Promise<{ devId: string, user: string, code: string, codeExp: number }>}
 */
export async function addToInventory(store, {
  devId,
  user,
  code,
  ttlMs = 30 * 24 * 3600 * 1000,
  goldenPcrDigests,
  goldenPcrDigest,
  ekTrust,
  ekPublic,
  clock = () => Date.now(),
}) {
  if (!devId) throw new Error("devId is required");
  if (!user) throw new Error("user is required");

  const enrolmentCode = code || crypto.randomBytes(16).toString("hex");
  const codeHash = hashCode(enrolmentCode);
  const nowMs = clock ? clock() : Date.now();
  const codeExp = nowMs + ttlMs;

  const record = {
    user,
    codeHash,
    codeExp,
    codeUsed: false,
    ...(goldenPcrDigests
      ? { goldenPcrDigests: Array.isArray(goldenPcrDigests) ? goldenPcrDigests : [goldenPcrDigests] }
      : goldenPcrDigest
      ? { goldenPcrDigests: [goldenPcrDigest] }
      : {}),
    ...(ekTrust ? { ekTrust } : {}),
    ...(ekPublic ? { ekPublic } : {}),
  };

  await store.set(`inventory/${devId}`, record);

  return {
    devId,
    user,
    code: enrolmentCode,
    codeExp,
    ...(record.goldenPcrDigests ? { goldenPcrDigests: record.goldenPcrDigests } : {}),
    ...(record.ekTrust ? { ekTrust: record.ekTrust } : {}),
    ...(record.ekPublic ? { ekPublic: record.ekPublic } : {}),
  };
}

/**
 * Retrieves inventory record for a devId.
 * @param {Object} store
 * @param {string} devId
 * @returns {Promise<Record<string, any>|null>}
 */
export async function getInventory(store, devId) {
  return store.get(`inventory/${devId}`);
}

/**
 * Verifies if an enrolment code is valid for an inventory record.
 *
 * @param {Record<string, any>} record - Inventory record from store
 * @param {string} code - Enrolment code to verify
 * @param {Function} [clock] - Clock function
 * @returns {{ valid: boolean, error?: string, reason?: string }}
 */
export function verifyCode(record, code, clock = () => Date.now()) {
  if (!record) {
    return { valid: false, error: "ek_not_in_inventory" };
  }

  if (record.codeUsed) {
    return { valid: false, error: "code_invalid", reason: "code_already_used" };
  }

  const nowMs = clock ? clock() : Date.now();
  if (record.codeExp && nowMs > record.codeExp) {
    return { valid: false, error: "code_invalid", reason: "code_expired" };
  }

  if (!code) {
    return { valid: false, error: "code_invalid", reason: "missing_code" };
  }

  const providedHash = hashCode(code);
  if (!safeEqual(providedHash, record.codeHash)) {
    return { valid: false, error: "code_invalid", reason: "code_mismatch" };
  }

  return { valid: true };
}

/**
 * Marks the one-time code as used in the inventory.
 * @param {Object} store
 * @param {string} devId
 * @returns {Promise<boolean>}
 */
export async function markCodeUsed(store, devId) {
  const record = await store.get(`inventory/${devId}`);
  if (!record) return false;

  record.codeUsed = true;
  await store.set(`inventory/${devId}`, record);
  return true;
}

export default {
  hashCode,
  addToInventory,
  getInventory,
  verifyCode,
  markCodeUsed,
};
