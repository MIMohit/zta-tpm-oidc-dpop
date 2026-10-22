import crypto from "node:crypto";
import { safeEqual } from "./internal-auth.js";

/**
 * Creates a nonce store for issuing and validating DPoP nonces.
 * Nonces rotate every tNonce seconds (default 60s). The previous nonce is also
 * accepted, so any issued nonce is valid for at least tNonce and up to 2 * tNonce seconds.
 *
 * @param {object} [options={}]
 * @param {number} [options.tNonce=60] - Nonce rotation period in seconds (Table 5: T_n = 60s)
 * @param {() => number} [options.clock] - Clock returning current epoch timestamp in ms
 * @returns {{ issue: () => string, valid: (nonce: string) => boolean, rotate: () => string, current: () => string }}
 */
export function createNonceStore(options = {}) {
  const tNonce = Number(options.tNonce ?? 60);
  const tNonceMs = tNonce * 1000;
  const clock = options.clock || (() => Date.now());

  let currentNonce = null;
  let currentCreated = 0;
  let previousNonce = null;

  function generateNonce() {
    return crypto.randomBytes(16).toString("base64url");
  }

  function rotateIfNeeded(now) {
    if (!currentNonce) {
      currentNonce = generateNonce();
      currentCreated = now;
      previousNonce = null;
      return;
    }
    const elapsed = now - currentCreated;
    if (elapsed >= tNonceMs) {
      if (elapsed < 2 * tNonceMs) {
        previousNonce = currentNonce;
      } else {
        previousNonce = null;
      }
      currentNonce = generateNonce();
      currentCreated = now;
    }
  }

  return {
    /**
     * Issues the current server nonce, rotating if elapsed >= tNonce.
     * @returns {string}
     */
    issue() {
      const now = clock();
      rotateIfNeeded(now);
      return currentNonce;
    },

    /**
     * Checks if a presented nonce matches the current or previous nonce.
     * @param {string} nonce
     * @returns {boolean}
     */
    valid(nonce) {
      if (!nonce || typeof nonce !== "string") {
        return false;
      }
      const now = clock();
      rotateIfNeeded(now);
      if (currentNonce && safeEqual(nonce, currentNonce)) {
        return true;
      }
      if (previousNonce && safeEqual(nonce, previousNonce)) {
        return true;
      }
      return false;
    },

    /**
     * Explicitly forces a rotation.
     * @returns {string}
     */
    rotate() {
      const now = clock();
      previousNonce = currentNonce;
      currentNonce = generateNonce();
      currentCreated = now;
      return currentNonce;
    },

    /**
     * Returns the current nonce without altering state unless uninitialized.
     * @returns {string}
     */
    current() {
      const now = clock();
      rotateIfNeeded(now);
      return currentNonce;
    },
  };
}

export default { createNonceStore };
