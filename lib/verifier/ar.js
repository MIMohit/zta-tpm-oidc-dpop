/**
 * @file ar.js
 * Attestation Result (AR) generation and verification.
 * Format per PLAN.md §2.4:
 * Compact JWS signed by Verifier (ES256).
 * Header: { alg: "ES256", typ: "ar+jwt", kid }
 * Claims: { iss: VERIFIER_ISSUER, sub: devId, dev: devId, jkt, status: "pass", nonce: n_V, iat, exp: iat + tauAR, jti }
 */

import crypto from "node:crypto";
import * as jose from "jose";
import { signJwt } from "../keys.js";

/**
 * Creates a signed Attestation Result (AR) JWT.
 *
 * @param {Object} params
 * @param {string} params.devId - Device identifier (H(EKpub))
 * @param {string} params.jkt - Thumbprint of K_B JWK
 * @param {string} params.nonce - Appraisal nonce n_V
 * @param {Object} params.verifierKey - { privateKey, kid } from loadOrCreateSigningKey
 * @param {string} [params.issuer="http://localhost:4005"]
 * @param {number} [params.tauAR=120] - AR lifetime in seconds
 * @param {Function} [params.clock] - Injected clock returning milliseconds
 * @returns {Promise<string>} Compact JWS
 */
export async function createAttestationResult({
  devId,
  jkt,
  nonce,
  verifierKey,
  issuer = "http://localhost:4005",
  tauAR = 120,
  clock = () => Date.now(),
}) {
  if (!devId) throw new Error("devId is required to issue AR");
  if (!jkt) throw new Error("jkt is required to issue AR");
  if (!nonce) throw new Error("nonce is required to issue AR");
  if (!verifierKey || !(verifierKey.privateKey || verifierKey.hsm)) {
    throw new Error("verifierKey (software or HSM) is required to issue AR");
  }

  const nowMs = clock ? clock() : Date.now();
  const nowS = Math.floor(nowMs / 1000);
  const expS = nowS + tauAR;
  const jti = crypto.randomUUID();

  const claims = {
    iss: issuer,
    sub: devId,
    dev: devId,
    jkt,
    status: "pass",
    nonce,
    iat: nowS,
    exp: expS,
    jti,
  };

  const header = {
    alg: "ES256",
    typ: "ar+jwt",
  };
  if (verifierKey.kid) {
    header.kid = verifierKey.kid;
  }

  const jwt = await signJwt(verifierKey, header, claims);

  return jwt;
}

/**
 * Verifies an Attestation Result (AR) JWT.
 *
 * @param {string} arJwt - Compact JWS AR string
 * @param {any} keyOrJwks - Public key, JWKS object, or remote JWK set
 * @param {Object} [options]
 * @param {string} [options.issuer]
 * @param {number} [options.clockTolerance=30]
 * @param {Function} [options.clock]
 * @returns {Promise<{ payload: Record<string, any>, protectedHeader: Record<string, any> }>}
 */
export async function verifyAttestationResult(arJwt, keyOrJwks, options = {}) {
  if (!arJwt || typeof arJwt !== "string") {
    throw new Error("Invalid AR: must be a compact JWS string");
  }

  const verifyOpts = {
    algorithms: ["ES256"],
    typ: "ar+jwt",
    clockTolerance: options.clockTolerance ?? 30,
  };
  if (options.issuer) {
    verifyOpts.issuer = options.issuer;
  }
  if (options.clock) {
    verifyOpts.currentDate = new Date(options.clock());
  }

  let key = keyOrJwks;
  if (keyOrJwks && typeof keyOrJwks === "object" && Array.isArray(keyOrJwks.keys)) {
    key = jose.createLocalJWKSet(keyOrJwks);
  } else if (keyOrJwks && keyOrJwks.publicJwk) {
    key = await jose.importJWK(keyOrJwks.publicJwk, "ES256");
  } else if (keyOrJwks && keyOrJwks.kty && !keyOrJwks.d) {
    key = await jose.importJWK(keyOrJwks, "ES256");
  }

  const { payload, protectedHeader } = await jose.jwtVerify(arJwt, key, verifyOpts);

  if (payload.status !== "pass") {
    throw new Error(`AR status is not pass: ${payload.status}`);
  }

  return { payload, protectedHeader };
}

export default {
  createAttestationResult,
  verifyAttestationResult,
};
