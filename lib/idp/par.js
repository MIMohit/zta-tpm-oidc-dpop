/**
 * @file lib/idp/par.js
 * Pushed Authorization Requests (PAR, RFC 9126) endpoint.
 * Validates and binds the client attestation result (AR) to dpop_jkt (RFC 9449 §10.1).
 * Store namespace: idp
 * Path: par/<request_uri>
 */

import crypto from "node:crypto";
import * as jose from "jose";
import { verifyAttestationResult } from "../verifier/ar.js";
import { on } from "../ablation.js";

/**
 * Handles POST /oauth/par
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {Object} context
 * @param {Object} context.store - idp store instance
 * @param {Record<string, any>} context.cfg - Server config
 * @param {any} [context.verifierJwks] - Verifier public JWKS or key set
 */
export async function handlePar(req, res, { store, cfg, verifierJwks }) {
  try {
    const {
      client_id,
      response_type,
      redirect_uri,
      code_challenge,
      code_challenge_method,
      dpop_jkt,
      attestation_result,
      state,
      acr_values,
      // Note: any client-supplied 'role', 'acr', or 'dev' params are explicitly ignored
    } = req.body;

    const nowMs = cfg.clock ? cfg.clock() : Date.now();
    const nowS = Math.floor(nowMs / 1000);

    // 1. Basic parameter validation
    if (!client_id) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing client_id",
      });
    }

    if (response_type !== "code") {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "response_type must be code",
      });
    }

    const expectedRedirectUri = cfg.agentUrl ? `${cfg.agentUrl}/callback` : "http://127.0.0.1:7000/callback";
    if (!redirect_uri || (redirect_uri !== expectedRedirectUri && redirect_uri !== "http://127.0.0.1:7000/callback")) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Invalid redirect_uri",
      });
    }

    if (!code_challenge) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing code_challenge",
      });
    }

    const method = (code_challenge_method || "S256").toUpperCase();
    if (method !== "S256") {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "code_challenge_method must be S256",
      });
    }

    if (on("M13")) {
      if (!dpop_jkt || typeof dpop_jkt !== "string") {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "Missing dpop_jkt",
        });
      }
    }

    if (on("M9")) {
      if (!attestation_result || typeof attestation_result !== "string") {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "Missing attestation_result",
        });
      }
    }

    // 2. Obtain Verifier JWKS
    let keyOrJwks = verifierJwks || cfg.verifierJwks || cfg.verifierKey;
    if (!keyOrJwks) {
      const verifierUrl = cfg.verifierUrl || "http://localhost:4005";
      keyOrJwks = jose.createRemoteJWKSet(new URL(`${verifierUrl}/v/jwks`));
    }

    // 3. Verify the AR (Attestation Result) JWS
    let arPayload = null;
    if (on("M9")) {
      try {
        const verified = await verifyAttestationResult(attestation_result, keyOrJwks, {
          clock: cfg.clock,
          clockTolerance: 0, // Strict expiry check: clock + 121s must fail with tauAR = 120
        });
        arPayload = verified.payload;
      } catch (err) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: `AR verification failed: ${err.message}`,
        });
      }

      // Strict time expiry check against injected clock
      if (arPayload.exp && nowS > arPayload.exp) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "AR expired",
        });
      }

      if (arPayload.status !== "pass") {
        return res.status(400).json({
          error: "invalid_request",
          error_description: `AR status not pass: ${arPayload.status}`,
        });
      }
    } else {
      // M9 OFF: Decode the AR without verifying it; an absent AR is allowed
      if (attestation_result && typeof attestation_result === "string") {
        try {
          arPayload = jose.decodeJwt(attestation_result);
        } catch {
          arPayload = {};
        }
      } else {
        arPayload = null;
      }
    }

    // 4. Check C2: AR.jkt == dpop_jkt
    if (on("M10")) {
      if (arPayload && arPayload.jkt !== dpop_jkt) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "ar_jkt_mismatch",
        });
      }
    }

    // 5. Single-use check for AR jti
    if (on("M11")) {
      const jti = arPayload?.jti;
      if (jti) {
        const alreadyUsed = await store.get(`ar_used/${jti}`);
        if (alreadyUsed) {
          return res.status(400).json({
            error: "invalid_request",
            error_description: "ar_already_used",
          });
        }
        await store.set(`ar_used/${jti}`, { used_at: nowMs });
      }
    }

    // 6. If DPoP header is present, verify its thumbprint == dpop_jkt (RFC 9449 §10.1)
    if (req.headers.dpop) {
      try {
        const dpopHeader = jose.decodeProtectedHeader(req.headers.dpop);
        if (!dpopHeader.jwk) {
          return res.status(400).json({
            error: "invalid_dpop_proof",
            error_description: "Missing embedded jwk in DPoP header",
          });
        }
        if (on("M13")) {
          const proofJkt = await jose.calculateJwkThumbprint(dpopHeader.jwk, "sha256");
          if (proofJkt !== dpop_jkt) {
            return res.status(400).json({
              error: "invalid_dpop_proof",
              error_description: "dpop_jkt_mismatch",
            });
          }
        }
      } catch (err) {
        return res.status(400).json({
          error: "invalid_dpop_proof",
          error_description: err.message,
        });
      }
    }

    // 7. Store PAR transaction (lifetime: 60 s)
    const request_uri = `urn:ietf:params:oauth:request_uri:${crypto.randomUUID()}`;
    const dev = on("M9")
      ? (arPayload?.dev || arPayload?.sub)
      : (req.body.device_id || req.body.dev || arPayload?.dev || arPayload?.sub || "unknown");

    const txn = {
      request_uri,
      client_id,
      response_type,
      redirect_uri,
      code_challenge,
      code_challenge_method: method,
      dpop_jkt,
      attestation_result,
      arPayload,
      dev,
      state: state || "",
      acr_values: acr_values || "",
      role: on("M14") ? undefined : req.body.role,
      acr: on("M14") ? undefined : (req.body.acr || req.body.acr_values),
      created_at: nowMs,
      expires_at: nowMs + (cfg.parLifetime || 60) * 1000,
    };

    await store.set(`par/${request_uri}`, txn);

    return res.status(201).json({
      request_uri,
      expires_in: cfg.parLifetime || 60,
    });
  } catch (err) {
    console.error("❌ [/oauth/par] Internal error:", err);
    return res.status(500).json({
      error: "server_error",
      error_description: err.message,
    });
  }
}

export default { handlePar };
