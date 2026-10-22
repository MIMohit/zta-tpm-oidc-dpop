/**
 * @file lib/idp/token.js
 * OAuth 2.0 / OIDC Token Endpoint (/oauth/token).
 * Supports authorization_code (with PKCE S256 and DPoP binding) and refresh_token grants.
 * Store namespace: idp
 * Paths: codes/<code>, refresh/<rt>
 */

import crypto from "node:crypto";
import * as jose from "jose";
import { verifyProof } from "../dpop.js";
import { roleOf } from "./directory.js";
import { internalFetch, safeEqual } from "../internal-auth.js";
import { on } from "../ablation.js";

/**
 * Handles POST /oauth/token
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {Object} context
 * @param {Object} context.store - idp store instance
 * @param {Record<string, any>} context.cfg - Server config
 * @param {Object} context.nonceStore - Nonce store for DPoP-Nonce
 * @param {Object} context.jtiCache - JTI cache for replay protection
 * @param {Object} context.idpKey - ES256 key { privateKey, publicJwk, kid }
 */
export async function handleToken(req, res, { store, cfg, nonceStore, jtiCache, idpKey }) {
  try {
    const { grant_type } = req.body || {};
    const nowMs = cfg.clock ? cfg.clock() : Date.now();
    const nowS = Math.floor(nowMs / 1000);

    const rawHost = req.get("host");
    const currentOrigin = rawHost ? `${req.protocol}://${rawHost}` : (cfg.idpIssuer || "http://localhost:5173");
    const candidateOrigins = Array.from(new Set([
      currentOrigin,
      cfg.idpIssuer || "http://localhost:5173",
      "http://localhost:5173",
    ]));

    // Ensure DPoP-Nonce header is always available
    const currentNonce = nonceStore ? nonceStore.issue() : crypto.randomBytes(16).toString("base64url");
    res.setHeader("DPoP-Nonce", currentNonce);

    /* -------------------------------------------------------------
       GRANT TYPE: authorization_code
    ------------------------------------------------------------- */
    if (grant_type === "authorization_code") {
      const { code, code_verifier, redirect_uri, client_id } = req.body;

      if (!code) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "Missing code parameter",
        });
      }

      // 1. DPoP Proof presence check
      const dpopHeader = req.headers.dpop;
      let proofResult = null;
      if (!dpopHeader || !dpopHeader.trim()) {
        if (on("M13")) {
          return res.status(400).json({
            error: "invalid_request",
            error_description: "Missing DPoP header",
          });
        }
      }

      // 2. Fetch authorization code record
      const codeRecord = await store.get(`codes/${code}`);
      if (!codeRecord) {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Authorization code invalid or expired",
        });
      }

      // Code expiry check (lifetime: 60 s)
      if (codeRecord.expires_at && nowMs > codeRecord.expires_at) {
        await store.del(`codes/${code}`);
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Authorization code expired",
        });
      }

      // 3. Verify PKCE S256
      if (!code_verifier) {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Missing PKCE code_verifier",
        });
      }

      const computedChallenge = crypto
        .createHash("sha256")
        .update(code_verifier)
        .digest("base64url");

      if (!safeEqual(computedChallenge, codeRecord.code_challenge)) {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "PKCE verification failed: challenge mismatch",
        });
      }

      // 4. Verify DPoP Proof against candidate token URLs
      if (dpopHeader && dpopHeader.trim()) {
        let lastErr = null;

        for (const origin of candidateOrigins) {
          const tokenUrl = `${origin}/oauth/token`;
          try {
            proofResult = await verifyProof({
              proof: dpopHeader,
              htm: "POST",
              htu: tokenUrl,
              expectedJkt: on("M13") ? codeRecord.jkt : undefined, // Proof thumbprint must match code.jkt
              nonceStore: on("M13") ? nonceStore : undefined,
              jtiCache,
              skewS: cfg.skew ?? 30,
              clock: cfg.clock,
            });
            lastErr = null;
            break;
          } catch (err) {
            lastErr = err;
            if (err.code !== "htu") {
              break;
            }
          }
        }

        if (lastErr && on("M13")) {
          if (lastErr.code === "use_dpop_nonce") {
            return res.status(400).json({
              error: "use_dpop_nonce",
              error_description: "DPoP nonce required or expired",
            });
          }
          return res.status(400).json({
            error: "invalid_dpop_proof",
            error_description: `DPoP proof verification failed: ${lastErr.message}`,
          });
        }

        // Proof thumbprint == code.jkt check
        if (on("M13") && proofResult && proofResult.jkt !== codeRecord.jkt) {
          return res.status(400).json({
            error: "invalid_grant",
            error_description: "DPoP proof key thumbprint does not match code binding",
          });
        }
      }

      // Single-use: delete code upon successful validation
      if (on("M11")) {
        await store.del(`codes/${code}`);
      }

      // 6. Look up role strictly from directory (or upstream Keycloak role in codeRecord)
      const requestRole = req.body?.role;
      const userRole = on("M14")
        ? (codeRecord.role || (await roleOf(codeRecord.u, store)) || "employee")
        : (codeRecord.role ?? requestRole ?? (await roleOf(codeRecord.u, store)) ?? "employee");

      const requestAcr = req.body?.acr;
      const acr = on("M14")
        ? (codeRecord.acr || "pwd")
        : (codeRecord.acr ?? requestAcr ?? "pwd");

      // 7. Mint Access Token (AT)
      const isBearer = !on("M13") && (!dpopHeader || !dpopHeader.trim());
      const boundJkt = proofResult?.jkt || codeRecord.jkt;

      const atPayload = {
        iss: cfg.idpIssuer || "http://localhost:5173",
        aud: "zta-api",
        sub: codeRecord.u,
        dev: codeRecord.dev,
        role: userRole,
        acr,
        auth_time: codeRecord.auth_time,
        iat: nowS,
        exp: nowS + (cfg.tAT ?? 300),
        jti: crypto.randomUUID(),
        client_id: codeRecord.client_id || "zta-agent",
      };

      if (!isBearer) {
        atPayload.cnf = {
          jkt: boundJkt,
        };
      }

      const atHeader = {
        alg: "ES256",
        typ: "at+jwt",
      };
      if (idpKey.kid) {
        atHeader.kid = idpKey.kid;
      }

      const accessToken = await new jose.SignJWT(atPayload)
        .setProtectedHeader(atHeader)
        .sign(idpKey.privateKey);

      // 8. Generate and store Refresh Token bound to { jkt, dev }
      const refreshToken = crypto.randomBytes(32).toString("base64url");
      const rtRecord = {
        rt: refreshToken,
        u: codeRecord.u,
        dev: codeRecord.dev,
        jkt: boundJkt,
        role: codeRecord.role || undefined,
        acr,
        auth_time: codeRecord.auth_time,
        created_at: nowS,
        exp: nowS + 86400 * 30, // 30 days
      };

      await store.set(`refresh/${refreshToken}`, rtRecord);

      return res.json({
        access_token: accessToken,
        token_type: isBearer ? "Bearer" : "DPoP",
        expires_in: cfg.tAT ?? 300,
        refresh_token: refreshToken,
        scope: "openid profile",
      });
    }

    /* -------------------------------------------------------------
       GRANT TYPE: refresh_token
    ------------------------------------------------------------- */
    if (grant_type === "refresh_token") {
      const { refresh_token } = req.body;

      if (!refresh_token) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "Missing refresh_token parameter",
        });
      }

      const dpopHeader = req.headers.dpop;
      let proofResult = null;
      if (!dpopHeader || !dpopHeader.trim()) {
        if (on("M13")) {
          return res.status(400).json({
            error: "invalid_request",
            error_description: "Missing DPoP header",
          });
        }
      }

      // 1. Fetch refresh token record
      const rtRecord = await store.get(`refresh/${refresh_token}`);
      if (!rtRecord) {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Invalid or expired refresh token",
        });
      }

      if (rtRecord.exp && nowS > rtRecord.exp) {
        await store.del(`refresh/${refresh_token}`);
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Refresh token expired",
        });
      }

      // 2. Verify DPoP proof matches rtRecord.jkt
      if (dpopHeader && dpopHeader.trim()) {
        let lastErr = null;

        for (const origin of candidateOrigins) {
          const tokenUrl = `${origin}/oauth/token`;
          try {
            proofResult = await verifyProof({
              proof: dpopHeader,
              htm: "POST",
              htu: tokenUrl,
              expectedJkt: on("M13") ? rtRecord.jkt : undefined,
              nonceStore: on("M13") ? nonceStore : undefined,
              jtiCache,
              skewS: cfg.skew ?? 30,
              clock: cfg.clock,
            });
            lastErr = null;
            break;
          } catch (err) {
            lastErr = err;
            if (err.code !== "htu") {
              break;
            }
          }
        }

        if (lastErr && on("M13")) {
          if (lastErr.code === "use_dpop_nonce") {
            return res.status(400).json({
              error: "use_dpop_nonce",
              error_description: "DPoP nonce required or expired",
            });
          }
          return res.status(400).json({
            error: "invalid_dpop_proof",
            error_description: `DPoP proof verification failed: ${lastErr.message}`,
          });
        }

        if (on("M13") && proofResult && proofResult.jkt !== rtRecord.jkt) {
          return res.status(400).json({
            error: "invalid_grant",
            error_description: "DPoP proof key does not match refresh token binding",
          });
        }
      }

      // 3. Query PIP device status: device MUST be active
      if (on("M22")) {
        let devStatus = "unknown";
        try {
          const pipUrl = cfg.pipUrl || "http://localhost:4003";
          const devRes = await internalFetch(`${pipUrl}/pip/device/${rtRecord.dev}`, {}, cfg);
          if (devRes.ok) {
            const devData = await devRes.json();
            devStatus = devData.status;
          }
        } catch (err) {
          console.warn("⚠️ [Token Refresh] Error querying PIP device status:", err.message);
        }

        if (devStatus !== "active") {
          // Device is revoked or suspended -> reject refresh
          return res.status(400).json({
            error: "invalid_grant",
            error_description: "device_not_active",
          });
        }
      }

      // 4. Rotate Refresh Token
      await store.del(`refresh/${refresh_token}`);
      const newRefreshToken = crypto.randomBytes(32).toString("base64url");
      const boundJkt = proofResult?.jkt || rtRecord.jkt;
      const newRtRecord = {
        ...rtRecord,
        jkt: boundJkt,
        rt: newRefreshToken,
        created_at: nowS,
      };
      await store.set(`refresh/${newRefreshToken}`, newRtRecord);

      // 5. Mint new Access Token keeping acr and auth_time
      const isBearer = !on("M13") && (!dpopHeader || !dpopHeader.trim());
      const userRole = rtRecord.role || (await roleOf(rtRecord.u, store)) || "employee";
      const atPayload = {
        iss: cfg.idpIssuer || "http://localhost:5173",
        aud: "zta-api",
        sub: rtRecord.u,
        dev: rtRecord.dev,
        role: userRole,
        acr: rtRecord.acr,
        auth_time: rtRecord.auth_time,
        iat: nowS,
        exp: nowS + (cfg.tAT ?? 300),
        jti: crypto.randomUUID(),
        client_id: "zta-agent",
      };

      if (!isBearer) {
        atPayload.cnf = {
          jkt: boundJkt,
        };
      }

      const atHeader = {
        alg: "ES256",
        typ: "at+jwt",
      };
      if (idpKey.kid) {
        atHeader.kid = idpKey.kid;
      }

      const accessToken = await new jose.SignJWT(atPayload)
        .setProtectedHeader(atHeader)
        .sign(idpKey.privateKey);

      return res.json({
        access_token: accessToken,
        token_type: isBearer ? "Bearer" : "DPoP",
        expires_in: cfg.tAT ?? 300,
        refresh_token: newRefreshToken,
        scope: "openid profile",
      });
    }

    return res.status(400).json({
      error: "unsupported_grant_type",
      error_description: `Grant type '${grant_type}' is not supported`,
    });
  } catch (err) {
    console.error("❌ [/oauth/token] Error:", err);
    return res.status(500).json({
      error: "server_error",
      error_description: err.message,
    });
  }
}

export default { handleToken };
