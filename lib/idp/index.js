/**
 * @file lib/idp/index.js
 * IdP Gate implementation (Algorithm 2).
 * Exposes OAuth 2.0 / OIDC facade: PAR, Authorize, Token, JWKS, Discovery, WebAuthn.
 */

import express from "express";
import crypto from "node:crypto";
import * as jose from "jose";
import { loadOrCreateSigningKey, publicJwks } from "../keys.js";
import { createStore } from "../store.js";
import { createNonceStore } from "../nonce.js";
import { createJtiCache } from "../jti-cache.js";
import { internalFetch } from "../internal-auth.js";
import { verifyAttestationResult } from "../verifier/ar.js";
import { verifyPassword, roleOf } from "./directory.js";
import { handlePar } from "./par.js";
import { handleAuthorize } from "./authorize.js";
import { handleToken } from "./token.js";
import {
  handleRegisterOptions,
  handleRegisterVerify,
  handleAuthOptions,
  handleAuthVerify,
} from "./webauthn.js";
import { handleKeycloakCallback } from "./keycloak-upstream.js";
import { on } from "../ablation.js";

/**
 * Extracts client IP respecting ZTA_SIM_IP_HEADER if enabled.
 *
 * @param {import('express').Request} req
 * @param {Record<string, any>} cfg
 * @returns {string}
 */
export function getClientIp(req, cfg) {
  if (cfg.simIpHeader && req.headers["x-zta-sim-ip"]) {
    return req.headers["x-zta-sim-ip"];
  }
  return req.socket?.remoteAddress || req.ip || "127.0.0.1";
}

/**
 * Executes Algorithm 2 (Attestation-gated token issuance check) after primary authentication.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {Object} txn - PAR transaction
 * @param {string} u - Authenticated username
 * @param {Object} ctx - { ip, now }
 * @param {Object} context
 * @param {Object} context.store - idp store instance
 * @param {Record<string, any>} context.cfg - Server configuration
 * @param {any} [context.verifierJwks] - Verifier public JWKS / keyset
 * @param {string} [context.role] - Optional role override from upstream
 */
export async function gateAfterPrimaryAuth(req, res, txn, u, ctx, { store, cfg, verifierJwks, role }) {
  const nowMs = cfg.clock ? cfg.clock() : Date.now();
  const nowS = Math.floor(nowMs / 1000);
  const dev = txn.dev;

  // Helper to record login event synchronously to PIP.
  // Every terminal gate failure calls this with success=false; that also ends the
  // OAuth transaction so an abandoned txn cannot linger in the session (N2).
  const recordPipLoginEvent = async (success) => {
    if (!success) delete req.session.oauthTxn;
    try {
      const pipUrl = cfg.pipUrl || "http://localhost:4003";
      await internalFetch(
        `${pipUrl}/pip/login-event`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            sub: u,
            dev,
            ip: ctx.ip,
            t: nowMs,
            success: Boolean(success),
          }),
        },
        cfg
      );
    } catch (err) {
      console.warn("⚠️ [gateAfterPrimaryAuth] Error recording PIP login event:", err.message);
    }
  };

  // 1. Re-verify the AR and its expiry (Alg. 2 line 1)
  let arPayload = null;
  if (on("M9")) {
    let keyOrJwks = verifierJwks || cfg.verifierJwks || cfg.verifierKey;
    if (!keyOrJwks) {
      const verifierUrl = cfg.verifierUrl || "http://localhost:4005";
      keyOrJwks = jose.createRemoteJWKSet(new URL(`${verifierUrl}/v/jwks`));
    }

    try {
      const verified = await verifyAttestationResult(txn.attestation_result, keyOrJwks, {
        clock: cfg.clock,
        clockTolerance: 0,
      });
      arPayload = verified.payload;
    } catch (err) {
      await recordPipLoginEvent(false);
      return res.status(403).json({
        error: "access_denied",
        reason: `ar_invalid: ${err.message}`,
      });
    }

    if (arPayload.exp && nowS > arPayload.exp) {
      await recordPipLoginEvent(false);
      return res.status(403).json({
        error: "access_denied",
        reason: "ar_expired",
      });
    }

    if (arPayload.status !== "pass") {
      await recordPipLoginEvent(false);
      return res.status(403).json({
        error: "access_denied",
        reason: "ar_not_pass",
      });
    }
  } else {
    // M9 OFF: Decode the AR without verifying it; an absent AR is allowed
    if (txn.attestation_result && typeof txn.attestation_result === "string") {
      try {
        arPayload = jose.decodeJwt(txn.attestation_result);
      } catch {
        arPayload = txn.arPayload || {};
      }
    } else {
      arPayload = txn.arPayload || {};
    }
  }

  // Check C2: AR.jkt == dpop_jkt
  if (on("M10")) {
    if (arPayload && arPayload.jkt !== txn.dpop_jkt) {
      await recordPipLoginEvent(false);
      return res.status(403).json({
        error: "access_denied",
        reason: "ar_jkt_mismatch",
      });
    }
  }

  const pipUrl = cfg.pipUrl || "http://localhost:4003";

  // 2. Check PIP device ownership and active status (Alg. 2 line 3)
  // AR.devId in Devices(u) and PIP.Status(AR.devId) == active
  if (on("M12")) {
    let pipDev;
    try {
      const pipDevRes = await internalFetch(`${pipUrl}/pip/device/${dev}`, {}, cfg);
      if (!pipDevRes.ok) {
        await recordPipLoginEvent(false);
        return res.status(403).json({
          error: "access_denied",
          reason: "device_not_found_in_pip",
        });
      }
      pipDev = await pipDevRes.json();
    } catch (err) {
      await recordPipLoginEvent(false);
      return res.status(403).json({
        error: "access_denied",
        reason: "pip_unavailable",
      });
    }

    const deviceOwner = pipDev.user ?? pipDev.owner;
    if (!deviceOwner || deviceOwner !== u || pipDev.status !== "active") {
      await recordPipLoginEvent(false);
      return res.status(403).json({
        error: "access_denied",
        reason: "device_not_assigned_to_user_or_inactive",
      });
    }
  }

  // 3. Compute risk score rho via PIP context (Alg. 2 line 4 / Alg. 4)
  let rho = 0;
  try {
    const ctxRes = await internalFetch(
      `${pipUrl}/pip/context`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sub: u,
          dev,
          ip: ctx.ip,
          now: nowMs,
        }),
      },
      cfg
    );
    if (ctxRes.ok) {
      const ctxData = await ctxRes.json();
      rho = Number(ctxData.risk ?? 0);
    }
  } catch (err) {
    console.warn("⚠️ [gateAfterPrimaryAuth] Error querying PIP context for risk:", err.message);
  }

  const thetaDeny = Number(cfg.thetaDeny ?? 0.85);
  const thetaLogin = Number(cfg.thetaLogin ?? 0.5);

  // 4. Alg. 2 lines 5-8: evaluate risk & step-up conditions
  if (rho >= thetaDeny) {
    await recordPipLoginEvent(false);
    return res.status(403).json({
      error: "access_denied",
      reason: "risk_score_too_high",
      risk: rho,
    });
  }

  if (rho >= thetaLogin || txn.acr_values === "mfa") {
    // Step-up required: verify WebAuthn credential enrolled for (u, dev)
    const credRecord = await store.get(`webauthn/${u}/${dev}`);
    if (!credRecord || !credRecord.credential) {
      await recordPipLoginEvent(false);
      return res.status(403).json({
        error: "mfa_not_enrolled",
        message: `MFA required (risk=${rho}) but not enrolled for user ${u} on device ${dev}`,
        risk: rho,
      });
    }

    // Save transaction state for step-up WebAuthn authentication
    txn.u = u;
    txn.gated = true;
    if (role) txn.role = role;
    txn.risk = rho;
    txn.ip = ctx.ip;
    req.session.oauthTxn = txn;
    req.session.webauthnUser = u;
    req.session.webauthnDev = dev;

    if (req.headers.accept?.includes("application/json") || req.xhr) {
      return res.json({ redirect: "/stepup.html", risk: rho });
    }
    return res.redirect("/stepup.html");
  }

  // 5. Normal login pass (acr = 'pwd')
  await recordPipLoginEvent(true);

  req.session.idpUser = {
    u,
    dev,
    acr: "pwd",
    auth_time: nowS,
  };

  // Issue authorization code bound to dpop_jkt
  const code = crypto.randomBytes(32).toString("base64url");
  const codeRecord = {
    code,
    u,
    dev,
    jkt: txn.dpop_jkt,
    role: role || txn.role || undefined,
    acr: "pwd",
    auth_time: nowS,
    code_challenge: txn.code_challenge,
    code_challenge_method: txn.code_challenge_method,
    redirect_uri: txn.redirect_uri,
    client_id: txn.client_id,
    expires_at: nowMs + (cfg.codeLifetime || 60) * 1000,
  };

  await store.set(`codes/${code}`, codeRecord);
  delete req.session.oauthTxn;

  const redirectUrl = `${txn.redirect_uri}?code=${code}&state=${encodeURIComponent(txn.state || "")}`;

  if (req.headers.accept?.includes("application/json") || req.xhr) {
    return res.json({ redirect: redirectUrl, code, acr: "pwd" });
  }
  return res.redirect(redirectUrl);
}

/**
 * Creates the IdP Express Router.
 *
 * @param {Record<string, any>} cfg
 * @param {Object} [options]
 * @param {Object} [options.store]
 * @param {string} [options.publicDir]
 * @param {any} [options.verifierJwks]
 * @returns {import('express').Router}
 */
export function createIdpRouter(cfg, options = {}) {
  const router = express.Router();
  const store = options.store || cfg.storeInstance || createStore("idp", cfg);
  const publicDir = options.publicDir || "./public";
  const verifierJwks = options.verifierJwks || cfg.verifierJwks;

  const nonceStore = createNonceStore({
    tNonce: cfg.tNonce ?? 60,
    clock: cfg.clock,
  });

  const jtiCache = createJtiCache({
    windowMs: (cfg.wJti ?? 120) * 1000,
    clock: cfg.clock,
  });

  let idpKeyPromise = null;
  function getIdpKey() {
    if (cfg.idpKey) return Promise.resolve(cfg.idpKey);
    if (!idpKeyPromise) {
      idpKeyPromise = loadOrCreateSigningKey("idp", cfg);
    }
    return idpKeyPromise;
  }

  // Warn at startup if simIpHeader is active
  if (cfg.simIpHeader) {
    console.warn("⚠️ [IDP WARNING] ZTA_SIM_IP_HEADER=1 is active: trusting X-ZTA-Sim-IP for demos/eval!");
  }

  /* -------------------------------------------------------------
     OAuth 2.0 / OIDC Authorization Server Endpoints
  ------------------------------------------------------------- */

  // POST /oauth/par
  router.post("/oauth/par", async (req, res) => {
    return handlePar(req, res, { store, cfg, verifierJwks });
  });

  // GET /oauth/authorize
  router.get("/oauth/authorize", async (req, res) => {
    return handleAuthorize(req, res, { store, cfg, publicDir });
  });

  // POST /oauth/login (Local directory mode)
  router.post("/oauth/login", async (req, res) => {
    try {
      const { username, password } = req.body;
      const txn = req.session.oauthTxn;

      if (!txn) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "No active OAuth transaction. Begin with /oauth/authorize.",
        });
      }

      // F5: Check txn expiry
      const nowMs = cfg.clock ? cfg.clock() : Date.now();
      if (txn.expires_at && nowMs > txn.expires_at) {
        delete req.session.oauthTxn;
        return res.status(400).json({
          error: "invalid_request",
          error_description: "OAuth transaction has expired. Please re-authenticate.",
        });
      }

      if (!username || !password) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "Missing username or password",
        });
      }

      const valid = await verifyPassword(username, password, store);
      if (!valid) {
        // Record failed login event
        const ip = getClientIp(req, cfg);
        const nowMs = cfg.clock ? cfg.clock() : Date.now();
        try {
          const pipUrl = cfg.pipUrl || "http://localhost:4003";
          await internalFetch(
            `${pipUrl}/pip/login-event`,
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                sub: username,
                dev: txn.dev,
                ip,
                t: nowMs,
                success: false,
              }),
            },
            cfg
          );
        } catch {}

        return res.status(401).json({
          error: "invalid_credentials",
          message: "Invalid username or password",
        });
      }

      const ctx = {
        ip: getClientIp(req, cfg),
        now: cfg.clock ? cfg.clock() : Date.now(),
      };

      return gateAfterPrimaryAuth(req, res, txn, username, ctx, {
        store,
        cfg,
        verifierJwks,
      });
    } catch (err) {
      console.error("❌ [/oauth/login] Error:", err);
      return res.status(500).json({ error: "login_error", message: err.message });
    }
  });

  // GET /oauth/upstream/callback (Keycloak upstream mode)
  router.get("/oauth/upstream/callback", async (req, res) => {
    return handleKeycloakCallback(req, res, {
      store,
      cfg,
      verifierJwks,
      gateAfterPrimaryAuth,
    });
  });

  // POST /oauth/token
  router.post("/oauth/token", async (req, res) => {
    const idpKey = await getIdpKey();
    return handleToken(req, res, {
      store,
      cfg,
      nonceStore,
      jtiCache,
      idpKey,
    });
  });

  // GET /oauth/jwks
  router.get("/oauth/jwks", async (req, res) => {
    try {
      const key = await getIdpKey();
      res.json(publicJwks(key));
    } catch (err) {
      res.status(500).json({ error: "jwks_error", message: err.message });
    }
  });

  // GET /.well-known/oauth-authorization-server
  router.get("/.well-known/oauth-authorization-server", (req, res) => {
    const rawHost = req.get("host");
    const issuer =
      cfg.idpIssuer && cfg.idpIssuer !== "http://localhost:5173"
        ? cfg.idpIssuer
        : rawHost
        ? `${req.protocol}://${rawHost}`
        : cfg.idpIssuer || "http://localhost:5173";
    res.json({
      issuer,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
      pushed_authorization_request_endpoint: `${issuer}/oauth/par`,
      jwks_uri: `${issuer}/oauth/jwks`,
      dpop_signing_alg_values_supported: ["ES256"],
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      require_pushed_authorization_requests: true,
    });
  });

  // GET /post-login
  router.get("/post-login", async (req, res) => {
    const user = req.session.idpUser;
    if (!user || !user.u || !user.dev) {
      return res.redirect("/");
    }

    const cred = await store.get(`webauthn/${user.u}/${user.dev}`);
    if (!cred || !cred.credential) {
      return res.redirect("/mfa-enroll.html");
    }

    return res.redirect("/remote-work.html");
  });

  /* -------------------------------------------------------------
     WebAuthn Endpoints
  ------------------------------------------------------------- */
  router.get("/mfa/register/options", async (req, res) => {
    return handleRegisterOptions(req, res, { store, cfg });
  });

  router.post("/mfa/register/verify", async (req, res) => {
    return handleRegisterVerify(req, res, { store, cfg });
  });

  router.get("/mfa/auth/options", async (req, res) => {
    return handleAuthOptions(req, res, { store, cfg });
  });

  router.post("/mfa/verify", async (req, res) => {
    return handleAuthVerify(req, res, { store, cfg });
  });

  return router;
}

export default {
  createIdpRouter,
  gateAfterPrimaryAuth,
  getClientIp,
};
