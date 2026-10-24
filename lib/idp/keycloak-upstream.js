/**
 * @file lib/idp/keycloak-upstream.js
 * Optional upstream Keycloak authentication mode (IDP_MODE=keycloak).
 * The gate acts as a confidential OAuth2 client to Keycloak, uses Keycloak for
 * password authentication & directory lookup, and then executes gateAfterPrimaryAuth.
 */

import crypto from "node:crypto";
import * as jose from "jose";

import { getClientIp } from "./client-ip.js";

// Keycloak signing keys, fetched from its JWKS endpoint and cached per issuer
const keycloakJwks = new Map();
function jwksFor(issuer) {
  if (!keycloakJwks.has(issuer)) {
    keycloakJwks.set(issuer, jose.createRemoteJWKSet(new URL(`${issuer}/protocol/openid-connect/certs`)));
  }
  return keycloakJwks.get(issuer);
}

function safeEqualStrings(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

/**
 * Redirects the browser to Keycloak for primary authentication.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {Object} txn - PAR transaction
 * @param {Record<string, any>} cfg
 */
export async function redirectToKeycloak(req, res, txn, cfg) {
  const code_verifier = crypto.randomBytes(32).toString("base64url");
  const code_challenge = crypto.createHash("sha256").update(code_verifier).digest("base64url");

  // state binds the callback to this browser session; nonce binds the ID token to this request
  const state = crypto.randomBytes(32).toString("base64url");
  const nonce = crypto.randomBytes(32).toString("base64url");

  req.session.upstream_code_verifier = code_verifier;
  req.session.upstream_state = state;
  req.session.upstream_nonce = nonce;
  req.session.oauthTxn = txn;

  const keycloakIssuer = cfg.keycloakIssuer || "http://localhost:8080/realms/zta-realm";
  const authEndpoint = `${keycloakIssuer}/protocol/openid-connect/auth`;
  const redirectUri = `${cfg.idpIssuer || "http://localhost:5173"}/oauth/upstream/callback`;

  const params = new URLSearchParams({
    client_id: cfg.keycloakClientId || "zta-gate",
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "openid profile email roles",
    code_challenge,
    code_challenge_method: "S256",
    state,
    nonce,
  });

  return res.redirect(`${authEndpoint}?${params.toString()}`);
}

/**
 * Handles the callback from Keycloak after user authentication.
 * Exchanges the authorization code for tokens, extracts user and role, and calls gateAfterPrimaryAuth.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {Object} context
 * @param {Object} context.store
 * @param {Record<string, any>} context.cfg
 * @param {any} [context.verifierJwks]
 * @param {Function} context.gateAfterPrimaryAuth
 */
export async function handleKeycloakCallback(req, res, { store, cfg, verifierJwks, gateAfterPrimaryAuth }) {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) {
      return res.status(401).send(`Upstream Keycloak authentication failed: ${error} - ${error_description || ""}`);
    }

    if (!code) {
      return res.status(400).send("Missing authorization code from Keycloak callback");
    }

    const txn = req.session.oauthTxn;
    if (!txn) {
      return res.status(400).send("No active OAuth transaction found for callback");
    }

    // Single use: the stored state, nonce and verifier are consumed by this callback
    const expectedState = req.session.upstream_state;
    const expectedNonce = req.session.upstream_nonce;
    const code_verifier = req.session.upstream_code_verifier;
    delete req.session.upstream_state;
    delete req.session.upstream_nonce;
    delete req.session.upstream_code_verifier;

    if (!expectedState || !safeEqualStrings(String(state || ""), expectedState)) {
      return res.status(400).send("Upstream callback state does not match this session");
    }

    const keycloakIssuer = cfg.keycloakIssuer || "http://localhost:8080/realms/zta-realm";
    const tokenEndpoint = `${keycloakIssuer}/protocol/openid-connect/token`;
    const redirectUri = `${cfg.idpIssuer || "http://localhost:5173"}/oauth/upstream/callback`;

    const bodyParams = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: cfg.keycloakClientId || "zta-gate",
      code: String(code),
      redirect_uri: redirectUri,
    });

    if (code_verifier) {
      bodyParams.append("code_verifier", code_verifier);
    }

    const headers = {
      "Content-Type": "application/x-www-form-urlencoded",
    };

    if (cfg.keycloakClientSecret) {
      const basic = Buffer.from(`${cfg.keycloakClientId || "zta-gate"}:${cfg.keycloakClientSecret}`).toString("base64");
      headers["Authorization"] = `Basic ${basic}`;
    }

    const tokenRes = await globalThis.fetch(tokenEndpoint, {
      method: "POST",
      headers,
      body: bodyParams.toString(),
    });

    if (!tokenRes.ok) {
      const errText = await tokenRes.text();
      return res.status(502).send(`Upstream Keycloak token exchange failed: ${errText}`);
    }

    const tokenData = await tokenRes.json();
    if (!tokenData.id_token) {
      return res.status(502).json({ error: "bad_gateway", message: "Upstream IdP token response has no ID token" });
    }

    // Identity and role come only from an ID token Keycloak signed for this client and request
    let claims;
    try {
      ({ payload: claims } = await jose.jwtVerify(tokenData.id_token, cfg.keycloakJwks || jwksFor(keycloakIssuer), {
        issuer: keycloakIssuer,
        audience: cfg.keycloakClientId || "zta-gate",
        currentDate: cfg.clock ? new Date(cfg.clock()) : undefined,
      }));
    } catch (err) {
      return res.status(401).json({ error: "upstream_id_token_invalid", message: err.message });
    }
    if (!expectedNonce || !safeEqualStrings(String(claims.nonce || ""), expectedNonce)) {
      return res.status(401).json({ error: "upstream_id_token_invalid", message: "ID token nonce does not match this request" });
    }

    const preferredUsername = claims.preferred_username || claims.sub;
    const roles = claims.realm_access?.roles || [];
    if (!preferredUsername) {
      return res.status(502).json({
        error: "bad_gateway",
        message: "Upstream ID token has no preferred_username or sub claim",
      });
    }

    // Role mapping
    const assignedRole = roles.includes("auditor") ? "auditor" : "employee";

    // Set upstream tokens in session for possible logout
    req.session.upstreamIdToken = tokenData.id_token;

    // Run Algorithm 2
    const ctx = {
      ip: getClientIp(req, cfg),
      now: cfg.clock ? cfg.clock() : Date.now(),
    };

    return gateAfterPrimaryAuth(req, res, txn, preferredUsername, ctx, {
      store,
      cfg,
      verifierJwks,
      role: assignedRole,
    });
  } catch (err) {
    console.error("❌ Keycloak upstream callback error:", err);
    return res.status(500).send(`Internal error during upstream callback: ${err.message}`);
  }
}

/**
 * Returns Keycloak end_session_endpoint URL if configured.
 * @param {string} [idTokenHint]
 * @param {Record<string, any>} cfg
 * @returns {string|null}
 */
export function getKeycloakLogoutUrl(idTokenHint, cfg) {
  if (cfg.idpMode !== "keycloak") return null;
  const keycloakIssuer = cfg.keycloakIssuer || "http://localhost:8080/realms/zta-realm";
  const endSessionEndpoint = `${keycloakIssuer}/protocol/openid-connect/logout`;
  const postLogout = cfg.idpIssuer || "http://localhost:5173";

  const params = new URLSearchParams({
    post_logout_redirect_uri: postLogout,
  });
  if (idTokenHint) {
    params.set("id_token_hint", idTokenHint);
  }

  return `${endSessionEndpoint}?${params.toString()}`;
}

export default {
  redirectToKeycloak,
  handleKeycloakCallback,
  getKeycloakLogoutUrl,
};
