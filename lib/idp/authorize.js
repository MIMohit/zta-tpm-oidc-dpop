/**
 * @file lib/idp/authorize.js
 * OAuth 2.0 / OIDC Authorization Endpoint (/oauth/authorize).
 * Loads transaction from PAR and renders login page (local mode) or redirects to Keycloak.
 */

import path from "node:path";
import { redirectToKeycloak } from "./keycloak-upstream.js";
import { on } from "../ablation.js";

/**
 * Handles GET /oauth/authorize
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {Object} context
 * @param {Object} context.store - idp store instance
 * @param {Record<string, any>} context.cfg - Server config
 * @param {string} [context.publicDir] - Absolute path to public directory
 */
export async function handleAuthorize(req, res, { store, cfg, publicDir }) {
  try {
    const { client_id, request_uri } = req.query;

    if (!request_uri) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing request_uri parameter (PAR is required)",
      });
    }

    const txn = await store.get(`par/${request_uri}`);
    if (!txn) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Unknown or expired request_uri",
      });
    }

    const nowMs = cfg.clock ? cfg.clock() : Date.now();
    if (txn.expires_at && nowMs > txn.expires_at) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Expired request_uri",
      });
    }

    if (client_id && txn.client_id && client_id !== txn.client_id) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "client_id mismatch with PAR request",
      });
    }

    // F5: Single-use PAR request_uri (delete from store upon consumption)
    if (on("M11")) {
      await store.del(`par/${request_uri}`);
    }

    // Save transaction in user session
    req.session.oauthTxn = txn;

    // Upstream Keycloak mode
    if (cfg.idpMode === "keycloak") {
      return redirectToKeycloak(req, res, txn, cfg);
    }

    // Local mode (default): serve login.html
    const loginHtmlPath = path.resolve(publicDir || "./public", "login.html");
    return res.sendFile(loginHtmlPath);
  } catch (err) {
    console.error("❌ [/oauth/authorize] Error:", err);
    return res.status(500).json({
      error: "server_error",
      error_description: err.message,
    });
  }
}

export default { handleAuthorize };
