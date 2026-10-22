/**
 * @file services/device-registry.js
 * Device Registry admin service (:4004).
 * Admin façade protected by requireAdmin (Bearer $ADMIN_TOKEN).
 * Proxies queries and status updates to the Attestation Verifier.
 */

import express from "express";
import { loadConfig } from "../lib/config.js";
import { requireAdmin, internalFetch } from "../lib/internal-auth.js";
import { devIdOf } from "../lib/sim-tpm/public-area.js";
import { isMain } from "../lib/main.js";
import { printBannerOnce } from "../lib/ablation.js";
import { mountHealth } from "../lib/health.js";

/**
 * Creates the Device Registry Express application.
 *
 * @param {Record<string, any>} [cfg]
 * @returns {import('express').Express}
 */
export function createApp(cfg = loadConfig()) {
  const app = express();
  mountHealth(app, "registry"); // public liveness + ablation state
  app.use(express.json());

  // Require admin authorization on registry routes
  app.use(requireAdmin(cfg));

  const verifierUrl = cfg.verifierUrl || "http://localhost:4005";

  /**
   * GET /registry/:devId
   * Proxies to Attestation Verifier GET /v/devices/:devId
   */
  app.get("/registry/:devId", async (req, res) => {
    try {
      const devId = req.params.devId;
      const verifierRes = await internalFetch(`${verifierUrl}/v/devices/${devId}`, {}, cfg);

      if (verifierRes.status === 404) {
        return res.status(404).json({ error: "device_not_found" });
      }

      const body = await verifierRes.json();
      res.status(verifierRes.status).json(body);
    } catch (err) {
      console.error("❌ [/registry/:devId] Proxy error:", err);
      res.status(502).json({ error: "verifier_unreachable", message: err.message });
    }
  });

  /**
   * POST /registry/:devId/revoke
   * Sets status to revoked on Verifier, which pushes to PIP synchronously.
   */
  app.post("/registry/:devId/revoke", async (req, res) => {
    try {
      const devId = req.params.devId;
      const verifierRes = await internalFetch(`${verifierUrl}/v/devices/${devId}/status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: "revoked" }),
      }, cfg);

      if (!verifierRes.ok) {
        const body = await verifierRes.json().catch(() => ({}));
        return res.status(verifierRes.status).json(body);
      }

      const now = cfg.clock ? cfg.clock() : Date.now();
      res.json({
        revoked: true,
        at: now,
      });
    } catch (err) {
      console.error("❌ [/registry/:devId/revoke] Proxy error:", err);
      res.status(502).json({ error: "verifier_unreachable", message: err.message });
    }
  });

  /**
   * POST /registry/:devId/reinstate
   * Sets status to active on Verifier, which pushes to PIP synchronously.
   */
  app.post("/registry/:devId/reinstate", async (req, res) => {
    try {
      const devId = req.params.devId;
      const verifierRes = await internalFetch(`${verifierUrl}/v/devices/${devId}/status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: "active" }),
      }, cfg);

      if (!verifierRes.ok) {
        const body = await verifierRes.json().catch(() => ({}));
        return res.status(verifierRes.status).json(body);
      }

      const now = cfg.clock ? cfg.clock() : Date.now();
      res.json({
        reinstated: true,
        at: now,
      });
    } catch (err) {
      console.error("❌ [/registry/:devId/reinstate] Proxy error:", err);
      res.status(502).json({ error: "verifier_unreachable", message: err.message });
    }
  });

  /**
   * POST /registry/inventory
   * Adds device to inventory and creates a one-time enrolment code.
   */
  app.post("/registry/inventory", async (req, res) => {
    try {
      let devId = req.body.devId;
      const ekPublic = req.body.ekPublic || req.body.ekPub;
      const user = req.body.user;

      if (!devId && ekPublic) {
        devId = await devIdOf(ekPublic);
      }

      if (!devId) {
        return res.status(400).json({
          error: "missing_dev_id",
          message: "devId or ekPublic is required",
        });
      }

      if (!user) {
        return res.status(400).json({
          error: "missing_user",
          message: "user is required",
        });
      }

      const invRes = await internalFetch(`${verifierUrl}/v/inventory`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          devId,
          user,
          code: req.body.code,
          ttlMs: req.body.ttlMs,
        }),
      }, cfg);

      const invData = await invRes.json();
      res.status(invRes.status).json(invData);
    } catch (err) {
      console.error("❌ [/registry/inventory] Error:", err);
      res.status(502).json({ error: "verifier_unreachable", message: err.message });
    }
  });

  /**
   * Retired legacy routes
   */
  app.post("/registry/enroll", (req, res) => {
    res.status(410).json({
      error: "endpoint_retired",
      message: "Legacy enrollment endpoint retired. Use /v/enrol flow on Attestation Service.",
    });
  });

  return app;
}

if (isMain(import.meta.url)) {
  printBannerOnce("device-registry");
  const cfg = loadConfig();
  const port = 4004;
  const host = "0.0.0.0";
  const app = createApp(cfg);
  app.listen(port, host, () => {
    console.log(`📘 Device Registry (Admin) listening on http://${host}:${port}`);
  });
}

export default {
  createApp,
};