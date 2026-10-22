/**
 * @file services/attestation-service.js
 * Attestation Verifier service (:4005).
 * Implements Algorithm 1 (Enrol & Appraise), AR signing, inventory checks,
 * and device registry state management.
 */

import express from "express";
import path from "node:path";
import { loadConfig } from "../lib/config.js";
import { createStore } from "../lib/store.js";
import { loadOrCreateSigningKey, publicJwks } from "../lib/keys.js";
import { requireInternal } from "../lib/internal-auth.js";
import { isMain } from "../lib/main.js";
import { startEnrol, finishEnrol } from "../lib/verifier/enrol.js";
import { requestAppraiseNonce, appraiseDevice } from "../lib/verifier/appraise.js";
import { addToInventory } from "../lib/verifier/inventory.js";
import { loadReferenceValues } from "../lib/verifier/reference-values.js";
import { internalFetch } from "../lib/internal-auth.js";
import { printBannerOnce } from "../lib/ablation.js";
import { mountHealth } from "../lib/health.js";

/**
 * Creates the Attestation Verifier Express application.
 *
 * @param {Record<string, any>} [cfg]
 * @returns {import('express').Express}
 */
export function createApp(cfg = loadConfig()) {
  const app = express();
  mountHealth(app, "verifier"); // public liveness + ablation state
  app.use(express.json({ limit: "4mb" }));

  const store = cfg.storeInstance || createStore("verifier", cfg);
  const dataDir = path.resolve(cfg.dataDir || cfg.ZTA_DATA_DIR || "./data");
  const trustAnchors = cfg.trustAnchors || path.join(dataDir, "vendor-ca");
  const ekRootsDir = cfg.ekRootsDir || path.join(dataDir, "ek-roots");
  const referenceValues = cfg.referenceValues || loadReferenceValues();

  let verifierKeyPromise = null;
  function getVerifierKey() {
    if (cfg.verifierKey) {
      return Promise.resolve(cfg.verifierKey);
    }
    if (!verifierKeyPromise) {
      verifierKeyPromise = loadOrCreateSigningKey("verifier", cfg);
    }
    return verifierKeyPromise;
  }

  /* -------------------------------------------------------------
     Public endpoints
  ------------------------------------------------------------- */

  // Public Verifier JWKS endpoint
  app.get("/v/jwks", async (req, res) => {
    try {
      const key = await getVerifierKey();
      res.json(publicJwks(key));
    } catch (err) {
      res.status(500).json({ error: "jwks_error", message: err.message });
    }
  });

  // Algorithm 1: Enrol start (E3)
  app.post("/v/enrol/start", async (req, res) => {
    try {
      const { code, ekCert, akPublic, kbPublic, ekPublic, srkPublic, ekCertChain, user } = req.body;
      const result = await startEnrol({
        code,
        ekCert,
        akPublic,
        kbPublic,
        ekPublic,
        srkPublic,
        ekCertChain,
        user,
        store,
        trustAnchors,
        ekRootsDir,
        cfg,
        clock: cfg.clock,
      });

      if (!result.ok) {
        return res.status(result.status || 403).json({
          error: result.error,
          message: result.message,
        });
      }

      res.json({
        sessionId: result.sessionId,
        blob: result.blob,
        nonce: result.nonce,
      });
    } catch (err) {
      console.error("❌ [/v/enrol/start] Error:", err);
      res.status(500).json({ error: "internal_error", message: err.message });
    }
  });

  // Algorithm 1: Enrol finish (E7–E8)
  app.post("/v/enrol/finish", async (req, res) => {
    try {
      const { sessionId, secret, quote, certify, eventLog } = req.body;
      const result = await finishEnrol({
        sessionId,
        secret,
        quote,
        certify,
        eventLog,
        store,
        cfg,
        referenceValues,
        clock: cfg.clock,
      });

      if (!result.ok) {
        return res.status(result.status || 403).json({
          error: result.error,
          message: result.message,
        });
      }

      res.json({
        devId: result.devId,
        jkt: result.jkt,
      });
    } catch (err) {
      console.error("❌ [/v/enrol/finish] Error:", err);
      res.status(500).json({ error: "internal_error", message: err.message });
    }
  });

  // Appraisal: Nonce request (L2)
  app.post("/v/appraise/nonce", async (req, res) => {
    try {
      const { devId } = req.body;
      const result = await requestAppraiseNonce({
        devId,
        store,
        clock: cfg.clock,
      });

      if (!result.ok) {
        return res.status(result.status || 403).json({
          error: result.error,
          message: result.message,
        });
      }

      res.json({
        nonceId: result.nonceId,
        nonce: result.nonce,
      });
    } catch (err) {
      console.error("❌ [/v/appraise/nonce] Error:", err);
      res.status(500).json({ error: "internal_error", message: err.message });
    }
  });

  // Appraisal: Quote evaluation & AR issuance (L4–L5)
  app.post("/v/appraise", async (req, res) => {
    try {
      const { devId, nonceId, quote, eventLog } = req.body;
      const verifierKey = await getVerifierKey();
      const result = await appraiseDevice({
        devId,
        nonceId,
        quote,
        eventLog,
        store,
        cfg,
        verifierKey,
        referenceValues,
        clock: cfg.clock,
      });

      if (!result.ok) {
        return res.status(result.status || 403).json({
          error: result.error,
          reason: result.reason,
        });
      }

      res.json({
        ar: result.ar,
      });
    } catch (err) {
      console.error("❌ [/v/appraise] Error:", err);
      res.status(500).json({ error: "internal_error", message: err.message });
    }
  });

  // Retired legacy endpoint pointer
  app.post("/attest/verify", (req, res) => {
    res.status(410).json({
      error: "attest_verify_retired",
      message: "Legacy attestation endpoint retired. Use /v/enrol and /v/appraise.",
    });
  });

  /* -------------------------------------------------------------
     Internal endpoints (Require X-ZTA-Internal)
  ------------------------------------------------------------- */
  const internalRouter = express.Router();
  internalRouter.use(requireInternal(cfg));

  // List enrolled devices
  internalRouter.get("/devices", async (req, res) => {
    try {
      const list = await store.list("registry");
      const devices = list.map((item) => ({
        devId: item.devId || item.id || item.key,
        user: item.user,
        status: item.status,
        jkt: item.jkt,
        enrolledAt: item.enrolledAt,
        last: item.last,
        akPub: item.akPub,
        kbPub: item.kbPub,
      }));
      res.json(devices);
    } catch (err) {
      res.status(500).json({ error: "devices_fetch_failed", message: err.message });
    }
  });

  // Get specific enrolled device
  internalRouter.get("/devices/:devId", async (req, res) => {
    try {
      const devId = req.params.devId;
      const dev = await store.get(`registry/${devId}`);
      if (!dev) {
        return res.status(404).json({ error: "device_not_found" });
      }
      res.json({ devId, ...dev });
    } catch (err) {
      res.status(500).json({ error: "device_fetch_failed", message: err.message });
    }
  });

  // Update device status (e.g. revoke) and push synchronously to PIP
  internalRouter.post("/devices/:devId/status", async (req, res) => {
    try {
      const devId = req.params.devId;
      const { status } = req.body;
      if (!status) {
        return res.status(400).json({ error: "missing_status" });
      }

      const dev = await store.get(`registry/${devId}`);
      if (!dev) {
        return res.status(404).json({ error: "device_not_found" });
      }

      dev.status = status;
      await store.set(`registry/${devId}`, dev);

      // Push synchronously to PIP
      if (cfg?.pipUrl) {
        try {
          await internalFetch(`${cfg.pipUrl}/pip/device/${devId}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status }),
          }, cfg);
        } catch (err) {
          console.warn(`⚠️ [/v/devices/:devId/status] PIP push error for ${devId}:`, err.message);
        }
      }

      res.json({ ok: true, devId, status });
    } catch (err) {
      res.status(500).json({ error: "status_update_failed", message: err.message });
    }
  });

  // Add device to inventory
  internalRouter.post("/inventory", async (req, res) => {
    try {
      const { devId, user, code, ttlMs } = req.body;
      if (!devId || !user) {
        return res.status(400).json({ error: "missing_dev_id_or_user", message: "devId and user are required" });
      }

      const inv = await addToInventory(store, {
        devId,
        user,
        code,
        ttlMs,
        clock: cfg.clock,
      });

      res.json(inv);
    } catch (err) {
      res.status(500).json({ error: "inventory_add_failed", message: err.message });
    }
  });

  app.use("/v", internalRouter);

  return app;
}

if (isMain(import.meta.url)) {
  printBannerOnce("attestation-service");
  const cfg = loadConfig();
  const port = 4005;
  const host = "0.0.0.0";
  const app = createApp(cfg);
  app.listen(port, host, () => {
    console.log(`🛡️ Attestation Service listening on http://${host}:${port}`);
  });
}

export default {
  createApp,
};
