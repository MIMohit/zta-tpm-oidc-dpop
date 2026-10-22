import express from "express";
import { loadConfig } from "./lib/config.js";
import { createStore } from "./lib/store.js";
import { requireInternal } from "./lib/internal-auth.js";
import { isMain } from "./lib/main.js";
import { risk } from "./lib/risk.js";
import { printBannerOnce } from "./lib/ablation.js";
import { mountHealth } from "./lib/health.js";

/**
 * Creates the PIP Express application.
 * @param {Record<string, any>} [cfg]
 * @returns {import('express').Express}
 */
export function createApp(cfg = loadConfig()) {
  const app = express();
  mountHealth(app, "pip"); // public liveness + ablation state
  app.use(express.json());

  // Require internal service token on all PIP routes
  app.use(requireInternal(cfg));

  const store = cfg.storeInstance || createStore("pip", cfg);

  /* -------------------------------
     UPDATE device attributes (Verifier only)
  -------------------------------- */
  app.post("/pip/device/:devId", async (req, res) => {
    const startTs = Date.now();
    const devId = req.params.devId || req.params.deviceId;

    const existing = (await store.get(`devices/${devId}`)) || {};
    const updated = { ...existing, devId, ...req.body };
    if (req.body.user && !updated.owner) updated.owner = req.body.user;
    if (req.body.owner && !updated.user) updated.user = req.body.owner;

    await store.set(`devices/${devId}`, updated);

    const pipDelay = Date.now() - startTs;
    console.log("⏱️ PIP delay:", pipDelay, "ms");
    res.json({ ok: true, device: updated });
  });

  /* -------------------------------
     READ device attributes
  -------------------------------- */
  app.get("/pip/device/:devId", async (req, res) => {
    const startTs = Date.now();
    const devId = req.params.devId || req.params.deviceId;

    const dev = await store.get(`devices/${devId}`);
    if (!dev) {
      const pipDelay = Date.now() - startTs;
      console.log("⏱️ PIP delay:", pipDelay, "ms");
      return res.json({ status: "unknown" });
    }

    const nowMs = cfg.clock ? cfg.clock() : Date.now();
    let attestation_age_s = 999999;
    if (dev.last_good_attestation !== undefined) {
      const lastGoodMs =
        dev.last_good_attestation < 1e11
          ? dev.last_good_attestation * 1000
          : dev.last_good_attestation;
      attestation_age_s = Math.max(0, Math.floor((nowMs - lastGoodMs) / 1000));
    } else if (typeof dev.attestation_age_s === "number") {
      attestation_age_s = dev.attestation_age_s;
    }

    const user = dev.user ?? dev.owner ?? null;
    const responseData = {
      devId,
      user,
      owner: user,
      status: dev.status || "unknown",
      jkt: dev.jkt,
      last_good_attestation: dev.last_good_attestation,
      attestation_age_s,
    };

    const pipDelay = Date.now() - startTs;
    console.log("⏱️ PIP delay:", pipDelay, "ms");
    res.json(responseData);
  });

  /* -------------------------------
     RECORD login event (IdP only)
  -------------------------------- */
  app.post("/pip/login-event", async (req, res) => {
    const startTs = Date.now();
    const { sub, dev, ip, t, success } = req.body;
    if (!sub) {
      return res.status(400).json({ error: "missing_sub" });
    }

    const nowMs = cfg.clock ? cfg.clock() : Date.now();
    const eventTime =
      t !== undefined ? (t < 1e11 ? t * 1000 : t) : nowMs;

    const event = {
      sub,
      dev,
      ip,
      t: eventTime,
      success: success === undefined ? true : Boolean(success),
    };

    const history = (await store.get(`history/${sub}`)) || [];
    history.push(event);
    if (history.length > 200) {
      history.splice(0, history.length - 200);
    }
    await store.set(`history/${sub}`, history);

    const pipDelay = Date.now() - startTs;
    console.log("⏱️ PIP delay:", pipDelay, "ms");
    res.json({ ok: true });
  });

  /* -------------------------------
     CONTEXT query (PDP / IdP)
  -------------------------------- */
  app.post("/pip/context", async (req, res) => {
    const startTs = Date.now();
    const { sub, dev, ip, now } = req.body;

    const nowMs =
      now !== undefined
        ? now < 1e11
          ? now * 1000
          : now
        : cfg.clock
        ? cfg.clock()
        : Date.now();

    const device = dev ? await store.get(`devices/${dev}`) : null;
    const status = device?.status || "unknown";
    const owner = device?.user ?? device?.owner ?? null;

    let attestation_age_s = 999999;
    if (device?.last_good_attestation !== undefined) {
      const lastGoodMs =
        device.last_good_attestation < 1e11
          ? device.last_good_attestation * 1000
          : device.last_good_attestation;
      attestation_age_s = Math.max(0, Math.floor((nowMs - lastGoodMs) / 1000));
    } else if (typeof device?.attestation_age_s === "number") {
      attestation_age_s = device.attestation_age_s;
    }

    const history = sub ? (await store.get(`history/${sub}`)) || [] : [];
    const deviceForRisk = device
      ? { ...device, attestation_age_s }
      : { attestation_age_s };

    const { rho, f } = risk({
      history,
      device: deviceForRisk,
      ctx: { sub, dev, ip, t: nowMs },
      cfg,
    });

    const pipDelay = Date.now() - startTs;
    console.log("⏱️ PIP delay:", pipDelay, "ms");

    res.json({
      status,
      owner,
      attestation_age_s,
      risk: rho,
      features: f,
    });
  });

  return app;
}

if (isMain(import.meta.url)) {
  printBannerOnce("pip");
  const cfg = loadConfig();
  const PORT = process.env.PORT || 4003;
  createApp(cfg).listen(PORT, () =>
    console.log(`🔍 PIP running on http://localhost:${PORT}`)
  );
}

export default { createApp };
