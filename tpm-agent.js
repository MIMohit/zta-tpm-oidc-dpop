/**
 * @file tpm-agent.js
 * Local Client Agent HTTP service (:7000, 127.0.0.1).
 * Hosts ZtaClient over HTTP with CORS restricted to http://localhost:5173.
 * TPM backend chosen by lib/tpm-factory.js: TPM_BACKEND=sim (default, data/agent/$AGENT_ID),
 * tpm (real TPM 2.0 via TPM_DEVICE=auto|tbs|linux|tcp; 503 tpm_unavailable while unreachable),
 * auto (real TPM if reachable, else SimTpm with a loud warning) and diagnostic-only windows-ek.
 */

import express from "express";
import cors from "cors";
import path from "node:path";
import process from "node:process";
import { loadConfig } from "./lib/config.js";
import { isMain } from "./lib/main.js";
import { internalFetch } from "./lib/internal-auth.js";
import { ZtaClient } from "./lib/agent-client.js";
import { createTpmBackend } from "./lib/tpm-factory.js";

/**
 * Creates and configures the TPM Agent Express application.
 *
 * @param {Record<string, any>} [cfg] - Configuration overrides
 * @param {Object} [options] - Injected test options or pre-configured client/TPM
 * @param {ZtaClient} [options.client] - Pre-instantiated ZtaClient
 * @param {any} [options.tpm] - Pre-instantiated TPM backend
 * @returns {import('express').Express}
 */
export function createApp(cfg = loadConfig(), options = {}) {
  const app = express();

  // CORS allowing only the trusted local web portal
  app.use(
    cors({
      origin: "http://localhost:5173",
      methods: ["GET", "POST", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization", "DPoP", "Accept"],
      credentials: true,
    })
  );

  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));

  let client = options.client || null;
  let clientPromise = null;
  let tpmInfo = options.tpmInfo || null;

  async function getClient() {
    if (client) return client;
    if (!clientPromise) {
      clientPromise = (async () => {
        let tpm = options.tpm;
        if (!tpm) {
          tpmInfo = await createTpmBackend(cfg, options);
          tpm = tpmInfo.tpm;
        } else {
          tpmInfo = {
            tpm,
            kind: tpm.kind || (tpm.constructor?.name === "RealTpm" ? "tpm" : "sim"),
            tpmBackend: cfg.tpmBackend || process.env.TPM_BACKEND || "sim",
            available: true,
          };
        }
        client = new ZtaClient({ tpm, cfg });
        if (client.enrolled) {
          client.startReattestation();
        }
        return client;
      })();
    }
    return clientPromise;
  }

  /**
   * Records a lost TPM (TPM_UNAVAILABLE after the backend's own reconnect attempt failed):
   * status reports it, TPM routes answer 503 and the next request retries the connection.
   * @returns {boolean} true when err means the TPM is unavailable
   */
  function noteTpmFailure(err) {
    if (err?.code !== "TPM_UNAVAILABLE" || !tpmInfo) return false;
    tpmInfo.available = false;
    tpmInfo.reason = err.message;
    if (typeof tpmInfo.reconnect !== "function" && typeof tpmInfo.tpm?.ping === "function") {
      tpmInfo.reconnect = async function reconnect() {
        try {
          await this.tpm.ping();
          this.available = true;
          this.reason = null;
          return true;
        } catch (e) {
          this.reason = e.message;
          return false;
        }
      };
    }
    console.warn(`⚠️ [tpm-agent] TPM unavailable: ${err.message}; answering 503 tpm_unavailable until it is reachable`);
    return true;
  }

  function tpmUnavailable(res) {
    return res.status(503).json({
      error: "tpm_unavailable",
      message: `TPM is unavailable: ${tpmInfo?.reason || "connection failed"}`,
    });
  }

  async function ensureTpmAvailable() {
    await getClient();
    if (tpmInfo && !tpmInfo.available) {
      if (typeof tpmInfo.reconnect === "function") {
        await tpmInfo.reconnect();
      }
    }
    return tpmInfo?.available ?? true;
  }

  // Eagerly trigger client init; app.locals.tpmReady resolves to the active backend info
  app.locals.tpmReady = getClient().then(
    () => tpmInfo,
    (err) => {
      console.warn("⚠️ [tpm-agent] Eager client init warning:", err.message);
      return tpmInfo;
    }
  );

  /* -------------------------------------------------------------
     Agent HTTP API Routes
  ------------------------------------------------------------- */

  // GET /agent/status → {enrolled, devId, jkt, lastAttestation, session: {user, acr, exp} | null}
  app.get("/agent/status", async (req, res) => {
    try {
      const c = await getClient();
      if (tpmInfo && !tpmInfo.available && typeof tpmInfo.reconnect === "function") {
        await tpmInfo.reconnect();
      } else if (tpmInfo?.available && typeof tpmInfo.tpm?.ping === "function") {
        // Real TPM: probe so status reflects a TPM lost (or reset and recovered) mid-run
        await tpmInfo.tpm.ping().catch((err) => noteTpmFailure(err));
      }
      const status = c.getStatus();
      const currentKind = tpmInfo?.kind || "sim";
      status.tpmBackend = tpmInfo?.tpmBackend || cfg.tpmBackend || "sim";
      status.kind = currentKind;
      status.backend = currentKind === "sim-fallback" ? "sim" : currentKind;
      if (tpmInfo?.device) status.tpmDevice = tpmInfo.device;
      if (tpmInfo?.fallback) {
        status.fallback = true;
        status.reason = tpmInfo.reason;
        status.warning = "TPM_BACKEND=auto: no real TPM reachable; using the SIMULATED TPM (device identity is NOT hardware-backed)";
      }
      if (tpmInfo && !tpmInfo.available) {
        status.tpm = "unavailable";
        status.reason = tpmInfo.reason;
      } else {
        status.tpm = "ok";
      }

      if (status.enrolled && status.devId) {
        try {
          const pipUrl = cfg.pipUrl || "http://localhost:4003";
          const pipRes = await internalFetch(`${pipUrl}/pip/device/${status.devId}`, {}, cfg);
          if (pipRes.ok) {
            const pipData = await pipRes.json();
            status.deviceStatus = pipData.status;
            status.pipStatus = pipData.status;
          }
        } catch {}
      }
      return res.json(status);
    } catch (err) {
      console.error("❌ [/agent/status] Error:", err);
      return res.status(500).json({ error: "status_failed", message: err.message });
    }
  });

  // POST /agent/enrol {code}
  app.post("/agent/enrol", async (req, res) => {
    try {
      const available = await ensureTpmAvailable();
      if (!available) {
        return tpmUnavailable(res);
      }
      const { code } = req.body || {};
      if (!code) {
        return res.status(400).json({ error: "missing_code", message: "Enrolment code required" });
      }
      const c = await getClient();
      const result = await c.enrol(code);
      return res.json(result);
    } catch (err) {
      console.error("❌ [/agent/enrol] Error:", err);
      if (noteTpmFailure(err)) return tpmUnavailable(res);
      return res.status(400).json({ error: "enrol_failed", message: err.message });
    }
  });

  // POST /agent/login {acr_values?} → {authorize_url}
  app.post("/agent/login", async (req, res) => {
    try {
      const available = await ensureTpmAvailable();
      if (!available) {
        return tpmUnavailable(res);
      }
      const c = await getClient();
      const acrValues = req.body?.acr_values || req.body?.acrValues;
      const loginResult = await c.startLogin({ acrValues });
      return res.json({
        authorize_url: loginResult.authorizeUrl,
        authorizeUrl: loginResult.authorizeUrl,
        request_uri: loginResult.requestUri,
        state: loginResult.state,
      });
    } catch (err) {
      console.error("❌ [/agent/login] Error:", err);
      if (noteTpmFailure(err)) return tpmUnavailable(res);
      return res.status(400).json({ error: "login_start_failed", message: err.message });
    }
  });

  // GET or POST /callback?code&state → finishLogin, then 302 http://localhost:5173/post-login
  app.all("/callback", async (req, res) => {
    try {
      const code = req.query.code || req.body?.code;
      const state = req.query.state || req.body?.state;
      if (!code) {
        return res.status(400).send("Missing authorization code");
      }
      const c = await getClient();
      await c.finishLogin(String(code), state ? String(state) : undefined);
      const postLoginUrl = cfg.idpIssuer
        ? `${cfg.idpIssuer}/post-login`
        : "http://localhost:5173/post-login";
      return res.redirect(302, postLoginUrl);
    } catch (err) {
      console.error("❌ [/callback] Error:", err);
      if (noteTpmFailure(err)) return tpmUnavailable(res);
      return res.status(500).send("Login failed: " + err.message);
    }
  });

  // GET /agent/resource/{*name} → proxies client.request()
  app.get("/agent/resource/{*name}", async (req, res) => {
    try {
      const available = await ensureTpmAvailable();
      if (!available) {
        return tpmUnavailable(res);
      }
      const rawName = req.params.name;
      const resourceName = Array.isArray(rawName) ? rawName.join("/") : String(rawName || "");
      if (!resourceName) {
        return res.status(400).json({ error: "missing_resource" });
      }

      const c = await getClient();
      const result = await c.request(resourceName);

      if (result.step_up || result.stepUp) {
        return res.status(401).json({
          step_up: true,
          stepUp: true,
          status: 401,
          error: "insufficient_user_authentication",
          acr_values: "mfa",
          ...result,
        });
      }

      if (result.status && result.status !== 200) {
        return res.status(result.status).json(result);
      }

      return res.status(200).json(result);
    } catch (err) {
      console.error("❌ [/agent/resource] Error:", err.message);
      if (noteTpmFailure(err)) return tpmUnavailable(res);
      if (
        err.message &&
        (err.message.includes("device_not_active") ||
          err.message.includes("device_revoked") ||
          err.message.includes("device_suspended"))
      ) {
        return res.status(403).json({ error: "device_not_active", message: err.message, status: 403 });
      }
      return res.status(500).json({ error: "request_failed", message: err.message });
    }
  });

  // POST /agent/logout
  app.post("/agent/logout", async (req, res) => {
    try {
      const c = await getClient();
      c.logout();
      return res.json({ ok: true });
    } catch (err) {
      console.error("❌ [/agent/logout] Error:", err);
      return res.status(500).json({ error: "logout_failed", message: err.message });
    }
  });

  // POST /agent/debug/tamper - dev-only (VERIFY3 V5): needs an explicit ZTA_DEBUG=1 outside
  // production, a JSON body (so a cross-site "simple" request cannot reach it without a CORS
  // preflight), no foreign Origin, and the simulated or software (tcp) TPM.
  app.post("/agent/debug/tamper", async (req, res) => {
    try {
      const isDebug = Boolean(cfg.debug) && cfg.ztaEnv !== "production" && process.env.ZTA_ENV !== "production";
      if (!isDebug) {
        return res
          .status(403)
          .json({ error: "debug_disabled", message: "Tamper disabled without ZTA_DEBUG=1 (never in production)" });
      }
      const origin = req.get("Origin");
      if (origin && origin !== "http://localhost:5173") {
        return res.status(403).json({ error: "origin_not_allowed", message: `Origin ${origin} may not call debug endpoints` });
      }
      if (!req.is("application/json")) {
        return res.status(415).json({ error: "unsupported_media_type", message: "Content-Type must be application/json" });
      }
      const c = await getClient();
      if (tpmInfo?.kind === "tpm" && tpmInfo.device && tpmInfo.device !== "tcp") {
        return res.status(403).json({ error: "tamper_not_allowed", message: "Tamper is only allowed on the software TPM (tcp)" });
      }
      await c.tamper(req.body?.desc || "agent debug tamper");
      return res.json({ tampered: true });
    } catch (err) {
      console.error("❌ [/agent/debug/tamper] Error:", err);
      if (noteTpmFailure(err)) return tpmUnavailable(res);
      return res.status(500).json({ error: "tamper_failed", message: err.message });
    }
  });

  return app;
}

if (isMain(import.meta.url)) {
  const cfg = loadConfig();
  const PORT = Number(process.env.PORT || 7000);
  const HOST = process.env.HOST || "127.0.0.1";
  const app = createApp(cfg);

  const server = app.listen(PORT, HOST, () => {
    console.log(`\n============================================================`);
    console.log(`🧩 Client TPM Agent running at http://${HOST}:${PORT}`);
    console.log(`🛡️ TPM_BACKEND: ${cfg.tpmBackend} | Target IdP: ${cfg.idpIssuer}`);
    console.log(`============================================================\n`);
    app.locals.tpmReady.then((info) => {
      if (!info) return;
      const active = info.kind === "sim-fallback" ? "sim (fallback)" : info.kind;
      const state = info.available ? "ready" : `UNAVAILABLE (${info.reason}) - 503 tpm_unavailable until reachable`;
      console.log(`🛡️ Active TPM backend: ${active}${info.device ? ` via ${info.device}` : ""} - ${state}`);
    });
  });

  let serverIpv6 = null;
  if (HOST === "127.0.0.1") {
    try {
      serverIpv6 = app.listen(PORT, "::1", () => {});
      serverIpv6.on("error", () => {});
    } catch {}
  }

  process.on("SIGINT", () => {
    server.close(() => {
      if (serverIpv6) {
        serverIpv6.close();
      }
      console.log("\n✅ TPM Agent shut down gracefully");
      process.exit(0);
    });
  });
}

export default { createApp };
