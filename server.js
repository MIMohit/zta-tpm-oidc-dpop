/**
 * @file server.js
 * Zero-Trust Portal & IdP Gate (:5173).
 * Implements Algorithm 2: attestation-gated token issuance, local/Keycloak IdP,
 * WebAuthn step-up authentication, and hardware-attested DPoP code binding.
 */

import express from "express";
import cors from "cors";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import session from "express-session";
import { loadConfig } from "./lib/config.js";
import { isMain } from "./lib/main.js";
import { internalFetch } from "./lib/internal-auth.js";
import { createIdpRouter } from "./lib/idp/index.js";
import { getKeycloakLogoutUrl } from "./lib/idp/keycloak-upstream.js";
import { printBannerOnce } from "./lib/ablation.js";
import { mountHealth } from "./lib/health.js";
import { listen, tlsServerOptions } from "./lib/tls.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Creates and configures the Express portal & IdP gate application.
 *
 * @param {Record<string, any>} [cfg] - Configuration overrides
 * @returns {import('express').Express}
 */
export function createApp(cfg = loadConfig()) {
  const app = express();
  mountHealth(app, "idp"); // public liveness + ablation state

  // Public static assets (cyber theme, html pages)
  app.use(express.static(path.join(__dirname, "public")));

  // F7: CORS restricted to http://localhost:5173
  app.use(
    cors({
      origin: cfg.portalCorsOrigin || "http://localhost:5173",
      credentials: true,
      exposedHeaders: ["DPoP-Nonce", "WWW-Authenticate"],
    })
  );

  // Body parsers (JSON & URL-encoded for OAuth forms)
  app.use(express.json({ limit: "2mb" }));
  app.use(express.urlencoded({ extended: false }));

  // Session configuration
  const memoryStore = new session.MemoryStore();
  app.use(
    session({
      store: cfg.sessionStore || memoryStore,
      name: "zta.sid",
      secret: cfg.sessionSecret || "dev-session-secret-change-in-production",
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: Boolean(tlsServerOptions()), // TLS: cookie never sent over plain HTTP
        path: "/",
      },
    })
  );

  // Optional debug request logger
  if (cfg.debug) {
    app.use((req, res, next) => {
      console.log(`[IDP] ${req.method} ${req.url}`);
      next();
    });
  }

  // Mount IdP / OAuth2 / WebAuthn routes
  const idpRouter = createIdpRouter(cfg, {
    publicDir: path.join(__dirname, "public"),
    verifierJwks: cfg.verifierJwks,
  });
  app.use(idpRouter);

  /* -------------------------------------------------------------
     Portal & Status API Endpoints
  ------------------------------------------------------------- */

  // Auth check endpoint (answers from IdP session)
  app.get("/api/auth/check", (req, res) => {
    const idpUser = req.session.idpUser;
    if (idpUser) {
      return res.json({
        authenticated: true,
        username: idpUser.u,
        acr: idpUser.acr,
        deviceId: idpUser.dev,
        deviceTrusted: true,
      });
    }

    const txn = req.session.oauthTxn;
    return res.json({
      authenticated: false,
      deviceId: txn?.dev || "unknown",
      deviceTrusted: false,
    });
  });

  // Repaired /logout endpoint
  app.get("/logout", (req, res) => {
    const upstreamIdToken = req.session.upstreamIdToken;
    req.session.destroy(() => {
      if (cfg.idpMode === "keycloak") {
        const logoutUrl = getKeycloakLogoutUrl(upstreamIdToken, cfg);
        if (logoutUrl) return res.redirect(logoutUrl);
      }
      res.redirect("/");
    });
  });

  // Repaired /api/devices endpoint: renders TPM devices from Attestation Verifier (requires auth)
  app.get("/api/devices", async (req, res) => {
    try {
      // F6: Require an authenticated idpUser session or Bearer admin token
      let authorized = false;
      const isIdpUser = Boolean(req.session?.idpUser?.u);
      if (isIdpUser) {
        authorized = true;
      } else {
        const authHeader = req.headers.authorization;
        const adminToken = cfg.adminToken || process.env.ADMIN_TOKEN;
        if (authHeader && authHeader.startsWith("Bearer ") && adminToken) {
          const token = authHeader.slice(7).trim();
          try {
            if (token.length === adminToken.length && crypto.timingSafeEqual(Buffer.from(token), Buffer.from(adminToken))) {
              authorized = true;
            }
          } catch {}
        }
      }

      if (!authorized) {
        return res.status(401).json({
          error: "unauthorized",
          message: "Authentication required: active IdP session or Bearer admin token required",
        });
      }

      const verifierUrl = cfg.verifierUrl || "http://localhost:4005";
      const devRes = await internalFetch(`${verifierUrl}/v/devices`, {}, cfg);
      if (!devRes.ok) {
        return res.status(502).send("Could not retrieve devices from attestation verifier");
      }
      const devices = await devRes.json();

      if (!Array.isArray(devices) || devices.length === 0) {
        return res.send(`
          <!DOCTYPE html>
          <html>
          <head><title>No TPM Devices</title>
          <style>body { font-family: Inter, sans-serif; background:#0f172a; color:#f1f5f9; text-align:center; padding:2rem; } a { color:#06b6d4; text-decoration:none; }</style>
          </head>
          <body>
            <h2>No TPM devices registered yet.</h2>
            <p><a href="/">← Back to home</a></p>
          </body>
          </html>
        `);
      }

      const devicesHTML = devices
        .map((dev) => {
          const { devId, user, status, jkt, enrolledAt, last } = dev;
          const statusColor =
            status === "active"
              ? "#4ade80"
              : status === "suspended"
              ? "#fbbf24"
              : "#f87171";
          const statusText =
            status === "active"
              ? "✅ ACTIVE"
              : status === "suspended"
              ? "⚠️ SUSPENDED"
              : "❌ REVOKED";
          const lastAttestStr = last ? new Date(last).toLocaleString() : "Never";
          const enrolledAtStr = enrolledAt ? new Date(enrolledAt).toLocaleString() : "Unknown";

          return `
          <div style="background:#1e293b;padding:1.5rem;margin:1rem auto;width:650px;border-radius:1rem;box-shadow:0 4px 12px rgba(0,0,0,0.3);text-align:left;">
            <h2 style="color:${statusColor}">${statusText} TPM Registration</h2>
            <p><b>Device ID:</b> <code style="color:#38bdf8;">${devId}</code></p>
            <p><b>Assigned User:</b> ${user || "Not assigned"}</p>
            <p><b>Status:</b> <span style="color:${statusColor}; font-weight:600;">${status}</span></p>
            <p><b>Device Identity:</b> TPM-bound</p>
            <p><b>Binding Key (jkt):</b><br/><code style="word-break:break-all; color:#38bdf8;">${jkt || "N/A"}</code></p>
            <p><b>Verification:</b> TPM quote + credential activation</p>
            <p><b>Trust Model:</b> Hardware-rooted Zero Trust</p>
            <p><b>Last Attestation:</b> ${lastAttestStr}</p>
            <p><b>Enrolled At:</b> ${enrolledAtStr}</p>
          </div>
          `;
        })
        .join("\n");

      const html = `
      <!DOCTYPE html>
      <html>
      <head><title>TPM Device Registry</title>
      <style>
        body { font-family: Inter, sans-serif; background:#0f172a; color:#f1f5f9; text-align:center; padding:2rem; }
        a { color:#06b6d4; text-decoration:none; }
      </style>
      </head>
      <body>
        <h1 style="color:#06b6d4;">🔐 TPM Device Registry</h1>
        ${devicesHTML}
        <p><a href="/">← Back to Home</a></p>
      </body>
      </html>
      `;
      res.send(html);
    } catch (err) {
      console.error("❌ [/api/devices] Error:", err);
      res.status(500).send("Error fetching devices: " + err.message);
    }
  });

  // Error handling middleware registered AFTER routes
  app.use((err, req, res, next) => {
    console.error("Unhandled portal error:", err);
    res.status(500).json({ error: "Internal server error", message: err.message });
  });

  return app;
}

if (isMain(import.meta.url)) {
  printBannerOnce("server");
  const cfg = loadConfig();
  const PORT = process.env.PORT || 5173;
  const HOST = process.env.HOST || "0.0.0.0";
  const app = createApp(cfg);

  const server = listen(app, PORT, HOST, (url) => {
      console.log(`\n============================================================`);
      console.log(`🚀 Zero-Trust Identity Provider & Portal running on ${url}`);
      console.log(`🔐 Mode: ${cfg.idpMode} | Store: ${cfg.store}`);
      console.log(`============================================================\n`);
    })
    .on("error", (err) => {
      if (err.code === "EADDRINUSE") {
        console.error(`❌ Error: Port ${PORT} is already in use`);
      } else {
        console.error("Server error:", err);
      }
      process.exit(1);
    });

  process.on("SIGINT", () => {
    server.close(() => {
      console.log("\n✅ Server shut down gracefully");
      process.exit(0);
    });
  });
}

export default { createApp };