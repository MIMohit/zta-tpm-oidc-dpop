import express from "express";
import cors from "cors";
import path from "node:path";
import * as jose from "jose";
import { loadConfig } from "./lib/config.js";
import { internalFetch } from "./lib/internal-auth.js";
import { isMain } from "./lib/main.js";
import { loadOrCreateSigningKey } from "./lib/keys.js";
import { DpopError, verifyProof } from "./lib/dpop.js";
import { createNonceStore } from "./lib/nonce.js";
import { createJtiCache } from "./lib/jti-cache.js";
import { createAuditLog } from "./lib/audit-log.js";
import { defaultPolicyData, loadPolicyData } from "./lib/policy.js";
import { on, printBannerOnce } from "./lib/ablation.js";
import { mountHealth } from "./lib/health.js";
import { listen } from "./lib/tls.js";
import { getClientIp } from "./lib/idp/client-ip.js";

/**
 * Creates the Policy Enforcement Point (PEP) Express application.
 * Implements Algorithm 3 (Per-request authorization at the PEP).
 *
 * @param {Record<string, any>} [cfg]
 * @returns {import('express').Express}
 */
export function createApp(cfg = loadConfig()) {
  const app = express();
  mountHealth(app, "pep"); // public liveness + ablation state

  // CORS: allow browser UI on 5173 and expose protocol headers
  app.use(
    cors({
      origin: [cfg.idpIssuer, "http://localhost:5173"].filter(Boolean),
      credentials: true,
      exposedHeaders: ["DPoP-Nonce", "WWW-Authenticate"],
    })
  );
  app.use(express.json());

  // Nonce store & JTI cache (scoped to PEP instance / injectable for tests)
  const nonceStore =
    cfg.nonceStore ||
    createNonceStore({
      tNonce: cfg.tNonce,
      clock: cfg.clock,
    });

  const jtiCache =
    cfg.jtiCache ||
    createJtiCache({
      wJti: cfg.wJti,
      clock: cfg.clock,
    });

  // Resolve IdP JWKS / public key for AT signature verification
  function resolveIdpJwks() {
    if (cfg.idpJwks) {
      if (typeof cfg.idpJwks === "function") return cfg.idpJwks;
      if (typeof cfg.idpJwks === "object" && Array.isArray(cfg.idpJwks.keys)) {
        return jose.createLocalJWKSet(cfg.idpJwks);
      }
      return cfg.idpJwks;
    }
    if (cfg.idpKey) return cfg.idpKey;
    if (cfg.idpPublicKey) return cfg.idpPublicKey;
    const idpIssuer = cfg.idpIssuer || cfg.IDP_ISSUER || "http://localhost:5173";
    return jose.createRemoteJWKSet(new URL(`${idpIssuer}/oauth/jwks`));
  }
  const idpJwks = resolveIdpJwks();

  // Policy resources data
  const policyData = cfg.policyData || (typeof cfg.policyDataPath === "string" ? loadPolicyData(cfg.policyDataPath) : defaultPolicyData);

  // Lazy or pre-injected signed audit log
  let auditLogPromise = null;
  function getAuditLog() {
    if (cfg.auditLog) return Promise.resolve(cfg.auditLog);
    if (!auditLogPromise) {
      auditLogPromise = (async () => {
        const auditKey = cfg.auditKey || (await loadOrCreateSigningKey("audit", cfg));
        const dataDir = cfg.dataDir || cfg.ZTA_DATA_DIR || "./data";
        const logFile = cfg.auditLogPath || path.join(dataDir, "audit", "pep.log");
        return createAuditLog({
          file: logFile,
          key: auditKey,
          clock: cfg.clock,
        });
      })();
    }
    return auditLogPromise;
  }

  // Main PEP route handler using Express 5 path syntax
  app.all("/api/{*path}", async (req, res) => {
    const pepStart = Date.now();
    const auditLog = await getAuditLog();

    function logAudit(decision, reason, a = null, jti = null, jkt = null, pip = null) {
      try {
        auditLog.append({
          a,
          uri: req.originalUrl || req.path,
          method: req.method,
          jti,
          jkt,
          decision,
          reason,
          pip,
        });
      } catch (err) {
        console.warn("⚠️ [PEP] Failed to append audit log record:", err.message);
      }
    }

    // 1. Map path + method to resource via policy/data.json
    let matchedResourceKey = null;
    let matchedResourceDef = null;

    for (const [key, resDef] of Object.entries(policyData.resources || {})) {
      if (resDef.path === req.path && (!resDef.ops || resDef.ops.includes(req.method))) {
        matchedResourceKey = key;
        matchedResourceDef = resDef;
        break;
      }
    }

    if (!matchedResourceKey || !matchedResourceDef) {
      return res.status(404).json({
        error: "not_found",
        message: "Resource not found or method not permitted for this path",
      });
    }

    // 2. Alg.3 Step 1: Authorization header scheme verification
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      const freshNonce = nonceStore.issue();
      logAudit("deny", "use_dpop_nonce");
      return res
        .status(401)
        .set("WWW-Authenticate", 'DPoP error="use_dpop_nonce"')
        .set("DPoP-Nonce", freshNonce)
        .json({
          error: "use_dpop_nonce",
          reason: "missing_authorization",
          message: "Missing Authorization header; DPoP scheme and server nonce required",
        });
    }

    const isBearer = authHeader.startsWith("Bearer ") || authHeader.toLowerCase().startsWith("bearer ");
    const isDpop = authHeader.startsWith("DPoP ") || authHeader.startsWith("dpop ");

    if (isBearer) {
      if (on("M15")) {
        const freshNonce = nonceStore.issue();
        logAudit("deny", "bearer_downgrade");
        return res
          .status(401)
          .set("WWW-Authenticate", 'DPoP error="invalid_token", error_description="Bearer scheme not allowed"')
          .set("DPoP-Nonce", freshNonce)
          .json({
            error: "invalid_token",
            reason: "bearer_downgrade",
            message: "Bearer downgrade blocked; DPoP scheme required",
          });
      }
    } else if (!isDpop) {
      const freshNonce = nonceStore.issue();
      logAudit("deny", "invalid_scheme");
      return res
        .status(401)
        .set("WWW-Authenticate", 'DPoP error="invalid_token"')
        .set("DPoP-Nonce", freshNonce)
        .json({
          error: "invalid_token",
          reason: "invalid_scheme",
          message: "Authorization scheme must be DPoP",
        });
    }

    const accessToken = authHeader.slice(isBearer ? 7 : 5).trim();
    if (!accessToken) {
      const freshNonce = nonceStore.issue();
      logAudit("deny", "missing_access_token");
      return res
        .status(401)
        .set("WWW-Authenticate", 'DPoP error="invalid_token"')
        .set("DPoP-Nonce", freshNonce)
        .json({
          error: "invalid_token",
          reason: "missing_access_token",
          message: "Missing access token in Authorization header",
        });
    }

    // Inspect proof payload to check nonce early if DPoP header present
    const dpopHeader = req.headers.dpop;
    let unverifiedProofPayload = null;
    let unverifiedProofJkt = null;
    if (dpopHeader && typeof dpopHeader === "string") {
      try {
        const parts = dpopHeader.trim().split(".");
        if (parts.length === 3) {
          unverifiedProofPayload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
          const unverifiedHeader = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
          if (unverifiedHeader?.jwk && !unverifiedHeader.jwk.d) {
            unverifiedProofJkt = await jose.calculateJwkThumbprint(unverifiedHeader.jwk, "sha256");
          }
        }
      } catch {
        // Ignore parse failure here; verifyProof will report malformed
      }

      if (on("M17")) {
        const nonceVal = unverifiedProofPayload?.nonce;
        if (!nonceVal || !nonceStore.valid(nonceVal)) {
          const freshNonce = nonceStore.issue();
          logAudit("deny", "use_dpop_nonce", null, unverifiedProofPayload?.jti || null, unverifiedProofJkt || null);
          return res
            .status(401)
            .set("WWW-Authenticate", 'DPoP error="use_dpop_nonce"')
            .set("DPoP-Nonce", freshNonce)
            .json({
              error: "use_dpop_nonce",
              reason: "use_dpop_nonce",
              message: "Invalid or missing DPoP nonce; fresh nonce issued",
            });
        }
      }
    }

    // 4. Alg.3 Step 3: Verify AT (iss, aud, typ, alg, exp) and require cnf.jkt
    let atPayload;
    try {
      const verifyOpts = {
        issuer: cfg.idpIssuer || cfg.IDP_ISSUER || "http://localhost:5173",
        audience: "zta-api",
        typ: "at+jwt",
        algorithms: ["ES256"],
      };
      if (cfg.clock) {
        verifyOpts.currentDate = new Date(cfg.clock());
      }
      const verifiedAt = await jose.jwtVerify(accessToken, idpJwks, verifyOpts);
      atPayload = verifiedAt.payload;
    } catch (err) {
      logAudit("deny", "invalid_token", null, unverifiedProofPayload?.jti || null, unverifiedProofJkt || null);
      return res
        .status(401)
        .set("WWW-Authenticate", `DPoP error="invalid_token", error_description="${err.message}"`)
        .json({
          error: "invalid_token",
          reason: "invalid_token",
          message: err.message,
        });
    }

    if (on("M16")) {
      if (!atPayload.cnf || typeof atPayload.cnf.jkt !== "string" || !atPayload.cnf.jkt) {
        logAudit("deny", "invalid_token", null, unverifiedProofPayload?.jti || null, unverifiedProofJkt || null);
        return res
          .status(401)
          .set("WWW-Authenticate", 'DPoP error="invalid_token", error_description="Missing cnf.jkt in access token"')
          .json({
            error: "invalid_token",
            reason: "invalid_token",
            message: "Missing cnf.jkt in access token",
          });
      }
    }

    // 5. Alg.3 Step 4: Verify DPoP proof with expectedJkt, htm, htu, ath, iat, jti replay
    let proofResult;
    if (!dpopHeader || typeof dpopHeader !== "string" || !dpopHeader.trim()) {
      if (isBearer) {
        // With M16..M19 still on, a Bearer request has no proof -> reject invalid_token unless the AT has no cnf
        if (atPayload.cnf?.jkt && on("M16")) {
          logAudit("deny", "invalid_token", null, null, null);
          return res
            .status(401)
            .set("WWW-Authenticate", 'DPoP error="invalid_token"')
            .json({
              error: "invalid_token",
              reason: "invalid_token",
              message: "Bearer request with cnf-bound token requires DPoP proof",
            });
        }
        proofResult = { jkt: null, payload: { jti: null } };
      } else {
        const freshNonce = nonceStore.issue();
        logAudit("deny", "use_dpop_nonce");
        return res
          .status(401)
          .set("WWW-Authenticate", 'DPoP error="use_dpop_nonce"')
          .set("DPoP-Nonce", freshNonce)
          .json({
            error: "use_dpop_nonce",
            reason: "use_dpop_nonce",
            message: "Missing DPoP proof; server nonce issued",
          });
      }
    } else {
      const currentPepPublicUrl = (cfg.pepPublicUrl || cfg.PEP_PUBLIC_URL || `http://${req.headers.host || "localhost:4001"}`).replace(/\/+$/, "");
      const expectedHtu = `${currentPepPublicUrl}${req.path}`;
      try {
        proofResult = await verifyProof({
          proof: dpopHeader,
          htm: req.method,
          htu: expectedHtu,
          accessToken,
          expectedJkt: on("M16") ? atPayload.cnf?.jkt : undefined,
          nonceStore: on("M17") ? nonceStore : undefined,
          jtiCache: on("M18") ? jtiCache : undefined,
          skewS: cfg.skew ?? 30,
          clock: cfg.clock,
          checks: {
            htm: on("M19"),
            htu: on("M19"),
            ath: on("M19"),
            iatWindow: on("M18"),
          },
        });
      } catch (err) {
        if (err instanceof DpopError) {
          if (err.code === "use_dpop_nonce") {
            const freshNonce = nonceStore.issue();
            logAudit("deny", "use_dpop_nonce", null, unverifiedProofPayload?.jti || null, unverifiedProofJkt || null);
            return res
              .status(401)
              .set("WWW-Authenticate", 'DPoP error="use_dpop_nonce"')
              .set("DPoP-Nonce", freshNonce)
              .json({
                error: "use_dpop_nonce",
                reason: "use_dpop_nonce",
                message: err.message,
              });
          }

          logAudit("deny", err.code, null, unverifiedProofPayload?.jti || null, unverifiedProofJkt || null);
          return res
            .status(401)
            .set("WWW-Authenticate", `DPoP error="invalid_token", error_description="${err.code}"`)
            .json({
              error: err.code,
              reason: err.code,
              message: err.message,
            });
        }

        logAudit("deny", "bad_proof", null, unverifiedProofPayload?.jti || null, unverifiedProofJkt || null);
        return res
          .status(401)
          .set("WWW-Authenticate", `DPoP error="invalid_token", error_description="${err.message}"`)
          .json({
            error: "invalid_token",
            reason: "bad_proof",
            message: err.message,
          });
      }
    }

    // 6. Alg.3 Step 5: Build attributes 'a' strictly from AT only
    const a = {
      sub: atPayload.sub,
      role: atPayload.role,
      acr: atPayload.acr,
      dev: atPayload.dev,
      auth_time: atPayload.auth_time,
    };
    if (!on("M20")) {
      if (req.headers["x-zta-role"]) {
        a.role = req.headers["x-zta-role"];
      }
      if (req.headers["x-zta-acr"]) {
        a.acr = req.headers["x-zta-acr"];
      }
    }

    // 7. Alg.3 Step 6: Call PDP evaluate
    const pdpUrl = cfg.pdpUrl || cfg.PDP_URL || "http://localhost:4002";
    const rawIp = getClientIp(req, cfg);
    const ip = rawIp === "::1" || rawIp === "::ffff:127.0.0.1" ? "127.0.0.1" : rawIp;

    let pdpData;
    try {
      const pdpRes = await internalFetch(
        `${pdpUrl}/pdp/evaluate`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            token: a,
            resource: matchedResourceKey,
            op: req.method,
            ip,
          }),
        },
        cfg
      );

      if (!pdpRes.ok) {
        throw new Error(`PDP HTTP error ${pdpRes.status}`);
      }
      pdpData = await pdpRes.json();
    } catch (err) {
      logAudit("deny", "pdp_unavailable", a, proofResult.payload.jti, proofResult.jkt);
      return res.status(500).json({
        error: "pdp_unavailable",
        reason: "pdp_unavailable",
        message: `PDP evaluation failed: ${err.message}`,
      });
    }

    // 8. Alg.3 Steps 7 & 8: Handle PDP decision, log audit, and forward or challenge
    if (pdpData.decision === "permit") {
      logAudit("permit", pdpData.reason, a, proofResult.payload.jti, proofResult.jkt, pdpData.pip || null);

      const resourceUrl = cfg.resourceUrl || cfg.RESOURCE_URL || "http://127.0.0.1:5001";
      const upstreamUrl = new URL(matchedResourceDef.upstream, resourceUrl);
      const clientUrl = new URL(req.url, "http://localhost");
      upstreamUrl.search = clientUrl.search;

      const internalToken = cfg.ztaInternalToken || cfg.ZTA_INTERNAL_TOKEN || process.env.ZTA_INTERNAL_TOKEN;
      const upstreamHeaders = {
        "X-ZTA-Internal": internalToken,
        "X-ZTA-Sub": a.sub,
        "X-ZTA-Dev": a.dev,
        Accept: "application/json",
      };

      const upstreamOpts = {
        method: req.method,
        headers: upstreamHeaders,
      };
      if (req.method !== "GET" && req.method !== "HEAD" && req.body) {
        upstreamOpts.headers["Content-Type"] = "application/json";
        upstreamOpts.body = JSON.stringify(req.body);
      }

      const upstreamRes = await globalThis.fetch(upstreamUrl, upstreamOpts);
      const upstreamJson = await upstreamRes.json();

      const pepDelay = Date.now() - pepStart;
      console.log("⏱️ PEP total delay:", pepDelay, "ms");

      return res.status(upstreamRes.status).json(upstreamJson);
    }

    if (pdpData.decision === "step_up") {
      logAudit("step_up", pdpData.reason, a, proofResult.payload.jti, proofResult.jkt, pdpData.pip || null);

      const pepDelay = Date.now() - pepStart;
      console.log("⏱️ PEP total delay:", pepDelay, "ms");

      return res
        .status(401)
        .set(
          "WWW-Authenticate",
          'DPoP error="insufficient_user_authentication", error_description="step-up required", acr_values="mfa"'
        )
        .json({
          error: "insufficient_user_authentication",
          acr_values: "mfa",
          reason: pdpData.reason,
        });
    }

    // Default: Deny -> 403
    logAudit("deny", pdpData.reason, a, proofResult.payload.jti, proofResult.jkt, pdpData.pip || null);

    const pepDelay = Date.now() - pepStart;
    console.log("⏱️ PEP total delay:", pepDelay, "ms");

    return res.status(403).json({
      error: "access_denied",
      reason: pdpData.reason,
    });
  });

  return app;
}

if (isMain(import.meta.url)) {
  printBannerOnce("pep");
  const cfg = loadConfig();
  const PORT = process.env.PORT || 4001;
  listen(createApp(cfg), PORT, undefined, (url) => console.log(`🛂 PEP running on ${url}`));
}

export default { createApp };
