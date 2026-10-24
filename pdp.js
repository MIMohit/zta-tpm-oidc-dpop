import express from "express";
import { loadConfig } from "./lib/config.js";
import { requireInternal, internalFetch } from "./lib/internal-auth.js";
import { isMain } from "./lib/main.js";
import { decide, defaultPolicyData, loadPolicyData } from "./lib/policy.js";
import { on, printBannerOnce } from "./lib/ablation.js";
import { mountHealth } from "./lib/health.js";
import { listen } from "./lib/tls.js";

/**
 * Creates the PDP Express application.
 * @param {Record<string, any>} [cfg]
 * @returns {import('express').Express}
 */
export function createApp(cfg = loadConfig()) {
  const opaUrl = cfg.opaUrl || process.env.OPA_URL;
  if (opaUrl && (!on("M20") || !on("M21"))) {
    throw new Error("OPA does not support ablated M20/M21 policy evaluation; use the JS engine (unset OPA_URL)");
  }

  const app = express();
  mountHealth(app, "pdp"); // public liveness + ablation state
  app.use(express.json());

  // Require internal service token on all PDP routes
  app.use(requireInternal(cfg));

  // T_su is a protocol time like T_AT and T_RA, so it follows the configuration (ZTA_T_SU)
  const basePolicy = cfg.policyData || defaultPolicyData;
  const policyData = typeof cfg.tSu === "number" ? { ...basePolicy, t_su_s: cfg.tSu } : basePolicy;

  app.post("/pdp/evaluate", async (req, res) => {
    const pdpStart = Date.now();

    const { token, resource, op = "GET", ip } = req.body;
    if (!token || !resource) {
      return res.status(400).json({
        error: "invalid_request",
        message: "token and resource are required",
      });
    }

    const nowMs = cfg.clock ? cfg.clock() : Date.now();
    const nowS = Math.floor(nowMs / 1000);

    // Call PIP for context
    const pipUrl = cfg.pipUrl || "http://localhost:4003";
    let pipResult = {
      status: "unknown",
      owner: null,
      attestation_age_s: 999999,
      risk: 1.0,
      features: [1, 1, 1, 1, 1, 1],
    };

    try {
      const pipRes = await internalFetch(
        `${pipUrl}/pip/context`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            sub: token.sub,
            dev: token.dev,
            ip,
            now: nowMs, // milliseconds: a login in the same second as the request must count as past
          }),
        },
        cfg
      );

      if (pipRes.ok) {
        pipResult = await pipRes.json();
      } else {
        console.warn(`⚠️ PIP returned ${pipRes.status} for context query`);
      }
    } catch (err) {
      console.warn("⚠️ Error fetching PIP context:", err.message);
    }

    // Build Rego-shaped input
    const authTime =
      typeof token.auth_time === "number"
        ? token.auth_time > 1e11
          ? Math.floor(token.auth_time / 1000)
          : token.auth_time
        : 0;

    const regoInput = {
      resource,
      op,
      now_s: nowS,
      risk: pipResult.risk,
      device: {
        status: pipResult.status,
        attestation_age_s: pipResult.attestation_age_s,
        owner: pipResult.owner,
      },
      token: {
        sub: token.sub,
        role: token.role,
        acr: token.acr,
        auth_time: authTime,
      },
    };

    let decision = "deny";
    let reason = "internal_error";

    const opaUrl = cfg.opaUrl || process.env.OPA_URL;
    if (opaUrl) {
      try {
        const opaRes = await globalThis.fetch(
          `${opaUrl}/v1/data/zta/authz/decision`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ input: regoInput }),
          }
        );
        if (opaRes.ok) {
          const opaData = await opaRes.json();
          decision = opaData.result?.decision || opaData.result || "deny";
          reason = opaData.result?.reason || `opa_${decision}`;
        } else {
          console.warn(`⚠️ OPA returned ${opaRes.status}, falling back to JS engine`);
          const res = decide(regoInput, policyData);
          decision = res.decision;
          reason = res.reason;
        }
      } catch (err) {
        console.warn("⚠️ OPA query failed, falling back to JS engine:", err.message);
        const res = decide(regoInput, policyData);
        decision = res.decision;
        reason = res.reason;
      }
    } else {
      const res = decide(regoInput, policyData);
      decision = res.decision;
      reason = res.reason;
    }

    const pdpDelay = Date.now() - pdpStart;
    console.log("⏱️ PDP decision delay:", pdpDelay, "ms");

    res.json({
      decision,
      reason,
      pip: {
        status: pipResult.status,
        attestation_age_s: pipResult.attestation_age_s,
        risk: pipResult.risk,
      },
    });
  });

  return app;
}

if (isMain(import.meta.url)) {
  printBannerOnce("pdp");
  const cfg = loadConfig();
  const PORT = process.env.PORT || 4002;
  listen(createApp(cfg), PORT, undefined, (url) => console.log(`🧠 PDP running on ${url}`));
}

export default { createApp };
