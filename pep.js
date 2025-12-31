import express from "express";
import fetch from "node-fetch";
import * as jose from "jose";

const app = express();
app.use(express.json());

/* -----------------------------------------
   🔐 TOKEN INTROSPECTION
------------------------------------------ */
async function introspectToken(accessToken) {
  try {
    const JWKS = jose.createRemoteJWKSet(
      new URL(
        "http://localhost:8080/realms/zta-realm/protocol/openid-connect/certs"
      )
    );

    const { payload } = await jose.jwtVerify(accessToken, JWKS, {
      issuer: "http://172.30.32.1:8080/realms/zta-realm",
      audience: ["remote-work-app", "account"]
    });

    return {
      active: true,
      sub: payload.sub,                               // cryptographic identity
      user: payload.preferred_username || payload.email, // 🔥 POLICY IDENTITY
      scope: payload.scope || ""
    };
  } catch (err) {
    console.error("❌ Token verification failed:", err.message);
    return { active: false };
  }
}

/* -----------------------------------------
   🔐 DPoP (DEV MODE SAFE)
------------------------------------------ */
function verifyDPoP(dpop) {
  if (!dpop) throw new Error("Missing DPoP");
  if (dpop.split(".").length !== 3) {
    console.warn("⚠️ Dev DPoP accepted");
    return true;
  }
  jose.decodeJwt(dpop);
  return true;
}

/* -----------------------------------------
   🛂 PEP
------------------------------------------ */
app.post("/pep/intercept", async (req, res) => {
  try {
    const {
      access_token,
      dpop_proof,
      resource,
      client_ip,
      mfa_passed,
      device_id
    } = req.body;

    if (!device_id) {
      return res.status(401).json({
        decision: "deny",
        reason: "Missing device_id"
      });
    }

    verifyDPoP(dpop_proof);

    const tokenInfo = await introspectToken(access_token);
    if (!tokenInfo.active) {
      return res.status(401).json({
        decision: "deny",
        reason: "Invalid token"
      });
    }

    console.log("🧬 Policy identity:", tokenInfo.user);
    console.log("🧬 Device identity:", device_id);

    const policyRequest = {
      user: tokenInfo.user,        // 🔥 FIX HERE
      device_id,
      scopes: tokenInfo.scope,
      resource,
      context: {
        ip: client_ip || "unknown",
        country: "unknown",
        mfa_passed
      }
    };

    const pdpRes = await fetch("http://localhost:4002/pdp/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(policyRequest)
    });

    const decision = await pdpRes.json();
    console.log("🧠 PDP decision:", decision);

    if (decision.decision === "permit") {
      return res.json({
        decision: "permit",
        forward_headers: {
          Authorization: `Bearer ${access_token}`
        }
      });
    }

    if (decision.decision === "mfa_required") {
      return res.json(decision);   // 🔥 DO NOT TURN INTO 403
    }

    if (decision.decision === "deny") {
      return res.json(decision);
    }

  } catch (err) {
    console.error("🔥 PEP error:", err);
    return res.status(500).json({
      decision: "deny",
      reason: "PEP internal error"
    });
  }
});

app.listen(4001, () =>
  console.log("🛂 PEP running on http://localhost:4001")
);
