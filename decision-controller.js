import express from "express";
import cors from "cors";
import fetch from "node-fetch";

const app = express();

app.use(cors({
  origin: "http://localhost:5173",
  credentials: true
}));
app.use(express.json());

app.get("/zta/access/audit", async (req, res) => {
  try {
    const access_token = req.headers.authorization?.replace("Bearer ", "");
    const dpop = req.headers.dpop;
    const device_id = req.headers["x-device-id"];

    if (!access_token || !dpop || !device_id) {
      return res.status(401).json({ error: "Missing credentials" });
    }

    /* 🔥 VPN-AWARE NETWORK SIGNAL */
    const client_ip =
      req.headers["x-public-ip"] ||
      req.headers["x-forwarded-for"] ||
      req.ip;

    const mfa_passed = req.headers["x-mfa-passed"] === "true";
        // 🔐 Server-side MFA invalidation on IP change
    if (
      req.headers["x-mfa-passed"] === "true" &&
      req.headers["x-last-ip"] &&
      req.headers["x-last-ip"] !== client_ip
    ) {
      console.warn("⚠ MFA invalidated due to network change");
      req.headers["x-mfa-passed"] = "false";
    }


    /* ---- PEP ---- */
    const pepRes = await fetch("http://localhost:4001/pep/intercept", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        access_token,
        dpop_proof: dpop,
        resource: "company.audit",
        client_ip,
        mfa_passed,
        device_id
      })
    });

    const decision = await pepRes.json();

    if (decision.decision === "mfa_required") {
      return res.status(401).json(decision);
    }
    if (decision.decision === "deny") {
      return res.status(403).json(decision);
    }

    /* 🔄 TRUST CONVERGENCE (AFTER MFA ONLY) */
    if (mfa_passed === true) {
      await fetch(`http://localhost:4003/pip/device/${device_id}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-MFA-COMPLETED": "true"   // 🔥 REQUIRED
        },
        body: JSON.stringify({
          last_ip: client_ip
        })
      });
    }


    const resourceRes = await fetch(
      "http://localhost:5001/company/audit",
      { headers: decision.forward_headers }
    );

    res.json(await resourceRes.json());

  } catch (err) {
    console.error("ZTA error:", err);
    res.status(500).json({ error: "ZTA failure" });
  }
});

app.listen(4000, () =>
  console.log("🎯 Decision Controller running on http://localhost:4000")
);
