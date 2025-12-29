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
    const access_token =
      req.headers.authorization?.replace("Bearer ", "") || null;
    const dpop = req.headers.dpop || null;
    const client_ip = req.headers["x-client-ip"] || "unknown";
    const mfa_passed = req.headers["x-mfa-passed"] === "true";
    const device_id = req.headers["x-device-id"];

    if (!access_token || !dpop || !device_id) {
      return res.status(401).json({
        error: "Missing token, DPoP, or device_id"
      });
    }

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

    if (decision.decision !== "permit") {
      return res.status(403).json(decision);
    }

    // 🔐 Trust the new network context AFTER successful access
    await fetch(`http://localhost:4003/pip/device/${device_id}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        last_ip: client_ip,
        last_country: "unknown"
      })
    });

    const resourceRes = await fetch(
      "http://localhost:5001/company/audit",
      { headers: decision.forward_headers }
    );

    const data = await resourceRes.json();
    return res.json(data);

  } catch (err) {
    console.error("🔥 ZTA Controller error:", err);
    return res.status(500).json({ error: "ZTA internal failure" });
  }
});

app.listen(4000, () =>
  console.log("🎯 Decision Controller running on http://localhost:4000")
);
