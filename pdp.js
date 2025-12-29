import express from "express";

const app = express();
app.use(express.json());

app.post("/pdp/evaluate", async (req, res) => {
  const { user, device_id, scopes, resource, context } = req.body;
  const { ip, country, mfa_passed } = context;

  const pipRes = await fetch(`http://localhost:4003/pip/device/${device_id}`);
  const dev = await pipRes.json();

  // DEBUG: log PIP device response and context
  console.log("📡 PIP device:", { device_id, dev, user, ip, country, mfa_passed });

  // --- DEVICE BINDING ---
  if (dev.user_id !== user) {
    console.log("🚫 Deny: User-device mismatch", { devUser: dev.user_id, tokenUser: user, dev });
    return res.json({
      decision: "deny",
      reason: "User-device mismatch"
    });
  }

  // --- IMPOSSIBLE TRAVEL (HIGH RISK) ---
  if (
    dev.last_country &&
    country &&
    dev.last_country !== country &&
    Date.now() - new Date(dev.last_seen).getTime() < 5 * 60 * 1000 &&
    !mfa_passed
  ) {
    console.log("⚠️ MFA required: Impossible travel detected", { dev, country, last_seen: dev.last_seen });
    return res.json({
      decision: "mfa_required",
      level: 2,
      reason: "Impossible travel detected"
    });
  }

  // --- NETWORK CHANGE (LOWER RISK) ---
// MFA is ONLY valid for the SAME IP and RECENT verification
  const mfaStillValid =
    mfa_passed &&
    dev.last_ip === ip &&
    Date.now() - new Date(dev.last_seen).getTime() < 10 * 60 * 1000; // 10 min

  if (dev.last_ip && dev.last_ip !== ip && !mfaStillValid) {
    console.log("⚠️ MFA required: Network change detected", {
      previous_ip: dev.last_ip,
      current_ip: ip
    });

    return res.json({
      decision: "mfa_required",
      level: 1,
      reason: "Network change detected"
    });
  }


  if (dev.status === "revoked") {
    return res.json({
      decision: "deny",
      reason: "Device revoked"
    });
  }

  // --- RESOURCE POLICY ---
  if (resource === "company.audit" && user !== "alice") {
    return res.json({
      decision: "deny",
      reason: "User not authorized for financial data"
    });
  }

  return res.json({
    decision: "permit",
    reason: "Policy satisfied"
  });
});

app.listen(4002, () =>
  console.log("🧠 PDP running on http://localhost:4002")
);
