import express from "express";

const app = express();
app.use(express.json());
function haversineDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // km
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1 * Math.PI / 180) *
    Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLon / 2) ** 2;

  return 2 * R * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}


app.post("/pdp/evaluate", async (req, res) => {
  const { user, device_id, scopes, resource, context } = req.body;
  const { ip, country, geo, mfa_passed } = context;

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

  // 🔴 LAYER 5: Sensitive resource hard deny
  const sensitiveResources = ["company.audit", "admin.panel"];

  if (sensitiveResources.includes(resource)) {
    const abnormal =
      dev.last_ip && dev.last_ip !== ip &&
      dev.last_country &&
      country &&
      dev.last_country !== "unknown" &&
      country !== "unknown" &&
      dev.last_country !== country;

    if (abnormal) {
      console.log("🚫 High-risk sensitive access denied", {
        resource,
        user,
        ip,
        country
      });

      return res.json({
        decision: "deny",
        reason: "High-risk access to sensitive resource"
      });
    }
  }

  // 🟡 LAYER 2: Country change
  if (
    dev.last_country &&
    dev.last_country !== country &&
    !mfa_passed
  ) {
    console.log("⚠️ MFA required: Country change", {
      from: dev.last_country,
      to: country
    });

    return res.json({
      decision: "mfa_required",
      level: 1,
      reason: "Geographic location changed"
    });
  }


  // 🟠 LAYER 4: Impossible travel
  if (
    dev.last_geo &&
    geo &&
    dev.last_geo_time
  ) {
    const distance = haversineDistance(
      dev.last_geo.lat,
      dev.last_geo.lon,
      geo.lat,
      geo.lon
    );

    const timeHours =
      (Date.now() - dev.last_geo_time) / (1000 * 60 * 60);

    const speed = distance / timeHours; // km/h

    if (speed > 900 && !mfa_passed) { // faster than commercial jet
      console.log("⚠️ MFA required: Impossible travel", {
        distance,
        timeHours,
        speed
      });

      return res.json({
        decision: "mfa_required",
        level: 2,
        reason: "Impossible travel detected"
      });
    }
  }


  // --- NETWORK CHANGE (LOWER RISK) ---
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
