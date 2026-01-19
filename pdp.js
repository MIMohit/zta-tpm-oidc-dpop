import express from "express";

const app = express();
app.use(express.json());

function haversineDistance(lat1, lon1, lat2, lon2) {
  const R = 6371;
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
  const pdpStart = Date.now();

  const { user, device_id, resource, context } = req.body;
  const { ip, country, geo, mfa_passed } = context;

  const pipRes = await fetch(`http://localhost:4003/pip/device/${device_id}`);
  const dev = await pipRes.json();

  console.log("📡 PIP device:", { dev, ip, country, mfa_passed });

  /* -------- DEVICE BINDING -------- */
  if (dev.user_id !== user) {
    const pdpDelay = Date.now() - pdpStart;
    console.log("⏱️ PDP decision delay:", pdpDelay, "ms");

    return res.json({
      decision: "deny",
      reason: "User-device mismatch"
    });
  }

  /* -------- SENSITIVE RESOURCE STEP-UP -------- */
  const sensitiveResources = ["company.audit", "admin.panel"];

  if (
    sensitiveResources.includes(resource) &&
    dev.last_ip &&
    dev.last_ip !== ip &&
    !mfa_passed
  ) {
    const pdpDelay = Date.now() - pdpStart;
    console.log("⏱️ PDP decision delay:", pdpDelay, "ms");

    return res.json({
      decision: "mfa_required",
      level: 2,
      reason: "Sensitive resource with network anomaly"
    });
  }

  /* -------- COUNTRY CHANGE -------- */
  if (
    dev.last_country &&
    dev.last_country !== country &&
    !mfa_passed
  ) {
    const pdpDelay = Date.now() - pdpStart;
    console.log("⏱️ PDP decision delay:", pdpDelay, "ms");

    return res.json({
      decision: "mfa_required",
      level: 1,
      reason: "Geographic location changed"
    });
  }

  /* -------- IMPOSSIBLE TRAVEL -------- */
  if (dev.last_geo && geo && dev.last_geo_time) {
    const distance = haversineDistance(
      dev.last_geo.lat,
      dev.last_geo.lon,
      geo.lat,
      geo.lon
    );

    const hours = (Date.now() - dev.last_geo_time) / (1000 * 60 * 60);
    const speed = distance / hours;

    if (speed > 900 && !mfa_passed) {
      const pdpDelay = Date.now() - pdpStart;
      console.log("⏱️ PDP decision delay:", pdpDelay, "ms");

      return res.json({
        decision: "mfa_required",
        level: 2,
        reason: "Impossible travel detected"
      });
    }
  }

  /* -------- NETWORK CHANGE -------- */
  if (dev.last_ip && dev.last_ip !== ip && !mfa_passed) {
    return res.json({
      decision: "mfa_required",
      level: 1,
      reason: "Network change detected"
    });
  }

  /* -------- DEVICE STATUS -------- */
  if (dev.status === "revoked") {
    const pdpDelay = Date.now() - pdpStart;
    console.log("⏱️ PDP decision delay:", pdpDelay, "ms");

    return res.json({
      decision: "deny",
      reason: "Device revoked"
    });
  }

  /* -------- RESOURCE AUTH -------- */
  if (resource === "company.audit" && user !== "alice") {
    const pdpDelay = Date.now() - pdpStart;
    console.log("⏱️ PDP decision delay:", pdpDelay, "ms");

    return res.json({
      decision: "deny",
      reason: "User not authorized"
    });
  }

  /* -------- FINAL PERMIT -------- */
  const pdpDelay = Date.now() - pdpStart;
  console.log("⏱️ PDP decision delay:", pdpDelay, "ms");

  return res.json({
    decision: "permit",
    reason: "Policy satisfied"
  });
});

app.listen(4002, () =>
  console.log("🧠 PDP running on http://localhost:4002")
);
