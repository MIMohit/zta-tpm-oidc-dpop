// pdp.js
app.post("/pdp/evaluate", async (req, res) => {
  const { user, device_id, scopes, resource } = req.body;

  // Ask PIP for attributes
  const pipRes = await fetch(`http://pip:4003/pip/device/${device_id}`);
  const deviceInfo = await pipRes.json();
  const scopeList = Array.isArray(scopes)
    ? scopes
    : scopes.split(" ");

  if (deviceInfo.user_id !== user) {
    return res.json({
      decision: "deny",
      reason: "User-device binding mismatch"
    });
  }

  // Evaluate policy
  if (
    deviceInfo.status === "active" &&
    deviceInfo.attestation_age < 86400 &&
    scopeList.includes("company.read") &&
    deviceInfo.user_id === user
  ) {
    return res.json({
      decision: "permit",
      reason: "Policy satisfied"
    });
  }

  return res.json({
    decision: "deny",
    reason: "Policy violation"
  });
});
