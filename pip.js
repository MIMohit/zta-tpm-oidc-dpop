import { db } from "./firebase.js";

app.get("/pip/device/:deviceId", async (req, res) => {
  const snap = await db.ref(`devices/${req.params.deviceId}`).once("value");

  if (!snap.exists()) {
    return res.json({ status: "unknown" });
  }

  const device = snap.val();

  res.json({
    status: device.status,
    attestation_age: Date.now() - new Date(device.last_seen).getTime(),
    user_id: device.user_id
  });
});
