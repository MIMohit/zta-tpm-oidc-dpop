import express from "express";
import { db } from "../firebase.js";

const app = express();
app.use(express.json());

const REGISTRY_PATH = "devices";

/**
 * Enroll / Update Device
 * Called after successful TPM attestation + user binding
 */
app.post("/registry/enroll", async (req, res) => {
  try {
    const { device_id, user_id } = req.body;

    if (!device_id) {
      return res.status(400).json({ error: "device_id is required" });
    }

    const deviceRef = db.ref(`${REGISTRY_PATH}/${device_id}`);

    const record = {
      device_id,
      user_id: user_id || null,
      status: "active",
      enrolled_at: new Date().toISOString(),
      last_seen: new Date().toISOString()
    };

    await deviceRef.set(record);

    res.json({
      enrolled: true,
      device_id
    });
  } catch (err) {
    console.error("🔥 Firebase enroll error:", err);
    res.status(500).json({ error: "Failed to enroll device" });
  }
});

/**
 * Get Device Status
 * Used by PIP / PDP / Keycloak checks
 */
app.get("/registry/:deviceId", async (req, res) => {
  try {
    const deviceRef = db.ref(`${REGISTRY_PATH}/${req.params.deviceId}`);
    const snapshot = await deviceRef.once("value");

    if (!snapshot.exists()) {
      return res.json({ status: "unknown" });
    }

    res.json(snapshot.val());
  } catch (err) {
    console.error("🔥 Firebase fetch error:", err);
    res.status(500).json({ error: "Failed to fetch device" });
  }
});

/**
 * Revoke Device (Zero Trust Superpower)
 */
app.post("/registry/:deviceId/revoke", async (req, res) => {
  await db.ref(`${REGISTRY_PATH}/${req.params.deviceId}/status`).set("revoked");
  res.json({ revoked: true });
});

app.listen(4004, () =>
  console.log("📘 Firebase Device Registry running on :4004")
);
