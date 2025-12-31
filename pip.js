import express from "express";
import { db } from "./firebase.js";

const app = express();
app.use(express.json());

/* -------------------------------
   READ device attributes
-------------------------------- */
app.get("/pip/device/:deviceId", async (req, res) => {
  const snap = await db.ref(`devices/${req.params.deviceId}`).once("value");
  if (!snap.exists()) {
    return res.json({ status: "unknown" });
  }
  res.json(snap.val());
});

/* -------------------------------
   UPDATE device attributes (SAFE)
-------------------------------- */
app.post("/pip/device/:deviceId", async (req, res) => {
  const { last_ip, ...rest } = req.body;

  // 🚨 BLOCK last_ip updates unless MFA proof is present
  if (last_ip && req.headers["x-mfa-completed"] !== "true") {
    console.warn("🚫 Blocked premature last_ip update");
    delete rest.last_ip;
  }

  await db.ref(`devices/${req.params.deviceId}`).update({
    ...rest,
    last_seen: new Date().toISOString()
  });

  res.json({ ok: true });
});

app.listen(4003, () =>
  console.log("🔍 PIP running on http://localhost:4003")
);
