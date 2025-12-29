import express from "express";
import { db } from "./firebase.js";

const app = express();
app.use(express.json());

// READ device attributes
app.get("/pip/device/:deviceId", async (req, res) => {
  const snap = await db.ref(`devices/${req.params.deviceId}`).once("value");

  if (!snap.exists()) {
    return res.json({ status: "unknown" });
  }

  res.json(snap.val());
});

// UPDATE dynamic attributes
app.post("/pip/device/:deviceId", async (req, res) => {
  await db.ref(`devices/${req.params.deviceId}`).update({
    ...req.body,
    last_seen: new Date().toISOString()
  });

  res.json({ ok: true });
});

app.listen(4003, () =>
  console.log("🔍 PIP running on http://localhost:4003")
);
