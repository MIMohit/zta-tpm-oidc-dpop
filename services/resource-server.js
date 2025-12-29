import express from "express";
import { db } from "../firebase.js";

const app = express();

app.get("/company/audit", async (req, res) => {
  try {
    const snap = await db.ref("audit_reports/company").once("value");

    if (!snap.exists()) {
      return res.status(404).json({ error: "No audit data" });
    }

    res.json({
      data: snap.val(),
      generated_at: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch audit data" });
  }
});

app.listen(5001, () =>
  console.log("📊 Resource Server (Firebase-backed) running on :5001")
);

console.log("📊 Resource server serving audit data");
