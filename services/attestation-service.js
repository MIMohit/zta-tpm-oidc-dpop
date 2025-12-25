import express from "express";
const app = express();
app.use(express.json());

app.post("/attest/verify", (req, res) => {
  const { device_id, user_id } = req.body;

  // Demo logic: accept if present
  if (!device_id || !user_id) {
    return res.json({ valid: false });
  }

  res.json({
    valid: true,
    checked_at: Date.now(),
    confidence: "hardware-backed"
  });
});

app.listen(4005, () =>
  console.log("🧪 Attestation Service on :4005")
);
