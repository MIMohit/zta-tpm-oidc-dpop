const button = document.getElementById("registerBtn");
const statusDiv = document.getElementById("status");

button.addEventListener("click", async () => {
  statusDiv.textContent = "🔐 Launching TPM attestation...";
  statusDiv.className = "";

  try {
    // 1️⃣ Ask backend to run PowerShell script (this will call your TPM)
    const trigger = await fetch("/run-attestation");

    if (!trigger.ok) throw new Error("TPM attestation script failed to run.");

    // 2️⃣ Once PowerShell finishes, backend will already have sent the data to /api/device/register/submit
    // So now we just check what’s in the device registry
    const res = await fetch("/api/devices");
    const devices = await res.json();
    console.log("📡 Registered devices:", devices);

    const [deviceId, details] = Object.entries(devices).pop();

    // 3️⃣ Show success message
    statusDiv.innerHTML = `
      <p>✅ <b>${deviceId}</b> registered successfully!</p>
      <p>Status: <b>${details.status}</b></p>
      <p><b>Manufacturer:</b> ${details.attestation.manufacturer}</p>
      <p><b>Version:</b> ${details.attestation.version}</p>
      <a href="/api/devices" target="_blank" class="link">📡 View all devices</a><br>
      <a href="/" class="link">🏠 Back to Home</a>
    `;
    statusDiv.className = "success";

  } catch (err) {
    console.error("❌ TPM Registration Error:", err);
    statusDiv.textContent = "❌ TPM Agent or Backend unreachable.";
    statusDiv.className = "error";
  }
});
