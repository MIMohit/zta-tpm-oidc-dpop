import express from "express";
import cors from "cors";
import { execSync } from "child_process";
import os from "os";
import fs from "fs";

const app = express();
app.use(cors({
  origin: "http://localhost:5173",
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type"]
}));
app.use(express.json());

const log = (...args) => console.log(new Date().toISOString(), ...args);

app.post("/tpm/attest", async (req, res) => {
  const { nonce } = req.body;
  if (!nonce) return res.status(400).json({ error: "Nonce missing" });

  log("Generating real TPM attestation for nonce:", nonce);

  try {
    // PowerShell script for gathering actual EK cert + hash
    const ps = `
    try {
        $ErrorActionPreference = 'Stop'
        $tpm = Get-WmiObject -Namespace 'root\\cimv2\\security\\microsofttpm' -Class Win32_Tpm
        $ekInfo = Get-TpmEndorsementKeyInfo -HashAlgorithm sha256
        if ($null -eq $tpm -or $null -eq $ekInfo) {
            Write-Output "ERROR:TPM_NOT_FOUND"
            exit 1
        }
        # Export manufacturer certificate temporarily
        $temp = [System.IO.Path]::GetTempFileName().Replace('.tmp','.cer')
        $ekInfo.manufacturerCertificates | Export-Certificate -FilePath $temp | Out-Null
        $ekCertBytes = [System.IO.File]::ReadAllBytes($temp)
        $ekCertBase64 = [Convert]::ToBase64String($ekCertBytes)
        $att = @{
            version       = $tpm.ManufacturerVersion
            manufacturer  = $tpm.ManufacturerIdTxt
            nonce         = "${nonce}"
            ek_hash       = $ekInfo.PublicKeyHash
            ek_cert_b64   = $ekCertBase64
            spec_version  = $tpm.SpecVersion
        }
        $json = $att | ConvertTo-Json -Depth 5
        [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    }
    catch {
        Write-Output "ERROR:$($_.Exception.Message)"
        exit 1
    }
    `;

    const raw = execSync(
      `"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -ExecutionPolicy Bypass -NoProfile -NoLogo -Command "${ps}"`,
      { encoding: "utf8", windowsHide: true }
    ).trim();

    console.log("🔍 PowerShell raw output:", raw);

    // Detect any PowerShell error
    if (!raw || raw.startsWith("ERROR")) {
      console.error("❌ PowerShell TPM error:", raw);
      return res.status(500).json({ error: "TPM access failed", details: raw });
    }

    // Clean PowerShell output
    const attestation_b64 = raw.replace(/^"+|"+$/g, "").replace(/\r?\n/g, "").trim();

    const payload = {
      user_id: "alice",
      device_id: os.hostname(),
      attestation_b64
    };

    log("✅ Real TPM attestation prepared:", payload);
    res.json(payload);

  } catch (err) {
    console.error("❌ TPM agent error:", err.message);
    res.status(500).json({
      error: "Failed to access TPM. Run this agent as Administrator.",
      details: err.message
    });
  }
});

app.listen(7000, () => {
  console.log("🧩 TPM Agent running at http://localhost:7000");
  console.log("Listening for attestation requests...");
});
