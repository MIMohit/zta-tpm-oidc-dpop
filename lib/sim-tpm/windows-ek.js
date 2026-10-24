/**
 * @file lib/sim-tpm/windows-ek.js
 * Diagnostic-only Windows TPM Endorsement Key reader.
 * Uses PowerShell Get-TpmEndorsementKeyInfo to read real EK cert & hash.
 * Unsupported methods (quote, certify, activateCredential, sign) fail closed.
 */

import { execSync } from "node:child_process";
import { TpmBackend } from "./backend.js";

export class WindowsEkTpm extends TpmBackend {
  constructor(options = {}) {
    super();
    this.options = options;
  }

  /**
   * Diagnostic-only: reads actual EK public information from Windows TPM via PowerShell.
   * @returns {Promise<{ publicArea: Record<string, any>, cert: string, details: any }>}
   */
  async getEk() {
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

    try {
      const raw = execSync(
        `"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -ExecutionPolicy Bypass -NoProfile -NoLogo -Command "${ps}"`,
        { encoding: "utf8", windowsHide: true }
      ).trim();

      if (!raw || raw.startsWith("ERROR")) {
        throw new Error(`TPM access failed: ${raw}`);
      }

      const cleanB64 = raw.replace(/^"+|"+$/g, "").replace(/\r?\n/g, "").trim();
      const parsed = JSON.parse(Buffer.from(cleanB64, "base64").toString("utf8"));

      return {
        publicArea: {
          type: "ecc",
          nameAlg: "sha256",
          ek_hash: parsed.ek_hash,
          diagnosticOnly: true,
        },
        cert: parsed.ek_cert_b64,
        details: parsed,
      };
    } catch (err) {
      throw new Error(`Failed to access Windows TPM: ${err.message}`);
    }
  }

  async createAk() {
    throw new Error("createAk is unsupported on diagnostic-only windows-ek backend");
  }

  async createKb() {
    throw new Error("createKb is unsupported on diagnostic-only windows-ek backend");
  }

  async activateCredential() {
    throw new Error("activateCredential is unsupported on diagnostic-only windows-ek backend");
  }

  async quote() {
    throw new Error("quote is unsupported on diagnostic-only windows-ek backend");
  }

  async certify() {
    throw new Error("certify is unsupported on diagnostic-only windows-ek backend");
  }

  async sign() {
    throw new Error("sign is unsupported on diagnostic-only windows-ek backend");
  }
}

export default WindowsEkTpm;
