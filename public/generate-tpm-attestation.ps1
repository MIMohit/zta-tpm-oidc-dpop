# ================================
# TPM Attestation Script (SERVICE)
# ================================

$ErrorActionPreference = "Stop"

try {
    # ---- TPM checks ----
    $tpmInfo = Get-Tpm
    if (-not $tpmInfo.TpmPresent) { throw "TPM not present" }
    if (-not $tpmInfo.TpmReady)   { throw "TPM not ready" }

    # ---- EK Info ----
    $tpmEkInfo = Get-TpmEndorsementKeyInfo -HashAlgorithm sha256
    $ekHash = $tpmEkInfo.PublicKeyHash

    # ---- TPM Manufacturer & Spec ----
    $tpmWmi = Get-WmiObject -Class Win32_Tpm -Namespace root\CIMV2\Security\MicrosoftTpm
    $manufacturer = $tpmWmi.ManufacturerIdTxt
    $specVersion  = $tpmWmi.SpecVersion

    # ---- EK Certificate (optional) ----
    $ekCert = $null

    if ($tpmEkInfo.AdditionalCertificates -and $tpmEkInfo.AdditionalCertificates.Count -gt 0) {
        $ekCert = [Convert]::ToBase64String($tpmEkInfo.AdditionalCertificates[0].RawData)
    }
    elseif ($tpmEkInfo.ManufacturerCertificates -and $tpmEkInfo.ManufacturerCertificates.Count -gt 0) {
        $ekCert = [Convert]::ToBase64String($tpmEkInfo.ManufacturerCertificates[0].RawData)
    }

    # ---- Device ID ----
    $deviceId = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID

    # ---- FINAL ATTESTATION OBJECT ----
    $attestation = @{
        device_id     = $deviceId
        manufacturer  = $manufacturer
        spec_version  = $specVersion
        ek_hash       = $ekHash
        ek_cert_b64   = $ekCert
        timestamp     = (Get-Date).ToUniversalTime().ToString("o")
    }

    # ---- OUTPUT PURE JSON ONLY ----
    $attestation | ConvertTo-Json -Depth 5

}
catch {
    @{
        error = $_.Exception.Message
    } | ConvertTo-Json
    exit 1
}
