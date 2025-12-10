# Generate TPM Attestation Script

Write-Host "Starting TPM Attestation Generation..." -ForegroundColor Cyan

try {
    # Get TPM information
    $tpmInfo = Get-Tpm
    
    if (-not $tpmInfo.TpmPresent) {
        throw "TPM is not present on this device"
    }
    
    if (-not $tpmInfo.TpmReady) {
        throw "TPM is not ready. Please ensure TPM is enabled in BIOS"
    }

    # Get TPM endorsement key info
    $tpmEkInfo = Get-TpmEndorsementKeyInfo -HashAlgorithm sha256

    # Get TPM manufacturer and version
    $tpmWmi = Get-WmiObject -Class Win32_Tpm -Namespace root\CIMV2\Security\MicrosoftTpm
    $manufacturer = $tpmWmi.ManufacturerIdTxt
    $specVersion = $tpmWmi.SpecVersion

    # Get EK Hash
    $ekHash = $tpmEkInfo.PublicKeyHash

    Write-Host "TPM Manufacturer: $manufacturer" -ForegroundColor Green
    Write-Host "TPM Spec Version: $specVersion" -ForegroundColor Green
    Write-Host "EK Hash: $ekHash" -ForegroundColor Green

    # Try to get EK certificate - check if file exists
    $ekCert = $null
    $ekCertPath = "D:\myEkcert.cer"
    
    if (Test-Path $ekCertPath) {
        try {
            $ekCertBytes = [System.IO.File]::ReadAllBytes($ekCertPath)
            if ($ekCertBytes.Length -gt 100) {
                $ekCert = [Convert]::ToBase64String($ekCertBytes)
                Write-Host "EK Certificate loaded from file" -ForegroundColor Green
            }
        } catch {
            Write-Host "Could not read EK certificate file" -ForegroundColor Yellow
        }
    }
    
    # Try getting from TPM if not found in file
    if (-not $ekCert) {
        try {
            if ($tpmEkInfo.AdditionalCertificates -and $tpmEkInfo.AdditionalCertificates.Count -gt 0) {
                $ekCert = [Convert]::ToBase64String($tpmEkInfo.AdditionalCertificates[0].RawData)
                Write-Host "EK Certificate found (AdditionalCertificates)" -ForegroundColor Green
            } elseif ($tpmEkInfo.ManufacturerCertificates -and $tpmEkInfo.ManufacturerCertificates.Count -gt 0) {
                $ekCert = [Convert]::ToBase64String($tpmEkInfo.ManufacturerCertificates[0].RawData)
                Write-Host "EK Certificate found (ManufacturerCertificates)" -ForegroundColor Green
            } else {
                Write-Host "No EK certificate available, using hash only" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "Could not read EK certificate: $_" -ForegroundColor Yellow
        }
    }

    # Get nonce from server
    Write-Host "Getting nonce from server..." -ForegroundColor Cyan
    $initResponse = Invoke-RestMethod -Uri "http://localhost:5173/api/device/register/init" -Method GET

    # Create attestation object
    $attestation = @{
        manufacturer = $manufacturer
        spec_version = $specVersion
        version = "2.0"
        ek_hash = $ekHash
        ek_cert_b64 = $ekCert
        nonce = $initResponse.nonce
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
    }

    # Convert to JSON and Base64
    $attestationJson = $attestation | ConvertTo-Json -Compress
    $attestationB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($attestationJson))

      # Generate device ID
    $deviceId = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID

    # Create request body
    $bodyObj = @{
        device_id = $deviceId
        attestation_b64 = $attestationB64
    }
    
    $body = $bodyObj | ConvertTo-Json -Compress

    # Save to file in the same folder as this script (public/) - use ASCII to avoid BOM
    $outputPath = Join-Path -Path $PSScriptRoot -ChildPath "attestation-data.json"
    Set-Content -Path $outputPath -Value $body -Encoding ASCII -Force

    Write-Host "`nTPM Attestation generated successfully!" -ForegroundColor Green
    Write-Host "Device ID: $deviceId" -ForegroundColor Green
    Write-Host "Data saved to: $outputPath" -ForegroundColor Green

} catch {
    Write-Host "`nERROR: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}

