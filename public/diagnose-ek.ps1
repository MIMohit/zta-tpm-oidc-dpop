# Run this script as Administrator to find and extract your real EK certificate

Write-Host "Diagnosing TPM and EK Certificate..." -ForegroundColor Cyan
Write-Host ""

# Check TPM status
Write-Host "1. Checking TPM Status..." -ForegroundColor Yellow
try {
    $tpm = Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm
    if ($tpm) {
        Write-Host "   [OK] TPM Found" -ForegroundColor Green
        Write-Host "   Manufacturer: $($tpm.ManufacturerIdTxt)" -ForegroundColor Gray
        Write-Host "   Version: $($tpm.ManufacturerVersion)" -ForegroundColor Gray
        Write-Host "   Spec Version: $($tpm.SpecVersion)" -ForegroundColor Gray
    } else {
        Write-Host "   [ERROR] No TPM found" -ForegroundColor Red
        exit
    }
} catch {
    Write-Host "   [ERROR] Error accessing TPM: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host "2. Checking EK Info..." -ForegroundColor Yellow
try {
    $ekInfo = Get-TpmEndorsementKeyInfo -HashAlgorithm sha256
    Write-Host "   [OK] EK Info Retrieved" -ForegroundColor Green
    Write-Host "   Public Key Hash: $($ekInfo.PublicKeyHash)" -ForegroundColor Gray
    
    if ($ekInfo.ManufacturerCertificates) {
        Write-Host "   [OK] Manufacturer Certificates Found: $($ekInfo.ManufacturerCertificates.Count)" -ForegroundColor Green
    } else {
        Write-Host "   [WARN] No Manufacturer Certificates in TPM" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   [ERROR] Error getting EK info: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "3. Attempting to Export EK Certificate..." -ForegroundColor Yellow

# Try multiple export methods
$exportSuccess = $false
$outputPath = "D:\real_ek_cert.cer"

# Method 1: Direct export from ManufacturerCertificates
if ($ekInfo.ManufacturerCertificates) {
    try {
        Write-Host "   Trying Method 1: Export-Certificate..." -ForegroundColor Gray
        $ekInfo.ManufacturerCertificates | Export-Certificate -Type CERT -FilePath $outputPath -Force | Out-Null
        
        $fileSize = (Get-Item $outputPath).Length
        Write-Host "   [OK] Exported to: $outputPath" -ForegroundColor Green
        Write-Host "   File size: $fileSize bytes" -ForegroundColor Gray
        
        if ($fileSize -lt 100) {
            Write-Host "   [WARN] File seems too small, might not be valid" -ForegroundColor Yellow
        } else {
            $exportSuccess = $true
        }
    } catch {
        Write-Host "   [ERROR] Method 1 failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Method 2: Try reading from Windows Certificate Store
if (-not $exportSuccess) {
    Write-Host "   Trying Method 2: Certificate Store..." -ForegroundColor Gray
    try {
        $certs = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { 
            $_.Subject -like "*EK*" -or $_.Subject -like "*Endorsement*" 
        }
        
        if ($certs) {
            Write-Host "   Found $($certs.Count) potential EK certificates in store" -ForegroundColor Green
            $cert = $certs[0]
            $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            [System.IO.File]::WriteAllBytes($outputPath, $certBytes)
            Write-Host "   [OK] Exported from store to: $outputPath" -ForegroundColor Green
            Write-Host "   File size: $($certBytes.Length) bytes" -ForegroundColor Gray
            $exportSuccess = $true
        } else {
            Write-Host "   [WARN] No EK certificates found in certificate store" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "   [ERROR] Method 2 failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Method 3: Check common TPM certificate locations
if (-not $exportSuccess) {
    Write-Host "   Trying Method 3: Common locations..." -ForegroundColor Gray
    $commonPaths = @(
        "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\*ek*",
        "$env:WINDIR\System32\config\systemprofile\AppData\Local\Microsoft\Crypto\RSA\*ek*"
    )
    
    foreach ($path in $commonPaths) {
        $files = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
        if ($files) {
            Write-Host "   Found files at: $path" -ForegroundColor Green
            foreach ($file in $files) {
                Write-Host "   - $($file.Name) ($($file.Length) bytes)" -ForegroundColor Gray
            }
        }
    }
}

Write-Host ""
Write-Host "4. Verifying Your Existing File..." -ForegroundColor Yellow
$existingFile = "D:\myEkcert.cer"
if (Test-Path $existingFile) {
    $size = (Get-Item $existingFile).Length
    Write-Host "   File: $existingFile" -ForegroundColor Gray
    Write-Host "   Size: $size bytes" -ForegroundColor Gray
    
    $bytes = [System.IO.File]::ReadAllBytes($existingFile)
    $hexPreview = ($bytes | Select-Object -First 16 | ForEach-Object { $_.ToString("X2") }) -join " "
    Write-Host "   First 16 bytes (hex): $hexPreview" -ForegroundColor Gray
    
    if ($size -lt 100) {
        Write-Host "   [ERROR] This file is too small to be a valid certificate!" -ForegroundColor Red
        Write-Host "   A real X.509 certificate should be 500-2000+ bytes" -ForegroundColor Red
    }
} else {
    Write-Host "   [ERROR] File not found: $existingFile" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
if ($exportSuccess) {
    Write-Host "[SUCCESS] Successfully exported EK certificate to: $outputPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "Update your PowerShell script to use this file:" -ForegroundColor Yellow
    Write-Host "`$localEkPath = `"$outputPath`"" -ForegroundColor Gray
} else {
    Write-Host "[WARNING] Could not export EK certificate automatically" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Cyan
    Write-Host "1. Your TPM may not have an EK certificate installed" -ForegroundColor Gray
    Write-Host "2. You may need to provision TPM with manufacturer tools" -ForegroundColor Gray
    Write-Host "3. Use EK hash instead (already working in your code)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "For now, you can modify server.js to accept devices with only EK hash" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")