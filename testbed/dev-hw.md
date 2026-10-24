# dev-hw: AMD fTPM Setup and Hardware Device Guide

This document describes how to configure, provision, and operate the physical Ryzen laptop hardware device (`dev-hw`) equipped with an AMD firmware TPM (fTPM 2.0).

---

## 1. BIOS Configuration & Safety Rules

1. **Enable AMD SVM (Secure Virtual Machine):**
   * BIOS / Advanced CPU Configuration → `SVM Mode` = **Enabled**.
2. **Enable AMD fTPM:**
   * BIOS / Security → `AMD fTPM switch` = **Enabled** (AMD CPU fTPM).
3. **CRITICAL: NEVER RUN `tpm2_clear`:**
   * Clearing the physical fTPM clears the Storage Root Key (SRK) and NV indices.
   * If the endorsement key certificate is stored in non-volatile storage, clearing may necessitate re-fetching the EK certificate from AMD's Authority Information Access (AIA) service.

---

## 2. Endorsement Key (EK) Certificate Provisioning

AMD fTPMs often do not preload the X.509 EK certificate into standard NVRAM index `0x01C00002` / `0x01C0000A`. There are two supported methods to obtain the certificate:

### Method A: Fetch from AMD AIA via `tpm2_getekcertificate`
AMD provisions certificates online via their AIA server using the TPM's public endorsement key:
```bash
# Read EK certificate using tpm2-tools:
tpm2_getekcertificate -o data/agent/dev-hw/ek-cert.der
```

### Method B: Export from Windows (Dual-Boot or Windows PE)
If running Windows or WinPE on the laptop:
```powershell
# PowerShell (Administrator)
$ek = Get-TpmEndorsementKeyInfo -HashAlgorithm SHA256
[System.IO.File]::WriteAllBytes("dev-hw-ek.cer", $ek.PublicKey)
```

### Trust Anchor Configuration
Every certificate in a roots directory must be a self-signed root; an intermediate placed there makes chain validation fail. Keep the AMD root and the AMD intermediate in separate directories. Verified on the Ryzen 7 5700U on 22 Oct 2026 (EK issuer `CN=PRG-RN`, root `CN=AMDTPM`, root SHA-256 fingerprint `67:BD:24:72:…:D0:C6:A1`):
```bash
mkdir -p data/agent/dev-hw data/ek-roots/amd data/ek-intermediates/amd
cd data/agent/dev-hw
tpm2_createek -c ek-rsa.ctx -G rsa -u ek-rsa.pub
tpm2_getekcertificate -u ek-rsa.pub -o ek-rsa.der     # fetched from ftpm.amd.com
tpm2_flushcontext -t
# Follow the AIA URLs: EK cert -> intermediate (PRG-RN) -> root (AMDTPM)
openssl x509 -inform der -in ek-rsa.der -noout -ext authorityInfoAccess
curl -fsS -o ../../ek-intermediates/amd/ica.der <CA Issuers URI from the EK cert>
openssl x509 -inform der -in ../../ek-intermediates/amd/ica.der -noout -ext authorityInfoAccess
curl -fsS <CA Issuers URI from the intermediate> | openssl x509 -inform der -out ../../ek-roots/amd/root.pem
openssl x509 -inform der -in ../../ek-intermediates/amd/ica.der -out ../../ek-intermediates/amd/ica.pem
openssl verify -CAfile ../../ek-roots/amd/root.pem -untrusted ../../ek-intermediates/amd/ica.pem \
  <(openssl x509 -inform der -in ek-rsa.der)
# Configure environment:
export EK_EXTRA_ROOTS_DIRS="data/ek-roots/amd"
export EK_INTERMEDIATES_DIR="data/ek-intermediates/amd"
export TPM_EK_CERT_FILE="data/agent/dev-hw/ek-rsa.der"
```

---

## 3. Persistent Storage Root Key (SRK) Recipe

The ZTA agent binds device keys to the Storage Root Key at persistent handle `0x81000101`:

```bash
# Create primary key under owner hierarchy (Storage hierarchy)
tpm2_createprimary -C o -g sha256 -G ecc -c /tmp/srk.ctx

# Make handle persistent at 0x81000101
tpm2_evictcontrol -C o -c /tmp/srk.ctx 0x81000101
rm -f /tmp/srk.ctx

# Set agent environment variable
export TPM_SRK_HANDLE="0x81000101"
```

---

## 4. Kernel Resource Manager Permissions (`/dev/tpmrm0`)

The physical device kernel exposes `/dev/tpmrm0`. The ZTA agent runs under an unprivileged user `zta`:
```bash
# Ensure user belongs to the tss group
sudo usermod -aG tss zta

# Verify access
ls -l /dev/tpmrm0
# Expected: crw-rw---- 1 tss tss ... /dev/tpmrm0
```

---

## 5. Event Log Access via `zta-eventlog.service`

On Omarchy (kernel 7.2.8-9-omarchy) the log is `0440 root:tss`, so an agent user in the `tss` group reads it directly and this service is not needed; set `TPM_EVENTLOG_PATH=/sys/kernel/security/tpm0/binary_bios_measurements`. On distributions where the log is `0440 root:root`, install the root oneshot service:

```ini
# /etc/systemd/system/zta-eventlog.service
[Unit]
Description=ZTA Event Log Copy (root oneshot)
DefaultDependencies=no
Before=zta-agent.service
ConditionPathExists=/sys/kernel/security/tpm0/binary_bios_measurements

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'mkdir -p /run/zta && cp /sys/kernel/security/tpm0/binary_bios_measurements /run/zta/binary_bios_measurements && chmod 0444 /run/zta/binary_bios_measurements'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now zta-eventlog.service
```

Agent environment:
```bash
export TPM_BACKEND="tpm"
export TPM_DEVICE="linux"
export TPM_EVENTLOG_PATH="/run/zta/binary_bios_measurements"
```

---

## 6. Freeze Rules During Evaluation

**CRITICAL: FREEZE SYSTEM UPDATES (`pacman -Syu`):**
* Any kernel, firmware (`linux-firmware`), systemd-boot, or GRUB update modifies binaries measured into PCR0, PCR4, and PCR7.
* During evaluation benchmarks (E1–E8), do NOT run `pacman -Syu` or modify EFI boot entries.
* If a hardware PCR4 change experiment is desired, create a separate distinct secondary kernel boot entry in `/boot/loader/entries/` rather than modifying the active baseline.
