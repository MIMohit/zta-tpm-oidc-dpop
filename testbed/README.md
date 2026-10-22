# ZTA vTPM Fleet Testbed

This testbed automates the provisioning, manufacture, lifecycle management, and evaluation of the Zero Trust Architecture (ZTA) device fleet using software TPMs (`swtpm`) and QEMU virtual machines under measured UEFI boot.

---

## 1. Fleet Device Table

Per Research Plan §5 and PLAN-MAC.md §6.1, the fleet consists of four virtual devices and one optional hardware device:

| Device | Type | Base Image | CA / Certificate | Agent Port | SSH Port | Purpose & Evaluation Role |
|---|---|---|---|---|---|---|
| `dev-good` | VM (vTPM) | `golden` | `good` (lab root CA) | `7101` | `2221` | Baseline honest device; measured boot reference values |
| `dev-tampered` | VM (vTPM) | `tampered` | `good` (lab root CA) | `7102` | `2222` | Tampered kernel/bootloader; tests PCR4 change & suspension |
| `dev-rogue` | VM (vTPM) | `golden` | `good` (genuine EK cert) | `7103` | `2223` | Genuine TPM EK cert, but omitted from inventory (A01) |
| `dev-foreign` | VM (vTPM) | `golden` | `foreign` (untrusted CA) | `7104` | `2224` | EK cert issued by foreign untrusted CA (A02) |
| `dev-hw` | Physical | Native Linux | AMD OEM manufacturer CA | `7105` | `2225` | Physical Ryzen laptop with AMD fTPM (latency & E2-E8) |

---

## 2. Host Prerequisites

The testbed scripts support both Arch Linux (`pacman`) and Debian/Ubuntu (`apt`), with developer dry-run and functional testing support on macOS (`brew`):

### Arch Linux (Target evaluation host):
```bash
sudo pacman -S --needed qemu-base qemu-img swtpm edk2-ovmf tpm2-tools openssl xorriso cdrtools python
```

### Debian / Ubuntu (Reviewer reproduction):
```bash
sudo apt-get install -y qemu-system-x86 qemu-utils swtpm swtpm-tools ovmf tpm2-tools openssl cloud-image-utils python3
```

### macOS (Apple Silicon / Intel - Developer preview):
```bash
brew install qemu swtpm shellcheck
```

---

## 3. Platform Limits & Architectural Findings

1. **macOS Hypervisor Framework (HVF) Limitation:**
   * In feasibility testing (Finding X10), Apple's Hypervisor.framework (`-accel hvf`) failed with `HV_BAD_ARGUMENT` when attached to TPM emulation devices (`tpm-tis-device` or `tpm-crb`).
   * On macOS, QEMU strictly uses pure emulation (`-accel tcg`). Production benchmark evaluations run on Linux with KVM (`accel=kvm`).
2. **UNIX Socket Length Limitation (Finding X10):**
   * macOS limits UNIX domain socket paths to approximately 104 bytes. Long paths cause `Path for UnixIO socket is too long`.
   * On macOS, sockets are placed in `/tmp/ztamac/`. On Linux, sockets are placed in `${XDG_RUNTIME_DIR}/zta/` (short paths ≤ 100 bytes).
3. **Firmware Measured Boot (Findings X4 & X5):**
   * Reference values are strictly tied to VM hardware topology and firmware `VARS.fd` (Finding X4).
   * Direct `-kernel` boot does NOT measure the kernel into PCR0–7 (Finding X5). Therefore, fleet VMs boot via UEFI (`OVMF_CODE.fd` / `edk2-aarch64-code.fd`) through shim/GRUB, measuring the kernel binary into PCR4 via `LoadImage`.

---

## 4. Resource & Memory Budget

Each virtual machine is provisioned with:
* RAM: `1536 MB`
* vCPUs: `2`
* Total 4-VM fleet allocation: `6 GB RAM` and `8 vCPUs`.
* Easily accommodates standard workstation and laptop hosts (16 GB - 32 GB RAM).

---

## 5. Freeze Rules During Evaluation Runs

* **Freeze OS Updates:** Package updates (`pacman -Syu` or `apt-get upgrade`) alter kernel binaries, systemd libraries, and GRUB EFI binaries, which alters PCR0, PCR4, and PCR7 reference values. Freeze package updates while conducting evaluation benchmarks (E1–E8).
* **Firmware Consistency:** Do not update host QEMU or OVMF/EDK2 packages between Reference Value capture (`rv-capture.sh`) and attack runs.

---

## 6. Quick Start

```bash
# 1. Initialize Certificate Authorities
./ca-init.sh good
./ca-init.sh foreign

# 2. Manufacture all fleet virtual TPMs
./manufacture.sh dev-good --ca good --profile p384
./manufacture.sh dev-tampered --ca good --profile p384
./manufacture.sh dev-rogue --ca good --profile p384
./manufacture.sh dev-foreign --ca foreign --profile p384

# 3. Add eligible devices to inventory (dev-rogue is skipped on purpose)
./inventory.sh dev-good alice
./inventory.sh dev-tampered alice
./inventory.sh dev-foreign bob

# 4. Fetch and build cloud images
./image-fetch.sh
./image-build.sh golden
./image-build.sh tampered

# 5. Boot and verify fleet
./fleet.sh up
./fleet.sh status
./fleet.sh down

# 6. Run lint and dry-run tests
bash tests/lint.sh
bash tests/dry-run.sh
```
