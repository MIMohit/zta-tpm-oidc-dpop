# Provenance of TCG Event Log Fixtures

## 1. tpm2-tools Fixtures
The binary event log fixtures in `tpm2-tools/` are sourced from the [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) project under `test/integration/fixtures/`:
- **Repository**: https://github.com/tpm2-software/tpm2-tools
- **Commit**: `915443b32e04fb4c8ddee80b653b234669395a6a`
- **Files**:
  - `event-arch-linux.bin`, `event-arch-linux.bin.warn`
  - `event-bootorder.bin`
  - `event-gce-ubuntu-2104-log.bin`
  - `event-moklisttrusted.bin`
  - `event-postcode.bin`
  - `event-sd-boot-fedora37.bin`
  - `event-uefi-sha1-log.bin` (legacy SHA-1 log fixture)
  - `event-uefiaction.bin`
  - `event-uefiservices.bin`
  - `event-uefivar.bin`
  - `event.bin`, `event.bin.yaml`
  - `specid-vendordata.bin`, `specid-vendordata.bin.yaml`

### License Notice (BSD-3-Clause)
```text
Copyright (c) 2017, Intel Corporation
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of Intel Corporation nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

## 2. QEMU + EDK2 + swtpm Captured Log (`qemu-edk2-swtpm/`)
- **Captured File**: `ubuntu-noble-arm64-edk2.bin` (5,647 bytes)
- **Ground Truth PCRs**: `ubuntu-noble-arm64-edk2.pcrs-sha256.txt` (read from kernel `/sys/class/tpm/tpm0/pcr-sha256/N`)
- **Kernel**: Ubuntu noble arm64 generic `6.8.0-142-generic` (`vmlinuz-generic` + `initrd-generic`) from `https://cloud-images.ubuntu.com/noble/current/unpacked/`
- **Environment**:
  - QEMU 11 (aarch64 `virt` machine, TCG acceleration)
  - swtpm 0.10.2 (`tpm-tis-device`)
  - Firmware: EDK2 `edk2-aarch64-code.fd` (`edk2-stable202408-prebuilt.qemu.org`)
- **Capture Command Line**:
  ```sh
  python3 -I provenance/capture_evlog.py <labdir> <Image> <initrd> <outprefix>
  ```
  Where QEMU boots:
  ```sh
  qemu-system-aarch64 -M virt -accel tcg,thread=multi -cpu max -smp 2 -m 1024 \
    -drive if=pflash,format=raw,readonly=on,file=edk2-aarch64-code.fd \
    -drive if=pflash,format=raw,file=vars.fd \
    -kernel vmlinuz -initrd initrd -append "console=ttyAMA0 rdinit=/bin/sh" \
    -chardev socket,id=chrtpm,path=/tmp/ztamac/swtpm.sock -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis-device,tpmdev=tpm0 -drive file=out.raw,format=raw,if=virtio \
    -display none -monitor none -net none
  ```
  And inside the guest:
  `cat /sys/kernel/security/tpm0/binary_bios_measurements > /dev/vda`

### Caveats (X4 & X5)
- **X4 (Topology Sensitivity)**: Event log PCR measurements are sensitive to the QEMU device topology and NVRAM variables (`VARS.fd`). Booting with different devices (e.g., adding/removing virtio drives or NICs) changes PCR1 (`EV_EFI_VARIABLE_BOOT`).
- **X5 (Direct Kernel Boot)**: Direct `-kernel` boot bypasses the EFI bootloader. As a result, PCR4 contains only firmware application launches and separators; the kernel and initrd are not measured into PCR0-7 by UEFI (the initrd is measured by the Linux EFI stub into PCR9). For full kernel measurement in PCR4, boot through OVMF/EDK2 -> shim -> GRUB -> kernel via `LoadImage`.

## qemu-ubuntu-noble (x86_64, KVM, shim + GRUB): `golden-grub-6.8.bin`, `tampered-grub-7.0.bin`

Recorded on the Ryzen testbed (Section "Testbed") from the KVM fleet built by `testbed/image-build.sh`;
used by A06 and by the reference-value profiles in `fixtures/rv/`.

- **Image**: Ubuntu 24.04 (noble) server cloud image, amd64, from `https://cloud-images.ubuntu.com/noble/current/`
  (checksum verified by `testbed/image-fetch.sh`), 12 GB qcow2 overlay per device.
- **Boot chain**: OVMF (Arch Linux `edk2-ovmf`, `OVMF_CODE.4m.fd`) -> shim -> GRUB -> kernel, with
  swtpm 0.10.2 per VM (`tpm-crb`), QEMU 11.1, KVM. GRUB measures its configuration, commands and the kernel
  into PCR8 and PCR9.
- **Capture**: a systemd unit in the guest copies `/sys/kernel/security/tpm0/binary_bios_measurements` to
  `/run/zta/` at boot; the agent sends that file. The golden log is from the second boot of `dev-good`
  (the first boot changes PCR5, the GPT, as cloud-init grows the partition).
  - `golden-grub-6.8.bin`: `dev-good`, kernel `6.8.0-147-generic`. Same file as `golden-b2.bin`, the source of
    `fixtures/rv/ubuntu-noble-grub.json` (PCR0-9) and `ubuntu-noble-grub-pcr0-7.json` (PCR0-7).
  - `tampered-grub-7.0.bin`: `dev-tampered`, built from the same image with `linux-image-generic-hwe-24.04`
    installed after the reference values were captured and rebooted into kernel `7.0.0-38-generic`. PCR0-7 are
    identical to the golden boot; PCR8 and PCR9 differ (pitfall P-2).
- **Caveat**: PCR1 depends on the VM's device topology and NVRAM (X4); the reference values are only valid for
  the fleet definition in `testbed/vm.sh`.
