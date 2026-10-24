# swtpm Fixtures

These fixtures were extracted from a local `swtpm` 0.10.2 manufacturing run using `swtpm_setup`.

## Provisioning Details
- **swtpm version:** 0.10.2
- **Setup command:**
  `swtpm_setup --tpm2 --tpmstate <dir> --create-ek-cert --create-platform-cert --pcr-banks sha256 --config <conf>`
- **Active PCR banks:** sha256
- **Persistent EKs:**
  - RSA-2048 (L-1) at persistent handle `0x81010001`
  - ECC NIST P-384 (H-3) at persistent handle `0x81010016`
- **NV Indices:**
  - `0x01c00002`: RSA-2048 EK Certificate (1024 bytes)
  - `0x01c00016`: ECC P-384 EK Certificate (850 bytes)
  - `0x01c08000`: Platform Certificate (978 bytes)
- **Issuer / CA:**
  - `swtpm-localca-issuer.pem`: Intermediate CA (`CN=swtpm-localca`)
  - `swtpm-localca-root.pem`: Root CA (`CN=swtpm-localca-rootca`)
