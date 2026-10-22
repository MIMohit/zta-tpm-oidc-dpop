/**
 * @file ek-cert.js
 * Endorsement Key (EK) certificate reading from TPM NV, TPM_EK_CERT_FILE, state directory, or Windows PowerShell.
 * Supports standard TCG NV indices (TCG EK Credential Profile §2.2.1.5 Table 3 & 4):
 *  - RSA: 0x01C00002 (L-1), 0x01C00012 (H-1)
 *  - ECC: 0x01C0000A (L-2), 0x01C00014 (H-2)
 *  - ECC384: 0x01C00016 (H-3, confirmed on swtpm 0.10.2)
 */
import fs from "node:fs";
import path from "node:path";
import tss from "tss.js";
import { WindowsEkTpm } from "../sim-tpm/windows-ek.js";

const { TPM_HANDLE } = tss;

export const NV_INDEX_EK_CERT_RSA = 0x01c00002;
export const NV_INDEX_EK_CERT_ECC = 0x01c0000a;
export const NV_INDEX_EK_CERT_ECC384 = 0x01c00016;

// TCG EK Credential Profile §2.2.1.5 Table 3 & 4
export const NV_INDICES_EK_CERT = {
  rsa: [0x01c00002, 0x01c00012], // L-1, H-1
  ecc: [0x01c0000a, 0x01c00014], // L-2, H-2
  ecc384: [0x01c00016],          // H-3 (confirmed on swtpm)
};

/**
 * Trims a buffer containing a DER X.509 certificate to its exact ASN.1 DER length
 * based on the outer SEQUENCE length tag (handles trailing 0x00 or 0xFF padding).
 *
 * @param {Buffer} buf
 * @returns {Buffer}
 */
export function trimDer(buf) {
  if (!buf || !Buffer.isBuffer(buf) || buf.length < 2) return buf;
  if (buf[0] !== 0x30) return buf; // not a SEQUENCE
  const b1 = buf[1];
  let len = 0;
  let headerLen = 2;
  if (b1 < 0x80) {
    len = b1;
    headerLen = 2;
  } else if (b1 === 0x81) {
    if (buf.length < 3) return buf;
    len = buf[2];
    headerLen = 3;
  } else if (b1 === 0x82) {
    if (buf.length < 4) return buf;
    len = buf.readUInt16BE(2);
    headerLen = 4;
  } else if (b1 === 0x83) {
    if (buf.length < 5) return buf;
    len = (buf[2] << 16) | buf.readUInt16BE(3);
    headerLen = 5;
  } else {
    return buf;
  }
  const total = headerLen + len;
  if (buf.length >= total) {
    return buf.subarray(0, total);
  }
  return buf;
}

/**
 * Reads an X.509 certificate from a specified file (accepts PEM or DER format).
 *
 * @param {string} filePath
 * @returns {Buffer|null} DER buffer or null
 */
export function readEkCertFromFile(filePath) {
  if (!filePath) return null;
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) return null;

  try {
    const content = fs.readFileSync(resolved);
    const text = content.toString("utf8").trim();
    if (text.includes("-----BEGIN CERTIFICATE-----")) {
      const b64 = text
        .replace(/-----BEGIN [^-]+-----/g, "")
        .replace(/-----END [^-]+-----/g, "")
        .replace(/\s+/g, "");
      return Buffer.from(b64, "base64");
    }
    return trimDer(content);
  } catch {
    return null;
  }
}

/**
 * Reads an X.509 EK certificate from TPM NV storage.
 *
 * @param {Object} conn - TpmConn instance
 * @param {"rsa"|"ecc"|"ecc384"} type
 * @returns {Promise<Buffer|null>} DER-encoded certificate or null
 */
export async function readEkCertFromNv(conn, type) {
  const indices = NV_INDICES_EK_CERT[type] || (type === "rsa" ? [0x01c00002] : [0x01c0000a]);

  for (const idx of indices) {
    const nvHandle = new TPM_HANDLE(idx);
    try {
      const pub = await conn.call("NV_ReadPublic", nvHandle);
      const size = pub?.nvPublic?.dataSize;
      if (!size || size <= 0) continue;

      let out = Buffer.alloc(0);
      for (let off = 0; off < size; off += 1024) {
        const chunkSize = Math.min(1024, size - off);
        const chunk = await conn.call("NV_Read", nvHandle, nvHandle, chunkSize, off);
        out = Buffer.concat([out, Buffer.from(chunk)]);
      }

      if (out.length > 0) {
        const trimmed = trimDer(out);
        if (trimmed && trimmed.length > 0 && trimmed[0] === 0x30) {
          trimmed.nvIndex = idx;
          return trimmed;
        }
      }
    } catch {}
  }

  return null;
}

/**
 * Reads an EK certificate from a fallback file in the state directory.
 *
 * @param {string} stateDir
 * @param {"rsa"|"ecc"|"ecc384"} type
 * @returns {Buffer|null}
 */
export function readEkCertFromDisk(stateDir, type) {
  if (!stateDir) return null;

  const candidates = [
    path.join(stateDir, `ek-cert-${type}.der`),
    path.join(stateDir, `ek-cert-${type}.crt`),
    path.join(stateDir, "ek-cert.der"),
    path.join(stateDir, "ek-cert.crt"),
  ];

  for (const p of candidates) {
    if (fs.existsSync(p)) {
      try {
        const content = fs.readFileSync(p);
        const text = content.toString("utf8").trim();
        if (text.includes("-----BEGIN CERTIFICATE-----")) {
          const b64 = text
            .replace(/-----BEGIN [^-]+-----/g, "")
            .replace(/-----END [^-]+-----/g, "")
            .replace(/\s+/g, "");
          return Buffer.from(b64, "base64");
        }
        return trimDer(content);
      } catch {}
    }
  }

  return null;
}

/**
 * Reads the EK certificate on Windows using PowerShell Get-TpmEndorsementKeyInfo.
 *
 * @returns {Promise<Buffer|null>}
 */
export async function readEkCertWindows() {
  if (process.platform !== "win32") return null;

  try {
    const winEk = new WindowsEkTpm();
    const info = await winEk.getEk();
    if (info?.cert) {
      return Buffer.from(info.cert, "base64");
    }
  } catch {}

  return null;
}

/**
 * Resolves the EK certificate through the source order:
 *  1. TPM NV storage (0x01C00002/12 for RSA, 0x01C0000A/14 for ECC, 0x01C00016 for ECC384)
 *  2. File specified by TPM_EK_CERT_FILE
 *  3. State directory file (ek-cert-<type>.der / ek-cert.der)
 *  4. (Win32) PowerShell export
 *
 * @param {Object} conn - TpmConn
 * @param {"rsa"|"ecc"|"ecc384"} type
 * @param {string} [stateDir]
 * @param {string} [certFile]
 * @returns {Promise<Buffer|null>}
 */
export async function readEkCert(conn, type, stateDir = null, certFile = process.env.TPM_EK_CERT_FILE) {
  // 1. TPM NV
  const nvCert = await readEkCertFromNv(conn, type);
  if (nvCert && nvCert.length > 0) return nvCert;

  // 2. TPM_EK_CERT_FILE
  if (certFile) {
    const fileCert = readEkCertFromFile(certFile);
    if (fileCert && fileCert.length > 0) return fileCert;
  }

  // 3. State dir
  const diskCert = readEkCertFromDisk(stateDir, type);
  if (diskCert && diskCert.length > 0) return diskCert;

  // 4. Windows PowerShell
  if (process.platform === "win32") {
    const winCert = await readEkCertWindows();
    if (winCert && winCert.length > 0) return winCert;
  }

  return null;
}

/**
 * Detects the EK type ("rsa" | "ecc" | "ecc384") when TPM_EK_TYPE=auto.
 * Auto order per PLAN-MAC.md §3.1 item 6: rsa -> ecc -> ecc384.
 *
 * @param {Object} conn
 * @param {string} [stateDir]
 * @param {string} [preferredType="auto"]
 * @returns {Promise<"rsa"|"ecc"|"ecc384">}
 */
export async function detectEkType(conn, stateDir = null, preferredType = "auto") {
  const norm = String(preferredType || "auto").toLowerCase();
  if (norm === "rsa" || norm === "ecc" || norm === "ecc384") {
    return norm;
  }

  // Check RSA cert
  const rsaCert = await readEkCert(conn, "rsa", stateDir);
  if (rsaCert) return "rsa";

  // Check ECC cert
  const eccCert = await readEkCert(conn, "ecc", stateDir);
  if (eccCert) return "ecc";

  // Check ECC384 cert
  const ecc384Cert = await readEkCert(conn, "ecc384", stateDir);
  if (ecc384Cert) return "ecc384";

  // Default to RSA
  return "rsa";
}

export default {
  readEkCert,
  readEkCertFromNv,
  readEkCertFromFile,
  readEkCertFromDisk,
  readEkCertWindows,
  detectEkType,
  trimDer,
  NV_INDEX_EK_CERT_RSA,
  NV_INDEX_EK_CERT_ECC,
  NV_INDEX_EK_CERT_ECC384,
  NV_INDICES_EK_CERT,
};
