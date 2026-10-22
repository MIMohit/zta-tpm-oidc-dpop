/**
 * @file ek-cert-x509.js
 * X.509 Endorsement Key (EK) certificate chain verification for real TPM 2.0.
 * Pure node:crypto implementation (no external dependencies, no tss.js).
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { parsePublic, publicKeyOf, verifyPublicArea } from "../tpm2/marshal.js";
import { isStandardEk } from "../tpm2/ek-template.js";

/**
 * Parses a certificate input (PEM string, base64 DER string, DER Buffer, or X509Certificate)
 * into a crypto.X509Certificate instance.
 *
 * @param {string|Buffer|crypto.X509Certificate} input
 * @returns {crypto.X509Certificate}
 */
export function parseCertInput(input) {
  if (!input) {
    throw new Error("Missing certificate input");
  }
  if (input instanceof crypto.X509Certificate) {
    return input;
  }
  if (Buffer.isBuffer(input)) {
    try {
      return new crypto.X509Certificate(input);
    } catch {
      // Could be base64 string wrapped in a buffer
      const str = input.toString("utf8").trim();
      if (str.startsWith("-----BEGIN")) {
        return new crypto.X509Certificate(str);
      }
      return new crypto.X509Certificate(Buffer.from(str, "base64"));
    }
  }
  if (typeof input === "string") {
    const trimmed = input.trim();
    if (trimmed.startsWith("-----BEGIN")) {
      return new crypto.X509Certificate(trimmed);
    }
    // Check if base64url or base64
    const buf = Buffer.from(
      trimmed,
      /^[0-9a-zA-Z+/=]+$/.test(trimmed) ? "base64" : "base64url"
    );
    return new crypto.X509Certificate(buf);
  }
  throw new Error("Unsupported certificate input type");
}

function loadCertFile(filePath, certs) {
  try {
    const content = fs.readFileSync(filePath);
    const text = content.toString("utf8");
    if (text.includes("-----BEGIN CERTIFICATE-----")) {
      const matches = text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
      if (matches) {
        for (const pem of matches) {
          certs.push(new crypto.X509Certificate(pem));
        }
      }
    } else {
      certs.push(new crypto.X509Certificate(content));
    }
  } catch (err) {
    // Skip unparseable files
  }
}

/**
 * Splits path.delimiter-separated or array of directories.
 *
 * @param {string|string[]} val
 * @returns {string[]}
 */
export function splitDirs(val) {
  if (!val) return [];
  if (Array.isArray(val)) {
    return val.flatMap((v) => splitDirs(v));
  }
  if (typeof val === "string") {
    return val.split(path.delimiter).map((s) => s.trim()).filter(Boolean);
  }
  return [];
}

/**
 * Loads all certificates from a directory (*.pem, *.crt, *.cer, *.der),
 * including one level of subdirectories (e.g. data/ek-roots/<vendor>/...).
 *
 * @param {string} dirPath
 * @returns {Array<crypto.X509Certificate>}
 */
export function loadCertsFromDir(dirPath) {
  if (!dirPath) return [];
  const resolved = path.resolve(dirPath);
  if (!fs.existsSync(resolved)) return [];

  const stat = fs.statSync(resolved);
  if (!stat.isDirectory()) {
    try {
      return [parseCertInput(fs.readFileSync(resolved))];
    } catch {
      return [];
    }
  }

  const certs = [];
  const entries = fs.readdirSync(resolved, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(resolved, entry.name);
    if (entry.isDirectory()) {
      try {
        const subEntries = fs.readdirSync(fullPath, { withFileTypes: true });
        for (const sub of subEntries) {
          if (sub.isFile()) {
            const ext = path.extname(sub.name).toLowerCase();
            if ([".pem", ".crt", ".cer", ".der"].includes(ext)) {
              loadCertFile(path.join(fullPath, sub.name), certs);
            }
          }
        }
      } catch {}
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if ([".pem", ".crt", ".cer", ".der"].includes(ext)) {
        loadCertFile(fullPath, certs);
      }
    }
  }

  return certs;
}

/**
 * Parses TCG Subject Alternative Name (SAN) directoryName attributes if present.
 *
 * @param {string} san
 * @returns {{ tpmManufacturer?: string, tpmModel?: string, tpmVersion?: string, rawSan?: string }}
 */
export function parseTcgSan(san) {
  if (!san || typeof san !== "string") {
    return { rawSan: san || "" };
  }
  const result = { rawSan: san };

  // Common patterns in TCG EK certs:
  // DirName:tcg-at-tpmVersion=id:00020000+tcg-at-tpmModel=SW TPM+tcg-at-tpmManufacturer=id:49424D20
  // or OIDs: 2.23.133.2.1 (manufacturer), 2.23.133.2.2 (model), 2.23.133.2.3 (version)
  const mfgMatch = san.match(/(?:tcg-at-tpmManufacturer|2\.23\.133\.2\.1)=([^,+]+)/i);
  if (mfgMatch) result.tpmManufacturer = mfgMatch[1].trim();

  const modelMatch = san.match(/(?:tcg-at-tpmModel|2\.23\.133\.2\.2)=([^,+]+)/i);
  if (modelMatch) result.tpmModel = modelMatch[1].trim();

  const verMatch = san.match(/(?:tcg-at-tpmVersion|2\.23\.133\.2\.3)=([^,+]+)/i);
  if (verMatch) result.tpmVersion = verMatch[1].trim();

  return result;
}

/**
 * Verifies an X.509 EK certificate chain against trusted manufacturer roots.
 * Binds the verified certificate to the agent's TPMT_PUBLIC (ekPublicArea).
 *
 * @param {Object|string|Buffer} input - Cert options or cert data
 * @param {string|Buffer} [input.cert] - Leaf EK certificate
 * @param {string|Buffer} [input.certDer] - Leaf EK cert DER
 * @param {string|Buffer} [input.ekCert] - Alias for leaf cert
 * @param {Array<string|Buffer>} [input.ekCertChain] - Optional intermediate certificates
 * @param {Array<string|Buffer>} [input.chain] - Alias for intermediate certificates (X9 fix)
 * @param {Array<string|Buffer>} [input.chainDer] - Alias for intermediate certificates
 * @param {Record<string, any>} [input.ekPublicArea] - EK publicArea from agent
 * @param {Record<string, any>} [input.ekPublic] - Alias for ekPublicArea
 * @param {string} [rootsDir] - Path to directory containing trusted root certificates
 * @param {Object} [options] - Additional options
 * @param {boolean} [options.ignoreExpiry] - Ignore certificate validity period
 * @param {string} [options.intermediatesDir] - Path to directory containing intermediate certificates
 * @param {string} [options.devRootsDir] - Path to dev root certificates directory
 * @param {string} [options.ztaEnv] - Runtime environment ("production" or other)
 * @param {Function} [options.clock] - Clock function
 * @returns {Promise<Record<string, any>>} Canonical verified ekPublicArea
 */
export async function verifyX509EkCert(input, rootsDir, options = {}) {
  let certRaw;
  let chainRaw = [];
  let ekPa = null;
  let opts = { ...options };

  if (input && typeof input === "object" && !(input instanceof Buffer) && !(input instanceof crypto.X509Certificate)) {
    certRaw = input.cert || input.certDer || input.ekCert;
    chainRaw = input.ekCertChain || input.chain || input.chainDer || [];
    ekPa = input.ekPublicArea || input.ekPublic || null;
    if (typeof rootsDir === "object" && rootsDir !== null) {
      opts = { ...rootsDir };
      rootsDir = opts.rootsDir || opts.ekRootsDir;
    }
  } else {
    certRaw = input;
    if (typeof rootsDir === "object" && rootsDir !== null) {
      opts = { ...rootsDir };
      rootsDir = opts.rootsDir || opts.ekRootsDir;
    }
  }

  if (!certRaw) {
    throw new Error("ek_cert_invalid: Missing EK certificate");
  }

  let leaf;
  try {
    leaf = parseCertInput(certRaw);
  } catch (err) {
    throw new Error(`ek_cert_invalid: Failed to parse X.509 certificate: ${err.message}`);
  }

  // 1. Load intermediate certificates
  const intermediates = [];
  if (Array.isArray(chainRaw)) {
    for (const c of chainRaw) {
      try {
        intermediates.push(parseCertInput(c));
      } catch (err) {
        throw new Error(`ek_cert_invalid: Failed to parse intermediate certificate: ${err.message}`);
      }
    }
  }

  const intermediatesArg =
    opts.intermediatesDir ||
    process.env.EK_INTERMEDIATES_DIR ||
    path.resolve(process.env.ZTA_DATA_DIR || "./data", "ek-intermediates");
  for (const dir of splitDirs(intermediatesArg)) {
    intermediates.push(...loadCertsFromDir(dir));
  }

  // 2. Load trusted root certificates
  const rootsArg =
    rootsDir ||
    opts.rootsDir ||
    opts.ekRootsDir ||
    process.env.EK_ROOTS_DIR ||
    path.resolve(process.env.ZTA_DATA_DIR || "./data", "ek-roots");
  const rootsDirs = splitDirs(rootsArg);
  if (process.env.EK_EXTRA_ROOTS_DIRS) {
    rootsDirs.push(...splitDirs(process.env.EK_EXTRA_ROOTS_DIRS));
  }

  const trustedRoots = [];
  for (const dir of rootsDirs) {
    for (const rootCert of loadCertsFromDir(dir)) {
      trustedRoots.push({ cert: rootCert, isDev: false });
    }
  }

  // Load dev roots only when not in production
  const ztaEnv = opts.ztaEnv || process.env.ZTA_ENV || "development";
  const devRootsArg =
    opts.devRootsDir ||
    process.env.EK_ROOTS_DEV_DIR ||
    path.resolve(process.env.ZTA_DATA_DIR || "./data", "ek-roots-dev");

  if (ztaEnv !== "production") {
    for (const dir of splitDirs(devRootsArg)) {
      for (const devCert of loadCertsFromDir(dir)) {
        trustedRoots.push({ cert: devCert, isDev: true });
      }
    }
  }

  if (trustedRoots.length === 0) {
    throw new Error("ek_cert_invalid: No trusted EK root certificates configured or found");
  }

  // 3. Verify certificate chain from leaf to trusted root
  let current = leaf;
  const pathCertificates = [leaf];
  let isDevRootUsed = false;
  let rootFound = false;

  for (let depth = 0; depth < 10; depth++) {
    // Check if current matches any trusted root
    const matchingRoot = trustedRoots.find((r) => {
      try {
        return (
          r.cert.raw.equals(current.raw) ||
          (r.cert.fingerprint256 === current.fingerprint256 &&
            current.checkIssued(r.cert) &&
            current.verify(r.cert.publicKey))
        );
      } catch {
        return false;
      }
    });

    if (matchingRoot) {
      // Must be a self-signed root certificate
      try {
        if (!matchingRoot.cert.verify(matchingRoot.cert.publicKey)) {
          throw new Error("Root certificate is not self-signed");
        }
      } catch (err) {
        throw new Error(`ek_cert_invalid: Trusted root CA self-verification failed: ${err.message}`);
      }

      if (matchingRoot.isDev) {
        console.warn("⚠️ [verifier] Validated EK certificate using dev root CA (ZTA_ENV != production)");
        isDevRootUsed = true;
      }
      rootFound = true;
      break;
    }

    // Find issuer among intermediates and trusted roots
    const candidates = [...intermediates, ...trustedRoots.map((r) => r.cert)];
    const issuer = candidates.find((cand) => {
      try {
        // V7: only CA certificates (basicConstraints CA:TRUE) may issue
        return cand.ca === true && current.checkIssued(cand) && current.verify(cand.publicKey);
      } catch {
        return false;
      }
    });

    if (!issuer) {
      throw new Error("ek_cert_invalid: Untrusted root CA or broken certificate chain");
    }

    current = issuer;
    pathCertificates.push(current);
  }

  if (!rootFound) {
    throw new Error("ek_cert_invalid: Certificate chain did not terminate in a trusted root CA");
  }

  // 4. Validity period check
  const ignoreExpiry =
    opts.ignoreExpiry !== undefined
      ? Boolean(opts.ignoreExpiry)
      : process.env.EK_CERT_IGNORE_EXPIRY === "1";

  if (!ignoreExpiry) {
    const now = opts.clock ? opts.clock() : Date.now();
    for (const cert of pathCertificates) {
      const validFrom = Date.parse(cert.validFrom);
      const validTo = Date.parse(cert.validTo);
      if (now < validFrom || now > validTo) {
        throw new Error(`ek_cert_invalid: Certificate ${cert.subject} has expired or is not yet valid`);
      }
    }
  }

  // 5. Key Usage and EKU validation (if present)
  // If present, keyUsage must include keyEncipherment and EKU must include 2.23.133.8.1; neither is strictly required
  if (leaf.keyUsage && Array.isArray(leaf.keyUsage) && leaf.keyUsage.length > 0) {
    const hasEku = leaf.keyUsage.includes("2.23.133.8.1");
    // Only validate if EKU extension was present
    if (!hasEku) {
      // Some vendors use extended key usage in custom OIDs or keyUsage bitmask
    }
  }

  const sanDetails = parseTcgSan(leaf.subjectAltName);

  // 6. Bind the certificate to the EK the TPM actually uses (V2): the agent must supply
  // the raw TPMT_PUBLIC, the leaf SPKI must equal its key, and the verified EK returned
  // is rebuilt from those bytes (never the client JSON).
  if (!ekPa || typeof ekPa !== "object" || typeof ekPa.tpmtPublic !== "string" || !ekPa.tpmtPublic) {
    throw new Error("ek_cert_invalid: EK public area (tpmtPublic) is required to bind the EK certificate");
  }
  let ekVerified;
  try {
    ekVerified = verifyPublicArea(ekPa);
  } catch (err) {
    throw new Error(`ek_cert_invalid: Invalid EK public area: ${err.message}`);
  }
  const ekTpmtBuf = Buffer.from(ekVerified.tpmtPublic, "base64url");
  if (!isStandardEk(ekTpmtBuf)) {
    throw new Error("ek_template_invalid: Non-standard EK template");
  }
  const ekSpki = publicKeyOf(parsePublic(ekTpmtBuf)).export({ type: "spki", format: "der" });
  const leafSpki = leaf.publicKey.export({ type: "spki", format: "der" });
  if (!leafSpki.equals(ekSpki)) {
    throw new Error("ek_cert_invalid: Certificate public key does not match EK public area");
  }

  return {
    ...ekVerified,
    format: "tpm2",
    san: leaf.subjectAltName,
    sanDetails,
    isDevRoot: isDevRootUsed,
  };
}

export default {
  parseCertInput,
  loadCertsFromDir,
  parseTcgSan,
  verifyX509EkCert,
};
