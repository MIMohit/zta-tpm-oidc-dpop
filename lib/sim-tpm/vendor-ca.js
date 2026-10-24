/**
 * @file vendor-ca.js
 * Simulated TPM Vendor CA: key generation, EK certificate issuance and verification.
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import * as jose from "jose";

/**
 * Creates or loads a simulated Vendor CA keypair.
 * Persists private JWK to <dir>/<name>.jwk and public JWK to <dir>/<name>.pub.jwk.
 *
 * @param {string} dir - Directory to store CA keys
 * @param {string} [name="sim-vendor"] - Name of the CA
 * @param {string} [issuer="SimTPM Vendor CA"] - CA issuer identifier
 * @returns {Promise<{ privateKey: any, publicJwk: Record<string, any>, kid: string, name: string, dir: string, issuer: string }>}
 */
export async function createVendorCa(dir, name = "sim-vendor", issuer = "SimTPM Vendor CA") {
  const resolvedDir = path.resolve(dir);
  fs.mkdirSync(resolvedDir, { recursive: true, mode: 0o700 });

  const privPath = path.join(resolvedDir, `${name}.jwk`);
  const pubPath = path.join(resolvedDir, `${name}.pub.jwk`);

  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    const privRaw = fs.readFileSync(privPath, "utf8");
    const pubRaw = fs.readFileSync(pubPath, "utf8");
    const privateJwk = JSON.parse(privRaw);
    const publicJwk = JSON.parse(pubRaw);
    const privateKey = await jose.importJWK(privateJwk, "ES256");
    const kid = publicJwk.kid || (await jose.calculateJwkThumbprint(publicJwk, "sha256"));
    return {
      privateKey,
      privateJwk,
      publicJwk,
      kid,
      name,
      dir: resolvedDir,
      issuer,
    };
  }

  // Generate new ES256 key pair
  const { privateKey, publicKey } = await jose.generateKeyPair("ES256", { extractable: true });
  const privateJwk = await jose.exportJWK(privateKey);
  const publicJwk = await jose.exportJWK(publicKey);
  const kid = await jose.calculateJwkThumbprint(publicJwk, "sha256");

  privateJwk.kid = kid;
  privateJwk.alg = "ES256";
  privateJwk.use = "sig";

  publicJwk.kid = kid;
  publicJwk.alg = "ES256";
  publicJwk.use = "sig";

  fs.writeFileSync(privPath, JSON.stringify(privateJwk, null, 2), {
    encoding: "utf8",
    mode: 0o600,
  });
  try {
    fs.chmodSync(privPath, 0o600);
  } catch {
    // Ignore chmod failure on non-POSIX filesystems
  }

  fs.writeFileSync(pubPath, JSON.stringify(publicJwk, null, 2), {
    encoding: "utf8",
    mode: 0o644,
  });

  return {
    privateKey,
    privateJwk,
    publicJwk,
    kid,
    name,
    dir: resolvedDir,
    issuer,
  };
}

/**
 * Issues a simulated EK certificate (compact JWS) for a given EK public area.
 * Format per PLAN.md §2.4:
 * header: { alg: "ES256", typ: "tpm-ek-cert+jwt", kid }
 * claims: { iss: "SimTPM Vendor CA", sub: <EK serial>, ek_pub: <publicArea>, tpm_manufacturer: "SIM", iat, exp: +10y }
 *
 * @param {Object|Record<string, any>} caKey - CA object or private key with kid and issuer
 * @param {Record<string, any>} ekPublicArea - Public area of the EK
 * @param {string} [serial] - Unique serial number for the EK
 * @returns {Promise<string>} Compact JWS
 */
export async function issueEkCert(caKey, ekPublicArea, serial = crypto.randomUUID()) {
  const kid = caKey.kid || caKey.publicJwk?.kid || caKey.privateJwk?.kid;
  const issuer = caKey.issuer || "SimTPM Vendor CA";

  let signingKey = caKey.privateKey;
  if (!signingKey || !signingKey.type) {
    const rawJwk = caKey.privateJwk || caKey;
    signingKey = await jose.importJWK(rawJwk, "ES256");
  }

  const now = Math.floor(Date.now() / 1000);
  const tenYearsSecs = 10 * 365 * 24 * 60 * 60;

  const claims = {
    iss: issuer,
    sub: String(serial),
    ek_pub: ekPublicArea,
    tpm_manufacturer: "SIM",
    iat: now,
    exp: now + tenYearsSecs,
  };

  const jwt = await new jose.SignJWT(claims)
    .setProtectedHeader({
      alg: "ES256",
      typ: "tpm-ek-cert+jwt",
      ...(kid ? { kid } : {}),
    })
    .sign(signingKey);

  return jwt;
}

/**
 * Normalizes trustAnchors input to an array of public JWKs.
 * @param {string|Array|Record<string, any>} trustAnchors
 * @returns {Array<Record<string, any>>}
 */
export function loadTrustAnchors(trustAnchors) {
  if (!trustAnchors) return [];

  // If a directory path string is provided
  if (typeof trustAnchors === "string") {
    const resolvedPath = path.resolve(trustAnchors);
    if (!fs.existsSync(resolvedPath)) {
      return [];
    }
    const stat = fs.statSync(resolvedPath);
    if (stat.isDirectory()) {
      const files = fs.readdirSync(resolvedPath);
      const anchors = [];
      for (const file of files) {
        if (file.endsWith(".pub.jwk") || file.endsWith(".jwk")) {
          // Avoid private keys
          if (file.endsWith(".pub.jwk") || !files.includes(file.replace(".jwk", ".pub.jwk"))) {
            try {
              const content = fs.readFileSync(path.join(resolvedPath, file), "utf8");
              const jwk = JSON.parse(content);
              if (jwk.kty && !jwk.d) {
                anchors.push(jwk);
              }
            } catch {
              // Ignore parse errors
            }
          }
        }
      }
      return anchors;
    } else {
      // Single file path
      const content = fs.readFileSync(resolvedPath, "utf8");
      const parsed = JSON.parse(content);
      return Array.isArray(parsed?.keys) ? parsed.keys : [parsed];
    }
  }

  if (Array.isArray(trustAnchors)) {
    return trustAnchors.map((item) => item.publicJwk || item).filter((item) => item?.kty);
  }

  if (trustAnchors.keys && Array.isArray(trustAnchors.keys)) {
    return trustAnchors.keys;
  }

  if (trustAnchors.publicJwk) {
    return [trustAnchors.publicJwk];
  }

  if (trustAnchors.kty) {
    return [trustAnchors];
  }

  return [];
}

/**
 * Verifies an EK certificate against trust anchors.
 * Returns the contained ek_pub public area if valid, or throws an Error.
 *
 * @param {string} cert - Compact JWS EK certificate
 * @param {string|Array|Record<string, any>} trustAnchors - Trust anchors
 * @returns {Promise<Record<string, any>>} The verified ek_pub publicArea
 * @throws {Error} If certificate cannot be verified
 */
export async function verifyEkCert(cert, trustAnchors) {
  if (!cert) {
    throw new Error("Invalid EK certificate: must be provided");
  }

  const isJws =
    typeof cert === "string" &&
    cert.split(".").length === 3 &&
    !cert.includes("-----BEGIN");

  if (!isJws) {
    const { verifyX509EkCert } = await import("../verifier/ek-cert-x509.js");
    const rootsDir = typeof trustAnchors === "string" ? trustAnchors : undefined;
    return verifyX509EkCert({ cert, certDer: cert }, rootsDir);
  }

  const anchors = loadTrustAnchors(trustAnchors);
  if (anchors.length === 0) {
    throw new Error("No trust anchors provided or found for EK certificate verification");
  }

  let protectedHeader;
  try {
    protectedHeader = jose.decodeProtectedHeader(cert);
  } catch (err) {
    throw new Error(`Failed to decode EK certificate header: ${err.message}`);
  }

  if (protectedHeader.alg !== "ES256") {
    throw new Error(`Unsupported EK certificate algorithm: ${protectedHeader.alg}`);
  }

  // Filter anchors by kid if kid is in protected header
  let candidates = anchors;
  if (protectedHeader.kid) {
    const matching = anchors.filter((a) => a.kid === protectedHeader.kid);
    if (matching.length > 0) {
      candidates = matching;
    }
  }

  let verifiedPayload = null;
  let lastError = null;

  for (const anchor of candidates) {
    try {
      const key = await jose.importJWK(anchor, "ES256");
      const { payload } = await jose.jwtVerify(cert, key);
      verifiedPayload = payload;
      break;
    } catch (err) {
      lastError = err;
    }
  }

  if (!verifiedPayload) {
    throw new Error(`EK certificate verification failed: ${lastError?.message || "Untrusted vendor CA"}`);
  }

  if (!verifiedPayload.ek_pub || typeof verifiedPayload.ek_pub !== "object") {
    throw new Error("EK certificate payload missing ek_pub property");
  }

  return verifiedPayload.ek_pub;
}

export default {
  createVendorCa,
  issueEkCert,
  loadTrustAnchors,
  verifyEkCert,
};
