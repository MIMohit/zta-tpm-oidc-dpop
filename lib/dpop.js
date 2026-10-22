import crypto from "node:crypto";
import * as jose from "jose";

/**
 * Custom error thrown on DPoP proof verification failures.
 * The code MUST be one of:
 * 'missing', 'malformed', 'use_dpop_nonce', 'bad_sig', 'jkt_mismatch',
 * 'htm', 'htu', 'ath', 'iat', 'replay'
 */
export class DpopError extends Error {
  /**
   * @param {string} code
   * @param {string} [message]
   */
  constructor(code, message) {
    super(message || code);
    this.name = "DpopError";
    this.code = code;
  }
}

/**
 * Normalises an HTTP URI according to RFC 9449 §4.3.1:
 * - Scheme and host in lowercase
 * - Port included if non-default
 * - Path present (if empty, '/')
 * - Query and fragment stripped
 *
 * @param {string} rawUrl
 * @returns {string}
 */
export function normalizeHtu(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") {
    throw new DpopError("malformed", "Invalid or missing HTU URL");
  }
  try {
    const u = new URL(rawUrl);
    const scheme = u.protocol.toLowerCase();
    const host = u.host.toLowerCase();
    const pathname = u.pathname || "/";
    return `${scheme}//${host}${pathname}`;
  } catch {
    throw new DpopError("malformed", `Cannot parse HTU URL: ${rawUrl}`);
  }
}

/**
 * Helper to strip private key parameters from a JWK object.
 * @param {Record<string, any>} jwk
 * @returns {Record<string, any>}
 */
function stripPrivateKeyProps(jwk) {
  if (!jwk || typeof jwk !== "object") return {};
  const { d, dp, dq, p, q, qi, k, ...publicArea } = jwk;
  return publicArea;
}

/**
 * Signs a DPoP proof using a custom signer callback (e.g. backed by SimTpm.sign)
 * or a private key, adhering to RFC 9449.
 *
 * Implements the manual construction `b64u(header).b64u(payload).b64u(P1363 sig)`
 * to support TPM callbacks where private key bytes never leave the hardware/simulator.
 *
 * @param {object} options
 * @param {(bytes: Buffer) => Promise<Buffer|Uint8Array|string>|Buffer|Uint8Array|string} [options.signer] - Custom signer function returning P1363 signature
 * @param {any} [options.privateKey] - Node KeyObject or JWK with private key (used if signer not provided)
 * @param {Record<string, any>} [options.publicJwk] - Public JWK to embed in the header
 * @param {string} options.htm - HTTP method
 * @param {string} options.htu - HTTP target URI
 * @param {string} [options.nonce] - Server nonce
 * @param {string} [options.accessToken] - Access token to bind via ath claim
 * @param {string} [options.jti] - Optional unique identifier
 * @param {number} [options.iat] - Optional issuance timestamp in seconds
 * @param {() => number} [options.clock] - Clock returning ms epoch
 * @param {boolean} [options.dangerousIncludeD] - Test hook: include private 'd' in header
 * @param {string} [options.dangerousAlg] - Test hook: override alg in header
 * @param {string} [options.dangerousTyp] - Test hook: override typ in header
 * @returns {Promise<string>} Compact DPoP proof JWT
 */
export async function signProof(options = {}) {
  const {
    htm,
    htu,
    nonce,
    accessToken,
    jti,
    iat,
    clock,
    dangerousIncludeD = false,
    dangerousAlg,
    dangerousTyp,
  } = options;

  let publicJwk = options.publicJwk;
  let signer = options.signer;
  let privateKey = options.privateKey;

  if (!htm || !htu) {
    throw new Error("signProof requires 'htm' and 'htu'");
  }

  // Derive publicJwk if not provided and privateKey is available
  if (!publicJwk && privateKey) {
    if (typeof privateKey === "object" && privateKey.kty) {
      publicJwk = stripPrivateKeyProps(privateKey);
    } else {
      const exported = await jose.exportJWK(privateKey);
      publicJwk = stripPrivateKeyProps(exported);
    }
  }

  if (!publicJwk) {
    throw new Error("signProof requires publicJwk or privateKey");
  }

  const header = {
    typ: dangerousTyp || "dpop+jwt",
    alg: dangerousAlg || "ES256",
    jwk: dangerousIncludeD ? publicJwk : stripPrivateKeyProps(publicJwk),
  };

  const nowSec = Math.floor((clock ? clock() : Date.now()) / 1000);
  const payload = {
    jti: jti || crypto.randomUUID(),
    htm: String(htm).toUpperCase(),
    htu: normalizeHtu(htu),
    iat: iat !== undefined ? iat : nowSec,
  };

  if (nonce) {
    payload.nonce = nonce;
  }

  if (accessToken) {
    payload.ath = crypto
      .createHash("sha256")
      .update(accessToken, "ascii")
      .digest("base64url");
  }

  const headerB64 = Buffer.from(JSON.stringify(header), "utf8").toString("base64url");
  const payloadB64 = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signingInput = `${headerB64}.${payloadB64}`;

  let sigB64;
  if (signer) {
    const sigBytes = await signer(Buffer.from(signingInput, "utf8"));
    if (typeof sigBytes === "string") {
      sigB64 = sigBytes;
    } else {
      sigB64 = Buffer.from(sigBytes).toString("base64url");
    }
  } else if (privateKey) {
    let priv = privateKey;
    if (priv.type === "private") {
      priv = crypto.KeyObject.from(priv);
    } else if (typeof priv === "object" && priv.kty) {
      priv = crypto.createPrivateKey({ key: priv, format: "jwk" });
    }
    const sigBuf = crypto.sign("sha256", Buffer.from(signingInput, "utf8"), {
      key: priv,
      dsaEncoding: "ieee-p1363",
    });
    sigB64 = sigBuf.toString("base64url");
  } else {
    throw new Error("signProof requires either a signer function or a privateKey");
  }

  return `${signingInput}.${sigB64}`;
}

/**
 * Verifies a DPoP proof per RFC 9449 and Algorithm 3 checks.
 *
 * @param {object} params
 * @param {string} params.proof - Compact DPoP proof JWT
 * @param {string} params.htm - Expected HTTP method
 * @param {string} params.htu - Expected HTTP URI
 * @param {string} [params.accessToken] - Access token if presented at resource server (ath check)
 * @param {string} [params.expectedJkt] - Expected RFC 7638 SHA-256 JWK thumbprint (from AT cnf.jkt or PAR dpop_jkt)
 * @param {{ valid: (nonce: string) => boolean }} [params.nonceStore] - Nonce store for nonce check
 * @param {{ seen: (jkt: string, jti: string) => boolean }} [params.jtiCache] - JTI cache for replay check
 * @param {number} [params.skewS=30] - Max allowable clock skew in seconds (δ = 30s)
 * @param {() => number} [params.clock] - Clock returning ms epoch
 * @returns {Promise<{ jkt: string, payload: Record<string, any> }>}
 */
export async function verifyProof(params = {}) {
  const {
    proof,
    htm,
    htu,
    accessToken,
    expectedJkt,
    nonceStore,
    jtiCache,
    skewS = 30,
    clock,
    checks = {},
  } = params;

  const checkHtm = checks.htm ?? true;
  const checkHtu = checks.htu ?? true;
  const checkAth = checks.ath ?? true;
  const checkIatWindow = checks.iatWindow ?? true;

  // Check 1: Missing proof
  if (!proof || typeof proof !== "string" || !proof.trim()) {
    throw new DpopError("missing", "Missing DPoP proof");
  }

  const trimmedProof = proof.trim();
  const parts = trimmedProof.split(".");
  if (parts.length !== 3) {
    throw new DpopError("malformed", "DPoP proof must have 3 segments");
  }

  // Pre-parse header to check for disallowed private key parameter 'd'
  try {
    const rawHeader = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    if (rawHeader?.jwk?.d !== undefined) {
      throw new DpopError("malformed", 'JWK header must not contain private key parameter "d"');
    }
  } catch (err) {
    if (err instanceof DpopError) throw err;
    throw new DpopError("malformed", "Failed to parse DPoP header JSON");
  }

  // Check 2: Verify JWS using jose EmbeddedJWK (typ: 'dpop+jwt', alg: 'ES256')
  let verification;
  try {
    verification = await jose.jwtVerify(trimmedProof, jose.EmbeddedJWK, {
      typ: "dpop+jwt",
      algorithms: ["ES256"],
    });
  } catch (err) {
    if (err.code === "ERR_JWS_SIGNATURE_VERIFICATION_FAILED") {
      throw new DpopError("bad_sig", "DPoP signature verification failed");
    }
    // All other jose validation failures (alg not allowed, typ invalid, jwk invalid, etc.)
    throw new DpopError("malformed", `DPoP proof verification failed: ${err.message}`);
  }

  const { payload, protectedHeader } = verification;

  // Validate embedded JWK
  if (!protectedHeader.jwk || typeof protectedHeader.jwk !== "object") {
    throw new DpopError("malformed", "Missing or invalid embedded jwk header");
  }
  if (protectedHeader.jwk.d !== undefined) {
    throw new DpopError("malformed", 'JWK header must not contain private key parameter "d"');
  }

  // Check 3: Calculate JWK thumbprint and verify expectedJkt (check C3)
  const jkt = await jose.calculateJwkThumbprint(protectedHeader.jwk, "sha256");
  if (expectedJkt && jkt !== expectedJkt) {
    throw new DpopError(
      "jkt_mismatch",
      `DPoP key thumbprint mismatch: expected ${expectedJkt}, got ${jkt}`
    );
  }

  // Check 4: Validate required payload claims
  if (!payload || typeof payload !== "object") {
    throw new DpopError("malformed", "DPoP payload must be an object");
  }
  if (!payload.jti || typeof payload.jti !== "string") {
    throw new DpopError("malformed", "Missing or invalid 'jti' claim");
  }
  if (checkHtm && (!payload.htm || typeof payload.htm !== "string")) {
    throw new DpopError("malformed", "Missing or invalid 'htm' claim");
  }
  if (checkHtu && (!payload.htu || typeof payload.htu !== "string")) {
    throw new DpopError("malformed", "Missing or invalid 'htu' claim");
  }
  if (checkIatWindow && typeof payload.iat !== "number") {
    throw new DpopError("malformed", "Missing or invalid 'iat' claim");
  }

  // Check 5: HTTP method match
  if (checkHtm && payload.htm) {
    if (payload.htm.toUpperCase() !== String(htm).toUpperCase()) {
      throw new DpopError(
        "htm",
        `HTTP method mismatch: expected ${htm}, got ${payload.htm}`
      );
    }
  }

  // Check 6: HTTP URI match (normalized)
  if (checkHtu && payload.htu) {
    let normalizedExpectedHtu;
    let normalizedProofHtu;
    try {
      normalizedExpectedHtu = normalizeHtu(htu);
      normalizedProofHtu = normalizeHtu(payload.htu);
    } catch (err) {
      if (err instanceof DpopError) {
        throw new DpopError("htu", err.message);
      }
      throw err;
    }
    if (normalizedProofHtu !== normalizedExpectedHtu) {
      throw new DpopError(
        "htu",
        `HTTP URI mismatch: expected ${normalizedExpectedHtu}, got ${normalizedProofHtu}`
      );
    }
  }

  // Check 7: Access token hash (ath)
  if (checkAth && accessToken !== undefined && accessToken !== null) {
    const expectedAth = crypto
      .createHash("sha256")
      .update(accessToken, "ascii")
      .digest("base64url");
    if (!payload.ath || payload.ath !== expectedAth) {
      throw new DpopError("ath", "Access token hash (ath) mismatch or missing");
    }
  }

  // Check 8: Issuance time skew (|iat - now| <= δ)
  if (checkIatWindow) {
    const nowSec = Math.floor((clock ? clock() : Date.now()) / 1000);
    const diffSec = Math.abs(nowSec - payload.iat);
    if (diffSec > skewS) {
      throw new DpopError(
        "iat",
        `DPoP proof iat out of skew window: now=${nowSec}, iat=${payload.iat}, diff=${diffSec}s > ${skewS}s`
      );
    }
  }

  // Check 9: Nonce check (if nonceStore provided)
  if (nonceStore) {
    const isNonceValid =
      typeof nonceStore.valid === "function"
        ? nonceStore.valid(payload.nonce)
        : typeof nonceStore === "function"
        ? nonceStore(payload.nonce)
        : false;
    if (!payload.nonce || !isNonceValid) {
      throw new DpopError("use_dpop_nonce", "Invalid or missing DPoP nonce");
    }
  }

  // Check 10: JTI cache replay check (check C4)
  if (jtiCache) {
    const isReplay = jtiCache.seen(jkt, payload.jti);
    if (isReplay) {
      throw new DpopError(
        "replay",
        `DPoP proof replay detected for jti ${payload.jti}`
      );
    }
  }

  return { jkt, payload };
}

export default {
  DpopError,
  normalizeHtu,
  signProof,
  verifyProof,
};
