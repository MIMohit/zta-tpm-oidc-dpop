import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import dotenv from "dotenv";

// Load environment variables from .env if present
dotenv.config({ quiet: true });

/**
 * Reads data/secrets.json if it exists (for dev fallback of tokens).
 * @param {string} dataDir
 * @returns {Record<string, string>}
 */
function readSecretsFile(dataDir) {
  try {
    const secretsPath = path.resolve(dataDir, "secrets.json");
    if (fs.existsSync(secretsPath)) {
      return JSON.parse(fs.readFileSync(secretsPath, "utf8"));
    }
  } catch {
    // Ignore missing or corrupt secrets file in dev
  }
  return {};
}

/**
 * Loads and validates configuration against Table 5 parameters and env overrides.
 * @param {Record<string, any>} [overrides={}]
 * @returns {Record<string, any>}
 */
export function loadConfig(overrides = {}) {
  const dataDir = overrides.dataDir || overrides.ZTA_DATA_DIR || process.env.ZTA_DATA_DIR || "./data";
  const resolvedDataDir = path.resolve(dataDir);
  const secrets = readSecretsFile(resolvedDataDir);

  const tauAR = Number(overrides.tauAR ?? overrides.ZTA_TAU_AR ?? process.env.ZTA_TAU_AR ?? 120);
  const tAT = Number(overrides.tAT ?? overrides.ZTA_T_AT ?? process.env.ZTA_T_AT ?? 300);
  const tRA = Number(overrides.tRA ?? overrides.ZTA_T_RA ?? process.env.ZTA_T_RA ?? 300);
  const tNonce = Number(overrides.tNonce ?? overrides.ZTA_T_NONCE ?? process.env.ZTA_T_NONCE ?? 60);
  const wJti = Number(overrides.wJti ?? overrides.ZTA_W_JTI ?? process.env.ZTA_W_JTI ?? 120);
  const skew = Number(overrides.skew ?? overrides.ZTA_SKEW ?? process.env.ZTA_SKEW ?? 30);
  const thetaLogin = Number(overrides.thetaLogin ?? overrides.ZTA_THETA_LOGIN ?? process.env.ZTA_THETA_LOGIN ?? 0.5);
  const thetaDeny = Number(overrides.thetaDeny ?? overrides.ZTA_THETA_DENY ?? process.env.ZTA_THETA_DENY ?? 0.85);
  const tSu = Number(overrides.tSu ?? overrides.ZTA_T_SU ?? process.env.ZTA_T_SU ?? 300);

  // Table 5 rationale assertion: W_J >= T_n + delta
  assert(
    wJti >= tNonce + skew,
    `Invalid config: W_J (${wJti}) must be >= T_n (${tNonce}) + delta (${skew})`
  );

  const idpIssuer = overrides.idpIssuer ?? overrides.IDP_ISSUER ?? process.env.IDP_ISSUER ?? "http://localhost:5173";
  const verifierUrl = overrides.verifierUrl ?? overrides.VERIFIER_URL ?? process.env.VERIFIER_URL ?? "http://localhost:4005";
  const pipUrl = overrides.pipUrl ?? overrides.PIP_URL ?? process.env.PIP_URL ?? "http://localhost:4003";
  const pdpUrl = overrides.pdpUrl ?? overrides.PDP_URL ?? process.env.PDP_URL ?? "http://localhost:4002";
  const pepPublicUrl = overrides.pepPublicUrl ?? overrides.PEP_PUBLIC_URL ?? process.env.PEP_PUBLIC_URL ?? "http://localhost:4001";
  const resourceUrl = overrides.resourceUrl ?? overrides.RESOURCE_URL ?? process.env.RESOURCE_URL ?? "http://127.0.0.1:5001";
  const agentUrl = overrides.agentUrl ?? overrides.AGENT_URL ?? process.env.AGENT_URL ?? "http://127.0.0.1:7000";

  const store = overrides.store ?? overrides.STORE ?? process.env.STORE ?? "file";
  const idpMode = overrides.idpMode ?? overrides.IDP_MODE ?? process.env.IDP_MODE ?? "local";

  const keycloakIssuer = overrides.keycloakIssuer ?? overrides.KEYCLOAK_ISSUER ?? process.env.KEYCLOAK_ISSUER ?? "http://localhost:8080/realms/zta-realm";
  const keycloakClientId = overrides.keycloakClientId ?? overrides.KEYCLOAK_CLIENT_ID ?? process.env.KEYCLOAK_CLIENT_ID ?? "zta-gate";
  const keycloakClientSecret = overrides.keycloakClientSecret ?? overrides.KEYCLOAK_CLIENT_SECRET ?? process.env.KEYCLOAK_CLIENT_SECRET ?? "";

  const ztaInternalToken = overrides.ztaInternalToken ?? overrides.ZTA_INTERNAL_TOKEN ?? process.env.ZTA_INTERNAL_TOKEN ?? secrets.ZTA_INTERNAL_TOKEN ?? "dev-internal-zta-secret-token";
  const adminToken = overrides.adminToken ?? overrides.ADMIN_TOKEN ?? process.env.ADMIN_TOKEN ?? secrets.ADMIN_TOKEN ?? "dev-admin-zta-secret-token";
  const sessionSecret = overrides.sessionSecret ?? overrides.SESSION_SECRET ?? process.env.SESSION_SECRET ?? secrets.SESSION_SECRET ?? "dev-session-secret-change-in-production";

  const tpmBackend = overrides.tpmBackend ?? overrides.TPM_BACKEND ?? process.env.TPM_BACKEND ?? "sim";
  const ekRootsDir = overrides.ekRootsDir ?? overrides.EK_ROOTS_DIR ?? process.env.EK_ROOTS_DIR ?? path.join(resolvedDataDir, "ek-roots");
  const ekCertPolicy = overrides.ekCertPolicy ?? overrides.EK_CERT_POLICY ?? process.env.EK_CERT_POLICY ?? "require";
  const ekCertIgnoreExpiry = Boolean(overrides.ekCertIgnoreExpiry ?? overrides.EK_CERT_IGNORE_EXPIRY ?? (process.env.EK_CERT_IGNORE_EXPIRY === "1"));
  const verifierGoldenTofu = Boolean(overrides.verifierGoldenTofu ?? overrides.VERIFIER_GOLDEN_TOFU ?? (process.env.VERIFIER_GOLDEN_TOFU === "1"));
  const ztaEnv = overrides.ztaEnv ?? overrides.ZTA_ENV ?? process.env.ZTA_ENV ?? "development";

  const debug = Boolean(overrides.debug ?? (process.env.ZTA_DEBUG && process.env.ZTA_DEBUG !== "0" && process.env.ZTA_DEBUG !== "false"));
  const simIpHeader = Boolean(overrides.simIpHeader ?? (process.env.ZTA_SIM_IP_HEADER && process.env.ZTA_SIM_IP_HEADER !== "0" && process.env.ZTA_SIM_IP_HEADER !== "false"));
  // Ablation (ZTA_ABLATE, ZTA_BASELINE, legacy ZTA_ABLATE_CNF/ZTA_ABLATE_NONCE) is parsed only by
  // lib/ablation.js configureFromEnv, which refuses in production; config carries no ablation keys.

  const opaUrl = overrides.opaUrl ?? overrides.OPA_URL ?? process.env.OPA_URL ?? null;

  const clock = overrides.clock ?? (() => Date.now());

  const risk = {
    weights: [0.25, 0.25, 0.10, 0.15, 0.15, 0.10],
    w1: 0.25,
    w2: 0.25,
    w3: 0.10,
    w4: 0.15,
    w5: 0.15,
    w6: 0.10,
    vMax: 900,
    fNormalizer: 5,
    nDays: 30,
    ...(overrides.risk || {})
  };

  const cfg = {
    // Table 5 protocol parameters
    tauAR,
    tAT,
    tRA,
    tNonce,
    wJti,
    skew,
    thetaLogin,
    thetaDeny,
    tSu,
    codeLifetime: 60,
    parLifetime: 60,
    enrolSessionLifetime: 60,
    risk,

    // Service URLs
    idpIssuer,
    verifierUrl,
    pipUrl,
    pdpUrl,
    pepPublicUrl,
    resourceUrl,
    agentUrl,

    // Store & Mode
    store,
    dataDir: resolvedDataDir,
    idpMode,

    // Upstream Keycloak
    keycloakIssuer,
    keycloakClientId,
    keycloakClientSecret,

    // Tokens
    ztaInternalToken,
    adminToken,
    sessionSecret,

    // TPM & Ops
    tpmBackend,
    ekRootsDir,
    ekCertPolicy,
    ekCertIgnoreExpiry,
    verifierGoldenTofu,
    ztaEnv,
    debug,
    simIpHeader,
    opaUrl,
    clock,

    // Uppercase aliases for compatibility
    IDP_ISSUER: idpIssuer,
    VERIFIER_URL: verifierUrl,
    PIP_URL: pipUrl,
    PDP_URL: pdpUrl,
    PEP_PUBLIC_URL: pepPublicUrl,
    RESOURCE_URL: resourceUrl,
    AGENT_URL: agentUrl,
    ZTA_DATA_DIR: resolvedDataDir,
    STORE: store,
    IDP_MODE: idpMode,
    KEYCLOAK_ISSUER: keycloakIssuer,
    KEYCLOAK_CLIENT_ID: keycloakClientId,
    KEYCLOAK_CLIENT_SECRET: keycloakClientSecret,
    ZTA_INTERNAL_TOKEN: ztaInternalToken,
    ADMIN_TOKEN: adminToken,
    TPM_BACKEND: tpmBackend,
    EK_ROOTS_DIR: ekRootsDir,
    EK_CERT_POLICY: ekCertPolicy,
    EK_CERT_IGNORE_EXPIRY: ekCertIgnoreExpiry,
    VERIFIER_GOLDEN_TOFU: verifierGoldenTofu,
    ZTA_ENV: ztaEnv,
    ZTA_DEBUG: debug,
    ZTA_SIM_IP_HEADER: simIpHeader,
    ZTA_TAU_AR: tauAR,
    ZTA_T_AT: tAT,
    ZTA_T_RA: tRA,
    ZTA_T_NONCE: tNonce,
    ZTA_W_JTI: wJti,
    ZTA_SKEW: skew,
    ZTA_THETA_LOGIN: thetaLogin,
    ZTA_THETA_DENY: thetaDeny,
    ZTA_T_SU: tSu,

    ...overrides
  };

  return cfg;
}

export default { loadConfig };
