/**
 * @file lib/ablation.js
 * Ablation switchboard core (WP-C1).
 * Mechanisms M1–M26, Baselines B0–B3, config parsing, banners, and run manifests.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import process from "node:process";
import { execSync } from "node:child_process";

export const MECHANISMS = [
  {
    id: "M1",
    layer: "Enrolment",
    title: "EK certificate chain to a vendor root, and SPKI = EK",
    modules: ["verifier/enrol", "ek-cert-x509"],
    attacks: ["A02", "A03"],
  },
  {
    id: "M2",
    layer: "Enrolment",
    title: "Inventory membership and one-time code",
    modules: ["verifier/enrol", "inventory"],
    attacks: ["A01"],
  },
  {
    id: "M3",
    layer: "Enrolment",
    title: "Credential activation (s′ = s)",
    modules: ["verifier/enrol"],
    attacks: ["A04"],
  },
  {
    id: "M4",
    layer: "Attestation",
    title: "Quote freshness (extraData = single-use n_V)",
    modules: ["verifier/enrol", "appraise"],
    attacks: ["A08"],
  },
  {
    id: "M5",
    layer: "Attestation",
    title: "Quote signer is the AK (name or qualified name)",
    modules: ["verifier/enrol"],
    attacks: ["A09"],
  },
  {
    id: "M6",
    layer: "Attestation",
    title: "PCR selection pinned to the reference-value profile (PCR0–7, or the set it declares)",
    modules: ["verifier/enrol"],
    attacks: ["A07"],
  },
  {
    id: "M7",
    layer: "Attestation",
    title: "Boot-state appraisal (event-log replay against RV, or golden digest)",
    modules: ["verifier/enrol", "tcg-eventlog"],
    attacks: ["A06", "A07"],
  },
  {
    id: "M8",
    layer: "Attestation",
    title: "Certification of K_B and its attributes",
    modules: ["verifier/enrol"],
    attacks: ["A05"],
  },
  {
    id: "M9",
    layer: "Issuance",
    title: "AR signature, expiry and status at PAR",
    modules: ["idp/par"],
    attacks: ["A10"],
  },
  {
    id: "M10",
    layer: "Issuance",
    title: "C2: AR.jkt = dpop_jkt",
    modules: ["idp/par"],
    attacks: ["A11"],
  },
  {
    id: "M11",
    layer: "Issuance",
    title: "Single use of AR jti, request_uri and code",
    modules: ["idp/par", "authorize", "token"],
    attacks: ["A12"],
  },
  {
    id: "M12",
    layer: "Issuance",
    title: "Device owner and status checked at login",
    modules: ["idp/index"],
    attacks: ["A13"],
  },
  {
    id: "M13",
    layer: "Issuance",
    title: "Token-endpoint DPoP: nonce, and proof key = code.jkt",
    modules: ["idp/token"],
    attacks: ["A14"],
  },
  {
    id: "M14",
    layer: "Issuance",
    title: "Role from the directory; request parameters ignored",
    modules: ["idp/par", "token"],
    attacks: ["A15"],
  },
  {
    id: "M15",
    layer: "Per-request",
    title: "DPoP scheme required (no Bearer)",
    modules: ["pep"],
    attacks: ["A16"],
  },
  {
    id: "M16",
    layer: "Per-request",
    title: "C3: Thumb(proof key) = AT.cnf.jkt",
    modules: ["pep"],
    attacks: ["A17"],
  },
  {
    id: "M17",
    layer: "Per-request",
    title: "PEP server nonce",
    modules: ["pep", "nonce"],
    attacks: ["A18", "A19"],
  },
  {
    id: "M18",
    layer: "Per-request",
    title: "jti replay cache and iat window",
    modules: ["pep", "jti-cache"],
    attacks: ["A19"],
  },
  {
    id: "M19",
    layer: "Per-request",
    title: "htm, htu and ath binding",
    modules: ["dpop"],
    attacks: ["A20"],
  },
  {
    id: "M20",
    layer: "Per-request",
    title: "Attributes only from AT; owner rule at the PDP",
    modules: ["pep", "policy"],
    attacks: ["A15"],
  },
  {
    id: "M21",
    layer: "Lifecycle",
    title: "Per-request device status and attestation age",
    modules: ["pdp", "pip", "policy"],
    attacks: ["A21"],
  },
  {
    id: "M22",
    layer: "Lifecycle",
    title: "Refresh refused for a device that is not active",
    modules: ["idp/token"],
    attacks: ["A21"],
  },
  {
    id: "M23",
    layer: "Lifecycle",
    title: "Replayed or unsigned evidence cannot suspend a device",
    modules: ["verifier/appraise"],
    attacks: ["A22"],
  },
  {
    id: "M24",
    layer: "Step-up",
    title: "Step-up accepted only in a gated transaction",
    modules: ["idp/webauthn"],
    attacks: ["A23"],
  },
  {
    id: "M25",
    layer: "Step-up",
    title: "One WebAuthn credential per (user, device); controlled replacement",
    modules: ["idp/webauthn"],
    attacks: ["A23"],
  },
  {
    id: "M26",
    layer: "Isolation",
    title: "Resource server reachable only from the PEP",
    modules: ["resource-server"],
    attacks: ["A24"],
  },
  {
    id: "M27",
    layer: "Adaptive MFA",
    title: "Risk-adaptive step-up at login: WebAuthn when rho >= theta_login, deny when rho >= theta_deny",
    modules: ["idp"],
    attacks: ["A25"],
  },
  {
    id: "M28",
    layer: "Adaptive MFA",
    title: "Per-request risk check at the PDP: rho >= theta(sensitivity) needs a recent step-up",
    modules: ["pdp", "policy"],
    attacks: ["A25"],
  },
];

export const MECHANISM_MAP = new Map(MECHANISMS.map((m) => [m.id, m]));

export const HYGIENE = ["M11", "M14", "M20", "M24", "M25", "M26"]; // on in every baseline

export const BASELINES = {
  B0: {
    title: "OIDC code + PKCE, Bearer",
    off: [
      "M1",
      "M2",
      "M3",
      "M4",
      "M5",
      "M6",
      "M7",
      "M8",
      "M9",
      "M10",
      "M12",
      "M13",
      "M15",
      "M16",
      "M17",
      "M18",
      "M19",
      "M21",
      "M22",
      "M23",
    ],
  },
  B1: {
    title: "B0 + DPoP with a software key",
    off: [
      "M1",
      "M2",
      "M3",
      "M4",
      "M5",
      "M6",
      "M7",
      "M8",
      "M9",
      "M10",
      "M12",
      "M17",
      "M18",
      "M21",
      "M22",
      "M23",
    ],
  },
  B2: {
    title: "B1 + attestation at login, not bound to the DPoP key",
    off: ["M8", "M10", "M17", "M18", "M21", "M22", "M23"],
  },
  B3: {
    title: "Full binding, no per-request state",
    off: ["M21"],
  },
  // A policy baseline for the adaptive-MFA evaluation (E6), not part of the attack matrix:
  // every login steps up, whatever the risk score.
  B4: {
    title: "Static MFA: WebAuthn step-up at every login",
    off: [],
    stepUp: "always",
  },
};

/**
 * The step-up policy in force: "always" (B4), "adaptive" (M27 on), or "off" (M27 off).
 * @returns {"always"|"adaptive"|"off"}
 */
export function stepUpPolicy() {
  const st = state();
  if (st.baseline && BASELINES[st.baseline]?.stepUp === "always") return "always";
  return on("M27") ? "adaptive" : "off";
}

function sortMechIds(ids) {
  return [...ids].sort((a, b) => {
    const na = parseInt(a.replace(/^M/, ""), 10);
    const nb = parseInt(b.replace(/^M/, ""), 10);
    return na - nb;
  });
}

// Module-level current configuration state
let currentOff = [];
let currentBaseline = null;
let currentSource = "default";
let initialized = false;

const printedBanners = new Set();

/**
 * Validates and normalizes mechanism ID.
 * Accepts "M7" or "-M7".
 * @param {string} rawId
 * @returns {string} normalized ID e.g. "M7"
 */
function normalizeMechId(rawId) {
  if (typeof rawId !== "string") {
    throw new Error(`Invalid mechanism id type: ${typeof rawId}`);
  }
  const clean = rawId.trim().replace(/^-+/, "");
  if (!MECHANISM_MAP.has(clean)) {
    throw new Error(`Unknown mechanism id: "${rawId}"`);
  }
  return clean;
}

/**
 * Parses config label string e.g. "full", "-M7", "-M3,-M7", "B0".."B3".
 * @param {string} label
 * @returns {{ off: string[], baseline: string | null }}
 */
export function parseConfigLabel(label) {
  if (!label || label === "full") {
    return { off: [], baseline: null };
  }
  const trimmed = label.trim();
  if (BASELINES[trimmed]) {
    return { off: sortMechIds(BASELINES[trimmed].off), baseline: trimmed };
  }

  const parts = trimmed.split(",").map((s) => s.trim()).filter(Boolean);
  const off = [];
  for (const part of parts) {
    if (BASELINES[part]) {
      off.push(...BASELINES[part].off);
    } else {
      off.push(normalizeMechId(part));
    }
  }

  return { off: sortMechIds(Array.from(new Set(off))), baseline: null };
}

/**
 * Configuration labels of the attack matrix: "full", "-M1"..."-M27", "B0".."B3".
 * B4 (static MFA) is a policy baseline for the adaptive-MFA evaluation only.
 * @returns {string[]}
 */
export function allConfigs() {
  return [
    "full",
    ...MECHANISMS.map((m) => `-${m.id}`),
    "B0",
    "B1",
    "B2",
    "B3",
  ];
}

function isProductionEnv(env) {
  return env.ZTA_ENV === "production" || env.NODE_ENV === "production";
}

/**
 * Configures the ablation switchboard.
 * Throws in production (ZTA_ENV=production) if off is non-empty.
 *
 * @param {object} [options]
 * @param {string[]} [options.off]
 * @param {string|null} [options.baseline]
 * @param {string} [options.source]
 * @returns {ReturnType<typeof state>}
 */
export function configureAblation({ off = [], baseline = null, source = "api" } = {}) {
  const offSet = new Set();

  if (baseline) {
    if (!BASELINES[baseline]) {
      throw new Error(`Unknown baseline: "${baseline}"`);
    }
    for (const id of BASELINES[baseline].off) {
      offSet.add(normalizeMechId(id));
    }
  }

  for (const raw of off) {
    offSet.add(normalizeMechId(raw));
  }

  const sortedOff = sortMechIds(Array.from(offSet));

  // Enforce production refusal
  if (isProductionEnv(process.env) && sortedOff.length > 0) {
    throw new Error(
      `Ablation is strictly forbidden in production (ZTA_ENV=production): attempted to disable ${sortedOff.join(", ")}`
    );
  }

  currentOff = sortedOff;
  currentBaseline = baseline;
  currentSource = source;
  initialized = true;

  return state();
}

/**
 * Configures ablation switchboard from environment variables.
 * Handles ZTA_ABLATE, ZTA_BASELINE, and legacy ZTA_ABLATE_CNF / ZTA_ABLATE_NONCE.
 * @param {Record<string, string|undefined>} [env=process.env]
 * @returns {ReturnType<typeof state>}
 */
export function configureFromEnv(env = process.env) {
  const off = [];
  const baseline = env.ZTA_BASELINE ? env.ZTA_BASELINE.trim() : null;
  if (baseline && !BASELINES[baseline]) {
    throw new Error(`Unknown ZTA_BASELINE: "${env.ZTA_BASELINE}" (expected one of ${Object.keys(BASELINES).join(", ")})`);
  }

  if (env.ZTA_ABLATE) {
    const parsed = parseConfigLabel(env.ZTA_ABLATE);
    off.push(...parsed.off);
  }

  // Legacy single-mechanism flags map onto the switchboard here and nowhere else.
  // Only "1"/"true" switch a mechanism off; unset, "", "0" and "false" leave it on.
  // Any other value is rejected so a typo cannot silently weaken or mislabel a run.
  const legacy = { ZTA_ABLATE_CNF: "M16", ZTA_ABLATE_NONCE: "M17" };
  for (const [name, id] of Object.entries(legacy)) {
    const raw = env[name];
    if (raw === undefined) continue;
    const v = String(raw).trim().toLowerCase();
    if (v === "1" || v === "true") {
      off.push(id);
    } else if (v !== "" && v !== "0" && v !== "false") {
      throw new Error(`Unrecognised ${name} value "${raw}" (use 1/true or 0/false; prefer ZTA_ABLATE=-${id})`);
    }
  }

  if (isProductionEnv(env) && (off.length > 0 || baseline)) {
    throw new Error(
      `Ablation is strictly forbidden in production (ZTA_ENV/NODE_ENV=production): refused ${baseline ?? off.join(", ")}`
    );
  }

  return configureAblation({ off, baseline, source: "env" });
}

/**
 * Checks if mechanism `id` is currently active (on).
 * Unknown id throws an Error (catches typos at guard sites).
 * Lazily configures from environment once if not already configured.
 * @param {string} id - e.g. "M7"
 * @returns {boolean}
 */
export function on(id) {
  if (!initialized) {
    configureFromEnv();
  }
  const clean = normalizeMechId(id);
  return !currentOff.includes(clean);
}

/**
 * Returns current ablation state.
 * @returns {{ label: string, baseline: string | null, off: string[], on: string[], hash: string }}
 */
export function state() {
  if (!initialized) {
    configureFromEnv();
  }

  let label;
  if (currentBaseline && BASELINES[currentBaseline]) {
    const baseOff = BASELINES[currentBaseline].off;
    const same =
      baseOff.length === currentOff.length &&
      baseOff.every((id) => currentOff.includes(id));
    if (same) {
      label = currentBaseline;
    } else {
      label = currentOff.length === 0 ? "full" : currentOff.map((id) => `-${id}`).join(",");
    }
  } else if (currentOff.length === 0) {
    label = "full";
  } else {
    label = currentOff.map((id) => `-${id}`).join(",");
  }

  const onList = MECHANISMS.filter((m) => !currentOff.includes(m.id)).map((m) => m.id);

  const hash = crypto
    .createHash("sha256")
    .update(label + currentOff.join(","))
    .digest("hex");

  return {
    label,
    baseline: currentBaseline,
    off: [...currentOff],
    on: onList,
    hash,
  };
}

/**
 * Resets ablation switchboard back to full design.
 * @returns {ReturnType<typeof state>}
 */
export function resetAblation() {
  currentOff = [];
  currentBaseline = null;
  currentSource = "api";
  initialized = true;
  return state();
}

/**
 * Runs an async callback with a given ablation configuration, always resetting afterwards.
 * @param {string|object} labelOrConfig
 * @param {() => Promise<any>|any} fn
 * @returns {Promise<any>}
 */
export async function withAblation(labelOrConfig, fn) {
  if (typeof labelOrConfig === "string") {
    const { off, baseline } = parseConfigLabel(labelOrConfig);
    configureAblation({ off, baseline, source: "withAblation" });
  } else if (labelOrConfig && typeof labelOrConfig === "object") {
    configureAblation({ ...labelOrConfig, source: "withAblation" });
  } else {
    throw new Error(`Invalid labelOrConfig: ${labelOrConfig}`);
  }

  try {
    return await fn();
  } finally {
    resetAblation();
  }
}

/**
 * Generates banner string for logging.
 * @param {string} [service]
 * @returns {string}
 */
export function banner(service) {
  const st = state();
  const prefix = service ? `[${service}] ` : "";
  if (st.off.length === 0) {
    return `${prefix}ablation: full design (${MECHANISMS.length}/${MECHANISMS.length} mechanisms)`;
  }
  const details = st.off
    .map((id) => `${id} (${MECHANISM_MAP.get(id)?.title || id})`)
    .join(", ");
  return `${prefix}⚠️ ABLATION ACTIVE [${st.label}]: off = ${details}`;
}

/**
 * Prints banner once per service to console.warn if not full, or console.info if full.
 * @param {string} [service="default"]
 */
export function printBannerOnce(service = "default") {
  if (printedBanners.has(service)) {
    return;
  }
  printedBanners.add(service);
  const st = state();
  if (st.off.length > 0) {
    console.warn(banner(service));
  } else {
    console.info(banner(service));
  }
}

function getGitInfo() {
  try {
    const commit = execSync("git rev-parse HEAD", {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    const status = execSync("git status --porcelain", {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return { commit, dirty: status.length > 0 };
  } catch {
    return { commit: "unknown", dirty: false };
  }
}

const CODE_HASH_ALGORITHM =
  "sha256 over sorted lines path NUL hex(sha256(file)) LF; excludes node_modules, data, results, testbed/{state,ca,images}";
const CODE_HASH_EXCLUDE = /^(node_modules|data|results|\.git|testbed\/(state|ca|images))(\/|$)/;

// Mirrors .gitignore for checkouts without git (an artifact tarball, an rsync copy).
const FALLBACK_IGNORE_DIRS = /(^|\/)(\.tpm-sim|results|__pycache__)$|^(paper-figures\/out|\.venv-figures|testbed\/(cache|ca))$/;
const FALLBACK_IGNORE_FILES = [
  /(^|\/)\.env$/,
  /(^|\/)\.env\.(?!example$)[^/]*$/,
  /(^|\/)firebase\.json$/,
  /(^|\/)serviceAccountKey\.json$/,
  /(^|\/)attestation-data\.json$/,
  /\.jwk$/,
  /\.log$/,
  /\.pyc$/,
  /^testbed\/attack-targets\.json$/,
];

function gitCodeFiles(cwd) {
  const out = execSync("git ls-files -z --cached --others --exclude-standard", {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
    maxBuffer: 64 * 1024 * 1024,
  });
  // Drop tracked files deleted in the working tree, as the walk never sees them.
  return out.split("\0").filter((f) => f && fs.existsSync(`${cwd}/${f}`));
}

function walkCodeFiles(cwd, rel = "", acc = []) {
  for (const ent of fs.readdirSync(rel ? `${cwd}/${rel}` : cwd, { withFileTypes: true })) {
    const p = rel ? `${rel}/${ent.name}` : ent.name;
    if (CODE_HASH_EXCLUDE.test(p)) continue;
    if (ent.isDirectory()) {
      if (!FALLBACK_IGNORE_DIRS.test(p)) walkCodeFiles(cwd, p, acc);
    } else if (!FALLBACK_IGNORE_FILES.some((re) => re.test(p))) {
      acc.push(p);
    }
  }
  return acc;
}

/**
 * Lists the files that identify the code: git's tracked and untracked
 * (non-ignored) files when git works, otherwise a directory walk with the
 * same ignore rules.
 * @param {string} [cwd=process.cwd()]
 * @param {{ useGit?: boolean }} [opts]
 * @returns {{ source: "git" | "walk", files: string[] }}
 */
export function listCodeFiles(cwd = process.cwd(), { useGit = true } = {}) {
  let source = "git";
  let files;
  try {
    if (!useGit) throw new Error("git disabled");
    files = gitCodeFiles(cwd);
  } catch {
    source = "walk";
    files = walkCodeFiles(cwd);
  }
  return {
    source,
    files: [...new Set(files)].filter((f) => !CODE_HASH_EXCLUDE.test(f)).sort(),
  };
}

/**
 * Identifies the code without any git write: sha256 over the sorted list of
 * "path NUL sha256(content)" for the files from listCodeFiles().
 * @param {string} [cwd=process.cwd()]
 * @returns {{ algorithm: string, sha256: string, files: number, source: string } | { algorithm: string, sha256: null, error: string }}
 */
export function codeContentHash(cwd = process.cwd()) {
  try {
    const { source, files } = listCodeFiles(cwd);
    const outer = crypto.createHash("sha256");
    let count = 0;
    for (const f of files) {
      let buf;
      try {
        buf = fs.readFileSync(`${cwd}/${f}`);
      } catch {
        continue; // tracked but deleted in the worktree
      }
      outer.update(f).update("\0").update(crypto.createHash("sha256").update(buf).digest("hex")).update("\n");
      count++;
    }
    return { algorithm: CODE_HASH_ALGORITHM, sha256: outer.digest("hex"), files: count, source };
  } catch (err) {
    return { algorithm: CODE_HASH_ALGORITHM, sha256: null, error: err.message };
  }
}

function getFilteredEnv() {
  const subset = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (
      k.startsWith("TPM_") ||
      k.startsWith("EK_") ||
      k.startsWith("VERIFIER_") ||
      k.startsWith("ZTA_") ||
      k === "OPA_URL"
    ) {
      subset[k] = v;
    }
  }
  return subset;
}

/**
 * Generates a run manifest per schema zta-run-manifest/1.
 * @param {Record<string, any>} [extra={}]
 * @returns {Record<string, any>}
 */
export function runManifest(extra = {}) {
  const st = state();
  return {
    schema: "zta-run-manifest/1",
    runId: crypto.randomUUID(),
    startedAt: new Date().toISOString(),
    label: st.label,
    baseline: st.baseline,
    off: st.off,
    on: st.on,
    hash: st.hash,
    git: getGitInfo(),
    code: codeContentHash(),
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    cpus: os.cpus().length,
    env: getFilteredEnv(),
    ...extra,
  };
}

/**
 * Writes run manifest to disk.
 * @param {string} file
 * @param {Record<string, any>} [extra={}]
 */
export function writeRunManifest(file, extra = {}) {
  const manifest = runManifest(extra);
  fs.writeFileSync(file, JSON.stringify(manifest, null, 2), "utf8");
  return manifest;
}

export default {
  MECHANISMS,
  MECHANISM_MAP,
  HYGIENE,
  BASELINES,
  parseConfigLabel,
  allConfigs,
  configureAblation,
  configureFromEnv,
  codeContentHash,
  listCodeFiles,
  on,
  state,
  resetAblation,
  withAblation,
  banner,
  printBannerOnce,
  runManifest,
  writeRunManifest,
};
