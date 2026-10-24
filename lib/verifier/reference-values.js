/**
 * @file reference-values.js
 * Reference values (RV) for measured boot verification.
 * Supports both legacy array (fixtures/golden-boot.json) and zta-rv/1 formats.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_FIXTURE_PATH = path.resolve(__dirname, "../../fixtures/golden-boot.json");

/** PCR set of profiles that do not declare one (the emulated golden boot). */
export const DEFAULT_PCRS = Object.freeze([0, 1, 2, 3, 4, 5, 6, 7]);

/**
 * Normalises a declared PCR list: unique integers in 0..23, ascending.
 * @param {unknown} list
 * @returns {number[]|null}
 */
function normalisePcrList(list) {
  if (!Array.isArray(list) || list.length === 0) return null;
  const out = [...new Set(list.map(Number))].sort((a, b) => a - b);
  if (out.some((p) => !Number.isInteger(p) || p < 0 || p > 23)) {
    throw new Error(`Invalid PCR list in reference values: ${JSON.stringify(list)}`);
  }
  return out;
}

/**
 * The PCR set a reference-value map covers: its keys. A device using this profile must
 * quote exactly these PCRs (M6), and its event log is replayed over them (M7).
 * @param {Record<number, Set<string>>} rv
 * @returns {number[]}
 */
export function pcrsOf(rv) {
  if (!rv || typeof rv !== "object") return [...DEFAULT_PCRS];
  return Object.keys(rv)
    .map(Number)
    .sort((a, b) => a - b);
}

/**
 * Loads reference values from a fixture file.
 * Accepts both legacy array format and zta-rv/1 object format.
 * Returns an object mapping PCR index (0..7) to a Set of allowed lowercase hex digests.
 *
 * @param {string} [fixturePath]
 * @returns {Record<number, Set<string>>}
 */
export function loadReferenceValues(fixturePath = process.env.VERIFIER_RV_PATH || DEFAULT_FIXTURE_PATH) {
  const resolved = path.resolve(fixturePath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Reference values fixture not found: ${resolved}`);
  }
  const raw = fs.readFileSync(resolved, "utf8");
  const parsed = JSON.parse(raw);

  // The profile's PCR set: declared by zta-rv/1 files ("pcrs"), PCR0..7 otherwise
  const declared = !Array.isArray(parsed) && parsed ? normalisePcrList(parsed.pcrs) : null;
  const rv = {};
  for (const pcr of declared || DEFAULT_PCRS) {
    rv[pcr] = new Set();
  }

  if (Array.isArray(parsed)) {
    for (const entry of parsed) {
      if (typeof entry.pcr === "number" && entry.digest) {
        const digestHex = String(entry.digest).toLowerCase();
        if (!rv[entry.pcr]) {
          rv[entry.pcr] = new Set();
        }
        rv[entry.pcr].add(digestHex);
      }
    }
  } else if (parsed && typeof parsed === "object") {
    // zta-rv/1 format: { format: "zta-rv/1", events: { "0": [{ digest, type, desc }] } }
    if (parsed.events && typeof parsed.events === "object") {
      for (const [pcrStr, evList] of Object.entries(parsed.events)) {
        const pcr = Number(pcrStr);
        if (!rv[pcr]) {
          if (declared) continue; // outside the declared profile
          rv[pcr] = new Set();
        }
        if (Array.isArray(evList)) {
          for (const entry of evList) {
            if (entry && entry.digest) {
              rv[pcr].add(String(entry.digest).toLowerCase());
            }
          }
        }
      }
    }
  }

  return rv;
}

/**
 * Resolves reference values path from configuration or environment variable VERIFIER_RV_PATH.
 * Defaults to fixtures/golden-boot.json.
 *
 * @param {string|Object} [cfgOrEnv]
 * @returns {Record<number, Set<string>>}
 */
export function loadReferenceValuesFrom(cfgOrEnv) {
  let targetPath = null;
  if (typeof cfgOrEnv === "string") {
    targetPath = cfgOrEnv;
  } else if (cfgOrEnv && typeof cfgOrEnv === "object") {
    targetPath = cfgOrEnv.VERIFIER_RV_PATH || cfgOrEnv.rvPath;
  }
  if (!targetPath) {
    targetPath = process.env.VERIFIER_RV_PATH || DEFAULT_FIXTURE_PATH;
  }
  return loadReferenceValues(targetPath);
}

/**
 * Loads named reference-value profiles from "name=path,name2=path2" (VERIFIER_RV_PROFILES).
 * @param {string|Record<string, Record<number, Set<string>>>} [spec]
 * @returns {Record<string, Record<number, Set<string>>>}
 */
export function loadRvProfiles(spec = process.env.VERIFIER_RV_PROFILES) {
  if (spec && typeof spec === "object") return spec;
  const profiles = {};
  for (const entry of String(spec || "").split(",").map((e) => e.trim()).filter(Boolean)) {
    const eq = entry.indexOf("=");
    if (eq <= 0) throw new Error(`Invalid VERIFIER_RV_PROFILES entry: ${entry}`);
    profiles[entry.slice(0, eq).trim()] = loadReferenceValues(entry.slice(eq + 1).trim());
  }
  return profiles;
}

/**
 * The reference-value profile for a device: the profile its inventory or registry record
 * names, else the verifier's default. Fails closed on an unknown profile name.
 * @param {{ rvProfile?: string }|null|undefined} record
 * @param {{ referenceValues?: Record<number, Set<string>>, rvProfiles?: Record<string, Record<number, Set<string>>> }} [opts]
 * @returns {Record<number, Set<string>>}
 */
export function profileFor(record, { referenceValues, rvProfiles } = {}) {
  const name = record?.rvProfile;
  if (name) {
    if (!rvProfiles || !Object.hasOwn(rvProfiles, name)) {
      throw new Error(`Unknown reference-value profile: ${name}`);
    }
    return rvProfiles[name];
  }
  return referenceValues || loadReferenceValuesFrom();
}

/**
 * Validates an event log against reference values.
 * Every event in the log must have its digest in RV[pcr].
 *
 * @param {Array<{ pcr: number, digest: string|Buffer, desc?: string }>} eventLog
 * @param {Record<number, Set<string>>} [rv]
 * @returns {{ valid: boolean, error?: string, failedEvent?: any }}
 */
export function verifyEventLog(eventLog, rv) {
  const referenceValues = rv || loadReferenceValuesFrom();
  if (!Array.isArray(eventLog)) {
    return { valid: false, error: "Event log must be an array" };
  }

  for (let i = 0; i < eventLog.length; i++) {
    const event = eventLog[i];
    if (typeof event.pcr !== "number" || !Object.hasOwn(referenceValues, event.pcr)) {
      return { valid: false, error: `PCR ${event?.pcr} of event ${i} is outside the reference-value profile`, failedEvent: event };
    }
    const digestHex = Buffer.isBuffer(event.digest)
      ? event.digest.toString("hex").toLowerCase()
      : String(event.digest || "").toLowerCase();

    const allowed = referenceValues[event.pcr];
    if (!allowed || !allowed.has(digestHex)) {
      return {
        valid: false,
        error: `Event ${i} (PCR ${event.pcr}, "${event.desc || ""}") digest not in reference values`,
        failedEvent: event,
      };
    }
  }

  return { valid: true };
}

export const DEFAULT_GOLDEN_PCRS_PATH = path.resolve(__dirname, "../../fixtures/golden-pcrs.json");

/**
 * Loads golden PCR values from a fixture file.
 * Returns an object mapping devId or model to an array of allowed hex digests.
 *
 * @param {string} [filePath]
 * @returns {Record<string, string[]|string>}
 */
export function loadGoldenPcrs(filePath = DEFAULT_GOLDEN_PCRS_PATH) {
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    return {};
  }
  try {
    const raw = fs.readFileSync(resolved, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    console.warn(`⚠️ [reference-values] Failed to parse ${resolved}:`, err.message);
    return {};
  }
}

/**
 * Verifies a PCR digest against golden PCR reference values.
 *
 * Source priority (PLAN-TPM §2.5.5):
 * (i) inventory goldenPcrDigests[]
 * (ii) fixtures/golden-pcrs.json
 * (iii) TOFU at enrolment if VERIFIER_GOLDEN_TOFU=1
 *
 * @param {Buffer|string|Object} pcrDigestOrOptions
 * @param {Record<string, any>} [devRecordArg]
 * @param {string} [rvFileArg]
 * @returns {{ valid: boolean, error?: string, source?: string, tofuCaptured?: boolean, digest?: string }}
 */
export function verifyGoldenPcr(pcrDigestOrOptions, devRecordArg, rvFileArg) {
  let pcrDigest, devRecord, rvFile, allowTofu;
  if (pcrDigestOrOptions && typeof pcrDigestOrOptions === "object" && !Buffer.isBuffer(pcrDigestOrOptions)) {
    pcrDigest = pcrDigestOrOptions.pcrDigest;
    devRecord = pcrDigestOrOptions.devRecord || {};
    rvFile = pcrDigestOrOptions.rvFile || DEFAULT_GOLDEN_PCRS_PATH;
    allowTofu = pcrDigestOrOptions.allowTofu;
  } else {
    pcrDigest = pcrDigestOrOptions;
    devRecord = devRecordArg || {};
    rvFile = rvFileArg || DEFAULT_GOLDEN_PCRS_PATH;
    allowTofu = devRecord.allowTofu;
  }

  if (!pcrDigest) {
    return { valid: false, error: "no reference values" };
  }

  const pcrDigestHex = (Buffer.isBuffer(pcrDigest) ? pcrDigest.toString("hex") : String(pcrDigest)).toLowerCase();

  // (i) Check inventory / devRecord goldenPcrDigests
  const invDigests = devRecord.goldenPcrDigests || (devRecord.goldenPcrDigest ? [devRecord.goldenPcrDigest] : null);
  if (Array.isArray(invDigests) && invDigests.length > 0) {
    const normalized = invDigests.map((d) => String(d).toLowerCase());
    if (normalized.includes(pcrDigestHex)) {
      return { valid: true, source: "inventory" };
    }
    return {
      valid: false,
      error: `Quoted PCR digest ${pcrDigestHex} does not match inventory golden PCRs`,
    };
  }

  // (ii) Check fixtures/golden-pcrs.json
  const goldenPcrs = loadGoldenPcrs(rvFile);
  const devId = devRecord.devId;
  const model = devRecord.tpmModel || devRecord.sanModel || devRecord.model;

  let fileDigests = null;
  if (devId && goldenPcrs[devId]) {
    fileDigests = goldenPcrs[devId];
  } else if (model && goldenPcrs[model]) {
    fileDigests = goldenPcrs[model];
  }

  if (fileDigests) {
    const list = Array.isArray(fileDigests) ? fileDigests : [fileDigests];
    const normalized = list.map((d) => String(d).toLowerCase());
    if (normalized.includes(pcrDigestHex)) {
      return { valid: true, source: "rv-file" };
    }
    return {
      valid: false,
      error: `Quoted PCR digest ${pcrDigestHex} does not match golden-pcrs.json`,
    };
  }

  // (iii) TOFU (Trust On First Use) at enrolment
  const tofuEnabled =
    allowTofu !== undefined
      ? Boolean(allowTofu)
      : (process.env.VERIFIER_GOLDEN_TOFU === "1" || devRecord.allowTofu === true);

  if (devRecord.rvSource === "tofu" && devRecord.goldenPcrDigest) {
    if (String(devRecord.goldenPcrDigest).toLowerCase() === pcrDigestHex) {
      return { valid: true, source: "tofu" };
    }
    return {
      valid: false,
      error: `Quoted PCR digest ${pcrDigestHex} does not match TOFU golden PCR digest ${devRecord.goldenPcrDigest}`,
    };
  }

  if (tofuEnabled) {
    return { valid: true, source: "tofu", tofuCaptured: true, digest: pcrDigestHex };
  }

  // Fail closed per §2.5.5: "no reference values"
  return { valid: false, error: "no reference values" };
}

export default {
  loadReferenceValues,
  loadReferenceValuesFrom,
  loadRvProfiles,
  profileFor,
  pcrsOf,
  verifyEventLog,
  loadGoldenPcrs,
  verifyGoldenPcr,
  DEFAULT_GOLDEN_PCRS_PATH,
};
