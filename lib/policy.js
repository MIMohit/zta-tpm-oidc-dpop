import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { on } from "./ablation.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Loads policy/data.json.
 * @param {string} [customPath]
 * @returns {Record<string, any>}
 */
export function loadPolicyData(customPath) {
  try {
    const dataPath = customPath || path.resolve(__dirname, "../policy/data.json");
    if (fs.existsSync(dataPath)) {
      return JSON.parse(fs.readFileSync(dataPath, "utf8"));
    }
  } catch (err) {
    console.warn("⚠️ Failed to load policy/data.json:", err.message);
  }
  return {
    resources: {},
    max_age_s: { low: 600, high: 330 },
    theta: { low: 0.5, high: 0.3 },
    t_su_s: 300,
    permissions: {},
  };
}

export const defaultPolicyData = loadPolicyData();

/**
 * Evaluates authorization policy mirroring policy/zta.rego.
 *
 * @param {object} input
 * @param {string} input.resource Resource identifier (e.g. "company.audit")
 * @param {string} [input.op="GET"] HTTP method / operation
 * @param {number} [input.now_s] Current time in seconds
 * @param {number} [input.now] Alternative current time (ms or s)
 * @param {number} [input.risk=0] Risk score [0, 1]
 * @param {object} [input.device] Device context {status, attestation_age_s, owner}
 * @param {object} [input.token] Token claims {sub, role, acr, auth_time}
 * @param {object} [data=defaultPolicyData] Policy data
 * @returns {{decision: "permit"|"deny"|"step_up", reason: string}}
 */
export function decide(input = {}, data = defaultPolicyData) {
  const resource = input.resource;
  const resDef = data?.resources?.[resource];
  if (!resDef) {
    return { decision: "deny", reason: "unknown_resource" };
  }

  const sens = resDef.sensitivity; // "low" | "high"
  if (!sens || !data?.max_age_s?.[sens] || data?.theta?.[sens] == null) {
    return { decision: "deny", reason: "invalid_resource_sensitivity" };
  }

  // --- device_ok ---
  const device = input.device || {};
  const status = device.status;
  const statusOk = status === "active";

  const maxAge = data.max_age_s[sens];
  const age = device.attestation_age_s;
  const ageOk = typeof age === "number" && age <= maxAge;

  const owner = device.owner ?? device.user;
  const sub = input.token?.sub;
  const ownerOk = owner != null && sub != null && owner === sub;

  const effectiveStatusOk = !on("M21") || statusOk;
  const effectiveAgeOk = !on("M21") || ageOk;
  const effectiveOwnerOk = !on("M20") || ownerOk;

  const device_ok = effectiveStatusOk && effectiveAgeOk && effectiveOwnerOk;

  // --- acr_ok ---
  const acr = input.token?.acr;
  const acr_ok = sens === "low" || acr === "mfa";

  // --- risk_ok ---
  const risk = typeof input.risk === "number" ? input.risk : 0;
  const theta = data.theta[sens];
  const riskBelowTheta = risk < theta;

  const now_s =
    typeof input.now_s === "number"
      ? input.now_s
      : typeof input.now === "number"
      ? input.now > 1e11
        ? Math.floor(input.now / 1000)
        : input.now
      : Math.floor(Date.now() / 1000);

  const authTimeRaw = input.token?.auth_time;
  const auth_time =
    typeof authTimeRaw === "number"
      ? authTimeRaw > 1e11
        ? Math.floor(authTimeRaw / 1000)
        : authTimeRaw
      : 0;

  const t_su_s = data.t_su_s ?? 300;
  const recentStepUp = acr === "mfa" && (now_s - auth_time <= t_su_s);
  const risk_ok = !on("M28") || riskBelowTheta || recentStepUp;

  // --- role_ok ---
  const role = input.token?.role;
  const op = input.op || "GET";
  const permissions = data.permissions?.[role] || [];
  const role_ok = permissions.some(
    (p) => p.resource === resource && Array.isArray(p.ops) && p.ops.includes(op)
  );

  // --- Mutually exclusive evaluation matching Rego ---
  // decision := "deny"    if not device_ok
  if (!device_ok) {
    let reason = "device_not_ok";
    if (on("M21") && !statusOk) {
      reason = !status || status === "unknown" ? "device_unknown" : `device_${status}`;
    } else if (on("M21") && !ageOk) {
      reason = "attestation_stale";
    } else if (on("M20") && !ownerOk) {
      reason = "device_owner_mismatch";
    }
    return { decision: "deny", reason };
  }

  // decision := "step_up" if { device_ok; not acr_ok }
  if (!acr_ok) {
    return { decision: "step_up", reason: "step_up_required" };
  }

  // decision := "step_up" if { device_ok; acr_ok; not risk_ok }
  if (!risk_ok) {
    return { decision: "step_up", reason: "step_up_required" };
  }

  // decision := "permit"  if { device_ok; acr_ok; risk_ok; role_ok }
  if (role_ok) {
    return { decision: "permit", reason: "policy_satisfied" };
  }

  // decision := "deny"    if { device_ok; acr_ok; risk_ok; not role_ok }
  return { decision: "deny", reason: "unauthorized_role" };
}

export default { decide, loadPolicyData, defaultPolicyData };
