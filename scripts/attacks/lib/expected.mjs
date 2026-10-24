/**
 * @file scripts/attacks/lib/expected.mjs
 * Predicted outcome (rejected / accepted / n/a) per (attack, variant, config).
 *
 * Every prediction is derived from the set of mechanisms that is OFF in the configuration,
 * so the baselines need no hand-written lists. For each (attack, variant) a rule names the
 * sufficient sets: the attack is predicted to succeed iff every mechanism of at least one
 * set is off. A set of size 1 means the mechanism alone is predicted necessary; a set of
 * size >= 2 means defence in depth (each member alone is predicted NOT necessary).
 */

import { parseConfigLabel } from "../../../lib/ablation.js";

/**
 * any: list of sufficient sets; na(off, baseline): string reason or null.
 * Keyed by attack id, then by variant ("*" applies to every variant of the attack).
 */
export const RULES = {
  A01: { "*": { any: [["M2"]] } },
  A02: { "*": { any: [["M1"]] } },
  // jws: tampered JWS payload (chain/signature half of M1). x509: valid cert of another TPM (SPKI = EK half of M1).
  A03: { "*": { any: [["M1"]] } },
  A04: { "*": { any: [["M3"]] } },
  A05: { "*": { any: [["M8"]] } },
  A06: { "*": { any: [["M7"]] } },
  A07: { "*": { any: [["M6", "M7"]] } },
  A08: { "*": { any: [["M4"]] } },
  A09: { "*": { any: [["M5"]] } },
  A10: { "*": { any: [["M9"]] } },
  A11: { "*": { any: [["M10"]] } },
  A12: { "*": { any: [["M11"]] } },
  A13: { "*": { any: [["M12"]] } },
  A14: { "*": { any: [["M13"]] } },
  // One run carries both escalation paths (role at PAR, role header at the PEP).
  A15: { "*": { any: [["M14"], ["M20"]] } },
  // M16 also refuses a Bearer presentation of a cnf-bound token (pep.js), so M15 alone is not enough.
  A16: { "*": { any: [["M15", "M16"]] } },
  A17: { "*": { any: [["M16"]] } },
  A18: { "*": { any: [["M17"]] } },
  A19: {
    // In-window replay: the nonce is still valid, only the jti cache stops it.
    immediate: { any: [["M18"]] },
    // Replay after T_n + skew: the expired nonce (M17) and the iat window (M18) both stop it.
    delayed: { any: [["M17", "M18"]] },
  },
  A20: { "*": { any: [["M19"]] } },
  A21: {
    at_revoked: { any: [["M21"]] },
    refresh_revoked: { any: [["M22"]] },
  },
  A22: {
    "*": {
      any: [["M23"]],
      // Without quote freshness the replayed quote is a valid appraisal (no DoS to measure);
      // B0/B1 have no attestation at all.
      na: (off, baseline) => {
        if (baseline === "B0" || baseline === "B1") return `n/a: baseline ${baseline} has no attestation verifier`;
        if (off.includes("M4")) return "n/a: M4 off, a replayed quote is appraised as fresh (no suspension path)";
        return null;
      },
    },
  },
  A23: {
    ungated_stepup: { any: [["M24"]] },
    race_registration: { any: [["M25"]] },
  },
  A24: { "*": { any: [["M26"]] } },
  // A new login from far away is stopped only at login (M27): the attacker's own login enters the
  // history the per-request score uses. A session moved after login is seen only by the PDP (M28).
  A25: {
    new_login: { any: [["M27"]] },
    moved_session: { any: [["M28"]] },
  },
};

function ruleFor(attackId, variant) {
  const r = RULES[attackId];
  if (!r) return null;
  return (variant && r[variant]) || r["*"] || null;
}

/** Mechanisms an (attack, variant) is tagged with (union of its sufficient sets). */
export function tagsFor(attackId, variant) {
  const r = RULES[attackId];
  if (!r) return [];
  const rules = variant ? [ruleFor(attackId, variant)] : Object.values(r);
  const tags = new Set();
  for (const rule of rules) for (const set of rule?.any || []) for (const m of set) tags.add(m);
  return [...tags];
}

/** True when the (attack, variant) rule says mechanism m is only defence in depth. */
export function isDidTag(attackId, variant, m) {
  const rule = ruleFor(attackId, variant);
  if (!rule) return false;
  const sets = rule.any.filter((s) => s.includes(m));
  return sets.length > 0 && sets.every((s) => s.length > 1);
}

/**
 * Predicted outcome for one (attack, variant) under a config.
 * @returns {"rejected"|"accepted"|"n/a"}
 */
export function expectedVariantOutcome(attackId, variant, configLabel) {
  const { off, baseline } = parseConfigLabel(configLabel);
  const rule = ruleFor(attackId, variant);
  if (!rule) return "rejected";
  if (typeof rule.na === "function" && rule.na(off, baseline)) return "n/a";
  return rule.any.some((set) => set.every((m) => off.includes(m))) ? "accepted" : "rejected";
}

/**
 * Applicability reason (string) or null, from the rule table.
 */
export function notApplicableReason(attackId, variant, configLabel) {
  const { off, baseline } = parseConfigLabel(configLabel);
  const rule = ruleFor(attackId, variant);
  if (rule && typeof rule.na === "function") return rule.na(off, baseline);
  return null;
}

/**
 * Predicted cell for an attack (all variants): accepted if any variant is predicted
 * accepted, n/a if every variant is n/a, else rejected.
 *
 * @param {string} attackId
 * @param {string} configLabel
 * @param {Array<string|null>} [variants]
 */
export function expectedOutcome(attackId, configLabel, variants = null) {
  const r = RULES[attackId];
  const vs = variants && variants.length ? variants : r ? Object.keys(r).filter((k) => k !== "*") : [];
  const list = vs.length ? vs : [null];
  const outs = list.map((v) => expectedVariantOutcome(attackId, v, configLabel));
  if (outs.includes("accepted")) return "accepted";
  if (outs.every((o) => o === "n/a")) return "n/a";
  return "rejected";
}

export default { RULES, tagsFor, isDidTag, expectedVariantOutcome, expectedOutcome, notApplicableReason };
