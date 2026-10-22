/**
 * @file scripts/attacks/lib/result.mjs
 * JSONL writer, schema normaliser, matrix builder, prediction diff and necessity analysis.
 *
 * Cells exist at two levels: per (attack, variant) and per attack (a rep counts as A when
 * any variant was accepted in that rep). Every cell that differs from expected.mjs is listed.
 */

import fs from "node:fs";
import path from "node:path";
import { expectedOutcome, expectedVariantOutcome, tagsFor, isDidTag } from "./expected.mjs";

const SHORT = { rejected: "R", accepted: "A", "n/a": "n/a", error: "E" };

/**
 * Validates and normalises a result record (schema zta-attack/1; the ablation, code and
 * evidence fields are additive).
 */
export function normaliseResult(raw) {
  const allowedOutcomes = ["rejected", "accepted", "n/a", "error"];
  const outcome = allowedOutcomes.includes(raw.outcome) ? raw.outcome : "error";

  let stoppedAt = null;
  if (outcome === "rejected" || outcome === "n/a" || outcome === "error") {
    stoppedAt = {
      service: raw.stoppedAt?.service ?? null,
      status: raw.stoppedAt?.status ?? null,
      reason: raw.stoppedAt?.reason ?? (outcome === "error" ? "execution error" : "unspecified"),
    };
  }

  const variant = raw.variant ?? null;
  return {
    schema: "zta-attack/1",
    runId: String(raw.runId || ""),
    ts: raw.ts || new Date().toISOString(),
    mode: raw.mode || "inproc",
    config: String(raw.config || "full"),
    baseline: raw.baseline ?? null,
    mechanismsOff: Array.isArray(raw.mechanismsOff) ? [...raw.mechanismsOff] : [],
    ablation: raw.ablation
      ? { label: raw.ablation.label, off: [...(raw.ablation.off || [])], hash: raw.ablation.hash }
      : null,
    attack: String(raw.attack || ""),
    variant,
    rep: Number(raw.rep || 1),
    goal: String(raw.goal || ""),
    adversary: String(raw.adversary || ""),
    expected: Array.isArray(raw.expected) ? [...raw.expected] : [],
    predicted: raw.predicted || (variant ? expectedVariantOutcome(raw.attack, variant, raw.config) : expectedOutcome(raw.attack, raw.config)),
    outcome,
    stoppedAt,
    evidence: raw.evidence ?? null,
    durationMs: Number(raw.durationMs || 0),
    codeHash: raw.codeHash ? String(raw.codeHash) : null,
    manifestHash: String(raw.manifestHash || ""),
  };
}

export function appendJsonlRow(filePath, row) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, JSON.stringify(row) + "\n", "utf8");
}

function repOutcome(repRows) {
  if (repRows.some((r) => r.outcome === "accepted")) return "A";
  if (repRows.some((r) => r.outcome === "error")) return "E";
  if (repRows.every((r) => r.outcome === "n/a")) return "n/a";
  return "R";
}

/**
 * Cell over reps: "R", "A", "n/a", "E", or "k/n" (k accepted of n reps) when reps disagree.
 */
export function computeCell(rows) {
  if (!rows || rows.length === 0) return "n/a";
  const repMap = new Map();
  for (const r of rows) {
    if (!repMap.has(r.rep)) repMap.set(r.rep, []);
    repMap.get(r.rep).push(r);
  }
  const outs = [...repMap.values()].map(repOutcome);
  if (outs.every((o) => o === outs[0])) return outs[0];
  const countA = outs.filter((o) => o === "A").length;
  const countE = outs.filter((o) => o === "E").length;
  return countE ? `${countA}/${outs.length} (E${countE})` : `${countA}/${outs.length}`;
}

function variantsOf(attack) {
  const v = attack.module?.variants;
  return Array.isArray(v) && v.length ? v : [null];
}

function rowKey(attackId, variant) {
  return variant ? `${attackId}:${variant}` : attackId;
}

/**
 * @returns {{ matrixMap: Map<string, Map<string,string>>, variantMap: Map<string, Map<string,string>>, configs, attacks }}
 */
export function buildMatrix({ allRows, attacks, configs }) {
  const matrixMap = new Map();
  const variantMap = new Map();
  for (const attack of attacks) {
    const cfgMap = new Map();
    for (const cfg of configs) {
      cfgMap.set(cfg, computeCell(allRows.filter((r) => r.attack === attack.id && r.config === cfg)));
    }
    matrixMap.set(attack.id, cfgMap);

    for (const variant of variantsOf(attack)) {
      if (!variant) continue;
      const vMap = new Map();
      for (const cfg of configs) {
        vMap.set(
          cfg,
          computeCell(allRows.filter((r) => r.attack === attack.id && r.variant === variant && r.config === cfg))
        );
      }
      variantMap.set(rowKey(attack.id, variant), vMap);
    }
  }
  return { matrixMap, variantMap, configs, attacks };
}

function matrixLines({ matrixMap, variantMap, configs, attacks }, sepChar) {
  const lines = [];
  for (const attack of attacks) {
    const cells = configs.map((cfg) => matrixMap.get(attack.id)?.get(cfg) || "n/a");
    lines.push([attack.id, (attack.expected || []).join(" "), ...cells]);
    for (const variant of variantsOf(attack)) {
      if (!variant) continue;
      const key = rowKey(attack.id, variant);
      const vcells = configs.map((cfg) => variantMap.get(key)?.get(cfg) || "n/a");
      lines.push([`${sepChar}${key}`, tagsFor(attack.id, variant).join(" "), ...vcells]);
    }
  }
  return lines;
}

export function formatMatrixCsv(data) {
  const rows = [["Attack", "Mechanisms", ...data.configs].join(",")];
  for (const l of matrixLines(data, "")) rows.push(l.map((c) => (/[, ]/.test(c) ? `"${c}"` : c)).join(","));
  return rows.join("\n") + "\n";
}

export function formatMatrixMarkdown(data) {
  const header = `| Attack | Mechanisms | ${data.configs.join(" | ")} |`;
  const sep = `| :--- | :--- | ${data.configs.map(() => ":---:").join(" | ")} |`;
  const lines = [header, sep];
  for (const l of matrixLines(data, "↳ ")) lines.push(`| ${l.join(" | ")} |`);
  return lines.join("\n") + "\n";
}

/**
 * Every (attack[:variant], config) cell whose observation differs from expected.mjs.
 */
export function predictionDiffs({ matrixMap, variantMap, configs, attacks }) {
  const diffs = [];
  for (const attack of attacks) {
    const variants = variantsOf(attack).filter(Boolean);
    for (const cfg of configs) {
      const observed = matrixMap.get(attack.id)?.get(cfg) || "n/a";
      const exp = SHORT[expectedOutcome(attack.id, cfg, variants.length ? variants : null)];
      if (observed !== exp) diffs.push({ cell: attack.id, attack: attack.id, variant: null, config: cfg, expected: exp, observed });
      for (const v of variants) {
        const key = rowKey(attack.id, v);
        const vObs = variantMap.get(key)?.get(cfg) || "n/a";
        const vExp = SHORT[expectedVariantOutcome(attack.id, v, cfg)];
        if (vObs !== vExp) diffs.push({ cell: key, attack: attack.id, variant: v, config: cfg, expected: vExp, observed: vObs });
      }
    }
  }
  return diffs;
}

export function formatPredictionDiff(data) {
  const diffs = predictionDiffs(data);
  let md = "# Prediction differences (observed vs expected.mjs)\n\n";
  if (diffs.length === 0) {
    md += "No differences: every attack and variant cell matches its prediction.\n";
    return md;
  }
  md += `${diffs.length} differing cell(s) (attack-level and variant-level rows are both listed):\n\n`;
  md += "| Cell | Config | Expected | Observed |\n| :--- | :--- | :---: | :---: |\n";
  for (const d of diffs) md += `| ${d.cell} | ${d.config} | ${d.expected} | ${d.observed} |\n`;
  return md + "\n";
}

/**
 * Necessity per mechanism, from observed cells only:
 *  - necessary: some attack or variant is R under full and A under -Mx alone
 *  - didPairs: an attack/variant tagged with Mx stays R under -Mx
 */
export function analyzeNecessity({ matrixMap, variantMap = new Map(), attacks, mechanisms }) {
  const necessity = {};
  for (const m of mechanisms) {
    const cfgLabel = `-${m.id}`;
    const flipping = [];
    const didPairs = [];
    const unexpectedlyAccepted = [];

    for (const attack of attacks) {
      const variants = variantsOf(attack);
      const units = variants[0] === null ? [[attack.id, null, matrixMap.get(attack.id)]] : variants.map((v) => [rowKey(attack.id, v), v, variantMap.get(rowKey(attack.id, v))]);
      for (const [key, variant, cells] of units) {
        if (!cells) continue;
        const full = cells.get("full");
        const abl = cells.get(cfgLabel);
        const tagged = tagsFor(attack.id, variant).includes(m.id);
        if (full === "R" && abl === "A") {
          flipping.push(key);
          if (!tagged) unexpectedlyAccepted.push(key);
        } else if (tagged && abl === "R") {
          didPairs.push({
            attack: key,
            predictedDid: isDidTag(attack.id, variant, m.id),
            reason: `stays R under -${m.id}`,
          });
        }
      }
    }

    necessity[m.id] = {
      layer: m.layer,
      title: m.title,
      status: flipping.length > 0 ? "necessary" : "not shown",
      flippingAttacks: flipping,
      untaggedFlips: unexpectedlyAccepted,
      didPairs,
    };
  }
  return necessity;
}

export default {
  normaliseResult,
  appendJsonlRow,
  computeCell,
  buildMatrix,
  formatMatrixCsv,
  formatMatrixMarkdown,
  predictionDiffs,
  formatPredictionDiff,
  analyzeNecessity,
};
