/**
 * @file scripts/attacks/lib/manifest.mjs
 * Per-configuration run manifests (VERIFY4 M1).
 *
 * Each configuration gets its own manifest built from the ablation state that was live
 * inside the trial context (never from the label alone), plus the code content hash that
 * runManifest() computes (sha256 over tracked and untracked sources, no git writes). The
 * hash is recomputed per configuration, so an edit to the tree during a run is visible.
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

import { runManifest } from "../../../lib/ablation.js";

/**
 * @param {Object} p
 * @param {string} p.runId
 * @param {string} p.mode
 * @param {string} p.config
 * @param {{label:string, baseline:string|null, off:string[], on?:string[], hash:string}} p.ablation
 * @param {Record<string, any>} [p.extra]
 */
export function configManifest({ runId, mode, tpm, config, ablation, extra = {} }) {
  const base = runManifest({ runId, mode, ...(tpm ? { tpm } : {}) });
  const manifest = {
    ...base,
    config,
    label: ablation.label,
    baseline: ablation.baseline ?? null,
    off: [...ablation.off],
    on: ablation.on ?? base.on,
    hash: ablation.hash,
    ...extra,
  };
  // Identifies (code, live ablation state, platform, mode) for this configuration.
  const manifestHash = crypto
    .createHash("sha256")
    .update(
      JSON.stringify({
        code: manifest.code?.sha256 ?? null,
        label: manifest.label,
        off: manifest.off,
        node: manifest.node,
        platform: manifest.platform,
        arch: manifest.arch,
        mode,
      })
    )
    .digest("hex")
    .slice(0, 16);
  return { ...manifest, manifestHash };
}

export function writeJson(file, obj) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n", "utf8");
}

export default { configManifest, writeJson };
