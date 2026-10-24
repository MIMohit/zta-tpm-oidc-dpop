#!/usr/bin/env node
/**
 * @file scripts/attacks/check-guards.mjs
 * Static guard site verification.
 * Verifies that every mechanism in MECHANISMS (M1–M26) appears as on("Mx") in the source tree.
 *
 * Usage:
 *   node scripts/attacks/check-guards.mjs
 */

import fs from "node:fs";
import path from "node:path";
import process from "node:process";

import { MECHANISMS } from "../../lib/ablation.js";

const ROOT_DIR = path.resolve(".");
const SCAN_DIRS = ["lib", "services"];
const SCAN_FILES = ["pep.js", "pdp.js", "pip.js", "server.js", "decision-controller.js", "tpm-agent.js"];
const IGNORE_PATTERNS = ["node_modules", ".git", "tests", "scratchpad", "results", "data", "testbed", "scripts"];

function collectFiles(dir) {
  let results = [];
  if (!fs.existsSync(dir)) return results;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (IGNORE_PATTERNS.some((p) => fullPath.includes(p))) continue;
    if (entry.isDirectory()) {
      results = results.concat(collectFiles(fullPath));
    } else if (entry.isFile() && (entry.name.endsWith(".js") || entry.name.endsWith(".mjs"))) {
      results.push(fullPath);
    }
  }
  return results;
}

const targetFiles = [];
for (const f of SCAN_FILES) {
  const p = path.join(ROOT_DIR, f);
  if (fs.existsSync(p)) targetFiles.push(p);
}
for (const d of SCAN_DIRS) {
  targetFiles.push(...collectFiles(path.join(ROOT_DIR, d)));
}

// Build file contents cache
const fileContents = targetFiles.map((file) => {
  const relPath = path.relative(ROOT_DIR, file);
  const content = fs.readFileSync(file, "utf8");
  return { file: relPath, content };
});

console.log("================================================================================");
console.log("🔍 STATIC GUARD SITE CHECK (M1–M26)");
console.log(`Scanning ${fileContents.length} source files...`);
console.log("================================================================================\n");

const findings = [];
let missingCount = 0;

for (const m of MECHANISMS) {
  const pattern = new RegExp(`on\\(\\s*["']${m.id}["']\\s*\\)`);
  const matches = [];

  for (const item of fileContents) {
    if (pattern.test(item.content)) {
      const lines = item.content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (pattern.test(lines[i])) {
          matches.push(`${item.file}:${i + 1}`);
        }
      }
    }
  }

  const found = matches.length > 0;
  if (!found) missingCount++;

  findings.push({
    id: m.id,
    layer: m.layer,
    title: m.title,
    found,
    sites: matches,
  });
}

console.log(`| ${"ID".padEnd(5)} | ${"Layer".padEnd(12)} | ${"Status".padEnd(8)} | ${"Guard Sites".padEnd(50)} |`);
console.log(`|${"-".repeat(7)}|${"-".repeat(14)}|${"-".repeat(10)}|${"-".repeat(52)}|`);

for (const f of findings) {
  const status = f.found ? "✅ FOUND" : "❌ MISSING";
  const sitesStr = f.found ? f.sites.join(", ") : "none";
  console.log(`| ${f.id.padEnd(5)} | ${f.layer.padEnd(12)} | ${status.padEnd(8)} | ${sitesStr.slice(0, 50).padEnd(50)} |`);
}

console.log("\n================================================================================");
if (missingCount === 0) {
  console.log(`🎉 All ${MECHANISMS.length} mechanisms found in source tree!`);
  console.log("================================================================================\n");
  process.exit(0);
} else {
  console.log(`⚠️  ${missingCount}/${MECHANISMS.length} mechanisms missing from source tree.`);
  console.log("================================================================================\n");
  process.exit(1);
}
