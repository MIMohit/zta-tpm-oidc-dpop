#!/usr/bin/env node
import path from "node:path";
import process from "node:process";
import fs from "node:fs";
import { loadConfig } from "../lib/config.js";
import { loadOrCreateSigningKey } from "../lib/keys.js";
import { verifyAuditLog } from "../lib/audit-log.js";

async function main() {
  const cfg = loadConfig();
  const defaultLogPath = path.join(cfg.dataDir, "audit", "pep.log");
  const targetFile = process.argv[2] ? path.resolve(process.argv[2]) : defaultLogPath;

  console.log(`[AUDIT] Verifying signed audit log: ${targetFile}`);

  if (!fs.existsSync(targetFile)) {
    console.error(`[AUDIT] Error: audit log file not found at ${targetFile}`);
    process.exit(1);
  }

  let auditKey;
  try {
    auditKey = await loadOrCreateSigningKey("audit", cfg);
  } catch (err) {
    console.error(`[AUDIT] Error loading audit signing key: ${err.message}`);
    process.exit(1);
  }

  const result = await verifyAuditLog(targetFile, {
    publicJwk: auditKey.publicJwk,
    cfg,
  });

  if (result.valid) {
    console.log(`[AUDIT] SUCCESS: ${result.count} entries verified. Hash chain and signatures OK.`);
    process.exit(0);
  } else {
    console.error(`[AUDIT] FAILURE: ${result.error}`);
    if (result.lineNum) {
      console.error(`[AUDIT] Line ${result.lineNum}: ${result.badLine}`);
    }
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(`[AUDIT] Fatal verification error:`, err);
  process.exit(1);
});
