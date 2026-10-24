#!/usr/bin/env node
/**
 * @file rv-capture.mjs
 * Reference values (RV) capture and generation tool.
 * Parses one or more TCG binary event logs, replays PCRs, and generates zta-rv/1 reference value files.
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {
  parseTcgEventLog,
  replayTcgEventLog,
  pcrCompositeDigest,
  toAppraisalEvents,
  TcgEventLogError,
} from "../lib/verifier/tcg-eventlog.js";

function parseArgs(args) {
  const options = {
    logs: [],
    live: false,
    name: "",
    out: "",
    merge: "",
    pcrs: [0, 1, 2, 3, 4, 5, 6, 7],
    bank: "sha256",
    qemuFingerprint: "",
    goldenPcrs: "",
    goldenPcrsFile: path.resolve("fixtures/golden-pcrs.json"),
    print: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--log") {
      while (i + 1 < args.length && !args[i + 1].startsWith("--")) {
        options.logs.push(args[++i]);
      }
    } else if (arg === "--live") {
      options.live = true;
    } else if (arg === "--name" && i + 1 < args.length) {
      options.name = args[++i];
    } else if (arg === "--out" && i + 1 < args.length) {
      options.out = args[++i];
    } else if (arg === "--merge" && i + 1 < args.length) {
      options.merge = args[++i];
    } else if (arg === "--pcrs" && i + 1 < args.length) {
      const val = args[++i];
      if (val.includes("-")) {
        const [start, end] = val.split("-").map(Number);
        options.pcrs = [];
        for (let p = start; p <= end; p++) options.pcrs.push(p);
      } else if (val.includes("..")) {
        const [start, end] = val.split("..").map(Number);
        options.pcrs = [];
        for (let p = start; p <= end; p++) options.pcrs.push(p);
      } else {
        options.pcrs = val.split(",").map((s) => Number(s.trim()));
      }
    } else if (arg === "--bank" && i + 1 < args.length) {
      options.bank = args[++i];
    } else if (arg === "--qemu-fingerprint" && i + 1 < args.length) {
      options.qemuFingerprint = args[++i];
    } else if (arg === "--golden-pcrs" && i + 1 < args.length) {
      options.goldenPcrs = args[++i];
    } else if (arg === "--golden-pcrs-file" && i + 1 < args.length) {
      options.goldenPcrsFile = args[++i];
    } else if (arg === "--print") {
      options.print = true;
    } else {
      console.error(`Unknown argument: ${arg}`);
      process.exit(1);
    }
  }

  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));

  if (options.live) {
    const livePath = "/sys/kernel/security/tpm0/binary_bios_measurements";
    if (!fs.existsSync(livePath)) {
      console.error(`Error: --live path not found: ${livePath}`);
      process.exit(2);
    }
    options.logs.push(livePath);
  }

  if (options.logs.length === 0) {
    console.error("Error: No input event log specified (use --log <file> or --live)");
    process.exit(1);
  }

  const name = options.name || (options.out ? path.basename(options.out, ".json") : "rv-capture");

  // Load existing RV if merge is requested
  let rvData = {
    format: "zta-rv/1",
    name,
    bank: options.bank,
    pcrs: options.pcrs,
    source: {
      logs: [],
      qemuFingerprint: options.qemuFingerprint || "",
      capturedAt: new Date().toISOString(),
    },
    events: {},
    compositeDigests: [],
  };

  if (options.merge && fs.existsSync(options.merge)) {
    try {
      const existing = JSON.parse(fs.readFileSync(options.merge, "utf8"));
      if (existing.format === "zta-rv/1") {
        rvData = existing;
      }
    } catch (err) {
      console.error(`Error reading merge file ${options.merge}:`, err.message);
      process.exit(2);
    }
  }

  for (const p of options.pcrs) {
    if (!rvData.events[p]) {
      rvData.events[p] = [];
    }
  }

  // Process each log
  for (const logPath of options.logs) {
    let buf;
    try {
      buf = fs.readFileSync(logPath);
    } catch (err) {
      console.error(`Error reading log file ${logPath}: ${err.message}`);
      process.exit(2);
    }

    let parsed;
    try {
      parsed = parseTcgEventLog(buf);
    } catch (err) {
      console.error(`Error parsing event log ${logPath}: ${err.message}`);
      process.exit(2);
    }

    const fileHash = crypto.createHash("sha256").update(buf).digest("hex");
    const filename = path.basename(logPath);

    if (!rvData.source.logs.some((l) => l.sha256 === fileHash)) {
      rvData.source.logs.push({ file: filename, sha256: fileHash });
    }

    // Replay log
    const replayed = replayTcgEventLog(parsed, { bank: options.bank, pcrs: options.pcrs });
    const composite = pcrCompositeDigest(replayed.pcrs, options.pcrs).toString("hex");
    if (!rvData.compositeDigests.includes(composite)) {
      rvData.compositeDigests.push(composite);
    }

    // Extract appraisal events
    const appEvents = toAppraisalEvents(parsed, { bank: options.bank, pcrs: options.pcrs });
    for (const ev of appEvents) {
      const pcrList = rvData.events[ev.pcr] || (rvData.events[ev.pcr] = []);
      if (!pcrList.some((e) => e.digest.toLowerCase() === ev.digest.toLowerCase())) {
        pcrList.push({
          digest: ev.digest.toLowerCase(),
          type: ev.typeName,
          desc: ev.desc,
        });
      }
    }
  }

  // Update golden PCRs file if requested
  if (options.goldenPcrs) {
    let goldenMap = {};
    if (fs.existsSync(options.goldenPcrsFile)) {
      try {
        goldenMap = JSON.parse(fs.readFileSync(options.goldenPcrsFile, "utf8"));
      } catch {}
    }
    goldenMap[options.goldenPcrs] = rvData.compositeDigests;
    fs.mkdirSync(path.dirname(path.resolve(options.goldenPcrsFile)), { recursive: true });
    fs.writeFileSync(options.goldenPcrsFile, JSON.stringify(goldenMap, null, 2) + "\n");
  }

  // Write output RV if requested
  if (options.out) {
    const outPath = path.resolve(options.out);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, JSON.stringify(rvData, null, 2) + "\n");
  }

  // Print summary if requested
  if (options.print) {
    console.log(`Reference Values: ${rvData.name} (${rvData.format})`);
    console.log(`Bank: ${rvData.bank}, PCRs: [${rvData.pcrs.join(", ")}]`);
    console.log(`Source Logs: ${rvData.source.logs.length}`);
    for (const l of rvData.source.logs) {
      console.log(`  - ${l.file} (sha256: ${l.sha256.slice(0, 16)}...)`);
    }
    console.log("Composite Digest(s):");
    for (const cd of rvData.compositeDigests) {
      console.log(`  ${cd}`);
    }
    console.log("\nPCR Digest Summary:");
    console.log("PCR | Distinct Digests | Event Types");
    console.log("----+------------------+-----------------------------");
    for (const p of options.pcrs) {
      const evs = rvData.events[p] || [];
      const types = [...new Set(evs.map((e) => e.type))].join(", ");
      console.log(`  ${p} |        ${String(evs.length).padStart(9)} | ${types}`);
    }
  }

  process.exit(0);
}

main().catch((err) => {
  console.error("Unexpected error:", err);
  process.exit(2);
});
