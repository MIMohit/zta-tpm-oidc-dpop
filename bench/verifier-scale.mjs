#!/usr/bin/env node
/**
 * @file bench/verifier-scale.mjs
 * E7: verifier throughput and latency as the fleet grows. N swtpm devices (lab CA) enrol,
 * then all re-attest concurrently in a loop for --duration seconds. Reports appraisals per
 * second, appraisal latency, and the verifier process's CPU use (to show whether the
 * verifier, not the clients, was the limit).
 *
 * Usage: taskset -c 6,7 node bench/verifier-scale.mjs [--sizes 10,25,50,100,200] [--duration 30]
 *        [--stack-cpus 0-5] [--idp keycloak] [--out DIR]
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

import { ZtaClient } from "../lib/agent-client.js";
import { loadConfig } from "../lib/config.js";
import { devIdOf } from "../lib/sim-tpm/public-area.js";
import { RealTpm } from "../lib/tpm-real/index.js";
import { prepareScaleFleet, startSwtpmSet } from "../scripts/attacks/lib/swtpm-fleet.mjs";
import { startLiveStack } from "../scripts/stack.mjs";
import { arg, environment, nowMs, summarize, writeCsv, writeJson } from "./lib.mjs";

/** CPU seconds (user + system) consumed so far by a Linux process, or null elsewhere. */
function cpuSeconds(pid) {
  try {
    const f = fs.readFileSync(`/proc/${pid}/stat`, "utf8").split(") ")[1].split(" ");
    return (Number(f[11]) + Number(f[12])) / 100; // utime + stime, USER_HZ = 100
  } catch {
    return null;
  }
}

async function measure(size, { durationS, stackCpus, idp, rows }) {
  const scale = prepareScaleFleet(size, process.env.ZTA_SWTPM_FLEET_DIR || undefined);
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "zta-e7-"));
  const set = await startSwtpmSet(scale.states.slice(0, size), workDir);
  const stack = await startLiveStack({ config: "full", idp, cpus: stackCpus, ekRootDirs: [scale.trustDir], timeScale: 1 });
  const tpms = [];
  try {
    const t = stack.targets;
    const cfg = loadConfig({ pepPublicUrl: t.pepUrl, idpIssuer: t.idpUrl, verifierUrl: t.verifierUrl, resourceUrl: t.resourceUrl });
    const clients = [];
    for (const [i, port] of set.ports.entries()) {
      const tpm = new RealTpm({ device: "swtpm", host: "127.0.0.1", port, dir: path.join(workDir, "agent", String(i)), ekType: "ecc384", ekCertChain: [scale.chain] });
      await tpm.init();
      tpms.push(tpm);
      const devId = await devIdOf((await tpm.getEk()).publicArea);
      const res = await fetch(`${t.verifierUrl}/v/inventory`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-ZTA-Internal": t.ztaInternalToken, Authorization: `Bearer ${t.adminToken}` },
        body: JSON.stringify({ devId, user: "alice" }),
      });
      const client = new ZtaClient({ tpm, cfg });
      await client.enrol((await res.json()).code);
      clients.push(client);
    }

    const lat = [];
    let errors = 0;
    const cpu0 = cpuSeconds(stack.pids.verifier);
    const t0 = nowMs();
    const deadline = t0 + durationS * 1000;
    await Promise.all(
      clients.map(async (c) => {
        while (nowMs() < deadline) {
          const s = nowMs();
          try {
            await c.attest();
            lat.push(nowMs() - s);
          } catch {
            errors++;
          }
        }
      })
    );
    const elapsed = (nowMs() - t0) / 1000;
    const cpu1 = cpuSeconds(stack.pids.verifier);
    const row = {
      devices: size,
      appraisalsPerS: lat.length / elapsed,
      errors,
      verifierCpuPct: cpu0 === null || cpu1 === null ? null : (100 * (cpu1 - cpu0)) / elapsed,
      ...Object.fromEntries(Object.entries(summarize(lat, { bootstrap: 0 })).filter(([k]) => ["median", "p95", "p99"].includes(k))),
    };
    rows.push(row);
    console.log(
      `N=${String(size).padStart(4)}: ${row.appraisalsPerS.toFixed(1)} appraisals/s, latency p50 ${row.median.toFixed(1)} p95 ${row.p95.toFixed(1)} ms, verifier CPU ${row.verifierCpuPct === null ? "n/a" : row.verifierCpuPct.toFixed(0) + "%"}, errors ${errors}`
    );
  } finally {
    for (const tpm of tpms) await tpm.close().catch(() => {});
    await stack.stop();
    await set.stop();
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}

async function main(argv = process.argv.slice(2)) {
  const sizes = arg(argv, "--sizes", "10,25,50,100,200").split(",").map(Number);
  const durationS = Number(arg(argv, "--duration", "30"));
  const stackCpus = arg(argv, "--stack-cpus", "0-5");
  const idp = arg(argv, "--idp", "keycloak");
  const outDir = path.resolve(arg(argv, "--out", "results/bench"));
  const rows = [];
  for (const size of sizes) await measure(size, { durationS, stackCpus, idp, rows });
  writeJson(path.join(outDir, "e7-verifier-scale.json"), { experiment: "E7", durationS, stackCpus, idp, env: environment(), rows });
  writeCsv(path.join(outDir, "e7-verifier-scale.csv"), rows);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
