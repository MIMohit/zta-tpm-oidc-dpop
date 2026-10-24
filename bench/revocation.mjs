#!/usr/bin/env node
/**
 * @file bench/revocation.mjs
 * E5: time from revoking a device to the first refused request, on a live stack with a real
 * swtpm device. The device polls the protected resource every --interval ms with TPM-signed
 * DPoP proofs; the administrator revokes it at a random moment through the registry API.
 * Delta = first refused response time - time the revocation request was sent.
 *
 * Under Full the PDP reads the device status per request (M21), so Delta is one round trip;
 * under B3 (no per-request state) the token stays valid until it expires (T_AT).
 *
 * Usage: node bench/revocation.mjs [--configs full:100,B3:5] [--interval 20] [--idp keycloak] [--out DIR]
 */

import path from "node:path";
import process from "node:process";

import { devIdOf } from "../lib/sim-tpm/public-area.js";
import { createContext } from "../scripts/attacks/lib/context.mjs";
import { prepareSwtpmFleet } from "../scripts/attacks/lib/swtpm-fleet.mjs";
import { startLiveStack } from "../scripts/stack.mjs";
import { arg, environment, nowMs, summarize, writeCsv, writeJson } from "./lib.mjs";

async function trialsFor(config, trials, { interval, idp, prepared, rows, stackCpus }) {
  const stack = await startLiveStack({ config, idp, cpus: stackCpus, ekRootDirs: [prepared.trustDir], timeScale: 1 });
  let ctx;
  try {
    ctx = await createContext({ mode: "live", targets: stack.targets, tpm: "swtpm", config });
    const client = ctx.clients.alice;
    const devId = await devIdOf((await client.tpm.getEk()).publicArea);
    for (let t = 0; t < trials; t++) {
      await client.enrol(await ctx.seedInventory({ devId, user: "alice" }));
      await ctx.loginWithDevice(client, { username: "alice", password: ctx.passwords.alice });
      const revokeAfter = 200 + Math.random() * 800;
      const start = nowMs();
      let revokedAt = null;
      let delta = null;
      let polls = 0;
      const revoker = new Promise((resolve) =>
        setTimeout(async () => {
          revokedAt = nowMs();
          const res = await ctx.revoke(devId);
          resolve(res.status);
        }, revokeAfter)
      );
      // Poll until refused after the revocation (or the safety limit: token lifetime + 30 s)
      while (nowMs() - start < 330000) {
        const sentAt = nowMs();
        const res = await client.request("/api/company/news");
        polls++;
        if (revokedAt !== null && sentAt >= revokedAt && res.status !== 200) {
          delta = nowMs() - revokedAt;
          break;
        }
        const wait = interval - (nowMs() - sentAt);
        if (wait > 0) await new Promise((r) => setTimeout(r, wait));
      }
      const revokeStatus = await revoker;
      rows.push({ config, trial: t, deltaMs: delta, polls, revokeStatus });
      console.log(`${config} trial ${t + 1}/${trials}: Delta ${delta === null ? "not observed" : `${delta.toFixed(1)} ms`} (${polls} polls)`);
    }
  } finally {
    if (ctx) await ctx.cleanup().catch(() => {});
    await stack.stop();
  }
}

async function main(argv = process.argv.slice(2)) {
  const plan = arg(argv, "--configs", "full:100,B3:5").split(",").map((p) => p.split(":"));
  const interval = Number(arg(argv, "--interval", "20"));
  const idp = arg(argv, "--idp", "keycloak");
  const stackCpus = arg(argv, "--stack-cpus", undefined);
  const outDir = path.resolve(arg(argv, "--out", "results/bench"));
  const prepared = prepareSwtpmFleet(process.env.ZTA_SWTPM_FLEET_DIR || undefined);
  const rows = [];
  for (const [config, n] of plan) await trialsFor(config, Number(n), { interval, idp, prepared, rows, stackCpus });
  const results = {};
  for (const [config] of plan) {
    const xs = rows.filter((r) => r.config === config && r.deltaMs !== null).map((r) => r.deltaMs);
    results[config] = { ...summarize(xs), notObserved: rows.filter((r) => r.config === config && r.deltaMs === null).length };
  }
  writeJson(path.join(outDir, "e5-revocation.json"), { experiment: "E5", interval, idp, env: environment(), results });
  writeCsv(path.join(outDir, "e5-revocation.csv"), rows);
  console.log(JSON.stringify(results, null, 1));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
