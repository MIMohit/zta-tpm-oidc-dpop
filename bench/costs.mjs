#!/usr/bin/env node
/**
 * @file bench/costs.mjs
 * E3 / E9: client-observed latency of each protocol phase on a live stack (separate
 * processes, Keycloak, HSM when installed) with a real swtpm device, per configuration.
 * For each phase the time spent inside TPM commands is recorded separately, so every
 * result splits into "TPM" and "network + servers".
 *
 * Phases: enrol (Alg. 1), re-attestation (appraisal), login (Keycloak + device gate +
 * token), login with WebAuthn step-up, protected request (DPoP, PEP, PDP).
 *
 * --hw uses this host's hardware TPM as the device (dev-hw: AMD fTPM, AMD EK chain, persistent
 * SRK), appraised against a profile captured from this boot's event log (PCR0..9 and 12).
 *
 * Usage: node bench/costs.mjs --configs full,B0,B1,B2,B3 [--n 100] [--requests 10] [--idp keycloak|local] [--hw] [--out DIR]
 *        node bench/costs.mjs --configs all [--n 30]        (E9: every configuration)
 *
 * --paired measures every configuration next to its own Full block, alternating which runs
 * first (ABBA), so slow drifts (JIT and cache warm-up, thermal state) cancel in the per-pair
 * differences; each sample records its block. Without it, configurations run once in order.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";

import { allConfigs } from "../lib/ablation.js";
import { ZtaClient } from "../lib/agent-client.js";
import { loadConfig } from "../lib/config.js";
import { RealTpm } from "../lib/tpm-real/index.js";
import { devIdOf } from "../lib/sim-tpm/public-area.js";
import { createContext } from "../scripts/attacks/lib/context.mjs";
import { prepareSwtpmFleet } from "../scripts/attacks/lib/swtpm-fleet.mjs";
import { startLiveStack } from "../scripts/stack.mjs";
import { SoftAuthenticator } from "../tests/helpers/soft-webauthn.js";
import { arg, environment, nowMs, summarize, writeCsv, writeJson } from "./lib.mjs";

const TPM_METHODS = ["getEk", "createAk", "createKb", "activateCredential", "quote", "certify", "sign", "readEventLog"];

/** Wraps the TPM backend so time spent in TPM commands accumulates in meter.tpmMs. */
function meterTpm(tpm) {
  const meter = { tpmMs: 0 };
  for (const m of TPM_METHODS) {
    if (typeof tpm[m] !== "function") continue;
    const orig = tpm[m].bind(tpm);
    tpm[m] = async (...a) => {
      const t0 = nowMs();
      try {
        return await orig(...a);
      } finally {
        meter.tpmMs += nowMs() - t0;
      }
    };
  }
  return meter;
}

/** dev-hw: AMD trust anchors and a reference profile captured from this boot's event log. */
function prepareHw(outDir) {
  const data = path.resolve("data");
  const rvFile = path.join(outDir, "omarchy-uki-profile.json");
  execFileSync(process.execPath, [path.resolve("scripts/rv-capture.mjs"), "--log", "/sys/kernel/security/tpm0/binary_bios_measurements", "--name", "omarchy-uki", "--pcrs", "0,1,2,3,4,5,6,7,8,9,12", "--out", rvFile], { stdio: "ignore" });
  process.env.TPM_EK_CERT_FILE ??= path.join(data, "agent", "dev-hw", "ek-rsa.der");
  process.env.TPM_EVENTLOG_PATH ??= "/sys/kernel/security/tpm0/binary_bios_measurements";
  return { roots: path.join(data, "ek-roots", "amd"), ints: path.join(data, "ek-intermediates", "amd"), rvFile };
}

async function measureConfig(config, { n, requests, prepared, samples, idp, stackCpus, hw, block = 0 }) {
  const stack = await startLiveStack({
    config,
    idp,
    cpus: stackCpus,
    ekRootDirs: [prepared.trustDir, ...(hw ? [hw.roots] : [])],
    ekIntermediateDirs: hw ? [hw.ints] : [],
    ...(hw ? { rvProfiles: `omarchy-uki=${hw.rvFile}` } : {}),
    timeScale: 1,
  });
  let ctx;
  let hwTpm = null;
  try {
    ctx = await createContext({ mode: "live", targets: stack.targets, tpm: "swtpm", config });
    let client = ctx.clients.alice;
    if (hw) {
      hwTpm = new RealTpm({ device: "linux", dir: fs.mkdtempSync(path.join(os.tmpdir(), "zta-hw-")), ekType: "rsa", srkHandle: process.env.TPM_SRK_HANDLE || "0x81000101" });
      await hwTpm.init();
      const t = stack.targets;
      client = new ZtaClient({ tpm: hwTpm, cfg: loadConfig({ pepPublicUrl: t.pepUrl, idpIssuer: t.idpUrl, verifierUrl: t.verifierUrl, resourceUrl: t.resourceUrl }) });
    }
    const meter = meterTpm(client.tpm);
    const devId = await devIdOf((await client.tpm.getEk()).publicArea);
    let recording = false;
    const phase = async (name, fn) => {
      meter.tpmMs = 0;
      const t0 = nowMs();
      await fn();
      if (recording) samples.push({ config, block, phase: name, totalMs: nowMs() - t0, tpmMs: meter.tpmMs });
    };

    // Iteration -1 is a discarded warm-up (JWKS fetches, JIT, connection pools)
    const factor = new SoftAuthenticator();
    for (let i = -1; i < n; i++) {
      recording = i >= 0;
      const code = await ctx.seedInventory({ devId, user: "alice", ...(hw ? { rvProfile: "omarchy-uki" } : {}) });
      await phase("enrol", () => client.enrol(code));
      await phase("re-attestation", () => client.attest());
      await phase("login", () => ctx.loginWithDevice(client, { username: "alice", password: ctx.passwords.alice }));
      for (let r = 0; r < requests; r++) {
        await phase("request", async () => {
          const res = await client.request("/api/company/news");
          if (res.status !== 200) throw new Error(`request failed under ${config}: ${res.status}`);
        });
      }
      if (i === -1) await ctx.seedWebauthn(factor, { user: "alice", client, password: ctx.passwords.alice });
      if (i < Math.ceil(n / 2)) {
        await phase("login + step-up", () => ctx.loginWithDevice(client, { username: "alice", password: ctx.passwords.alice, acrValues: "mfa", softAuth: factor }));
      }
    }
  } finally {
    if (hwTpm) await hwTpm.close().catch(() => {});
    if (ctx) await ctx.cleanup().catch(() => {});
    await stack.stop();
  }
}

async function main(argv = process.argv.slice(2)) {
  const list = arg(argv, "--configs", "full,B0,B1,B2,B3");
  const configs = list === "all" ? allConfigs() : list.split(",");
  const n = Number(arg(argv, "--n", "100"));
  const requests = Number(arg(argv, "--requests", "10"));
  const outDir = path.resolve(arg(argv, "--out", "results/bench"));
  const tag = arg(argv, "--tag", list === "all" ? "e9" : "e3");
  const idp = arg(argv, "--idp", "keycloak");
  const stackCpus = arg(argv, "--stack-cpus", undefined);
  const prepared = prepareSwtpmFleet(process.env.ZTA_SWTPM_FLEET_DIR || undefined);
  fs.mkdirSync(outDir, { recursive: true });
  const hw = argv.includes("--hw") ? prepareHw(outDir) : null;

  const paired = argv.includes("--paired");
  const others = configs.filter((c) => c !== "full");
  // Schedule of (config, block): paired = per other config a Full block next to it, order alternating
  const schedule = paired
    ? others.flatMap((c, i) => (i % 2 === 0 ? [["full", i], [c, i]] : [[c, i], ["full", i]]))
    : configs.map((c) => [c, 0]);

  const samples = [];
  const results = {};
  for (const [config, block] of schedule) {
    const t0 = Date.now();
    try {
      await measureConfig(config, { n, requests, prepared, samples, idp, stackCpus, hw, block });
    } catch (err) {
      results[config] = { error: err.message };
      console.error(`${config}: ${err.message}`);
      continue;
    }
    results[config] = {};
    for (const ph of [...new Set(samples.filter((s) => s.config === config).map((s) => s.phase))]) {
      const xs = samples.filter((s) => s.config === config && s.phase === ph);
      results[config][ph] = { total: summarize(xs.map((s) => s.totalMs)), tpm: summarize(xs.map((s) => s.tpmMs)) };
    }
    const r = results[config];
    console.log(
      `${config.padEnd(6)} ` +
        Object.entries(r)
          .map(([ph, v]) => `${ph} ${v.total.median.toFixed(1)} ms (TPM ${v.tpm.median.toFixed(1)})`)
          .join(" | ") +
        `  [${Math.round((Date.now() - t0) / 1000)} s]`
    );
  }

  writeJson(path.join(outDir, `${tag}-costs.json`), { experiment: tag.toUpperCase(), device: hw ? "hardware fTPM" : "swtpm", idp, n, requests, configs, paired, env: environment(), results });
  writeCsv(path.join(outDir, `${tag}-costs-samples.csv`), samples);
  console.log(`Wrote ${path.join(outDir, `${tag}-costs.json`)}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
