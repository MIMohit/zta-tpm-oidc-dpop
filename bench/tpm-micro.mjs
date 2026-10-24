#!/usr/bin/env node
/**
 * @file bench/tpm-micro.mjs
 * E2: latency of each TPM 2.0 command the protocol uses, on the hardware fTPM and on swtpm.
 * Each command runs `warmup` times untimed, then `runs` times timed, sequentially.
 *
 * Usage: node bench/tpm-micro.mjs --device linux|swtpm [--runs 200] [--warmup 20] [--out DIR]
 *   linux: /dev/tpmrm0 with TPM_SRK_HANDLE (dev-hw); swtpm: a fresh lab-CA swtpm process
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

import { RealTpm } from "../lib/tpm-real/index.js";
import { makeCredentialAny, nameOfAny } from "../lib/verifier/evidence.js";
import { prepareSwtpmFleet, startSwtpmFleet } from "../scripts/attacks/lib/swtpm-fleet.mjs";
import { arg, environment, nowMs, summarize, writeCsv, writeJson } from "./lib.mjs";

const PCR_SETS = { pcr0_7: [0, 1, 2, 3, 4, 5, 6, 7], pcr0_9: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] };

async function main(argv = process.argv.slice(2)) {
  const device = arg(argv, "--device", "swtpm");
  const runs = Number(arg(argv, "--runs", "200"));
  const warmup = Number(arg(argv, "--warmup", "20"));
  const outDir = path.resolve(arg(argv, "--out", "results/bench"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "zta-tpm-micro-"));

  let fleet = null;
  let tpm;
  if (device === "swtpm") {
    const prepared = prepareSwtpmFleet(process.env.ZTA_SWTPM_FLEET_DIR || undefined);
    fleet = await startSwtpmFleet(prepared, stateDir);
    const dev = fleet.devices["alice-laptop"];
    tpm = new RealTpm({ device: "swtpm", host: "127.0.0.1", port: dev.port, dir: path.join(stateDir, "agent"), ekType: "ecc384", ekCertChain: [dev.chain] });
  } else {
    tpm = new RealTpm({ device: "linux", dir: path.join(stateDir, "agent"), ekType: process.env.TPM_EK_TYPE || "rsa", srkHandle: process.env.TPM_SRK_HANDLE || "0x81000101" });
  }
  await tpm.init();

  const results = {};
  const samples = [];
  async function bench(name, fn) {
    for (let i = 0; i < warmup; i++) await fn();
    const xs = [];
    for (let i = 0; i < runs; i++) {
      const t0 = nowMs();
      await fn();
      xs.push(nowMs() - t0);
    }
    results[name] = summarize(xs);
    for (const [i, x] of xs.entries()) samples.push({ device, command: name, run: i, ms: x });
    const r = results[name];
    console.log(`${device.padEnd(6)} ${name.padEnd(22)} median ${r.median.toFixed(2)} ms  IQR [${r.q1.toFixed(2)}, ${r.q3.toFixed(2)}]  p95 ${r.p95.toFixed(2)}`);
  }

  try {
    const ek = await tpm.getEk();
    const data = crypto.randomBytes(32);

    await bench("Create AK", () => tpm.createAk());
    await bench("Create K_B", () => tpm.createKb());
    // The keys used below are the latest AK / K_B
    const ak2 = await tpm.createAk();
    const kb2 = await tpm.createKb();
    const ak2Name = nameOfAny(ak2.publicArea);
    await bench("ActivateCredential", async () => {
      const blob = makeCredentialAny(ek.publicArea, ak2Name, crypto.randomBytes(32));
      await tpm.activateCredential(ak2.handle, blob);
    });
    for (const [label, pcrs] of Object.entries(PCR_SETS)) {
      await bench(`Quote ${label}`, () => tpm.quote(ak2.handle, crypto.randomBytes(32).toString("base64url"), pcrs));
    }
    await bench("Certify K_B", () => tpm.certify(kb2.handle, ak2.handle, crypto.randomBytes(32).toString("base64url")));
    await bench("Sign (DPoP proof)", () => tpm.sign(kb2.handle, crypto.createHash("sha256").update(data).digest()));
  } finally {
    await tpm.close().catch(() => {});
    if (fleet) await fleet.stop();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }

  const report = { experiment: "E2", device, runs, warmup, env: environment(), results };
  writeJson(path.join(outDir, `e2-tpm-${device}.json`), report);
  writeCsv(path.join(outDir, `e2-tpm-${device}-samples.csv`), samples);
  console.log(`Wrote ${path.join(outDir, `e2-tpm-${device}.json`)}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
