#!/usr/bin/env node
/**
 * @file scripts/fuzz/fuzz.mjs
 * Mutation fuzzer for the parsers and verifiers that take attacker-controlled bytes
 * (scripts/fuzz/targets.mjs). Deterministic: the same --seed gives the same inputs.
 *
 * Each input is classified:
 *   rejected  - clean rejection by the parser or verifier
 *   parsed    - accepted as well-formed (fine for parsers; for signed objects only the seed)
 *   accepted  - a mutated signed object verified: a FALSE ACCEPT (security bug)
 *   unchecked - an unexpected exception type (TypeError, RangeError...): a robustness bug
 *   hang      - no answer within the watchdog time (the worker is restarted)
 * Findings are saved as files for replay.
 *
 * Usage: node scripts/fuzz/fuzz.mjs [--targets eventlog,attest,tpmt,x509,dpop,quote]
 *                                   [--iters 100000] [--seed 1] [--out results/fuzz]
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";

const WATCHDOG_MS = 5000;

/** xorshift128+ PRNG: deterministic and fast. */
function prng(seed) {
  let s0 = BigInt(seed) | 1n;
  let s1 = (BigInt(seed) * 0x9e3779b97f4a7c15n) & 0xffffffffffffffffn;
  return () => {
    let x = s0;
    const y = s1;
    s0 = y;
    x ^= (x << 23n) & 0xffffffffffffffffn;
    s1 = x ^ y ^ (x >> 17n) ^ (y >> 26n);
    return Number((s1 + y) & 0xffffffffn) / 0x100000000;
  };
}

const INTERESTING = [0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x10000, 0x7fffffff, 0xffffffff];

/** One to four mutations of a seed (or a splice of two seeds). */
export function mutate(seeds, rnd) {
  const pick = (n) => Math.floor(rnd() * n);
  let buf = Buffer.from(seeds[pick(seeds.length)]);
  const ops = 1 + pick(4);
  for (let k = 0; k < ops; k++) {
    if (buf.length === 0) buf = Buffer.from([pick(256)]);
    const at = pick(buf.length);
    switch (pick(9)) {
      case 0: // bit flip
        buf[at] ^= 1 << pick(8);
        break;
      case 1: // random byte
        buf[at] = pick(256);
        break;
      case 2: // interesting 8-bit
        buf[at] = INTERESTING[pick(5)] & 0xff;
        break;
      case 3: // interesting 16-bit, big or little endian (TPM is BE, TCG logs are LE)
        if (at + 2 <= buf.length) {
          const v = INTERESTING[pick(INTERESTING.length)] & 0xffff;
          pick(2) ? buf.writeUInt16BE(v, at) : buf.writeUInt16LE(v, at);
        }
        break;
      case 4: // interesting 32-bit
        if (at + 4 <= buf.length) {
          const v = INTERESTING[pick(INTERESTING.length)] >>> 0;
          pick(2) ? buf.writeUInt32BE(v, at) : buf.writeUInt32LE(v, at);
        }
        break;
      case 5: // truncate
        buf = buf.subarray(0, at);
        break;
      case 6: // insert random bytes
        buf = Buffer.concat([buf.subarray(0, at), crypto.randomBytes(1 + pick(16)).map(() => pick(256)), buf.subarray(at)]);
        break;
      case 7: // duplicate a chunk
        {
          const len = 1 + pick(Math.min(64, buf.length - at));
          buf = Buffer.concat([buf.subarray(0, at + len), buf.subarray(at, at + len), buf.subarray(at + len)]);
        }
        break;
      case 8: // splice with another seed
        {
          const other = seeds[pick(seeds.length)];
          const cut = pick(other.length + 1);
          buf = Buffer.concat([buf.subarray(0, at), other.subarray(cut)]);
        }
        break;
    }
  }
  return buf;
}

async function workerMain() {
  const { target, iters, seed, start } = workerData;
  const { loadTargets, CLEAN_ERRORS } = await import("./targets.mjs");
  const t = (await loadTargets())[target];
  const rnd = prng(seed);
  // Skip the inputs a previous worker already handled (after a hang restart)
  for (let i = 0; i < start; i++) mutate(t.seeds, rnd);
  const counts = { rejected: 0, parsed: 0, accepted: 0, unchecked: 0 };
  for (let i = start; i < iters; i++) {
    const input = i < t.seeds.length ? Buffer.from(t.seeds[i]) : mutate(t.seeds, rnd);
    parentPort.postMessage({ type: "begin", i, input });
    let outcome;
    let detail = null;
    try {
      outcome = await t.check(input);
    } catch (err) {
      outcome = CLEAN_ERRORS.has(err?.constructor?.name) ? "rejected" : "unchecked";
      if (outcome === "unchecked") detail = `${err?.constructor?.name}: ${err?.message}`.slice(0, 300);
    }
    counts[outcome] = (counts[outcome] || 0) + 1;
    if (outcome === "accepted" || outcome === "unchecked") parentPort.postMessage({ type: "finding", i, outcome, detail, input });
  }
  parentPort.postMessage({ type: "done", counts });
}

async function runTarget(target, { iters, seed, outDir }) {
  const report = { target, iters, seed, counts: { rejected: 0, parsed: 0, accepted: 0, unchecked: 0, hang: 0 }, findings: [], uniqueUnchecked: {} };
  const findingsDir = path.join(outDir, "findings", target);
  const save = (kind, i, input, detail) => {
    fs.mkdirSync(findingsDir, { recursive: true });
    const file = path.join(findingsDir, `${kind}-${i}.bin`);
    fs.writeFileSync(file, input);
    report.findings.push({ kind, i, detail, file: path.relative(outDir, file) });
  };
  let start = 0;
  const t0 = Date.now();
  while (start < iters) {
    const result = await new Promise((resolve) => {
      const w = new Worker(new URL(import.meta.url), { workerData: { target, iters, seed, start } });
      let last = null;
      let timer = null;
      const arm = () => {
        clearTimeout(timer);
        timer = setTimeout(() => {
          w.terminate();
          resolve({ hang: last });
        }, WATCHDOG_MS);
      };
      arm();
      w.on("message", (m) => {
        if (m.type === "begin") {
          last = m;
          arm();
        } else if (m.type === "finding") {
          const key = m.detail?.replace(/\d+/g, "N") || m.outcome;
          if (m.outcome === "unchecked") {
            report.uniqueUnchecked[key] = (report.uniqueUnchecked[key] || 0) + 1;
            if (report.uniqueUnchecked[key] <= 3) save("unchecked", m.i, Buffer.from(m.input), m.detail);
          } else {
            save("accepted", m.i, Buffer.from(m.input), m.detail);
          }
        } else if (m.type === "done") {
          clearTimeout(timer);
          resolve(m.error ? { error: new Error(`${target} worker failed: ${m.error}`) } : { done: m.counts });
        }
      });
      w.on("error", (err) => {
        clearTimeout(timer);
        resolve({ error: err });
      });
    });
    if (result.done) {
      for (const [k, v] of Object.entries(result.done)) report.counts[k] += v;
      break;
    }
    if (result.hang) {
      report.counts.hang += 1;
      save("hang", result.hang.i, Buffer.from(result.hang.input), `no answer within ${WATCHDOG_MS} ms`);
      start = result.hang.i + 1;
      continue;
    }
    throw result.error;
  }
  report.seconds = Math.round((Date.now() - t0) / 1000);
  return report;
}

async function main() {
  const args = process.argv.slice(2);
  const opt = (name, dflt) => (args.includes(name) ? args[args.indexOf(name) + 1] : dflt);
  const targets = opt("--targets", "eventlog,attest,tpmt,x509,dpop,quote").split(",");
  const iters = Number(opt("--iters", "100000"));
  const seed = Number(opt("--seed", "1"));
  const outDir = path.resolve(opt("--out", "results/fuzz"));
  fs.mkdirSync(outDir, { recursive: true });
  const summary = { at: new Date().toISOString(), node: process.version, iters, seed, targets: [] };
  for (const target of targets) {
    const r = await runTarget(target, { iters, seed, outDir });
    summary.targets.push(r);
    const c = r.counts;
    console.log(
      `${target.padEnd(9)} ${String(iters).padStart(8)} inputs in ${String(r.seconds).padStart(5)} s | rejected ${c.rejected} parsed ${c.parsed} | ` +
        `FALSE ACCEPT ${c.accepted} | unchecked ${c.unchecked} (${Object.keys(r.uniqueUnchecked).length} kinds) | hang ${c.hang}`
    );
    for (const [k, n] of Object.entries(r.uniqueUnchecked)) console.log(`    unchecked x${n}: ${k}`);
  }
  fs.writeFileSync(path.join(outDir, "fuzz-report.json"), JSON.stringify(summary, null, 2));
  console.log(`Report: ${path.join(outDir, "fuzz-report.json")}`);
}

if (isMainThread) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
} else {
  workerMain().catch((err) => {
    parentPort.postMessage({ type: "done", counts: {}, error: String(err) });
    throw err;
  });
}
