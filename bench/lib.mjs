/**
 * @file bench/lib.mjs
 * Shared helpers for the timing benchmarks: high-resolution timing, summary statistics
 * (median, IQR, p95, p99, bootstrap CI of the median), host environment capture, CSV/JSON.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

/** Milliseconds since an arbitrary origin, sub-microsecond resolution. */
export function nowMs() {
  return Number(process.hrtime.bigint()) / 1e6;
}

/** Times fn() and returns [result, elapsed ms]. */
export async function timed(fn) {
  const t0 = nowMs();
  const r = await fn();
  return [r, nowMs() - t0];
}

function quantile(sorted, q) {
  if (sorted.length === 0) return NaN;
  const i = (sorted.length - 1) * q;
  const lo = Math.floor(i);
  const hi = Math.ceil(i);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (i - lo);
}

/** Deterministic PRNG for the bootstrap, so reported CIs are reproducible. */
function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Summary of a sample of latencies (ms).
 * @param {number[]} xs
 * @param {{ bootstrap?: number, seed?: number }} [opts]
 */
export function summarize(xs, { bootstrap = 2000, seed = 7 } = {}) {
  const s = [...xs].sort((a, b) => a - b);
  const med = quantile(s, 0.5);
  let ci = [NaN, NaN];
  if (s.length >= 5 && bootstrap > 0) {
    const rnd = mulberry32(seed);
    const meds = new Array(bootstrap);
    const buf = new Array(s.length);
    for (let b = 0; b < bootstrap; b++) {
      for (let i = 0; i < s.length; i++) buf[i] = s[Math.floor(rnd() * s.length)];
      buf.sort((a, b2) => a - b2);
      meds[b] = quantile(buf, 0.5);
    }
    meds.sort((a, b) => a - b);
    ci = [quantile(meds, 0.025), quantile(meds, 0.975)];
  }
  return {
    n: s.length,
    median: med,
    q1: quantile(s, 0.25),
    q3: quantile(s, 0.75),
    p95: quantile(s, 0.95),
    p99: quantile(s, 0.99),
    min: s[0],
    max: s[s.length - 1],
    ci95: ci,
  };
}

function sh(cmd, args) {
  try {
    return execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
}

function readFile(p) {
  try {
    return fs.readFileSync(p, "utf8").trim();
  } catch {
    return null;
  }
}

/** Host conditions that must be reported with any timing result. */
export function environment() {
  return {
    at: new Date().toISOString(),
    host: os.hostname(),
    platform: `${os.type()} ${os.release()} ${os.arch()}`,
    cpu: os.cpus()[0]?.model,
    onlineCpus: os.cpus().length,
    memGiB: Math.round(os.totalmem() / 2 ** 30),
    node: process.version,
    loadavg: os.loadavg(),
    smt: readFile("/sys/devices/system/cpu/smt/control"),
    boost: readFile("/sys/devices/system/cpu/cpufreq/boost"),
    governor: readFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
    scalingDriver: readFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver"),
    powerProfile: sh("powerprofilesctl", ["get"]),
    acOnline: readFile("/sys/class/power_supply/AC/online") ?? readFile("/sys/class/power_supply/ACAD/online"),
    swtpm: sh("swtpm", ["--version"]),
    tls: process.env.ZTA_TLS === "1",
  };
}

export function writeJson(file, obj) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(obj, null, 2));
}

/** Writes rows (array of flat objects) as CSV with the keys of the first row. */
export function writeCsv(file, rows) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (rows.length === 0) {
    fs.writeFileSync(file, "");
    return;
  }
  const keys = Object.keys(rows[0]);
  const esc = (v) => (typeof v === "string" && /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
  fs.writeFileSync(file, [keys.join(","), ...rows.map((r) => keys.map((k) => esc(r[k])).join(","))].join("\n") + "\n");
}

export function arg(argv, name, dflt) {
  const i = argv.indexOf(name);
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : dflt;
}
