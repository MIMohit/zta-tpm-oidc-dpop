#!/usr/bin/env node
/**
 * @file bench/load.mjs
 * E4: PEP behaviour under open-loop load (constant arrival rate), Full configuration, on a
 * live stack (Keycloak, HSM when installed) pinned to --stack-cpus; run this process pinned
 * to other cores (taskset).
 *
 * Method. A real swtpm device enrols, logs in through the IdP and re-attests every 5 minutes.
 * Its access token is the template for K load clients: each gets a token with the same
 * claims, bound (cnf.jkt) to its own software key and signed by the IdP's key (HSM or file),
 * so client-side signing is not the bottleneck. The PEP's verification path is unchanged:
 * token signature and claims, DPoP proof (nonce, jti, htm/htu/ath), PDP decision with
 * per-request device state from the PIP, then the resource server.
 * Latency is measured from each request's scheduled send time (no coordinated omission).
 *
 * Usage: taskset -c 6,7 node bench/load.mjs [--rates 50,100,200,400,800] [--duration 60]
 *        [--warmup 10] [--runs 5] [--clients 64] [--stack-cpus 0-5] [--idp keycloak] [--out DIR]
 */

import crypto from "node:crypto";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";
import * as jose from "jose";

const RESOURCE = "/api/company/news";

// ----------------------------------------------------------------------------- worker

async function workerMain() {
  const { pepUrl, clients, rate, durationS, warmupS } = workerData;
  const u = new URL(RESOURCE, pepUrl);
  // HTTPS when the stack runs with TLS; the CA comes from NODE_EXTRA_CA_CERTS (verification stays on)
  const mod = u.protocol === "https:" ? https : http;
  const agent = new mod.Agent({ keepAlive: true, maxSockets: 512 });
  const htu = `${pepUrl.replace(/\/$/, "")}${RESOURCE}`;
  const keys = await Promise.all(
    clients.map(async (c) => ({ ...c, key: await jose.importJWK(c.privateJwk, "ES256"), ath: crypto.createHash("sha256").update(c.token).digest("base64url") }))
  );
  let nonce = null;

  function send(c, extraHeaders = {}) {
    return new Promise((resolve) => {
      const req = mod.request(
        { host: u.hostname, port: u.port, path: u.pathname, method: "GET", agent, headers: { Authorization: `DPoP ${c.token}`, ...extraHeaders } },
        (res) => {
          const n = res.headers["dpop-nonce"];
          if (n) nonce = n;
          res.resume();
          res.on("end", () => resolve(res.statusCode));
        }
      );
      req.on("error", () => resolve(0));
      req.setTimeout(10000, () => {
        req.destroy();
        resolve(0);
      });
      req.end();
    });
  }

  async function proof(c) {
    return new jose.SignJWT({ htm: "GET", htu, jti: crypto.randomUUID(), iat: Math.floor(Date.now() / 1000), ath: c.ath, ...(nonce ? { nonce } : {}) })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: c.publicJwk })
      .sign(c.key);
  }

  // Obtain the server nonce
  await send(keys[0], { DPoP: await proof(keys[0]) });
  const nonceTimer = setInterval(async () => send(keys[0], { DPoP: await proof(keys[0]) }), 50000);

  const lat = [];
  let sent = 0;
  let ok = 0;
  let errors = 0;
  const statuses = {};
  const t0 = performance.now();
  const total = Math.floor(rate * (durationS + warmupS));
  const inflight = new Set();
  for (let k = 0; k < total; k++) {
    const due = t0 + (k * 1000) / rate;
    const wait = due - performance.now();
    if (wait > 1) await new Promise((r) => setTimeout(r, wait));
    const c = keys[k % keys.length];
    const p = (async () => {
      const dpop = await proof(c);
      const status = await send(c, { DPoP: dpop });
      const done = performance.now();
      if ((due - t0) / 1000 >= warmupS) {
        sent++;
        statuses[status] = (statuses[status] || 0) + 1;
        if (status === 200) {
          ok++;
          lat.push(done - due);
        } else {
          errors++;
        }
      }
    })();
    inflight.add(p);
    p.finally(() => inflight.delete(p));
  }
  await Promise.all(inflight);
  clearInterval(nonceTimer);
  agent.destroy();
  parentPort.postMessage({ sent, ok, errors, statuses, lat, elapsedS: (performance.now() - t0) / 1000 - warmupS });
}

// ----------------------------------------------------------------------------- main

function percentile(sorted, q) {
  if (!sorted.length) return NaN;
  const i = (sorted.length - 1) * q;
  const lo = Math.floor(i);
  return sorted[lo] + (sorted[Math.ceil(i)] - sorted[lo]) * (i - lo);
}

async function mintTokens({ template, header, count, targets }) {
  const { loadOrCreateSigningKey, signJwt } = await import("../lib/keys.js");
  let fileKey = null;
  const out = [];
  for (let i = 0; i < count; i++) {
    const { privateKey, publicKey } = await jose.generateKeyPair("ES256", { extractable: true });
    const publicJwk = await jose.exportJWK(publicKey);
    const privateJwk = await jose.exportJWK(privateKey);
    const jkt = await jose.calculateJwkThumbprint(publicJwk, "sha256");
    const now = Math.floor(Date.now() / 1000);
    const payload = { ...template, cnf: { jkt }, jti: crypto.randomUUID(), iat: now, exp: now + 4 * 3600 };
    let token;
    if (targets.hsm) {
      token = execFileSync(process.execPath, [path.resolve("scripts/hsm-sign.mjs")], {
        input: JSON.stringify({ key: "idp", header, payload }),
        env: { ...process.env, ...targets.hsm },
        encoding: "utf8",
      }).trim();
    } else {
      fileKey ??= await loadOrCreateSigningKey("idp", { dataDir: targets.dataDir, store: "file" });
      token = await signJwt(fileKey, { ...header, kid: fileKey.kid }, payload);
    }
    out.push({ token, publicJwk, privateJwk });
  }
  return out;
}

async function main(argv = process.argv.slice(2)) {
  const { arg, environment, writeJson, writeCsv } = await import("./lib.mjs");
  const { startLiveStack } = await import("../scripts/stack.mjs");
  const { createContext } = await import("../scripts/attacks/lib/context.mjs");
  const { prepareSwtpmFleet } = await import("../scripts/attacks/lib/swtpm-fleet.mjs");

  const rates = arg(argv, "--rates", "50,100,200,400,800").split(",").map(Number);
  const durationS = Number(arg(argv, "--duration", "60"));
  const warmupS = Number(arg(argv, "--warmup", "10"));
  const runs = Number(arg(argv, "--runs", "5"));
  const nClients = Number(arg(argv, "--clients", "64"));
  const workers = Number(arg(argv, "--workers", "2"));
  const stackCpus = arg(argv, "--stack-cpus", "0-5");
  const idp = arg(argv, "--idp", "keycloak");
  const outDir = path.resolve(arg(argv, "--out", "results/bench"));

  const prepared = prepareSwtpmFleet(process.env.ZTA_SWTPM_FLEET_DIR || undefined);
  const stack = await startLiveStack({ config: "full", idp, cpus: stackCpus, ekRootDirs: [prepared.trustDir], timeScale: 1 });
  let ctx;
  const rows = [];
  try {
    ctx = await createContext({ mode: "live", targets: stack.targets, tpm: "swtpm", config: "full" });
    const device = ctx.clients.alice;
    await device.enrol(ctx.codes["alice-laptop"]);
    await ctx.loginWithDevice(device, { username: "alice", password: ctx.passwords.alice });
    const reattest = setInterval(() => device.attest().catch((e) => console.error("re-attestation failed:", e.message)), 300000);

    const { payload: template, protectedHeader: header } = { payload: jose.decodeJwt(device.accessToken), protectedHeader: jose.decodeProtectedHeader(device.accessToken) };
    const clients = await mintTokens({ template, header: { alg: header.alg, typ: header.typ }, count: nClients, targets: stack.targets });
    console.log(`E4: ${nClients} clients, rates ${rates.join(",")} req/s, ${durationS}s (+${warmupS}s warm-up) x ${runs} runs, stack on CPUs ${stackCpus}`);

    for (let run = 1; run <= runs; run++) {
      for (const rate of rates) {
        const per = Math.ceil(clients.length / workers);
        const results = await Promise.all(
          Array.from({ length: workers }, (_, w) =>
            new Promise((resolve, reject) => {
              const wk = new Worker(new URL(import.meta.url), {
                workerData: { pepUrl: stack.targets.pepUrl, clients: clients.slice(w * per, (w + 1) * per), rate: rate / workers, durationS, warmupS },
              });
              wk.once("message", resolve);
              wk.once("error", reject);
            })
          )
        );
        const lat = results.flatMap((r) => r.lat).sort((a, b) => a - b);
        const sent = results.reduce((a, r) => a + r.sent, 0);
        const ok = results.reduce((a, r) => a + r.ok, 0);
        const statuses = {};
        for (const r of results) for (const [k, v] of Object.entries(r.statuses)) statuses[k] = (statuses[k] || 0) + v;
        const row = {
          run,
          offered: rate,
          achieved: ok / durationS,
          sent,
          errorRate: sent ? (sent - ok) / sent : 0,
          p50: percentile(lat, 0.5),
          p95: percentile(lat, 0.95),
          p99: percentile(lat, 0.99),
          statuses: JSON.stringify(statuses),
        };
        rows.push(row);
        console.log(
          `run ${run} rate ${String(rate).padStart(5)}: achieved ${row.achieved.toFixed(0).padStart(5)}/s  p50 ${row.p50.toFixed(1)} p95 ${row.p95.toFixed(1)} p99 ${row.p99.toFixed(1)} ms  errors ${(100 * row.errorRate).toFixed(2)}% ${row.statuses}`
        );
      }
    }
    clearInterval(reattest);
  } finally {
    if (ctx) await ctx.cleanup().catch(() => {});
    await stack.stop();
  }
  writeJson(path.join(outDir, "e4-load.json"), { experiment: "E4", idp, nClients, workers, durationS, warmupS, runs, stackCpus, hsm: Boolean(stack.targets.hsm), env: environment(), rows });
  writeCsv(path.join(outDir, "e4-load.csv"), rows);
}

if (isMainThread) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
} else {
  workerMain().catch((err) => {
    throw err;
  });
}
