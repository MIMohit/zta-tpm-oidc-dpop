#!/usr/bin/env node
/**
 * @file scripts/stack.mjs
 * Runs the server stack as separate processes (PIP, PDP, verifier, registry, resource
 * server, PEP, IdP gate) for one ablation configuration, on a fresh data directory, and
 * waits until every service reports that configuration on /health. Used by the live attack
 * runs (one fresh stack per trial) and for benchmarks.
 *
 * Usage:
 *   node scripts/stack.mjs up --config full|-M5|B2 [--idp keycloak|local] [--host IP]
 *                             [--data DIR] [--targets testbed/attack-targets.json]
 *   (up keeps running until Ctrl+C, then stops the stack)
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { execFileSync, spawn } from "node:child_process";

import { isMain } from "../lib/main.js";

const REPO = path.resolve(import.meta.dirname, "..");

export const SERVICES = [
  { name: "pip", script: "pip.js", port: 4003 },
  { name: "pdp", script: "pdp.js", port: 4002 },
  { name: "verifier", script: "services/attestation-service.js", port: 4005 },
  { name: "registry", script: "services/device-registry.js", port: 4004 },
  { name: "resource", script: "services/resource-server.js", port: 5001, internal: true },
  { name: "pep", script: "pep.js", port: 4001 },
  { name: "idp", script: "server.js", port: 5173 },
];

/** The address every client uses for the stack (VMs, the host, the load/attack host). */
export function defaultPublicHost() {
  if (process.env.ZTA_PUBLIC_HOST) return process.env.ZTA_PUBLIC_HOST;
  for (const addrs of Object.values(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family === "IPv4" && !a.internal) return a.address;
    }
  }
  return "127.0.0.1";
}

// Protocol time parameters (lib/config.js defaults, seconds). Live attack runs scale them down
// so time-dependent attacks (e.g. replay after the nonce window) run in seconds, not minutes.
const TIME_PARAMS = { ZTA_TAU_AR: 120, ZTA_T_AT: 300, ZTA_T_RA: 300, ZTA_T_NONCE: 60, ZTA_W_JTI: 120, ZTA_SKEW: 30, ZTA_T_SU: 300 };

/** Environment for protocol times scaled by `scale` (1 = defaults). */
export function timeEnv(scale = 1) {
  if (scale === 1) return {};
  return Object.fromEntries(Object.entries(TIME_PARAMS).map(([k, v]) => [k, String(Math.max(1, Math.round(v * scale)))]));
}

const PKCS11_LIBS = [
  process.env.ZTA_PKCS11_LIB,
  "/usr/lib/softhsm/libsofthsm2.so",
  "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
  "/opt/homebrew/lib/softhsm/libsofthsm2.so",
  "/usr/local/lib/softhsm/libsofthsm2.so",
].filter(Boolean);

/** The SoftHSM PKCS#11 module, or null when SoftHSM is not installed. */
export function findPkcs11Lib() {
  return PKCS11_LIBS.find((p) => fs.existsSync(p)) || null;
}

/** A fresh SoftHSM token for one stack: { env, hsm } for the services and the harness. */
function createHsmToken(dir) {
  const lib = findPkcs11Lib();
  if (!lib) throw new Error("hsm requested but SoftHSM is not installed (libsofthsm2.so not found)");
  const tokens = path.join(dir, "softhsm", "tokens");
  fs.mkdirSync(tokens, { recursive: true });
  const conf = path.join(dir, "softhsm", "softhsm2.conf");
  fs.writeFileSync(conf, `directories.tokendir = ${tokens}\nobjectstore.backend = file\n`);
  const pin = crypto.randomBytes(8).toString("hex");
  execFileSync("softhsm2-util", ["--init-token", "--free", "--label", "zta", "--pin", pin, "--so-pin", crypto.randomBytes(8).toString("hex")], {
    env: { ...process.env, SOFTHSM2_CONF: conf },
    stdio: "ignore",
  });
  const env = { SOFTHSM2_CONF: conf, ZTA_HSM: "pkcs11", ZTA_PKCS11_LIB: lib, ZTA_PKCS11_TOKEN: "zta", ZTA_PKCS11_PIN: pin };
  return { env, hsm: env };
}

/** ZTA_ABLATE / ZTA_BASELINE for a configuration label ("full", "-M5", "B2"). */
export function ablationEnv(config) {
  if (!config || config === "full") return {};
  if (/^B\d+$/.test(config)) return { ZTA_BASELINE: config };
  return { ZTA_ABLATE: config };
}

/** IDP_MODE=keycloak settings from testbed/keycloak.sh (client secret stays in testbed/state). */
/**
 * TLS material of the testbed (testbed/tls.sh), created on first use. Every client process that
 * talks to a TLS stack, the harness included, must trust the testbed CA through
 * NODE_EXTRA_CA_CERTS, which Node reads only at start-up, so it cannot be set here.
 * @param {string} host - public host the certificate must cover
 */
export function testbedTls(host) {
  const dir = process.env.ZTA_TLS_DIR || path.join(REPO, "testbed", "state", "tls");
  const files = { ca: path.join(dir, "ca.pem"), cert: path.join(dir, "server.pem"), key: path.join(dir, "server.key") };
  if (!fs.existsSync(files.cert) || !fs.existsSync(files.key)) {
    execFileSync(path.join(REPO, "testbed", "tls.sh"), [], { env: { ...process.env, ZTA_PUBLIC_HOST: host }, stdio: "ignore" });
  }
  if (path.resolve(process.env.NODE_EXTRA_CA_CERTS || "") !== path.resolve(files.ca)) {
    throw new Error(`TLS stack: start this process with NODE_EXTRA_CA_CERTS=${files.ca} so it trusts the testbed CA`);
  }
  return files;
}

function keycloakEnv(tls) {
  const out = execFileSync(path.join(REPO, "testbed/keycloak.sh"), ["env"], { encoding: "utf8", env: { ...process.env, ZTA_TLS: tls ? "1" : "0" } });
  return Object.fromEntries(
    out
      .split("\n")
      .filter((l) => l.includes("="))
      .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)])
  );
}

function copyCerts(srcDir, destDir, pattern = /\.(pem|der|crt|cer)$/) {
  if (!srcDir || !fs.existsSync(srcDir)) return 0;
  fs.mkdirSync(destDir, { recursive: true });
  let n = 0;
  for (const f of fs.readdirSync(srcDir)) {
    if (pattern.test(f) && fs.statSync(path.join(srcDir, f)).isFile()) {
      fs.copyFileSync(path.join(srcDir, f), path.join(destDir, `${path.basename(srcDir)}-${f}`));
      n++;
    }
  }
  return n;
}

async function waitHealthy(url, label, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let last = "no answer";
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(1000) });
      if (res.ok) {
        const body = await res.json().catch(() => ({}));
        if (body?.ablation?.label === label) return;
        last = `label ${body?.ablation?.label}`;
      } else {
        last = `HTTP ${res.status}`;
      }
    } catch (err) {
      last = err.message;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`${url} not healthy for ${label}: ${last}`);
}

/**
 * Starts the stack for one configuration.
 *
 * @param {Object} opts
 * @param {string} [opts.config="full"]
 * @param {"keycloak"|"local"} [opts.idp="keycloak"]
 * @param {string} [opts.host] - public host for issuer and service URLs
 * @param {string} [opts.dataDir] - fresh directory (created; removed by stop() if we created it)
 * @param {string[]} [opts.ekRootDirs] - EK trust anchors (roots only)
 * @param {string[]} [opts.ekIntermediateDirs]
 * @param {string} [opts.rvProfiles] - VERIFIER_RV_PROFILES (name=path,...)
 * @param {number} [opts.timeScale=1] - scale for protocol time parameters (see timeEnv)
 * @param {boolean|"auto"} [opts.hsm="auto"] - signing keys in a SoftHSM token (auto: when installed)
 * @param {string} [opts.cpus] - pin the services to these CPUs (taskset list, e.g. "0-5"; Linux only)
 * @param {boolean} [opts.tls] - HTTPS on every service (default: ZTA_TLS=1); see testbedTls
 * @param {Record<string,string>} [opts.env] - extra environment
 * @returns {Promise<{ targets: Object, dataDir: string, stop: () => Promise<void> }>}
 */
export async function startLiveStack({
  config = "full",
  idp = "keycloak",
  host = defaultPublicHost(),
  dataDir,
  ekRootDirs = [],
  ekIntermediateDirs = [],
  rvProfiles = `ubuntu-grub=${path.join(REPO, "fixtures/rv/ubuntu-noble-grub.json")}`,
  timeScale = 1,
  hsm = "auto",
  cpus,
  tls = process.env.ZTA_TLS === "1",
  env = {},
} = {}) {
  const ownDir = !dataDir;
  const dir = dataDir || fs.mkdtempSync(path.join(os.tmpdir(), "zta-stack-"));
  fs.mkdirSync(path.join(dir, "logs"), { recursive: true });

  const secrets = {
    ZTA_INTERNAL_TOKEN: crypto.randomBytes(32).toString("hex"),
    ADMIN_TOKEN: crypto.randomBytes(32).toString("hex"),
    SESSION_SECRET: crypto.randomBytes(32).toString("hex"),
  };
  fs.writeFileSync(path.join(dir, "secrets.json"), JSON.stringify(secrets, null, 2), { mode: 0o600 });

  const rootsDir = path.join(dir, "ek-roots");
  const intDir = path.join(dir, "ek-intermediates");
  fs.mkdirSync(rootsDir, { recursive: true });
  fs.mkdirSync(intDir, { recursive: true });
  for (const d of ekRootDirs) copyCerts(d, rootsDir);
  for (const d of ekIntermediateDirs) copyCerts(d, intDir);

  const useHsm = hsm === "auto" ? Boolean(findPkcs11Lib()) : Boolean(hsm);
  const hsmToken = useHsm ? createHsmToken(dir) : null;

  const tlsFiles = tls ? testbedTls(host) : null;
  const scheme = tls ? "https" : "http";
  const url = (port) => `${scheme}://${host}:${port}`;
  const resourceUrl = `${scheme}://127.0.0.1:5001`;
  const baseEnv = {
    ...process.env,
    ZTA_DATA_DIR: dir,
    STORE: "file",
    IDP_ISSUER: url(5173),
    VERIFIER_URL: url(4005),
    PIP_URL: url(4003),
    PDP_URL: url(4002),
    PEP_PUBLIC_URL: url(4001),
    RESOURCE_URL: resourceUrl,
    ...(tlsFiles ? { ZTA_TLS_CERT: tlsFiles.cert, ZTA_TLS_KEY: tlsFiles.key, NODE_EXTRA_CA_CERTS: tlsFiles.ca } : {}),
    EK_ROOTS_DIR: rootsDir,
    EK_INTERMEDIATES_DIR: intDir,
    VERIFIER_RV_PROFILES: rvProfiles,
    ZTA_SIM_IP_HEADER: "1", // evaluation only: lets the harness set the login IP (risk input)
    // The testbed agents' callbacks (dev-good .. dev-hw), registered for the agent client. The agent's
    // redirect listener runs on the device itself (RFC 8252 loopback redirect), so it stays HTTP.
    AGENT_REDIRECT_URIS: [7101, 7102, 7103, 7104, 7105].map((p) => `http://${host}:${p}/callback`).join(","),
    IDP_MODE: idp,
    ...(idp === "keycloak" ? keycloakEnv(tls) : {}),
    ...ablationEnv(config),
    ...timeEnv(timeScale),
    ...(hsmToken ? hsmToken.env : {}),
    ...env,
  };
  delete baseEnv.ZTA_ABLATE_CNF;
  delete baseEnv.ZTA_ABLATE_NONCE;
  if (!ablationEnv(config).ZTA_ABLATE) delete baseEnv.ZTA_ABLATE;
  if (!ablationEnv(config).ZTA_BASELINE) delete baseEnv.ZTA_BASELINE;

  const procs = [];
  const stop = async () => {
    await Promise.all(
      procs.map(
        (p) =>
          p.exitCode === null &&
          p.signalCode === null &&
          new Promise((resolve) => {
            const kill = setTimeout(() => p.kill("SIGKILL"), 3000);
            p.once("exit", () => {
              clearTimeout(kill);
              resolve();
            });
            p.kill("SIGTERM");
          })
      )
    );
    if (ownDir) fs.rmSync(dir, { recursive: true, force: true });
  };

  try {
    for (const svc of SERVICES) {
      const log = fs.openSync(path.join(dir, "logs", `${svc.name}.log`), "a");
      const [cmd, args] =
        cpus && process.platform === "linux"
          ? ["taskset", ["-c", cpus, process.execPath, path.join(REPO, svc.script)]]
          : [process.execPath, [path.join(REPO, svc.script)]];
      const p = spawn(cmd, args, {
        cwd: REPO,
        env: { ...baseEnv, PORT: String(svc.port) },
        stdio: ["ignore", log, log],
      });
      fs.closeSync(log);
      procs.push(p);
    }
    const label = config;
    await Promise.all(
      SERVICES.filter((s) => !s.internal && s.name !== "pip" && s.name !== "pdp").map((s) =>
        waitHealthy(`${scheme}://127.0.0.1:${s.port}/health`, label, 20000)
      )
    );
  } catch (err) {
    await stop();
    throw err;
  }

  const targets = {
    pepUrl: url(4001),
    idpUrl: url(5173),
    verifierUrl: url(4005),
    registryUrl: url(4004),
    resourceUrl,
    tls: tlsFiles ? { ca: tlsFiles.ca } : null,
    adminToken: secrets.ADMIN_TOKEN,
    ztaInternalToken: secrets.ZTA_INTERNAL_TOKEN,
    idpMode: idp,
    config,
    timeScale,
    cpus: cpus || null,
    hsm: hsmToken ? hsmToken.hsm : null,
    dataDir: dir,
  };
  const pids = Object.fromEntries(SERVICES.map((svc, i) => [svc.name, procs[i]?.pid]));
  return { targets, dataDir: dir, pids, stop };
}

function parseArgs(argv) {
  const o = { cmd: argv[0] };
  for (let i = 1; i < argv.length; i++) {
    const k = argv[i];
    if (k === "--config") o.config = argv[++i];
    else if (k === "--idp") o.idp = argv[++i];
    else if (k === "--host") o.host = argv[++i];
    else if (k === "--data") o.dataDir = argv[++i];
    else if (k === "--targets") o.targetsFile = argv[++i];
    else throw new Error(`Unknown argument: ${k}`);
  }
  return o;
}

if (isMain(import.meta.url)) {
  const o = parseArgs(process.argv.slice(2));
  if (o.cmd !== "up") {
    console.error("Usage: node scripts/stack.mjs up --config <label> [--idp keycloak|local] [--host IP] [--data DIR] [--targets FILE]");
    process.exit(2);
  }
  const stack = await startLiveStack({
    config: o.config,
    idp: o.idp,
    host: o.host,
    dataDir: o.dataDir,
    ekRootDirs: (process.env.ZTA_EK_ROOT_DIRS || "").split(",").filter(Boolean),
    ekIntermediateDirs: (process.env.ZTA_EK_INTERMEDIATE_DIRS || "").split(",").filter(Boolean),
  });
  const targetsFile = o.targetsFile || path.join(REPO, "testbed/attack-targets.json");
  fs.writeFileSync(targetsFile, JSON.stringify(stack.targets, null, 2), { mode: 0o600 });
  console.log(`Stack up (${o.config || "full"}, ${o.idp || "keycloak"}); targets: ${targetsFile}; data: ${stack.dataDir}`);
  const shutdown = async () => {
    await stack.stop();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
