/**
 * @file scripts/attacks/lib/swtpm-fleet.mjs
 * Real TPM 2.0 devices for the attack harness: one swtpm process (TCG reference code) per
 * device, manufactured with X.509 EK certificates from two local CAs. alice-laptop, bob-laptop
 * and rogue get EK certificates from the trusted lab CA; evil gets one from a foreign CA the
 * verifier does not trust. Manufacturing runs once per cache directory; every trial starts
 * from a fresh copy of the manufactured state, so trials never share TPM state.
 */

import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawn } from "node:child_process";

// Every swtpm this process started and that is still running
const running = new Set();

/**
 * Kills every swtpm this process started that is still running (after a timed-out trial,
 * whose context may never have returned a stop handle).
 * @returns {number} how many were killed
 */
export function killAllSwtpm() {
  let n = 0;
  for (const p of running) {
    p.kill("SIGKILL");
    n++;
  }
  running.clear();
  return n;
}

export const FLEET_DEVICES = Object.freeze({
  "alice-laptop": "lab",
  "bob-laptop": "lab",
  rogue: "lab",
  evil: "foreign",
});

/**
 * True when swtpm and swtpm_setup are on PATH.
 * @returns {boolean}
 */
export function swtpmAvailable() {
  try {
    execFileSync("swtpm", ["--version"], { stdio: "ignore" });
    execFileSync("swtpm_setup", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function writeCaConfig(caDir, name) {
  const statedir = path.join(caDir, name);
  fs.mkdirSync(statedir, { recursive: true });
  const conf = path.join(caDir, `${name}-localca.conf`);
  fs.writeFileSync(
    conf,
    `statedir = ${statedir}\nsigningkey = ${statedir}/signkey.pem\nissuercert = ${statedir}/issuercert.pem\ncertserial = ${statedir}/certserial\n`
  );
  const opts = path.join(caDir, `${name}-localca.options`);
  fs.writeFileSync(opts, `--platform-manufacturer ZTA-Lab\n--platform-version 2.1\n--platform-model swtpm\n`);
  const setup = path.join(caDir, `${name}-setup.conf`);
  fs.writeFileSync(
    setup,
    `create_certs_tool = swtpm_localca\ncreate_certs_tool_config = ${conf}\ncreate_certs_tool_options = ${opts}\nactive_pcr_banks = sha256\n`
  );
  return { statedir, setup };
}

/**
 * Manufactures the fleet once into cacheDir (idempotent).
 * @param {string} [cacheDir]
 * @returns {{ cacheDir: string, labRootPem: string, chains: Record<string, string>, states: Record<string, string> }}
 */
export function prepareSwtpmFleet(cacheDir = path.join(os.tmpdir(), "zta-swtpm-fleet")) {
  const marker = path.join(cacheDir, "manufactured.json");
  if (!fs.existsSync(marker)) {
    fs.rmSync(cacheDir, { recursive: true, force: true });
    const caDir = path.join(cacheDir, "ca");
    const cas = { lab: writeCaConfig(caDir, "lab"), foreign: writeCaConfig(caDir, "foreign") };
    for (const [name, ca] of Object.entries(FLEET_DEVICES)) {
      const state = path.join(cacheDir, "state", name);
      fs.mkdirSync(state, { recursive: true });
      execFileSync(
        "swtpm_setup",
        ["--tpm2", "--tpmstate", state, "--create-ek-cert", "--create-platform-cert", "--pcr-banks", "sha256", "--config", cas[ca].setup],
        { stdio: "ignore" }
      );
    }
    fs.writeFileSync(marker, JSON.stringify({ devices: FLEET_DEVICES, at: new Date().toISOString() }, null, 2));
  }
  const ca = (name) => path.join(cacheDir, "ca", name);
  const chains = {};
  const states = {};
  for (const [name, caName] of Object.entries(FLEET_DEVICES)) {
    chains[name] = fs.readFileSync(path.join(ca(caName), "issuercert.pem"), "utf8");
    states[name] = path.join(cacheDir, "state", name);
  }
  // A directory holding only the lab root, for verifiers in other processes: a roots
  // directory must not contain the intermediate or the CA's signing key
  const trustDir = path.join(cacheDir, "trust");
  fs.mkdirSync(trustDir, { recursive: true });
  fs.copyFileSync(path.join(ca("lab"), "swtpm-localca-rootca-cert.pem"), path.join(trustDir, "lab-root.pem"));
  return {
    cacheDir,
    labRootPem: path.join(ca("lab"), "swtpm-localca-rootca-cert.pem"),
    trustDir,
    chains,
    states,
  };
}

/**
 * Manufactures n extra lab-CA devices "scale-1".."scale-n" (E7), cached like the fleet.
 * @returns {{ trustDir: string, chain: string, states: string[] }}
 */
export function prepareScaleFleet(n, cacheDir = path.join(os.tmpdir(), "zta-swtpm-fleet")) {
  const base = prepareSwtpmFleet(cacheDir);
  const setup = path.join(cacheDir, "ca", "lab-setup.conf");
  const states = [];
  for (let i = 1; i <= n; i++) {
    const state = path.join(cacheDir, "scale", `scale-${i}`);
    if (!fs.existsSync(path.join(state, "tpm2-00.permall"))) {
      fs.mkdirSync(state, { recursive: true });
      execFileSync("swtpm_setup", ["--tpm2", "--tpmstate", state, "--create-ek-cert", "--pcr-banks", "sha256", "--config", setup], { stdio: "ignore" });
    }
    states.push(state);
  }
  return { trustDir: base.trustDir, chain: base.chains["alice-laptop"], states };
}

/** Starts one swtpm per state directory (copied into workDir); returns ports and a stop(). */
export async function startSwtpmSet(states, workDir) {
  const procs = [];
  const ports = [];
  try {
    for (const [i, src] of states.entries()) {
      const state = path.join(workDir, "swtpm-set", String(i));
      fs.mkdirSync(path.dirname(state), { recursive: true });
      fs.cpSync(src, state, { recursive: true });
      const port = await freePort();
      const proc = spawn("swtpm", ["socket", "--tpm2", "--server", `type=tcp,port=${port},bindaddr=127.0.0.1`, "--flags", "not-need-init,startup-clear", "--tpmstate", `dir=${state}`], { stdio: "ignore" });
      procs.push(proc);
      running.add(proc);
      proc.once("exit", () => running.delete(proc));
      await waitForTpm(port);
      ports.push(port);
    }
  } catch (err) {
    for (const p of procs) p.kill("SIGKILL");
    throw err;
  }
  return {
    ports,
    async stop() {
      for (const p of procs) if (p.exitCode === null) p.kill("SIGTERM");
      await Promise.all(procs.map((p) => (p.exitCode === null ? new Promise((r) => p.once("exit", r)) : null)));
    },
  };
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

// TPM2_GetRandom(2): a complete, harmless command. A bare connect-and-close probe can leave
// swtpm spinning on the dead connection, so readiness is checked with a real exchange.
const GET_RANDOM = Buffer.from("80010000000c0000017b0002", "hex");

function probeOnce(port) {
  return new Promise((resolve) => {
    const s = net.connect({ host: "127.0.0.1", port });
    const done = (ok) => {
      s.destroy();
      resolve(ok);
    };
    s.setTimeout(1000, () => done(false));
    s.on("error", () => done(false));
    s.on("connect", () => s.write(GET_RANDOM));
    s.on("data", (d) => done(d.length >= 10 && d.readUInt16BE(0) === 0x8001));
  });
}

async function waitForTpm(port, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await probeOnce(port)) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`swtpm on port ${port} did not answer TPM2_GetRandom`);
}

/**
 * Starts one swtpm per device on a fresh copy of its manufactured state.
 * @param {ReturnType<typeof prepareSwtpmFleet>} prepared
 * @param {string} workDir - per-trial directory
 * @returns {Promise<{ devices: Record<string, { port: number, chain: string }>, stop: () => Promise<void> }>}
 */
export async function startSwtpmFleet(prepared, workDir) {
  const procs = [];
  const devices = {};
  try {
    for (const name of Object.keys(FLEET_DEVICES)) {
      const state = path.join(workDir, "swtpm", name);
      fs.mkdirSync(path.dirname(state), { recursive: true });
      fs.cpSync(prepared.states[name], state, { recursive: true });
      const port = await freePort();
      const proc = spawn(
        "swtpm",
        ["socket", "--tpm2", "--server", `type=tcp,port=${port},bindaddr=127.0.0.1`, "--flags", "not-need-init,startup-clear", "--tpmstate", `dir=${state}`],
        { stdio: "ignore" }
      );
      procs.push(proc);
      running.add(proc);
      proc.once("exit", () => running.delete(proc));
      await waitForTpm(port);
      devices[name] = { port, chain: prepared.chains[name] };
    }
  } catch (err) {
    for (const p of procs) p.kill("SIGKILL");
    throw err;
  }
  return {
    devices,
    async stop() {
      await Promise.all(
        procs.map((p) => {
          if (p.exitCode !== null || p.signalCode !== null) return null;
          return new Promise((resolve) => {
            const kill = setTimeout(() => p.kill("SIGKILL"), 2000);
            p.once("exit", () => {
              clearTimeout(kill);
              resolve();
            });
            p.kill("SIGTERM");
          });
        })
      );
    },
  };
}
