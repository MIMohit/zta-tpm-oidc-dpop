#!/usr/bin/env node
/**
 * @file scripts/fleet-check.mjs
 * End-to-end check of the KVM fleet against a fresh live stack (Keycloak, HSM): each VM's
 * agent enrols with evidence from its own TPM over its real UEFI measured boot, then the
 * user logs in through Keycloak (this script plays the browser) and the agent requests a
 * protected resource with TPM-signed DPoP proofs.
 *
 * Expected: dev-good enrols, logs in and gets the resource; dev-tampered (another kernel,
 * measured into PCR8/9 by GRUB) fails appraisal; dev-rogue (not in inventory) and dev-foreign
 * (EK certificate from an untrusted CA) are refused at enrolment.
 *
 * With --profile pcr0-7 the verifier uses the same golden events but only PCR0..7 (the
 * original design): dev-tampered is then expected to get access, which is pitfall P-2.
 *
 * --with-hw adds dev-hw: the agent on this host's hardware TPM (AMD fTPM, AMD EK chain,
 * persistent SRK), appraised against a profile captured from this host's current boot log
 * (Limine + systemd-stub UKI: PCR0..9 and 12; PCR11 is excluded because systemd extends it
 * at runtime outside the firmware event log).
 *
 * Usage: node scripts/fleet-check.mjs [--out results/fleet-check] [--config full] [--profile grub|pcr0-7] [--with-hw]
 */

import fs from "node:fs";
import { execFileSync, spawn } from "node:child_process";
import path from "node:path";
import process from "node:process";

import { isMain } from "../lib/main.js";
import { startLiveStack, defaultPublicHost } from "./stack.mjs";
import { keycloakBrowserLogin } from "./attacks/lib/keycloak-login.mjs";

const REPO = path.resolve(import.meta.dirname, "..");
const TESTBED = path.join(REPO, "testbed");

const DEVICES = [
  { dev: "dev-good", user: "alice", inventory: true, expect: "access" },
  { dev: "dev-tampered", user: "alice", inventory: true, expect: "enrol_refused" },
  { dev: "dev-rogue", user: "alice", inventory: false, expect: "enrol_refused" },
  { dev: "dev-foreign", user: "bob", inventory: true, expect: "enrol_refused" },
];
const PASSWORDS = { alice: process.env.ZTA_ALICE_PASSWORD || "alice-pass", bob: process.env.ZTA_BOB_PASSWORD || "bob-pass" };

function agentPort(dev) {
  const env = fs.readFileSync(path.join(TESTBED, "config.env"), "utf8");
  const m = env.match(new RegExp(`^PORT_AGENT_${dev.replace(/-/g, "_")}=(\\d+)`, "m"));
  if (!m) throw new Error(`No agent port for ${dev}`);
  return Number(m[1]);
}

/** Root-only and intermediate-only trust directories for the testbed's lab CA. */
function trustDirs() {
  const base = path.join(TESTBED, "state", "trust");
  const roots = path.join(base, "roots");
  const ints = path.join(base, "intermediates");
  fs.mkdirSync(roots, { recursive: true });
  fs.mkdirSync(ints, { recursive: true });
  fs.copyFileSync(path.join(TESTBED, "ca", "good", "root.pem"), path.join(roots, "lab-root.pem"));
  fs.copyFileSync(path.join(TESTBED, "ca", "good", "issuer.pem"), path.join(ints, "lab-issuer.pem"));
  return { roots, ints };
}

async function json(res) {
  return res.json().catch(() => ({}));
}

async function checkDevice(d, { targets, inventoryCodes }) {
  const agent = `http://127.0.0.1:${agentPort(d.dev)}`;
  const out = { dev: d.dev, user: d.user, expect: d.expect, steps: {} };

  const enrolRes = await fetch(`${agent}/agent/enrol`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code: inventoryCodes[d.dev] || "not-in-inventory" }),
  });
  const enrol = await json(enrolRes);
  out.steps.enrol = { status: enrolRes.status, ...(enrolRes.ok ? { devId: enrol.devId, jkt: enrol.jkt } : { error: enrol.message || enrol.error }) };
  if (!enrolRes.ok) {
    out.outcome = "enrol_refused";
    return out;
  }

  const startRes = await fetch(`${agent}/agent/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  const start = await json(startRes);
  if (!startRes.ok) {
    out.steps.login = { status: startRes.status, error: start.message || start.error };
    out.outcome = "login_refused";
    return out;
  }
  const kc = await keycloakBrowserLogin({ authorizeUrl: start.authorizeUrl, username: d.user, password: PASSWORDS[d.user] });
  out.steps.login = { status: kc.status, ...(kc.data.error ? { error: kc.data.error_description || kc.data.error } : {}) };
  if (!kc.data.redirect || kc.status >= 400) {
    out.outcome = "login_refused";
    return out;
  }
  const cb = await fetch(kc.data.redirect, { redirect: "manual" });
  out.steps.callback = { status: cb.status };
  if (cb.status >= 400) {
    out.outcome = "login_refused";
    return out;
  }

  const resRes = await fetch(`${agent}/agent/resource/company/news`);
  out.steps.resource = { status: resRes.status };
  out.outcome = resRes.ok ? "access" : "access_denied";
  return out;
}

/** dev-hw: AMD trust anchors, the EK's devId, and a reference profile from this boot's log. */
function prepareHw() {
  const data = path.join(REPO, "data");
  const amdRoots = path.join(data, "ek-roots", "amd");
  const amdInts = path.join(data, "ek-intermediates", "amd");
  const ekCert = path.join(data, "agent", "dev-hw", "ek-rsa.der");
  for (const p of [amdRoots, amdInts, ekCert]) {
    if (!fs.existsSync(p)) throw new Error(`dev-hw needs ${p} (see testbed/dev-hw.md)`);
  }
  const rvFile = path.join(REPO, "results", "fleet-check", "omarchy-uki-ryzen.json");
  fs.mkdirSync(path.dirname(rvFile), { recursive: true });
  execFileSync(process.execPath, [
    path.join(REPO, "scripts", "rv-capture.mjs"),
    "--log", "/sys/kernel/security/tpm0/binary_bios_measurements",
    "--name", "omarchy-uki-ryzen",
    "--pcrs", "0,1,2,3,4,5,6,7,8,9,12",
    "--out", rvFile,
  ], { stdio: "ignore" });
  const probe = execFileSync(process.execPath, [path.join(REPO, "scripts", "hw-devid.mjs")], {
    encoding: "utf8",
    env: { ...process.env, ...hwEnv() },
  })
    .trim()
    .split("\n")
    .at(-1); // RealTpm logs to stdout before the devId line
  return { amdRoots, amdInts, ekCert, rvFile, devId: probe };
}

function hwEnv() {
  return {
    TPM_BACKEND: "tpm",
    TPM_DEVICE: "linux",
    TPM_SRK_HANDLE: "0x81000101",
    TPM_EK_TYPE: "rsa",
    TPM_EK_CERT_FILE: path.join(REPO, "data", "agent", "dev-hw", "ek-rsa.der"),
    TPM_EVENTLOG_PATH: "/sys/kernel/security/tpm0/binary_bios_measurements",
    TPM_STATE_DIR: path.join(REPO, "data", "agent", "dev-hw", "tpm"),
  };
}

function startHwAgent(targets) {
  const env = {
    ...process.env,
    ...hwEnv(),
    AGENT_ID: "dev-hw",
    PORT: "7105",
    HOST: "0.0.0.0",
    AGENT_URL: targets.idpUrl.replace(/:\d+$/, ":7105"),
    IDP_ISSUER: targets.idpUrl,
    VERIFIER_URL: targets.verifierUrl,
    PEP_PUBLIC_URL: targets.pepUrl,
    PIP_URL: targets.idpUrl.replace(/:\d+$/, ":4003"),
    ZTA_DATA_DIR: path.join(REPO, "data", "agent", "dev-hw", "agent-data"),
  };
  const log = fs.openSync(path.join(REPO, "results", "fleet-check", "dev-hw-agent.log"), "w");
  return spawn(process.execPath, [path.join(REPO, "tpm-agent.js")], { cwd: REPO, env, stdio: ["ignore", log, log] });
}

async function waitAgent(port) {
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`http://127.0.0.1:${port}/agent/status`)).ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`agent on ${port} did not start`);
}

export async function main(argv = process.argv.slice(2)) {
  const outDir = path.resolve(argv[argv.indexOf("--out") + 1] && argv.includes("--out") ? argv[argv.indexOf("--out") + 1] : "results/fleet-check");
  const config = argv.includes("--config") ? argv[argv.indexOf("--config") + 1] : "full";
  const profile = argv.includes("--profile") ? argv[argv.indexOf("--profile") + 1] : "grub";
  const rvFile = { grub: "fixtures/rv/ubuntu-noble-grub.json", "pcr0-7": "fixtures/rv/ubuntu-noble-grub-pcr0-7.json" }[profile];
  if (!rvFile) throw new Error(`Unknown --profile ${profile} (grub or pcr0-7)`);
  const expectations = profile === "pcr0-7" ? { "dev-tampered": "access" } : {};
  const withHw = argv.includes("--with-hw");
  const hw = withHw ? prepareHw() : null;
  const trust = trustDirs();

  const stack = await startLiveStack({
    config,
    idp: "keycloak",
    host: defaultPublicHost(),
    ekRootDirs: [trust.roots, ...(hw ? [hw.amdRoots] : [])],
    ekIntermediateDirs: [trust.ints, ...(hw ? [hw.amdInts] : [])],
    rvProfiles: `ubuntu-grub=${path.join(REPO, rvFile)}${hw ? `,omarchy-uki=${hw.rvFile}` : ""}`,
  });
  const { targets } = stack;
  const report = { at: new Date().toISOString(), config, profile, rvFile, stack: { idp: targets.idpMode, hsm: Boolean(targets.hsm), host: targets.idpUrl }, devices: [] };
  try {
    const inventoryCodes = {};
    for (const d of DEVICES.filter((x) => x.inventory)) {
      const devId = fs.readFileSync(path.join(TESTBED, "state", d.dev, "ek", "devid-p384.txt"), "utf8").trim();
      const res = await fetch(`${targets.verifierUrl}/v/inventory`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-ZTA-Internal": targets.ztaInternalToken, Authorization: `Bearer ${targets.adminToken}` },
        body: JSON.stringify({ devId, user: d.user, rvProfile: "ubuntu-grub" }),
      });
      if (!res.ok) throw new Error(`Inventory add failed for ${d.dev}: ${res.status} ${JSON.stringify(await json(res))}`);
      inventoryCodes[d.dev] = (await res.json()).code;
    }
    let hwAgent = null;
    if (hw) {
      hwAgent = startHwAgent(targets);
      const res = await fetch(`${targets.verifierUrl}/v/inventory`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-ZTA-Internal": targets.ztaInternalToken, Authorization: `Bearer ${targets.adminToken}` },
        body: JSON.stringify({ devId: hw.devId, user: "alice", rvProfile: "omarchy-uki" }),
      });
      if (!res.ok) throw new Error(`Inventory add failed for dev-hw: ${res.status}`);
      inventoryCodes["dev-hw"] = (await res.json()).code;
      await waitAgent(7105);
    }
    const devices = hw ? [...DEVICES, { dev: "dev-hw", user: "alice", inventory: true, expect: "access" }] : DEVICES;
    try {
    for (const base of devices) {
      const d = { ...base, expect: expectations[base.dev] || base.expect };
      const r = await checkDevice(d, { targets, inventoryCodes });
      r.pass = r.outcome === d.expect;
      report.devices.push(r);
      console.log(`${r.pass ? "✔" : "✖"} ${d.dev.padEnd(13)} ${r.outcome.padEnd(14)} (expected ${d.expect})  ${JSON.stringify(r.steps)}`);
    }
    } finally {
      if (hwAgent) hwAgent.kill("SIGTERM");
    }
  } finally {
    await stack.stop();
  }
  fs.mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, `fleet-check-${report.at.replace(/[:.]/g, "-")}.json`);
  fs.writeFileSync(file, JSON.stringify(report, null, 2));
  console.log(`Report: ${file}`);
  return report.devices.every((d) => d.pass) ? 0 : 1;
}

if (isMain(import.meta.url)) {
  main().then((code) => process.exit(code), (err) => {
    console.error(`❌ ${err.message}`);
    process.exit(2);
  });
}
