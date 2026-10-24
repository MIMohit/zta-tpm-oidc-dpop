#!/usr/bin/env node
/**
 * @file tpm-sim-ctl.mjs
 * Control and probe tool for IBM tpm_server (MS simulator protocol).
 * Usage:
 *   node scripts/tpm-sim-ctl.mjs probe
 *   node scripts/tpm-sim-ctl.mjs power-cycle
 *   node scripts/tpm-sim-ctl.mjs reset
 *   node scripts/tpm-sim-ctl.mjs power-off
 *   node scripts/tpm-sim-ctl.mjs power-on
 */
import net from "node:net";
import crypto from "node:crypto";
import tss from "tss.js";
import { TcpSimDevice } from "../lib/tpm-real/devices.js";

const { Tpm, TPM_CAP, TPM_PT } = tss;

const HOST = process.env.TPM_TCP_HOST || "127.0.0.1";
const PORT = +(process.env.TPM_TCP_PORT || 2321);
const PLATFORM_PORT = PORT + 1;

// MS simulator platform command codes
const SIGNAL_POWER_ON = 1;
const SIGNAL_POWER_OFF = 2;
const SIGNAL_NV_ON = 11;

function sendPlatformSignal(sig, { host = HOST, port = PLATFORM_PORT, timeoutMs = 3000 } = {}) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host, port }, () => {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(sig >>> 0);
      s.write(b);
    });
    const t = setTimeout(() => {
      s.destroy();
      reject(new Error(`Platform port ${host}:${port} timeout`));
    }, timeoutMs);
    s.once("data", (d) => {
      clearTimeout(t);
      s.end();
      resolve(d.readUInt32BE(0));
    });
    s.on("error", (e) => {
      clearTimeout(t);
      reject(e);
    });
  });
}

/**
 * Connects tss.js through our crash-safe TcpSimDevice (G3: the stock tss.js TCP
 * device throws an unhandled socket error when no TPM is listening). No leaked
 * handle flush here, so a running agent's loaded keys are left alone.
 */
async function connectTpm() {
  const tpm = new Tpm(true);
  tpm.device = new TcpSimDevice({ host: HOST, port: PORT, powerOn: false, timeoutMs: 3000 });
  await new Promise((resolve, reject) => tpm.connect((err) => (err ? reject(err) : resolve())));
  const call = (fn, ...args) =>
    new Promise((resolve, reject) => {
      tpm[fn](...args, (err, res) => (err ? reject(err) : resolve(res)));
    });
  // Startup(CLEAR) after a power-on; TPM_RC_INITIALIZE (already started) is tolerated.
  tpm.allowErrors();
  await call("Startup", tss.TPM_SU.CLEAR).catch(() => {});
  return { tpm, call };
}

async function probe() {
  // Ensure simulator is powered on
  try {
    await sendPlatformSignal(SIGNAL_POWER_ON);
    await sendPlatformSignal(SIGNAL_NV_ON);
  } catch (err) {
    // If platform port is unreachable, tpm.connect below will report
  }

  const { tpm, call } = await connectTpm();

  try {
    // Query TPM_PT_MANUFACTURER
    const cap = await call("GetCapability", TPM_CAP.TPM_PROPERTIES, TPM_PT.MANUFACTURER, 1);
    const mfrProp = cap?.capabilityData?.tpmProperty?.[0];
    const val = mfrProp ? mfrProp.value : 0;
    const hex = val.toString(16).padStart(8, "0");
    const ascii = Buffer.from(hex, "hex").toString("ascii");
    console.log(`[probe] TPM_PT_MANUFACTURER: 0x${hex} ('${ascii.trim()}') [IBM]`);

    // GetRandom
    const rnd = await call("GetRandom", 8);
    const rndHex = Buffer.from(rnd).toString("hex");
    console.log(`[probe] GetRandom(8): ${rndHex}`);
  } finally {
    tpm.close();
  }
}

async function powerCycle() {
  console.log(`[ctl] Sending PowerOff to ${HOST}:${PLATFORM_PORT}...`);
  const offRes = await sendPlatformSignal(SIGNAL_POWER_OFF);
  console.log(`[ctl] PowerOff -> ${offRes}`);

  console.log(`[ctl] Sending PowerOn to ${HOST}:${PLATFORM_PORT}...`);
  const onRes = await sendPlatformSignal(SIGNAL_POWER_ON);
  console.log(`[ctl] PowerOn -> ${onRes}`);

  console.log(`[ctl] Sending NvOn to ${HOST}:${PLATFORM_PORT}...`);
  const nvRes = await sendPlatformSignal(SIGNAL_NV_ON);
  console.log(`[ctl] NvOn -> ${nvRes}`);
  console.log("[ctl] TPM power cycle complete (PCRs reset to 0)");
}

async function powerOn() {
  console.log(`[ctl] Sending PowerOn to ${HOST}:${PLATFORM_PORT}...`);
  const onRes = await sendPlatformSignal(SIGNAL_POWER_ON);
  console.log(`[ctl] PowerOn -> ${onRes}`);
  const nvRes = await sendPlatformSignal(SIGNAL_NV_ON);
  console.log(`[ctl] NvOn -> ${nvRes}`);
}

async function powerOff() {
  console.log(`[ctl] Sending PowerOff to ${HOST}:${PLATFORM_PORT}...`);
  const offRes = await sendPlatformSignal(SIGNAL_POWER_OFF);
  console.log(`[ctl] PowerOff -> ${offRes}`);
}

async function tamper() {
  // First attempt: if agent is running on 127.0.0.1:7000, trigger via debug endpoint
  try {
    const res = await fetch("http://127.0.0.1:7000/agent/debug/tamper", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ desc: "tpm-sim-ctl tamper" }),
    });
    if (res.ok) {
      console.log(`[ctl] Tampered PCR4 via running agent debug endpoint`);
      return;
    }
  } catch {}

  console.log(`[ctl] Connecting to TPM on ${HOST}:${PORT} to tamper PCR4...`);
  const { tpm, call } = await connectTpm();

  try {
    const rogueDigest = crypto.randomBytes(32);
    await call("PCR_Extend", tss.TPM_HANDLE.pcr(4), [new tss.TPMT_HA(tss.TPM_ALG_ID.SHA256, rogueDigest)]);
    console.log(`[ctl] Tampered PCR4 with rogue measurement: ${rogueDigest.toString("hex")}`);
  } finally {
    tpm.close();
  }
}

async function main() {
  const cmd = process.argv[2] || "probe";
  switch (cmd) {
    case "probe":
      await probe();
      break;
    case "power-cycle":
    case "reset":
      await powerCycle();
      break;
    case "power-on":
      await powerOn();
      break;
    case "power-off":
      await powerOff();
      break;
    case "tamper":
      await tamper();
      break;
    default:
      console.error(`Unknown command: ${cmd}`);
      console.error("Usage: node scripts/tpm-sim-ctl.mjs [probe|power-cycle|reset|power-on|power-off|tamper]");
      process.exit(1);
  }
}

main().catch((err) => {
  console.error("[ctl] Error:", err.message || err);
  process.exit(1);
});
