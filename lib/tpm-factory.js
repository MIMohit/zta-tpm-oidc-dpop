/**
 * @file lib/tpm-factory.js
 * Factory for TPM backends: TPM_BACKEND=sim|tpm|auto|windows-ek.
 *
 * Behaviours:
 *  - sim: Simulated TPM 2.0 (lib/sim-tpm/tpm.js) with vendor CA and persistent state
 *  - windows-ek: Diagnostic Windows EK backend (lib/sim-tpm/windows-ek.js)
 *  - auto: Attempts RealTpm.open(); falls back to SimTpm with a loud banner if unreachable
 *  - tpm: Real TPM 2.0 backend; if unreachable, keeps agent up and returns non-throwing info with reconnect()
 *
 * Never throws because a TPM is missing.
 */

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { loadConfig } from "./config.js";

/** Reads a TPM setting from cfg (camelCase) or the environment. */
function setting(cfg, key, envName, dflt) {
  return cfg[key] ?? process.env[envName] ?? dflt;
}

/**
 * Resolves TPM_DEVICE=auto to the concrete transport (tcp|linux|tbs) so that
 * RealTpm's measured-boot emulation and PCR rules see the device it really talks to.
 */
export function resolveDeviceType(device = "auto") {
  const dev = String(device).toLowerCase();
  if (dev !== "auto") return dev;
  if (process.platform === "win32") return "tbs";
  if (process.platform === "linux" && (fs.existsSync("/dev/tpmrm0") || fs.existsSync("/dev/tpm0"))) return "linux";
  return "tcp";
}

/**
 * Builds RealTpm constructor options from cfg / env (PLAN-TPM.md §2.6).
 * @param {Record<string, any>} cfg
 * @param {string} agentDir
 */
export function realTpmOptions(cfg, agentDir) {
  return {
    agentDir,
    dir: setting(cfg, "tpmStateDir", "TPM_STATE_DIR", null) || path.join(agentDir, "tpm"),
    device: resolveDeviceType(setting(cfg, "tpmDevice", "TPM_DEVICE", "auto")),
    host: setting(cfg, "tpmTcpHost", "TPM_TCP_HOST", "127.0.0.1"),
    port: Number(setting(cfg, "tpmTcpPort", "TPM_TCP_PORT", 2321)),
    ctrlPort: setting(cfg, "tpmSwtpmCtrlPort", "TPM_SWTPM_CTRL_PORT", null)
      ? Number(setting(cfg, "tpmSwtpmCtrlPort", "TPM_SWTPM_CTRL_PORT", null))
      : undefined,
    powerOn: String(setting(cfg, "tpmTcpPowerOn", "TPM_TCP_POWERON", "1")) !== "0",
    timeoutMs: Number(setting(cfg, "tpmConnectTimeoutMs", "TPM_CONNECT_TIMEOUT_MS", 3000)),
    ekType: setting(cfg, "tpmEkType", "TPM_EK_TYPE", "auto"),
    srkHandle: Number(setting(cfg, "tpmSrkHandle", "TPM_SRK_HANDLE", 0x81000001)),
  };
}

async function newRealTpm(cfg, agentDir) {
  const { RealTpm } = await import("./tpm-real/index.js");
  const tpm = new RealTpm(realTpmOptions(cfg, agentDir));
  tpm.kind = "tpm";
  return tpm;
}

function describeFailure(cfg, realTpm, err) {
  const opts = realTpm?.options || {};
  const dev = opts.device || resolveDeviceType(setting(cfg, "tpmDevice", "TPM_DEVICE", "auto"));
  const where = (dev === "tcp" || dev === "swtpm") ? `${dev} ${opts.host || "127.0.0.1"}:${opts.port || 2321}` : dev;
  return `${where}: ${err?.message || err?.code || err}`;
}

/** The loud TPM_BACKEND=auto fallback banner (PLAN-TPM.md §2.6). */
export function fallbackBanner(reason) {
  const bar = "⚠️ ═════════════════════════════════════════════════════════════════";
  return [
    bar,
    `⚠️  TPM_BACKEND=auto: no real TPM reachable (${reason})`,
    "⚠️  FALLING BACK TO THE SIMULATED TPM - device identity is NOT hardware-backed",
    bar,
  ].join("\n");
}

/**
 * Creates and initializes a TPM backend instance based on configuration.
 *
 * @param {Record<string, any>} [cfg] - Configuration object
 * @param {Object} [options] - Additional options
 * @param {string} [options.agentId] - Agent ID (default 'alice-laptop')
 * @param {string} [options.agentDir] - Agent root directory (e.g. data/agent/alice-laptop)
 * @param {string} [options.dataDir] - Data root directory (default ./data)
 * @returns {Promise<{ tpm: any, kind: "sim"|"tpm"|"sim-fallback"|"windows-ek", tpmBackend: string, available: boolean, reason?: string, fallback?: boolean, reconnect?: () => Promise<boolean> }>}
 */
export async function createTpmBackend(cfg = loadConfig(), options = {}) {
  const tpmBackend = String(cfg.tpmBackend || process.env.TPM_BACKEND || "sim").toLowerCase();
  const agentId = options.agentId || process.env.AGENT_ID || cfg.agentId || "alice-laptop";
  const dataDir = path.resolve(options.dataDir || cfg.dataDir || cfg.ZTA_DATA_DIR || "./data");
  const agentDir = options.agentDir || path.join(dataDir, "agent", agentId);

  // Helper to initialize SimTpm
  async function initSimTpm(kind = "sim") {
    const { SimTpm } = await import("./sim-tpm/tpm.js");
    const { createVendorCa, issueEkCert } = await import("./sim-tpm/vendor-ca.js");
    const vendorCaDir = path.join(dataDir, "vendor-ca");

    let caKey = null;
    try {
      caKey = await createVendorCa(vendorCaDir, "sim-vendor", "SimTPM Vendor CA");
    } catch {}

    // Construct WITHOUT dir: SimTpm's constructor boots (golden-boot PCR replay) and every
    // extendPcr() persists, so passing dir here would overwrite an existing tpm.json - and its
    // EK - before it is loaded. Attach the dir afterwards and load the persisted state instead.
    const tpm = new SimTpm({ caKey, clock: cfg.clock });
    tpm.dir = path.resolve(agentDir);
    tpm.kind = kind;
    tpm._loadFromDisk();
    await tpm.init(); // generates and persists an EK only when tpm.json has none

    // If EK cert is missing, issue and persist it using vendor CA
    const ek = await tpm.getEk();
    if (!ek.cert && caKey) {
      const cert = await issueEkCert(caKey, ek.publicArea);
      tpm.setEkCert(cert);
    }

    return tpm;
  }

  // 1. Diagnostic-only Windows EK
  if (tpmBackend === "windows-ek") {
    const { WindowsEkTpm } = await import("./sim-tpm/windows-ek.js");
    const tpm = new WindowsEkTpm();
    tpm.kind = "windows-ek";
    tpm.dir = agentDir;
    return {
      tpm,
      kind: "windows-ek",
      tpmBackend: "windows-ek",
      available: true,
    };
  }

  // 2. Auto mode: probe RealTpm; fall back to SimTpm on failure with loud warning
  if (tpmBackend === "auto") {
    let realTpm = null;
    try {
      realTpm = await newRealTpm(cfg, agentDir);
      await realTpm.open();
      return {
        tpm: realTpm,
        kind: "tpm",
        tpmBackend: "auto",
        device: realTpm.deviceType,
        available: true,
      };
    } catch (err) {
      if (realTpm) await realTpm.close().catch(() => {});
      const reason = describeFailure(cfg, realTpm, err);
      const banner = fallbackBanner(reason);
      console.warn(`\n${banner}\n`);

      const simTpm = await initSimTpm("sim-fallback");
      return {
        tpm: simTpm,
        kind: "sim-fallback",
        tpmBackend: "auto",
        available: true,
        fallback: true,
        reason,
        warning: banner,
      };
    }
  }

  // 3. Explicit Real TPM mode: never throws; the agent stays up and answers 503 until the TPM appears
  if (tpmBackend === "tpm") {
    let realTpm;
    try {
      realTpm = await newRealTpm(cfg, agentDir);
    } catch (err) {
      // e.g. unknown TPM_DEVICE value: report as unavailable rather than crash the agent
      console.warn(`⚠️ [tpm-factory] Cannot create real TPM backend: ${err.message}`);
      return { tpm: null, kind: "tpm", tpmBackend: "tpm", available: false, reason: err.message, reconnect: async () => false };
    }

    const tpmInfo = {
      tpm: realTpm,
      kind: "tpm",
      tpmBackend: "tpm",
      device: realTpm.deviceType,
      available: false,
      reason: null,
      async reconnect() {
        if (this.available) return true;
        try {
          await this.tpm.open();
          this.available = true;
          this.reason = null;
          console.log(`✅ [tpm-factory] Real TPM connected (${this.device})`);
          return true;
        } catch (e) {
          await this.tpm.close().catch(() => {});
          this.available = false;
          this.reason = describeFailure(cfg, this.tpm, e);
          return false;
        }
      },
    };

    try {
      await realTpm.open();
      tpmInfo.available = true;
    } catch (err) {
      await realTpm.close().catch(() => {});
      tpmInfo.available = false;
      tpmInfo.reason = describeFailure(cfg, realTpm, err);
      console.warn(`⚠️ [tpm-factory] TPM_BACKEND=tpm: real TPM unavailable (${tpmInfo.reason}); agent stays up, TPM operations answer 503 tpm_unavailable until it is reachable`);
    }

    return tpmInfo;
  }

  if (tpmBackend !== "sim") {
    console.warn(`⚠️ [tpm-factory] Unknown TPM_BACKEND '${tpmBackend}', using the simulated TPM`);
  }

  // 4. Default: SimTpm (TPM_BACKEND=sim)
  const simTpm = await initSimTpm("sim");
  return {
    tpm: simTpm,
    kind: "sim",
    tpmBackend: "sim",
    available: true,
  };
}

export default { createTpmBackend };
