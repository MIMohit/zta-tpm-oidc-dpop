/**
 * @file measured-boot.js
 * Emulated measured boot for TCP devices and PCR event log management.
 * Replays golden-boot.json into PCR0..7 when a software TPM powers on with all-zero PCRs.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import tss from "tss.js";
import { TpmError } from "./tpm-conn.js";
import { replayEventLog } from "../sim-tpm/attest.js";

const { TPM_HANDLE, TPM_ALG_ID, TPMS_PCR_SELECTION, TPMT_HA } = tss;

const PCR0_7_SELECTION = [new TPMS_PCR_SELECTION(TPM_ALG_ID.SHA256, Buffer.from([0xff, 0x00, 0x00]))];

function loadGoldenBoot(customPath) {
  const p = customPath || path.resolve(import.meta.dirname, "../../fixtures/golden-boot.json");
  if (fs.existsSync(p)) {
    try {
      return JSON.parse(fs.readFileSync(p, "utf8"));
    } catch {
      // Fallback
    }
  }
  return [
    { pcr: 0, desc: "CRTM: Core Root of Trust for Measurement", digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    { pcr: 0, desc: "UEFI: Base Firmware Code", digest: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3" },
    { pcr: 1, desc: "UEFI: Host Platform Configuration", digest: "b5a2c96250612366ea8c2c10df6be08602df3649022e497220c8b7b05ff161ac" },
    { pcr: 2, desc: "UEFI: Option ROM and Device Drivers", digest: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592" },
    { pcr: 3, desc: "UEFI: Option ROM Configuration and Data", digest: "044852b2a6703b057691660ab9ec41300f7457704772048d70f552e8290cb733" },
    { pcr: 4, desc: "UEFI: Bootloader Executable (shim/GRUB)", digest: "7d793037a0760186574b0282f2f435e708170e62ffc672111225f4859a7a49b6" },
    { pcr: 4, desc: "OS: Kernel Image and Initramfs", digest: "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d" },
    { pcr: 5, desc: "GPT: Partition Table and Boot Config", digest: "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a" },
    { pcr: 6, desc: "State: Resume from S4/S5 and Power State", digest: "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c" },
    { pcr: 7, desc: "SecureBoot: Policy (PK, KEK, db, dbx) - SecureBoot=on", digest: "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918" },
  ];
}

// Software TPMs reached directly (no firmware in front of them): the agent emulates
// firmware by replaying the golden boot, and test tampering may extend PCR0-7.
const EMULATED_FIRMWARE_DEVICES = new Set(["tcp", "swtpm"]);

export class MeasuredBootManager {
  /**
   * @param {Object} options
   * @param {Object} options.conn - TpmConn instance
   * @param {string} options.deviceType - "tcp" | "linux" | "tbs"
   * @param {string} [options.goldenBootPath]
   * @param {Array} [options.savedEventLog] - Previously saved event log from disk
   */
  constructor({ conn, deviceType = "tcp", goldenBootPath = null, savedEventLog = null }) {
    this.conn = conn;
    this.deviceType = deviceType;
    this.goldenBootPath = goldenBootPath;
    this.eventLog = Array.isArray(savedEventLog) ? [...savedEventLog] : null;
    this.eventLogPath = null;
    this.eventLogMode = null;
    this.warnedUnavailable = false;
  }

  /**
   * Initializes PCRs and event log.
   */
  async init() {
    if (this.deviceType === "linux") {
      this.eventLogPath = process.env.TPM_EVENTLOG_PATH || "/sys/kernel/security/tpm0/binary_bios_measurements";
      this.eventLogMode = (process.env.TPM_EVENTLOG || "auto").toLowerCase();
      this.eventLog = null;
      return;
    }

    if (!EMULATED_FIRMWARE_DEVICES.has(this.deviceType)) {
      // Hardware TPMs do not emulate measured boot; event log is null
      this.eventLog = null;
      return;
    }

    // Read current PCR0..7 values
    const pr = await this.conn.call("PCR_Read", PCR0_7_SELECTION);
    const pcrs = (pr.pcrValues || []).map((d) => Buffer.from(d.buffer));

    const isAllZero = pcrs.length >= 8 && pcrs.every((p) => p.every((b) => b === 0));

    const goldenEvents = loadGoldenBoot(this.goldenBootPath);

    if (isAllZero) {
      // Replay golden boot events
      this.eventLog = [];
      for (const evt of goldenEvents) {
        const digestBuf = Buffer.from(evt.digest, "hex");
        await this.conn.call("PCR_Extend", TPM_HANDLE.pcr(evt.pcr), [new TPMT_HA(TPM_ALG_ID.SHA256, digestBuf)]);
        this.eventLog.push({
          pcr: evt.pcr,
          digest: evt.digest,
          desc: evt.desc,
        });
      }
    } else {
      // PCRs are already extended
      if (!this.eventLog || this.eventLog.length === 0) {
        this.eventLog = [...goldenEvents];
        try {
          const replayed = replayEventLog(this.eventLog);
          const pcrDigNow = crypto.createHash("sha256").update(Buffer.concat(pcrs)).digest("hex");
          if (pcrDigNow !== replayed.digest.toString("hex")) {
            console.warn("⚠️ [RealTpm] PCRs changed outside the agent");
          }
        } catch {}
      } else {
        // Compare with replay of our saved event log
        try {
          const replayed = replayEventLog(this.eventLog);
          const pcrDigNow = crypto.createHash("sha256").update(Buffer.concat(pcrs)).digest("hex");
          const pcrDigReplayed = replayed.digest.toString("hex");
          if (pcrDigNow !== pcrDigReplayed) {
            console.warn("⚠️ [RealTpm] PCRs changed outside the agent");
          }
        } catch {}
      }
    }
  }

  /**
   * Reads the current measured boot event log.
   * For Linux devices, reads fresh from TPM_EVENTLOG_PATH on each call.
   * @returns {Array|Object|null}
   */
  readEventLog() {
    if (this.deviceType === "linux") {
      const mode = (process.env.TPM_EVENTLOG || this.eventLogMode || "auto").toLowerCase();
      if (mode === "off") {
        return null;
      }
      const logPath = process.env.TPM_EVENTLOG_PATH || this.eventLogPath || "/sys/kernel/security/tpm0/binary_bios_measurements";
      try {
        const raw = fs.readFileSync(logPath);
        return {
          format: "tcg2-binary",
          data: raw.toString("base64url"),
        };
      } catch (err) {
        if (mode === "require") {
          const tpmErr = new TpmError("EVENTLOG_UNAVAILABLE", 0, { unavailable: true });
          tpmErr.code = "EVENTLOG_UNAVAILABLE";
          throw tpmErr;
        }
        if (!this.warnedUnavailable) {
          console.warn(`⚠️ [RealTpm] Event log unavailable at ${logPath} (${err.code || err.errno}): falling back to golden-PCR mode`);
          this.warnedUnavailable = true;
        }
        return null;
      }
    }

    if (this.eventLog === null) return null;
    return JSON.parse(JSON.stringify(this.eventLog));
  }

  /**
   * Extends a PCR measurement. Refuses firmware PCRs 0..7 on hardware devices.
   *
   * @param {number} pcr
   * @param {Buffer|string} digest
   * @param {string} [desc=""]
   */
  async extendPcr(pcr, digest, desc = "") {
    if (pcr < 0 || pcr > 7) {
      throw new Error(`Invalid PCR index: ${pcr} (expected 0..7)`);
    }

    if (!EMULATED_FIRMWARE_DEVICES.has(this.deviceType) && pcr >= 0 && pcr <= 7) {
      throw new Error(`Refusing extend on firmware PCR ${pcr} for device type '${this.deviceType}'`);
    }

    const digestBuf = typeof digest === "string" ? Buffer.from(digest, "hex") : Buffer.from(digest);
    if (digestBuf.length !== 32) {
      throw new Error(`PCR extend digest must be 32 bytes (SHA-256), got ${digestBuf.length}`);
    }

    await this.conn.call("PCR_Extend", TPM_HANDLE.pcr(pcr), [new TPMT_HA(TPM_ALG_ID.SHA256, digestBuf)]);

    if (this.eventLog !== null) {
      this.eventLog.push({
        pcr,
        digest: digestBuf.toString("hex"),
        desc: String(desc),
      });
    }
  }

  /**
   * Tamper helper (TCP only). Extends PCR4 with a rogue measurement.
   * @param {string} [desc="rogue measurement"]
   */
  async tamper(desc = "rogue measurement") {
    if (!EMULATED_FIRMWARE_DEVICES.has(this.deviceType)) {
      throw new Error("tamper() is only supported on software TPMs without firmware (tcp, swtpm)");
    }
    const rogueDigest = crypto.createHash("sha256").update(desc).digest();
    await this.extendPcr(4, rogueDigest, desc);
  }
}
