/**
 * @file tcg-eventlog.js
 * TCG PC Client crypto-agile event log parser, replayer, and evidence decoder.
 * Conforms to TCG PC Client Specific Implementation Specification for Conventional BIOS / EFI 2.0.
 */

import crypto from "node:crypto";

export const EV = {
  PREBOOT_CERT: 0x0,
  POST_CODE: 0x1,
  NO_ACTION: 0x3,
  SEPARATOR: 0x4,
  ACTION: 0x5,
  EVENT_TAG: 0x6,
  S_CRTM_CONTENTS: 0x7,
  S_CRTM_VERSION: 0x8,
  CPU_MICROCODE: 0x9,
  PLATFORM_CONFIG_FLAGS: 0xa,
  TABLE_OF_DEVICES: 0xb,
  COMPACT_HASH: 0xc,
  IPL: 0xd,
  IPL_PARTITION_DATA: 0xe,
  NONHOST_CODE: 0xf,
  NONHOST_CONFIG: 0x10,
  NONHOST_INFO: 0x11,
  OMIT_BOOT_DEVICE_EVENTS: 0x12,
  EFI_VARIABLE_DRIVER_CONFIG: 0x80000001,
  EFI_VARIABLE_BOOT: 0x80000002,
  EFI_BOOT_SERVICES_APPLICATION: 0x80000003,
  EFI_BOOT_SERVICES_DRIVER: 0x80000004,
  EFI_RUNTIME_SERVICES_DRIVER: 0x80000005,
  EFI_GPT_EVENT: 0x80000006,
  EFI_ACTION: 0x80000007,
  EFI_PLATFORM_FIRMWARE_BLOB: 0x80000008,
  EFI_HANDOFF_TABLES: 0x80000009,
  EFI_PLATFORM_FIRMWARE_BLOB2: 0x8000000a,
  EFI_HANDOFF_TABLES2: 0x8000000b,
  EFI_VARIABLE_BOOT2: 0x8000000c,
  EFI_HCRTM_EVENT: 0x80000010,
  EFI_VARIABLE_AUTHORITY: 0x800000e0,
  EFI_SPDM_FIRMWARE_BLOB: 0x800000e1,
  EFI_SPDM_FIRMWARE_CONFIG: 0x800000e2,
};

export const ALG = {
  0x0004: { name: "sha1", size: 20 },
  0x000b: { name: "sha256", size: 32 },
  0x000c: { name: "sha384", size: 48 },
  0x000d: { name: "sha512", size: 64 },
  0x0012: { name: "sm3_256", size: 32 },
};

const EV_NAME_MAP = new Map(
  Object.entries(EV).map(([k, v]) => [v, k.startsWith("EV_") ? k : "EV_" + k])
);

export class TcgEventLogError extends Error {
  /**
   * @param {string} message
   * @param {"truncated"|"not_crypto_agile"|"bad_spec_id"|"unknown_alg"|"too_large"|"bad_digest_count"} code
   */
  constructor(message, code) {
    super(message);
    this.name = "TcgEventLogError";
    this.code = code;
  }
}

export const MAX_LOG_BYTES = 2 * 1024 * 1024;
export const MAX_EVENTS = 10000;
export const MAX_EVENT_DATA = 1024 * 1024;

/**
 * Parses a binary TCG PC Client crypto-agile event log.
 *
 * @param {Buffer} buf
 * @returns {{
 *   specId: {
 *     signature: string,
 *     platformClass: number,
 *     specVersion: string,
 *     uintnSize: number,
 *     algorithms: Array<{ algId: number, name: string, digestSize: number }>,
 *     vendorInfo: Buffer
 *   },
 *   events: Array<{
 *     index: number,
 *     offset: number,
 *     pcr: number,
 *     type: number,
 *     typeName: string,
 *     digests: Record<string, Buffer>,
 *     data: Buffer
 *   }>,
 *   trailingBytes: number
 * }}
 */
export function parseTcgEventLog(buf) {
  if (!Buffer.isBuffer(buf)) {
    buf = Buffer.from(buf || "");
  }

  if (buf.length > MAX_LOG_BYTES) {
    throw new TcgEventLogError(`Buffer exceeds MAX_LOG_BYTES (${buf.length} > ${MAX_LOG_BYTES})`, "too_large");
  }

  // Legacy header: TCG_PCClientPCREvent (pcr: u32, type: u32, digest: 20B, eventSize: u32) = 32 bytes minimum
  if (buf.length < 32) {
    throw new TcgEventLogError("Buffer too short for legacy TCG header", "truncated");
  }

  const pcr = buf.readUInt32LE(0);
  const etype = buf.readUInt32LE(4);
  let eventSize = buf.readUInt32LE(28);

  if (32 + eventSize > buf.length) {
    throw new TcgEventLogError("Legacy header event data truncated", "truncated");
  }

  const specBuf = buf.subarray(32, 32 + eventSize);

  // Must be EV_NO_ACTION (0x3) and start with "Spec ID Event03"
  if (etype !== EV.NO_ACTION || specBuf.length < 16) {
    throw new TcgEventLogError("Not a crypto-agile event log", "not_crypto_agile");
  }

  const sig = specBuf.subarray(0, 16).toString("latin1").replace(/\0+$/, "");
  if (sig !== "Spec ID Event03") {
    throw new TcgEventLogError(`Unsupported event log signature: ${sig}`, "not_crypto_agile");
  }

  // Spec ID Event structure:
  // Signature: 16B
  // platformClass: u32 (offset 16)
  // specVersionMinor: u8 (offset 20)
  // specVersionMajor: u8 (offset 21)
  // specErrata: u8 (offset 22)
  // uintnSize: u8 (offset 23)
  // numberOfAlgorithms: u32 (offset 24)
  if (specBuf.length < 28) {
    throw new TcgEventLogError("Spec ID structure truncated before algorithm table", "truncated");
  }

  const platformClass = specBuf.readUInt32LE(16);
  const specVersionMinor = specBuf.readUInt8(20);
  const specVersionMajor = specBuf.readUInt8(21);
  const specErrata = specBuf.readUInt8(22);
  const uintnSize = specBuf.readUInt8(23);
  const numberOfAlgorithms = specBuf.readUInt32LE(24);

  let sOff = 28;
  const algorithms = [];
  const algSizes = new Map();

  for (let i = 0; i < numberOfAlgorithms; i++) {
    if (sOff + 4 > specBuf.length) {
      throw new TcgEventLogError("Spec ID algorithm table truncated", "truncated");
    }
    const algId = specBuf.readUInt16LE(sOff);
    const digestSize = specBuf.readUInt16LE(sOff + 2);
    sOff += 4;
    const name = ALG[algId]?.name || `unknown_${algId}`;
    algorithms.push({ algId, name, digestSize });
    algSizes.set(algId, digestSize);
  }

  if (sOff >= specBuf.length) {
    throw new TcgEventLogError("Spec ID vendor info size truncated", "truncated");
  }
  const vendorInfoSize = specBuf.readUInt8(sOff);
  sOff += 1;

  let vendorInfo;
  if (sOff + vendorInfoSize <= specBuf.length) {
    vendorInfo = specBuf.subarray(sOff, sOff + vendorInfoSize);
  } else if (32 + sOff + vendorInfoSize <= buf.length) {
    // Some logs (e.g. specid-vendordata.bin) record eventSize excluding vendorInfo bytes
    vendorInfo = buf.subarray(32 + sOff, 32 + sOff + vendorInfoSize);
    eventSize = Math.max(eventSize, sOff + vendorInfoSize);
  } else {
    throw new TcgEventLogError("Spec ID vendor info data truncated", "truncated");
  }

  const specId = {
    signature: "Spec ID Event03",
    platformClass,
    specVersion: `${specVersionMajor}.${specVersionMinor}.${specErrata}`,
    uintnSize,
    algorithms,
    vendorInfo,
  };

  // Parse TCG_PCR_EVENT2 events
  let o = 32 + eventSize;
  let index = 0;
  const events = [];
  let trailingBytes = 0;

  while (o < buf.length) {
    // If fewer than 12 bytes remain, check if they are trailing zeros
    if (buf.length - o < 12) {
      let allZero = true;
      for (let j = o; j < buf.length; j++) {
        if (buf[j] !== 0) {
          allZero = false;
          break;
        }
      }
      if (allZero) {
        trailingBytes = buf.length - o;
        break;
      }
      throw new TcgEventLogError("Truncated TCG_PCR_EVENT2 header", "truncated");
    }

    const eventStart = o;
    const evPcr = buf.readUInt32LE(o);
    const evType = buf.readUInt32LE(o + 4);
    const count = buf.readUInt32LE(o + 8);

    // Trailing zero padding detector
    if (evType === 0 && count === 0) {
      trailingBytes = buf.length - eventStart;
      break;
    }

    o += 12;

    if (count > algorithms.length) {
      throw new TcgEventLogError(`Event digest count ${count} exceeds Spec ID algorithm count ${algorithms.length}`, "bad_digest_count");
    }

    const digests = {};
    for (let c = 0; c < count; c++) {
      if (o + 2 > buf.length) {
        throw new TcgEventLogError("Truncated digest algorithm ID", "truncated");
      }
      const algId = buf.readUInt16LE(o);
      o += 2;

      if (!algSizes.has(algId)) {
        throw new TcgEventLogError(`Unknown algorithm ID 0x${algId.toString(16)} not in Spec ID`, "unknown_alg");
      }
      const dSize = algSizes.get(algId);
      if (o + dSize > buf.length) {
        throw new TcgEventLogError("Truncated digest payload in event", "truncated");
      }
      const dBuf = buf.subarray(o, o + dSize);
      o += dSize;

      const algName = ALG[algId]?.name || `unknown_${algId}`;
      digests[algName] = dBuf;
    }

    if (o + 4 > buf.length) {
      throw new TcgEventLogError("Truncated event data length", "truncated");
    }
    const dataLen = buf.readUInt32LE(o);
    o += 4;

    if (dataLen > MAX_EVENT_DATA) {
      throw new TcgEventLogError(`Event data length ${dataLen} exceeds MAX_EVENT_DATA`, "too_large");
    }
    if (o + dataLen > buf.length) {
      throw new TcgEventLogError("Truncated event data payload", "truncated");
    }
    const data = buf.subarray(o, o + dataLen);
    o += dataLen;

    const typeName = EV_NAME_MAP.get(evType) || (evType in EV ? (evType.toString().startsWith("EV_") ? evType : "EV_" + evType) : `EV_0x${evType.toString(16)}`);

    events.push({
      index,
      offset: eventStart,
      pcr: evPcr,
      type: evType,
      typeName,
      digests,
      data,
    });
    index++;

    if (events.length > MAX_EVENTS) {
      throw new TcgEventLogError(`Event count exceeds MAX_EVENTS (${MAX_EVENTS})`, "too_large");
    }
  }

  return {
    specId,
    events,
    trailingBytes,
  };
}

/**
 * Replays a parsed TCG event log into PCR registers.
 *
 * @param {Object} parsed
 * @param {Object} [options]
 * @param {string|number} [options.bank="sha256"]
 * @param {number[]} [options.pcrs=[0, 1, 2, 3, 4, 5, 6, 7]]
 * @returns {{ pcrs: Record<number, Buffer>, startupLocality: number|null }}
 */
export function replayTcgEventLog(parsed, { bank = "sha256", pcrs = [0, 1, 2, 3, 4, 5, 6, 7] } = {}) {
  const algName = typeof bank === "number" ? (ALG[bank]?.name || "sha256") : bank;
  let dSize = 32;
  for (const entry of Object.values(ALG)) {
    if (entry.name === algName) {
      dSize = entry.size;
      break;
    }
  }

  const pcrMap = {};
  for (const p of pcrs) {
    pcrMap[p] = Buffer.alloc(dSize, 0);
  }

  let startupLocality = null;

  for (const ev of parsed.events) {
    if (ev.type === EV.NO_ACTION) {
      // Check for StartupLocality event on PCR0
      if (
        ev.pcr === 0 &&
        ev.data.length >= 17 &&
        ev.data.subarray(0, 16).toString("latin1").startsWith("StartupLocality\0")
      ) {
        startupLocality = ev.data[16];
        if (0 in pcrMap) {
          pcrMap[0] = Buffer.alloc(dSize, 0);
          pcrMap[0][dSize - 1] = startupLocality;
        }
      }
      continue;
    }

    const dig = ev.digests[algName];
    if (dig && (ev.pcr in pcrMap)) {
      pcrMap[ev.pcr] = crypto.createHash(algName).update(Buffer.concat([pcrMap[ev.pcr], dig])).digest();
    }
  }

  return {
    pcrs: pcrMap,
    startupLocality,
  };
}

/**
 * Computes composite digest over selected PCRs: SHA-256(PCR0 || ... || PCR7).
 * Same as sim-tpm/attest.js pcrDigest.
 *
 * @param {Record<number, Buffer|string>|Array<Buffer|string>} pcrMap
 * @param {number[]} [pcrs=[0, 1, 2, 3, 4, 5, 6, 7]]
 * @returns {Buffer}
 */
export function pcrCompositeDigest(pcrMap, pcrs = [0, 1, 2, 3, 4, 5, 6, 7]) {
  const parts = [];
  for (const p of pcrs) {
    const val = Array.isArray(pcrMap) ? pcrMap[p] : pcrMap?.[p];
    if (!val) {
      parts.push(Buffer.alloc(32, 0));
    } else if (Buffer.isBuffer(val)) {
      parts.push(val.length === 32 ? val : Buffer.from(val).subarray(0, 32));
    } else if (typeof val === "string") {
      parts.push(Buffer.from(val, "hex"));
    } else {
      parts.push(Buffer.from(val));
    }
  }
  return crypto.createHash("sha256").update(Buffer.concat(parts)).digest();
}

/**
 * Extracts a human-readable description from an event payload.
 *
 * @param {{ type: number, typeName: string, data: Buffer }} ev
 * @returns {string}
 */
export function describeEvent(ev) {
  if (!ev || !ev.data || ev.data.length === 0) {
    return ev?.typeName || "";
  }

  const { type, data } = ev;

  // 1. EFI_ACTION / ACTION text
  if (type === EV.ACTION || type === EV.EFI_ACTION) {
    return data.toString("utf8").replace(/\0+$/, "");
  }

  // 2. UEFI Variable names
  if (
    type === EV.EFI_VARIABLE_BOOT ||
    type === EV.EFI_VARIABLE_BOOT2 ||
    type === EV.EFI_VARIABLE_DRIVER_CONFIG ||
    type === EV.EFI_VARIABLE_AUTHORITY
  ) {
    if (data.length >= 32) {
      const nlen = Number(data.readBigUInt64LE(16));
      if (nlen > 0 && 32 + nlen * 2 <= data.length) {
        return data.subarray(32, 32 + nlen * 2).toString("utf16le").replace(/\0+$/, "");
      }
    }
  }

  // 3. Separator value
  if (type === EV.SEPARATOR) {
    if (data.length >= 4) {
      return `0x${data.readUInt32LE(0).toString(16).padStart(8, "0")}`;
    }
    return "0x00000000";
  }

  // 4. App device-path tail
  if (
    type === EV.EFI_BOOT_SERVICES_APPLICATION ||
    type === EV.EFI_BOOT_SERVICES_DRIVER ||
    type === EV.EFI_RUNTIME_SERVICES_DRIVER
  ) {
    if (data.length >= 32) {
      const dlen = Number(data.readBigUInt64LE(24));
      const dp = data.subarray(32, Math.min(data.length, 32 + dlen));
      let o = 0;
      while (o + 4 <= dp.length) {
        const nt = dp.readUInt8(o);
        const nst = dp.readUInt8(o + 1);
        const nl = dp.readUInt16LE(o + 2);
        if (nl < 4 || o + nl > dp.length) break;
        if (nt === 0x04 && nst === 0x04) {
          return dp.subarray(o + 4, o + nl).toString("utf16le").replace(/\0+$/, "");
        }
        o += nl;
      }
    }
  }

  // 5. S_CRTM_VERSION
  if (type === EV.S_CRTM_VERSION) {
    if (data.length >= 2 && data[1] === 0) {
      const s16 = data.toString("utf16le").replace(/\0+$/, "");
      if (/^[\x20-\x7e]+$/.test(s16)) return s16;
    }
    const s8 = data.toString("utf8").replace(/\0+$/, "");
    if (/^[\x20-\x7e]+$/.test(s8)) return s8;
  }

  // Generic ASCII fallback
  const str = data.toString("utf8").replace(/\0+$/, "");
  if (/^[\x20-\x7e]+$/.test(str) && str.length >= 2) {
    return str;
  }

  return ev.typeName || `EV_0x${type.toString(16)}`;
}

/**
 * Converts a parsed TCG event log to the appraisal events format expected by verifyEventLog.
 * Drops NO_ACTION events and events outside the specified PCR range.
 *
 * @param {Object} parsed
 * @param {Object} [options]
 * @param {string|number} [options.bank="sha256"]
 * @param {number[]} [options.pcrs=[0, 1, 2, 3, 4, 5, 6, 7]]
 * @returns {Array<{ pcr: number, digest: string, type: number, typeName: string, desc: string }>}
 */
export function toAppraisalEvents(parsed, { bank = "sha256", pcrs = [0, 1, 2, 3, 4, 5, 6, 7] } = {}) {
  const algName = typeof bank === "number" ? (ALG[bank]?.name || "sha256") : bank;
  const pcrSet = new Set(pcrs);
  const result = [];

  for (const ev of parsed.events) {
    if (!pcrSet.has(ev.pcr)) continue;
    if (ev.type === EV.NO_ACTION) continue;

    const digBuf = ev.digests[algName];
    if (!digBuf) continue;

    result.push({
      pcr: ev.pcr,
      digest: digBuf.toString("hex").toLowerCase(),
      type: ev.type,
      typeName: ev.typeName,
      desc: describeEvent(ev),
    });
  }

  return result;
}

/**
 * Informational: checks if EV_SEPARATOR and EV_EFI_ACTION events have digests equal to hash of data.
 *
 * @param {Object} parsed
 * @param {string|number} [bank="sha256"]
 * @returns {Array<{ index: number, type: number }>}
 */
export function checkEventDataDigests(parsed, bank = "sha256") {
  const algName = typeof bank === "number" ? (ALG[bank]?.name || "sha256") : bank;
  const bad = [];

  for (const ev of parsed.events) {
    if (ev.type === EV.SEPARATOR || ev.type === EV.EFI_ACTION || ev.type === EV.ACTION) {
      const dig = ev.digests[algName];
      if (dig) {
        const computed = crypto.createHash(algName).update(ev.data).digest();
        if (Buffer.compare(dig, computed) !== 0) {
          bad.push({ index: ev.index, type: ev.type });
        }
      }
    }
  }

  return bad;
}

/**
 * Decodes evidence log: legacy JSON array or tcg2-binary.
 *
 * @param {any} eventLog
 * @returns {{
 *   kind: "legacy-array" | "tcg2-binary" | "none",
 *   parsed?: Object,
 *   events?: Array<any>
 * }}
 */
export function decodeEvidenceLog(eventLog) {
  if (!eventLog) {
    return { kind: "none" };
  }

  if (Array.isArray(eventLog)) {
    return { kind: "legacy-array", events: eventLog };
  }

  if (typeof eventLog === "object" && eventLog.format === "tcg2-binary") {
    let buf;
    if (Buffer.isBuffer(eventLog.data)) {
      buf = eventLog.data;
    } else if (typeof eventLog.data === "string") {
      buf = Buffer.from(eventLog.data, "base64url");
    } else {
      throw new TcgEventLogError("Invalid tcg2-binary payload", "truncated");
    }

    if (buf.length > MAX_LOG_BYTES) {
      throw new TcgEventLogError(`Binary log exceeds MAX_LOG_BYTES (${buf.length} > ${MAX_LOG_BYTES})`, "too_large");
    }

    const parsed = parseTcgEventLog(buf);
    const events = toAppraisalEvents(parsed);
    return { kind: "tcg2-binary", parsed, events };
  }

  return { kind: "none" };
}

export default {
  EV,
  ALG,
  TcgEventLogError,
  MAX_LOG_BYTES,
  MAX_EVENTS,
  MAX_EVENT_DATA,
  parseTcgEventLog,
  replayTcgEventLog,
  pcrCompositeDigest,
  describeEvent,
  toAppraisalEvents,
  checkEventDataDigests,
  decodeEvidenceLog,
};
