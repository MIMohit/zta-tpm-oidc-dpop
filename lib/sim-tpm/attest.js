/**
 * @file attest.js
 * TPMS_ATTEST binary marshalling and parsing for TPM 2.0 quote and certify emulation.
 */

import crypto from "node:crypto";
import { nameOf } from "./public-area.js";

export const TPM_GENERATED_VALUE = 0xff544347;
export const TPM_ST_ATTEST_QUOTE = 0x8018;
export const TPM_ST_ATTEST_CERTIFY = 0x8017;
export const TPM_ALG_SHA256 = 0x000b;

/**
 * Converts input to a Buffer.
 * @param {Buffer|Uint8Array|string} val
 * @returns {Buffer}
 */
function toBuf(val) {
  if (Buffer.isBuffer(val)) return val;
  if (val instanceof Uint8Array) return Buffer.from(val);
  if (typeof val === "string") {
    // If 64 hex characters, treat as hex
    if (/^[0-9a-fA-F]{64}$/.test(val)) {
      return Buffer.from(val, "hex");
    }
    // If base64url
    if (/^[A-Za-z0-9_-]{43}$/.test(val)) {
      return Buffer.from(val, "base64url");
    }
    return Buffer.from(val, "utf8");
  }
  return Buffer.from(val || "");
}

/**
 * Helper to encode a buffer into TPM2B format (u16 size || data).
 * @param {Buffer} data
 * @returns {Buffer}
 */
function writeTPM2B(data) {
  const buf = toBuf(data);
  const sizeBuf = Buffer.alloc(2);
  sizeBuf.writeUInt16BE(buf.length, 0);
  return Buffer.concat([sizeBuf, buf]);
}

/**
 * Computes the cumulative PCR digest over PCR0..7.
 * pcrDigest = SHA256(PCR0 || ... || PCR7)
 *
 * @param {Array<Buffer|string>|Record<number, Buffer|string>} pcrs
 * @returns {Buffer} 32-byte SHA-256 digest
 */
export function pcrDigest(pcrs) {
  const parts = [];
  for (let i = 0; i < 8; i++) {
    const val = Array.isArray(pcrs) ? pcrs[i] : pcrs?.[i];
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
  const concatenated = Buffer.concat(parts);
  return crypto.createHash("sha256").update(concatenated).digest();
}

/**
 * Replays a measured boot event log starting from all-zero PCRs.
 * Each extension is PCR[i] = SHA256(PCR[i] || event.digest).
 *
 * @param {Array<{ pcr: number, digest: string|Buffer, desc?: string }>} log
 * @returns {{ pcrs: Buffer[], digest: Buffer }}
 */
export function replayEventLog(log = []) {
  const pcrs = Array.from({ length: 8 }, () => Buffer.alloc(32, 0));
  for (const event of log) {
    const idx = event.pcr;
    if (idx >= 0 && idx < 8) {
      const dBuf = typeof event.digest === "string" ? Buffer.from(event.digest, "hex") : Buffer.from(event.digest);
      pcrs[idx] = crypto.createHash("sha256").update(pcrs[idx]).update(dBuf).digest();
    }
  }
  const digest = pcrDigest(pcrs);
  return { pcrs, digest };
}

/**
 * Binary-marshals a TPMS_ATTEST structure.
 *
 * Binary layout per PLAN.md §2.4:
 * magic u32 (0xFF544347)
 * type u16 (0x8018 QUOTE, 0x8017 CERTIFY)
 * qualifiedSigner TPM2B(Name(AK))
 * extraData TPM2B(n_V)
 * clockInfo (clock u64, resetCount u32, restartCount u32, safe u8)
 * firmwareVersion u64
 * attested:
 *   - QUOTE: count u32 (1), hash u16 (0x000B), sizeofSelect u8 (3), bitmap (3 bytes), TPM2B(pcrDigest)
 *   - CERTIFY: TPM2B(Name(obj)), TPM2B(qualifiedName)
 *
 * @param {Object} params
 * @param {number} params.type - 0x8018 (QUOTE) or 0x8017 (CERTIFY)
 * @param {Buffer|Object} params.signerName - Name of signing AK
 * @param {Buffer|string} params.extraData - Nonce n_V
 * @param {number|BigInt} [params.clock]
 * @param {Object} [params.clockInfo]
 * @param {number|BigInt} [params.fw]
 * @param {number|BigInt} [params.firmwareVersion]
 * @param {Object|Buffer} params.attested
 * @returns {Buffer}
 */
export function marshalAttest(params) {
  const {
    type,
    signerName,
    extraData,
    clock = Date.now(),
    clockInfo = {},
    fw = 0n,
    firmwareVersion = fw,
    attested,
  } = params;

  if (type !== TPM_ST_ATTEST_QUOTE && type !== TPM_ST_ATTEST_CERTIFY) {
    throw new Error(`Unsupported attest type: 0x${type?.toString(16)}`);
  }

  const signerBuf = Buffer.isBuffer(signerName)
    ? signerName
    : (typeof signerName === "object" ? nameOf(signerName) : Buffer.from(signerName));

  const extraDataBuf = toBuf(extraData);

  const headerBuf = Buffer.alloc(4 + 2);
  headerBuf.writeUInt32BE(TPM_GENERATED_VALUE, 0);
  headerBuf.writeUInt16BE(type, 4);

  const qSignerTPM2B = writeTPM2B(signerBuf);
  const extraDataTPM2B = writeTPM2B(extraDataBuf);

  const clockNum = BigInt(clockInfo.clock ?? clock);
  const resetCount = clockInfo.resetCount ?? 0;
  const restartCount = clockInfo.restartCount ?? 0;
  const safe = clockInfo.safe ?? 1;

  const clockBuf = Buffer.alloc(8 + 4 + 4 + 1);
  clockBuf.writeBigUInt64BE(clockNum, 0);
  clockBuf.writeUInt32BE(resetCount, 8);
  clockBuf.writeUInt32BE(restartCount, 12);
  clockBuf.writeUInt8(safe, 16);

  const fwNum = BigInt(firmwareVersion);
  const fwBuf = Buffer.alloc(8);
  fwBuf.writeBigUInt64BE(fwNum, 0);

  let attestedBuf;
  if (Buffer.isBuffer(attested)) {
    attestedBuf = attested;
  } else if (type === TPM_ST_ATTEST_QUOTE) {
    // TPML_PCR_SELECTION: count u32, hash u16, sizeofSelect u8, pcrSelect (3 bytes)
    const selBuf = Buffer.alloc(4 + 2 + 1 + 3);
    selBuf.writeUInt32BE(1, 0);
    selBuf.writeUInt16BE(TPM_ALG_SHA256, 4);
    selBuf.writeUInt8(3, 6);
    const bitmap = attested?.pcrSelect?.pcrSelect || Buffer.from([0xff, 0x00, 0x00]);
    bitmap.copy(selBuf, 7, 0, 3);

    const digestBuf = toBuf(attested?.pcrDigest || Buffer.alloc(32, 0));
    const digestTPM2B = writeTPM2B(digestBuf);
    attestedBuf = Buffer.concat([selBuf, digestTPM2B]);
  } else {
    // CERTIFY: TPM2B(name), TPM2B(qualifiedName)
    const objName = Buffer.isBuffer(attested?.name)
      ? attested.name
      : (typeof attested?.name === "object" ? nameOf(attested.name) : Buffer.from(attested?.name || ""));
    const qName = Buffer.isBuffer(attested?.qualifiedName)
      ? attested.qualifiedName
      : (typeof attested?.qualifiedName === "object" ? nameOf(attested.qualifiedName) : (attested?.qualifiedName ? Buffer.from(attested.qualifiedName) : objName));

    attestedBuf = Buffer.concat([writeTPM2B(objName), writeTPM2B(qName)]);
  }

  return Buffer.concat([
    headerBuf,
    qSignerTPM2B,
    extraDataTPM2B,
    clockBuf,
    fwBuf,
    attestedBuf,
  ]);
}

/**
 * Parses a binary TPMS_ATTEST buffer.
 *
 * @param {Buffer|string} buf
 * @returns {Object} Parsed attest structure
 */
export function parseAttest(buf) {
  let data = buf;
  if (typeof data === "string") {
    data = Buffer.from(data, "base64url");
  }
  if (!Buffer.isBuffer(data)) {
    throw new Error("Invalid buffer passed to parseAttest");
  }

  if (data.length < 6) {
    throw new Error("Buffer too short for TPMS_ATTEST header");
  }

  let offset = 0;
  const magic = data.readUInt32BE(offset);
  offset += 4;
  if (magic !== TPM_GENERATED_VALUE) {
    throw new Error(`Invalid TPM magic: 0x${magic.toString(16)} (expected 0x${TPM_GENERATED_VALUE.toString(16)})`);
  }

  const type = data.readUInt16BE(offset);
  offset += 2;

  // qualifiedSigner TPM2B
  const signerLen = data.readUInt16BE(offset);
  offset += 2;
  const qualifiedSigner = data.subarray(offset, offset + signerLen);
  offset += signerLen;

  // extraData TPM2B
  const extraDataLen = data.readUInt16BE(offset);
  offset += 2;
  const extraData = data.subarray(offset, offset + extraDataLen);
  offset += extraDataLen;

  // clockInfo
  const clock = data.readBigUInt64BE(offset);
  offset += 8;
  const resetCount = data.readUInt32BE(offset);
  offset += 4;
  const restartCount = data.readUInt32BE(offset);
  offset += 4;
  const safe = data.readUInt8(offset);
  offset += 1;

  // firmwareVersion
  const firmwareVersion = data.readBigUInt64BE(offset);
  offset += 8;

  const result = {
    magic,
    type,
    qualifiedSigner,
    extraData,
    clockInfo: {
      clock,
      resetCount,
      restartCount,
      safe,
    },
    firmwareVersion,
    attested: {},
  };

  if (type === TPM_ST_ATTEST_QUOTE) {
    const count = data.readUInt32BE(offset);
    offset += 4;
    const hash = data.readUInt16BE(offset);
    offset += 2;
    const sizeofSelect = data.readUInt8(offset);
    offset += 1;
    const pcrSelect = data.subarray(offset, offset + sizeofSelect);
    offset += sizeofSelect;

    const digestLen = data.readUInt16BE(offset);
    offset += 2;
    const pcrDigestBuf = data.subarray(offset, offset + digestLen);
    offset += digestLen;

    result.attested = {
      pcrSelect: {
        count,
        hash,
        sizeofSelect,
        pcrSelect,
      },
      pcrDigest: pcrDigestBuf,
    };
    result.pcrDigest = pcrDigestBuf;
  } else if (type === TPM_ST_ATTEST_CERTIFY) {
    const nameLen = data.readUInt16BE(offset);
    offset += 2;
    const nameBuf = data.subarray(offset, offset + nameLen);
    offset += nameLen;

    const qNameLen = data.readUInt16BE(offset);
    offset += 2;
    const qNameBuf = data.subarray(offset, offset + qNameLen);
    offset += qNameLen;

    result.attested = {
      name: nameBuf,
      qualifiedName: qNameBuf,
    };
    result.name = nameBuf;
  } else {
    result.attested = {
      raw: data.subarray(offset),
    };
  }

  return result;
}

export default {
  TPM_GENERATED_VALUE,
  TPM_ST_ATTEST_QUOTE,
  TPM_ST_ATTEST_CERTIFY,
  TPM_ALG_SHA256,
  pcrDigest,
  replayEventLog,
  marshalAttest,
  parseAttest,
};
