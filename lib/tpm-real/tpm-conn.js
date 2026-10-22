/**
 * @file tpm-conn.js
 * Quarantine layer for tss.js:
 *  - Promisified and strictly serialized command queue (G10)
 *  - Raw response byte capture for TPMS_ATTEST (G2 u64 bug workaround)
 *  - TPM error and response code normalisation
 *  - Leak flushing on connect (G4)
 *  - Safe open/close and reconnect logic
 */
import tss from "tss.js";

const { Tpm, TPM_HANDLE, TPM_CAP, TPM_SU, TPM_RC } = tss;

export class TpmError extends Error {
  /**
   * @param {string} message
   * @param {number} [rc=0]
   * @param {{ unavailable?: boolean }} [opts] - unavailable: the TPM could not be reached (comms failure)
   */
  constructor(message, rc = 0, { unavailable = false } = {}) {
    super(message);
    this.name = "TpmError";
    this.rc = rc >>> 0;
    if (unavailable) {
      this.code = "TPM_UNAVAILABLE";
    } else {
      const rcName = TPM_RC[rc];
      this.code = rcName ? `TPM_RC_${rcName}` : `TPM_RC_0x${(this.rc).toString(16)}`;
    }
  }
}

const UNAVAILABLE_CODES = new Set([
  "TPM_UNAVAILABLE",
  "TPM_TIMEOUT",
  "ECONNREFUSED",
  "ECONNRESET",
  "EPIPE",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "ENOENT",
]);

/**
 * True when an error means the TPM cannot currently be used: the device/socket is gone,
 * or the TPM was reset and needs Startup again (TPM_RC_INITIALIZE, 0x100).
 * @param {any} err
 * @returns {boolean}
 */
export function isTpmUnavailable(err) {
  if (!err) return false;
  if (UNAVAILABLE_CODES.has(err.code)) return true;
  return err.name === "TpmError" && (err.rc >>> 0) === 0x100;
}

/**
 * True for TPM handle/reference errors (stale transient handle, e.g. after a TPM reset):
 * TPM_RC_HANDLE in any handle/parameter/session position and TPM_RC_REFERENCE_H0..S6.
 * @param {any} err
 * @returns {boolean}
 */
export function isHandleError(err) {
  if (!err) return false;
  if (err.code === "TPM_RC_HANDLE") return true;
  const rc = (err.rc || 0) >>> 0;
  if (rc === 0) return false;
  if ((rc & 0x0bf) === 0x08b) return true; // format-1 TPM_RC_HANDLE (0x08B | N<<8 | P/S bits)
  return rc >= 0x910 && rc <= 0x91e; // TPM_RC_REFERENCE_H0..H6 / S0..S6
}

export class TpmConn {
  /**
   * @param {Object} device - Device conforming to connect/dispatchCommand/close
   * @param {Object} [options]
   */
  constructor(device, options = {}) {
    this.device = device;
    this.options = options;
    this.tpm = null;
    this._queue = Promise.resolve();
    this._lastResp = null;
    this._commsErr = null;
    this._isOpen = false;
    this._origDispatch = null;
  }

  /**
   * Opens the device, attaches tss.js, issues Startup(CLEAR), and flushes leaked handles.
   */
  async open() {
    if (this._isOpen) return;

    this.tpm = new Tpm(true);
    // Overwrite default device before connect is called
    this.tpm.device = this.device;

    // Capture raw response bytes for commands that return TPMS_ATTEST, and remember
    // transport failures (socket closed etc.) so they surface as TPM_UNAVAILABLE.
    // Wrapped once: open() runs again on every reconnect.
    if (!this._origDispatch) {
      this._origDispatch = this.device.dispatchCommand.bind(this.device);
      this.device.dispatchCommand = (cmd, cont) => {
        this._origDispatch(cmd, (err, resp) => {
          this._lastResp = resp ? Buffer.from(resp) : null;
          if (err) this._commsErr = err;
          cont(err, resp);
        });
      };
    }

    await new Promise((resolve, reject) => {
      this.tpm.connect((err) => {
        if (err) reject(Object.assign(err, { code: UNAVAILABLE_CODES.has(err.code) ? err.code : "TPM_UNAVAILABLE" }));
        else resolve();
      });
    });

    this._isOpen = true;

    // Send Startup(CLEAR) - tolerate TPM_RC_INITIALIZE (0x100) if already started
    try {
      this.tpm.allowErrors();
      await this._invokeCommand("Startup", TPM_SU.CLEAR);
    } catch (err) {
      const rc = this.tpm.lastResponseCode >>> 0;
      if (err.code === "TPM_UNAVAILABLE") throw err;
      if (rc !== 0x100) {
        // Not TPM_RC_INITIALIZE, re-throw
        throw new TpmError(`Startup(CLEAR) failed: ${err.message}`, rc);
      }
    }

    // Flush leaked transient objects and sessions (G4)
    // Only on TCP and Linux devices; TBS manages sessions/handles per context
    const devType = this.options.device || process.env.TPM_DEVICE || "auto";
    if (devType !== "tbs" && process.platform !== "win32") {
      await this.flushLeaked().catch(() => {});
      // Reset Dictionary Attack lockout if running against simulator with empty lockout auth
      try {
        await this._invokeCommand("DictionaryAttackLockReset", new TPM_HANDLE(tss.TPM_RH.LOCKOUT));
        await this._invokeCommand("DictionaryAttackParameters", new TPM_HANDLE(tss.TPM_RH.LOCKOUT), 100, 0, 0);
      } catch {}
    }
  }

  /**
   * Flushes all leaked transient objects (0x80xxxxxx) and sessions (0x02/0x03xxxxxx).
   */
  async flushLeaked() {
    const flushRange = async (handleType) => {
      try {
        const cap = await this._invokeCommand("GetCapability", TPM_CAP.HANDLES, handleType, 32);
        const handles = cap?.capabilityData?.handle || [];
        for (const h of handles) {
          try {
            await this._invokeCommand("FlushContext", h);
          } catch {}
        }
        return handles.length;
      } catch {
        return 0;
      }
    };

    // 0x80000000 = Transient objects
    // 0x02000000 = Loaded HMAC sessions
    // 0x03000000 = Loaded Policy sessions
    await flushRange(0x80000000);
    await flushRange(0x02000000);
    await flushRange(0x03000000);
  }

  /**
   * Sets command sessions on the underlying TPM object for the next command.
   * @param  {...any} sessions
   */
  withSessions(...sessions) {
    if (this.tpm) {
      this.tpm.withSessions(...sessions);
    }
    return this;
  }

  /**
   * Low-level invocation of a tss.js command.
   * @private
   */
  _invokeCommand(fn, ...args) {
    return new Promise((resolve, reject) => {
      if (!this.tpm) {
        return reject(new TpmError(`${fn} failed: TPM connection is closed`, 0, { unavailable: true }));
      }
      if (!this.tpm[fn]) {
        return reject(new Error(`Tpm command '${fn}' does not exist`));
      }
      this._commsErr = null;
      this.tpm[fn](...args, (err, res) => {
        if (err) {
          const msg = err.message || String(err);
          if (this._commsErr) {
            this._commsErr = null;
            return reject(new TpmError(`${fn} failed: ${msg}`, 0, { unavailable: true }));
          }
          const rc = ((this.tpm && this.tpm.lastResponseCode) || 0) >>> 0;
          const tpmErr = new TpmError(`${fn} failed: ${msg}`, rc);
          reject(tpmErr);
        } else {
          resolve(res);
        }
      });
    });
  }

  /**
   * Dispatches a command through the serialized queue.
   * Guarantees at most one command in flight at any time (G10).
   *
   * @param {string} fn
   * @param  {...any} args
   * @returns {Promise<any>}
   */
  call(fn, ...args) {
    const execute = async () => {
      try {
        return await this._invokeCommand(fn, ...args);
      } catch (err) {
        // Lost TPM (socket closed / TPM reset): mark the connection unusable. Reconnecting
        // needs backend state (handles, measured boot) to be rebuilt, so RealTpm does it.
        if (isTpmUnavailable(err)) this._isOpen = false;
        throw err;
      }
    };

    const task = () => execute();
    const result = this._queue.then(task, task);
    this._queue = result.catch(() => {});
    return result;
  }

  /**
   * Slices raw TPMS_ATTEST bytes from the last captured response buffer.
   * Bypasses the tss.js uint64 32-bit shift bug (G2).
   *
   * @returns {Buffer} Raw TPMS_ATTEST bytes
   */
  rawAttest() {
    if (!this._lastResp || this._lastResp.length < 16) {
      throw new Error("No raw attest response available");
    }
    const tag = this._lastResp.readUInt16BE(0);
    // 0x8002 = TPM_ST_SESSIONS (paramSize at 10..14, TPM2B_ATTEST at 14)
    // 0x8001 = TPM_ST_NO_SESSIONS (TPM2B_ATTEST at 10)
    const paramOffset = tag === 0x8002 ? 14 : 10;
    if (this._lastResp.length < paramOffset + 2) {
      throw new Error("Response buffer too short for TPM2B_ATTEST size header");
    }
    const n = this._lastResp.readUInt16BE(paramOffset);
    if (this._lastResp.length < paramOffset + 2 + n) {
      throw new Error(`Response buffer too short: expected ${paramOffset + 2 + n} bytes, got ${this._lastResp.length}`);
    }
    return Buffer.from(this._lastResp.subarray(paramOffset + 2, paramOffset + 2 + n));
  }

  /**
   * Closes the TPM connection and device.
   */
  async close() {
    this._isOpen = false;
    if (this.tpm) {
      try {
        this.tpm.close();
      } catch {}
      this.tpm = null;
    }
    if (this.device) {
      try {
        await this.device.close();
      } catch {}
    }
    this._lastResp = null;
  }
}
