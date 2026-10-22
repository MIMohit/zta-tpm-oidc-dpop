/**
 * @file devices.js
 * Crash-safe TPM 2.0 device implementations for tss.js.
 * Provides:
 *  - TcpSimDevice: MS simulator protocol (IBM tpm_server / swtpm), crash-safe, graceful ECONNREFUSED
 *  - LinuxDevice: Direct /dev/tpmrm0 (RM) or /dev/tpm0 device access
 *  - TbsDevice: Windows TBS (tbs.dll) via koffi
 *  - selectDevice(cfg): Device factory for auto|tcp|linux|tbs
 *  - tpmReachable(cfg): Non-throwing probe for software TPM availability
 */
import net from "node:net";
import fs from "node:fs";

const TPM_SEND_COMMAND = 8;
const SIGNAL_POWER_ON = 1;
const SIGNAL_NV_ON = 11;

const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
};

/**
 * Sends a platform signal to the MS simulator platform port (port + 1).
 */
function sendPlatformSignal(host, port, sig, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    let s;
    let settled = false;
    const cleanup = () => {
      if (t) clearTimeout(t);
      if (s) {
        s.removeAllListeners();
        s.destroy();
      }
    };
    const done = (err, val) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (err) reject(err);
      else resolve(val);
    };

    const t = setTimeout(() => {
      done(Object.assign(new Error(`Platform port ${host}:${port} timeout`), { code: "TPM_TIMEOUT" }));
    }, timeoutMs);

    try {
      s = net.connect({ host, port });
      s.on("error", (e) => done(Object.assign(e, { code: e.code || "TPM_UNAVAILABLE" })));
      s.on("connect", () => s.write(u32(sig)));
      s.on("data", (d) => {
        if (d.length >= 4) {
          done(null, d.readUInt32BE(0));
        }
      });
    } catch (err) {
      done(err);
    }
  });
}

/**
 * Crash-safe MS-simulator-protocol TCP device for tss.js.
 */
export class TcpSimDevice {
  constructor({ host = "127.0.0.1", port = 2321, powerOn = true, timeoutMs = 3000 } = {}) {
    this.host = host;
    this.port = Number(port);
    this.powerOn = Boolean(powerOn);
    this.timeoutMs = Number(timeoutMs);
    this.sock = null;
    this.pending = null;
    this.buf = Buffer.alloc(0);
    this._closed = false;
  }

  async open() {
    this._closed = false;
    if (this.powerOn) {
      // Platform port: idempotent on an already-powered IBM tpm_server (no reset)
      const platPort = this.port + 1;
      for (const sig of [SIGNAL_POWER_ON, SIGNAL_NV_ON]) {
        await sendPlatformSignal(this.host, platPort, sig, this.timeoutMs);
      }
    }

    await new Promise((resolve, reject) => {
      let settled = false;
      const done = (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(t);
        if (err) {
          if (s) {
            s.removeAllListeners();
            s.destroy();
          }
          reject(err);
        } else {
          this.sock = s;
          resolve();
        }
      };

      const t = setTimeout(() => {
        done(Object.assign(new Error(`TPM connect timeout to ${this.host}:${this.port}`), { code: "TPM_TIMEOUT" }));
      }, this.timeoutMs);

      const s = net.connect({ host: this.host, port: this.port });
      s.once("connect", () => done(null));
      s.on("error", (e) => {
        const err = Object.assign(e, { code: e.code || "TPM_UNAVAILABLE" });
        if (this.pending) {
          const p = this.pending;
          this.pending = null;
          p(err);
        } else {
          done(err);
        }
      });
      s.on("close", () => {
        this.sock = null;
        if (this.pending) {
          const p = this.pending;
          this.pending = null;
          p(Object.assign(new Error("TPM socket closed"), { code: "TPM_UNAVAILABLE" }));
        }
      });
      s.on("data", (d) => this._onData(d));
    });
  }

  connect(cb) {
    this.open().then(
      () => cb(null),
      (e) => cb(e)
    );
    return null;
  }

  _onData(d) {
    this.buf = Buffer.concat([this.buf, d]);
    if (this.buf.length < 4) return;
    const n = this.buf.readUInt32BE(0);
    if (this.buf.length < 8 + n) return;

    const resp = Buffer.from(this.buf.subarray(4, 4 + n));
    const ack = this.buf.readUInt32BE(4 + n);
    this.buf = this.buf.length > 8 + n ? Buffer.from(this.buf.subarray(8 + n)) : Buffer.alloc(0);

    const p = this.pending;
    this.pending = null;
    p?.(ack === 0 ? null : new Error(`TPM simulator bad ack: ${ack}`), resp);
  }

  dispatchCommand(cmd, cb) {
    if (!this.sock || this._closed) {
      return setImmediate(cb, Object.assign(new Error("TPM socket closed"), { code: "TPM_UNAVAILABLE" }));
    }
    this.pending = (err, resp) => setImmediate(cb, err, resp);
    const packet = Buffer.concat([u32(TPM_SEND_COMMAND), Buffer.from([0]), u32(cmd.length), cmd]);
    this.sock.write(packet);
  }

  close() {
    this._closed = true;
    if (this.sock) {
      this.sock.removeAllListeners();
      this.sock.destroy();
      this.sock = null;
    }
    this.pending = null;
    this.buf = Buffer.alloc(0);
  }
}

/**
 * Raw TPM 2.0 TCP device for swtpm socket (--server type=tcp,port=...).
 * Does NOT use MS-simulator framing; sends and receives raw TPM2 command/response bytes.
 */
export class SwtpmTcpDevice {
  constructor({ host = "127.0.0.1", port = 2321, ctrlPort = null, timeoutMs = 3000 } = {}) {
    this.host = host;
    this.port = Number(port);
    this.ctrlPort = ctrlPort ? Number(ctrlPort) : (process.env.TPM_SWTPM_CTRL_PORT ? Number(process.env.TPM_SWTPM_CTRL_PORT) : null);
    this.timeoutMs = Number(timeoutMs);
    this.sock = null;
    this.pending = null;
    this.buf = Buffer.alloc(0);
    this._closed = false;
  }

  async open() {
    this._closed = false;

    // Optional CMD_INIT over ctrl channel if ctrlPort configured
    if (this.ctrlPort) {
      await this._sendCtrlInit().catch(() => {});
    }

    await new Promise((resolve, reject) => {
      let settled = false;
      const done = (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(t);
        if (err) {
          if (s) {
            s.removeAllListeners();
            s.destroy();
          }
          reject(err);
        } else {
          this.sock = s;
          resolve();
        }
      };

      const t = setTimeout(() => {
        done(Object.assign(new Error(`swtpm connect timeout to ${this.host}:${this.port}`), { code: "TPM_TIMEOUT" }));
      }, this.timeoutMs);

      const s = net.connect({ host: this.host, port: this.port });
      s.once("connect", () => done(null));
      s.on("error", (e) => {
        const err = Object.assign(e, { code: e.code || "TPM_UNAVAILABLE" });
        if (this.pending) {
          const p = this.pending;
          this.pending = null;
          p(err);
        } else {
          done(err);
        }
      });
      s.on("close", () => {
        this.sock = null;
        if (this.pending) {
          const p = this.pending;
          this.pending = null;
          p(Object.assign(new Error("swtpm socket closed"), { code: "TPM_UNAVAILABLE" }));
        }
      });
      s.on("data", (d) => this._onData(d));
    });
  }

  async _sendCtrlInit() {
    return new Promise((resolve, reject) => {
      const s = net.connect({ host: this.host, port: this.ctrlPort });
      const t = setTimeout(() => {
        s.destroy();
        resolve();
      }, this.timeoutMs);

      s.once("connect", () => {
        // PTM_INIT = 1, flags = 0 (4 bytes cmd + 4 bytes flags)
        const cmd = Buffer.alloc(8);
        cmd.writeUInt32BE(1, 0);
        cmd.writeUInt32BE(0, 4);
        s.write(cmd);
      });

      s.once("data", () => {
        clearTimeout(t);
        s.destroy();
        resolve();
      });

      s.on("error", () => {
        clearTimeout(t);
        s.destroy();
        resolve();
      });
    });
  }

  connect(cb) {
    this.open().then(
      () => cb(null),
      (e) => cb(e)
    );
    return null;
  }

  _onData(d) {
    this.buf = Buffer.concat([this.buf, d]);
    // TPM2 response header: tag (2B), paramSize (4B), responseCode (4B)
    if (this.buf.length < 6) return;
    const respSize = this.buf.readUInt32BE(2);
    if (this.buf.length < respSize) return;

    const resp = Buffer.from(this.buf.subarray(0, respSize));
    this.buf = this.buf.length > respSize ? Buffer.from(this.buf.subarray(respSize)) : Buffer.alloc(0);

    const p = this.pending;
    this.pending = null;
    p?.(null, resp);
  }

  dispatchCommand(cmd, cb) {
    if (!this.sock || this._closed) {
      return setImmediate(cb, Object.assign(new Error("swtpm socket closed"), { code: "TPM_UNAVAILABLE" }));
    }
    this.pending = (err, resp) => setImmediate(cb, err, resp);
    this.sock.write(cmd);
  }

  close() {
    this._closed = true;
    if (this.sock) {
      this.sock.removeAllListeners();
      this.sock.destroy();
      this.sock = null;
    }
    this.pending = null;
    this.buf = Buffer.alloc(0);
  }
}

/**
 * Direct Linux character device interface (/dev/tpmrm0 or /dev/tpm0).
 */
export class LinuxDevice {
  constructor({ path: devPath, timeoutMs = 3000 } = {}) {
    this.devPath = devPath || (fs.existsSync("/dev/tpmrm0") ? "/dev/tpmrm0" : "/dev/tpm0");
    this.timeoutMs = Number(timeoutMs);
    this.fd = null;
  }

  async open() {
    if (!fs.existsSync(this.devPath)) {
      const err = new Error(`TPM device not found: ${this.devPath}`);
      err.code = "ENOENT";
      throw err;
    }
    this.fd = await fs.promises.open(this.devPath, "r+");
  }

  connect(cb) {
    this.open().then(
      () => cb(null),
      (e) => cb(e)
    );
  }

  async _dispatch(cmd) {
    if (!this.fd) {
      throw Object.assign(new Error("TPM device not open"), { code: "TPM_UNAVAILABLE" });
    }
    await this.fd.write(cmd, 0, cmd.length, null);
    const respBuf = Buffer.alloc(4096);
    const { bytesRead } = await this.fd.read(respBuf, 0, 4096, null);
    return respBuf.subarray(0, bytesRead);
  }

  dispatchCommand(cmd, cb) {
    this._dispatch(cmd).then(
      (resp) => cb(null, resp),
      (err) => cb(err)
    );
  }

  async close() {
    if (this.fd) {
      await this.fd.close().catch(() => {});
      this.fd = null;
    }
  }
}

/**
 * Windows TPM Base Services (TBS) device via koffi.
 */
export class TbsDevice {
  constructor({ timeoutMs = 3000 } = {}) {
    this.timeoutMs = Number(timeoutMs);
    this.hCtx = null;
    this._tbs = null;
  }

  async open() {
    if (process.platform !== "win32") {
      throw Object.assign(new Error("TBS device is only supported on Windows"), { code: "ERR_UNSUPPORTED_PLATFORM" });
    }
    let koffi;
    try {
      koffi = (await import("koffi")).default;
    } catch {
      throw Object.assign(new Error("koffi library is required for Windows TBS device"), { code: "ERR_KOFFI_MISSING" });
    }

    const tbsLib = koffi.load("tbs.dll");
    const TBS_CONTEXT_PARAMS2 = koffi.struct("TBS_CONTEXT_PARAMS2", {
      version: "uint32",
      flags: "uint32",
    });

    const Tbsi_Context_Create = tbsLib.func("uint32 __stdcall Tbsi_Context_Create(TBS_CONTEXT_PARAMS2 *params, void **hCtx)");
    const Tbsip_Submit_Command = tbsLib.func("uint32 __stdcall Tbsip_Submit_Command(void *hCtx, uint32 locality, uint32 priority, const uint8_t *cmd, uint32 cmdLen, uint8_t *resp, uint32 *respLen)");
    const Tbsip_Context_Close = tbsLib.func("uint32 __stdcall Tbsip_Context_Close(void *hCtx)");

    const params = { version: 2, flags: 1 << 2 }; // TBS_CONTEXT_CREATE_FLAGS_INCLUDE_TPM20 = 4
    const hCtxPtr = [null];
    const rc = Tbsi_Context_Create(params, hCtxPtr);
    if (rc !== 0) {
      throw Object.assign(new Error(`Tbsi_Context_Create failed with 0x${rc.toString(16)}`), { code: `TBS_ERR_${rc.toString(16)}` });
    }

    this.hCtx = hCtxPtr[0];
    this._tbs = { Tbsip_Submit_Command, Tbsip_Context_Close };
  }

  connect(cb) {
    this.open().then(
      () => cb(null),
      (e) => cb(e)
    );
  }

  dispatchCommand(cmd, cb) {
    if (!this.hCtx || !this._tbs) {
      return setImmediate(cb, Object.assign(new Error("TBS context not open"), { code: "TPM_UNAVAILABLE" }));
    }
    try {
      const resp = Buffer.alloc(4096);
      const respLen = [4096];
      const rc = this._tbs.Tbsip_Submit_Command(this.hCtx, 0, 200, cmd, cmd.length, resp, respLen);
      if (rc !== 0) {
        return cb(new Error(`Tbsip_Submit_Command failed with rc=0x${rc.toString(16)}`));
      }
      cb(null, resp.subarray(0, respLen[0]));
    } catch (err) {
      cb(err);
    }
  }

  close() {
    if (this.hCtx && this._tbs) {
      try {
        this._tbs.Tbsip_Context_Close(this.hCtx);
      } catch {}
      this.hCtx = null;
    }
  }
}

/**
 * Selects and instantiates the appropriate TPM device based on configuration.
 *
 * @param {Object} [cfg]
 * @param {string} [cfg.device] - auto | tcp | linux | tbs
 * @param {string} [cfg.host]
 * @param {number} [cfg.port]
 * @param {boolean} [cfg.powerOn]
 * @param {number} [cfg.timeoutMs]
 * @returns {TcpSimDevice|LinuxDevice|TbsDevice}
 */
export function selectDevice(cfg = {}) {
  const devType = (cfg.device || process.env.TPM_DEVICE || "auto").toLowerCase();
  const host = cfg.host || process.env.TPM_TCP_HOST || "127.0.0.1";
  const port = Number(cfg.port || process.env.TPM_TCP_PORT || 2321);
  const powerOn = cfg.powerOn ?? (process.env.TPM_TCP_POWERON !== "0");
  const timeoutMs = Number(cfg.timeoutMs || process.env.TPM_CONNECT_TIMEOUT_MS || 3000);

  if (devType === "tcp") {
    return new TcpSimDevice({ host, port, powerOn, timeoutMs });
  }
  if (devType === "swtpm") {
    const ctrlPort = cfg.ctrlPort || (process.env.TPM_SWTPM_CTRL_PORT ? Number(process.env.TPM_SWTPM_CTRL_PORT) : null);
    return new SwtpmTcpDevice({ host, port, ctrlPort, timeoutMs });
  }
  if (devType === "linux") {
    return new LinuxDevice({ timeoutMs });
  }
  if (devType === "tbs") {
    return new TbsDevice({ timeoutMs });
  }
  if (devType === "auto") {
    if (process.platform === "win32") {
      return new TbsDevice({ timeoutMs });
    }
    if (process.platform === "linux" && (fs.existsSync("/dev/tpmrm0") || fs.existsSync("/dev/tpm0"))) {
      return new LinuxDevice({ timeoutMs });
    }
    return new TcpSimDevice({ host, port, powerOn, timeoutMs });
  }
  throw new Error(`Unknown TPM device type: ${devType}`);
}

/**
 * Probes whether a software TPM is currently reachable on the specified TCP endpoint.
 * Never throws an unhandled error or crashes the process.
 *
 * @param {Object} [options]
 * @param {string} [options.host] - Default 127.0.0.1
 * @param {number} [options.port] - Default 2321
 * @param {number} [options.timeoutMs] - Default 500 ms
 * @returns {Promise<boolean>}
 */
export async function tpmReachable({ host = process.env.TPM_TCP_HOST || "127.0.0.1", port = +(process.env.TPM_TCP_PORT || 2321), timeoutMs = 500 } = {}) {
  return new Promise((resolve) => {
    let s;
    let settled = false;
    const cleanup = () => {
      if (t) clearTimeout(t);
      if (s) {
        s.removeAllListeners();
        s.destroy();
      }
    };
    const finish = (result) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(result);
    };

    const t = setTimeout(() => finish(false), timeoutMs);

    try {
      s = net.connect({ host, port: Number(port) });
      s.on("error", () => finish(false));
      s.once("connect", () => {
        // Send a lightweight GetRandom(8) command to confirm it's actually a responsive TPM simulator
        // TPM2_GetRandom(8): tag=0x8001 (no session), size=12, cc=0x0000017B (TPM_CC_GetRandom), bytesRequested=8
        const cmd = Buffer.from([
          0x80, 0x01,             // TPM_ST_NO_SESSIONS
          0x00, 0x00, 0x00, 0x0c, // size = 12
          0x00, 0x00, 0x01, 0x7b, // TPM_CC_GetRandom
          0x00, 0x08              // 8 bytes
        ]);
        const packet = Buffer.concat([u32(TPM_SEND_COMMAND), Buffer.from([0]), u32(cmd.length), cmd]);
        s.write(packet);
        s.once("data", (d) => {
          // If response has simulator framing and ack=0
          if (d.length >= 8) {
            finish(true);
          } else {
            finish(true);
          }
        });
      });
    } catch {
      finish(false);
    }
  });
}

/**
 * Probes whether a swtpm raw socket is currently reachable on the specified TCP endpoint.
 *
 * @param {Object} [options]
 * @param {string} [options.host] - Default 127.0.0.1
 * @param {number} [options.port] - Default 2321
 * @param {number} [options.timeoutMs] - Default 500 ms
 * @returns {Promise<boolean>}
 */
export async function swtpmReachable({ host = process.env.TPM_TCP_HOST || "127.0.0.1", port = +(process.env.TPM_TCP_PORT || 2321), timeoutMs = 500 } = {}) {
  return new Promise((resolve) => {
    let s;
    let settled = false;
    const cleanup = () => {
      if (t) clearTimeout(t);
      if (s) {
        s.removeAllListeners();
        s.destroy();
      }
    };
    const finish = (result) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(result);
    };

    const t = setTimeout(() => finish(false), timeoutMs);

    try {
      s = net.connect({ host, port: Number(port) });
      s.on("error", () => finish(false));
      s.once("connect", () => {
        // Raw TPM2_GetRandom(8) command
        const cmd = Buffer.from([
          0x80, 0x01,             // TPM_ST_NO_SESSIONS
          0x00, 0x00, 0x00, 0x0c, // size = 12
          0x00, 0x00, 0x01, 0x7b, // TPM_CC_GetRandom
          0x00, 0x08              // 8 bytes
        ]);
        s.write(cmd);
        s.once("data", (d) => {
          if (d.length >= 10) {
            finish(true);
          } else {
            finish(false);
          }
        });
      });
    } catch {
      finish(false);
    }
  });
}

