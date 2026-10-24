/**
 * @file tcg-eventlog.test.mjs
 * Unit tests for TCG PC Client crypto-agile event log parser, replayer, and RV capture.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";

import {
  EV,
  ALG,
  TcgEventLogError,
  MAX_LOG_BYTES,
  MAX_EVENT_DATA,
  parseTcgEventLog,
  replayTcgEventLog,
  pcrCompositeDigest,
  toAppraisalEvents,
  checkEventDataDigests,
  describeEvent,
  decodeEvidenceLog,
} from "../lib/verifier/tcg-eventlog.js";

import {
  loadReferenceValues,
  loadReferenceValuesFrom,
} from "../lib/verifier/reference-values.js";

import { MeasuredBootManager } from "../lib/tpm-real/measured-boot.js";
import { TpmError } from "../lib/tpm-real/tpm-conn.js";

const FIXTURES_DIR = path.resolve("fixtures/eventlogs");
const EXPECTED_PATH = path.join(FIXTURES_DIR, "expected.json");
const expectedData = JSON.parse(fs.readFileSync(EXPECTED_PATH, "utf8"));

test("TCG Event Log Unit Tests", async (t) => {
  await t.test("1. Crypto-agile fixtures in expected.json parse and match ground truth", () => {
    for (const [relPath, exp] of Object.entries(expectedData.logs)) {
      if (!exp.agile) continue;
      const fullPath = path.join(FIXTURES_DIR, relPath);
      const buf = fs.readFileSync(fullPath);

      const parsed = parseTcgEventLog(buf);
      assert.ok(parsed.specId, `specId missing for ${relPath}`);
      assert.strictEqual(parsed.events.length, exp.events, `Event count mismatch for ${relPath}`);

      // Check algorithm table
      const parsedAlgs = {};
      for (const a of parsed.specId.algorithms) {
        parsedAlgs[a.name] = a.digestSize;
      }
      for (const [algName, size] of Object.entries(exp.algs)) {
        assert.strictEqual(parsedAlgs[algName], size, `Alg size mismatch for ${algName} in ${relPath}`);
      }

      // Check pcrsUsed
      const pcrsUsed = [...new Set(parsed.events.map((e) => e.pcr))].sort((a, b) => a - b);
      assert.deepStrictEqual(pcrsUsed, exp.pcrsUsed, `pcrsUsed mismatch for ${relPath}`);

      // Replay SHA-256 PCR0..7
      if (exp.sha256) {
        const replayed = replayTcgEventLog(parsed, { bank: "sha256", pcrs: [0, 1, 2, 3, 4, 5, 6, 7] });
        for (let p = 0; p < 8; p++) {
          const expectedHex = exp.sha256[String(p)];
          if (expectedHex) {
            const actualHex = replayed.pcrs[p].toString("hex").toLowerCase();
            assert.strictEqual(actualHex, expectedHex.toLowerCase(), `PCR${p} replay mismatch for ${relPath}`);
          }
        }

        const comp = pcrCompositeDigest(replayed.pcrs, [0, 1, 2, 3, 4, 5, 6, 7]).toString("hex").toLowerCase();
        assert.strictEqual(comp, exp.sha256QuoteDigestPcr0to7.toLowerCase(), `Composite digest mismatch for ${relPath}`);
      }
    }
  });

  await t.test("2. ubuntu-noble-arm64-edk2.bin replayed PCR0..7 equals pcrs-sha256.txt kernel ground truth", () => {
    const logPath = path.join(FIXTURES_DIR, "qemu-edk2-swtpm/ubuntu-noble-arm64-edk2.bin");
    const txtPath = path.join(FIXTURES_DIR, "qemu-edk2-swtpm/ubuntu-noble-arm64-edk2.pcrs-sha256.txt");
    const buf = fs.readFileSync(logPath);
    const txt = fs.readFileSync(txtPath, "utf8");

    // Parse ground truth lines: "0 f39f09c767..."
    const kernelPcrs = {};
    for (const line of txt.trim().split("\n")) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 2) {
        kernelPcrs[Number(parts[0])] = parts[1].toLowerCase();
      }
    }

    const parsed = parseTcgEventLog(buf);
    const replayed = replayTcgEventLog(parsed, { bank: "sha256", pcrs: [0, 1, 2, 3, 4, 5, 6, 7] });

    for (let p = 0; p < 8; p++) {
      assert.strictEqual(
        replayed.pcrs[p].toString("hex").toLowerCase(),
        kernelPcrs[p],
        `PCR${p} does not match kernel ground truth sysfs`
      );
    }
  });

  await t.test("3. event-uefi-sha1-log.bin throws TcgEventLogError with code not_crypto_agile", () => {
    const logPath = path.join(FIXTURES_DIR, "tpm2-tools/event-uefi-sha1-log.bin");
    const buf = fs.readFileSync(logPath);

    assert.throws(
      () => parseTcgEventLog(buf),
      (err) => {
        assert.ok(err instanceof TcgEventLogError);
        assert.strictEqual(err.code, "not_crypto_agile");
        return true;
      }
    );
  });

  await t.test("4. specid-vendordata.bin: 0 events, vendorInfo parsed, replay gives all-zero PCRs", () => {
    const logPath = path.join(FIXTURES_DIR, "tpm2-tools/specid-vendordata.bin");
    const buf = fs.readFileSync(logPath);

    const parsed = parseTcgEventLog(buf);
    assert.strictEqual(parsed.events.length, 0);
    assert.strictEqual(parsed.specId.vendorInfo.toString("hex"), "deadbeef");

    const replayed = replayTcgEventLog(parsed, { bank: "sha256", pcrs: [0, 1, 2, 3, 4, 5, 6, 7] });
    for (let p = 0; p < 8; p++) {
      assert.strictEqual(replayed.pcrs[p].toString("hex"), "00".repeat(32));
    }
  });

  await t.test("5. Trailing-zero tolerance: fixture + 64 KiB of zeros parses identically, trailingBytes === 65536", () => {
    const logPath = path.join(FIXTURES_DIR, "qemu-edk2-swtpm/ubuntu-noble-arm64-edk2.bin");
    const originalBuf = fs.readFileSync(logPath);
    const paddedBuf = Buffer.concat([originalBuf, Buffer.alloc(65536, 0)]);

    const origParsed = parseTcgEventLog(originalBuf);
    const paddedParsed = parseTcgEventLog(paddedBuf);

    assert.strictEqual(paddedParsed.events.length, origParsed.events.length);
    assert.strictEqual(paddedParsed.trailingBytes, 65536);
    assert.deepStrictEqual(
      paddedParsed.events.map((e) => ({ pcr: e.pcr, type: e.type, digests: e.digests })),
      origParsed.events.map((e) => ({ pcr: e.pcr, type: e.type, digests: e.digests }))
    );
  });

  await t.test("6. Truncation fuzz: prefix parse or TcgEventLogError without hanging or other errors", () => {
    const start = Date.now();
    for (const [relPath, exp] of Object.entries(expectedData.logs)) {
      if (!exp.agile) continue;
      const buf = fs.readFileSync(path.join(FIXTURES_DIR, relPath));
      const len = buf.length;

      let offsets = [];
      if (len < 4096) {
        for (let i = 0; i < len; i++) offsets.push(i);
      } else {
        const step = Math.floor(len / 97);
        for (let i = 0; i < len; i += step) offsets.push(i);
      }

      for (const off of offsets) {
        const cut = buf.subarray(0, off);
        try {
          const parsed = parseTcgEventLog(cut);
          // If it parsed successfully, replay must succeed
          const replayed = replayTcgEventLog(parsed);
          assert.ok(replayed.pcrs);
        } catch (err) {
          assert.ok(
            err instanceof TcgEventLogError,
            `Expected TcgEventLogError for ${relPath} cut at ${off}, got ${err.name}: ${err.message}`
          );
        }
      }
    }
    const elapsed = Date.now() - start;
    assert.ok(elapsed < 5000, `Truncation fuzz took too long: ${elapsed} ms`);
  });

  await t.test("7. Mutations: unknown_alg, bad_digest_count, eventSize = 0xFFFFFFFF, buffer > MAX_LOG_BYTES", () => {
    const logPath = path.join(FIXTURES_DIR, "tpm2-tools/event.bin");
    const buf = Buffer.from(fs.readFileSync(logPath));

    // Buffer above MAX_LOG_BYTES -> too_large
    const hugeBuf = Buffer.alloc(MAX_LOG_BYTES + 10);
    assert.throws(
      () => parseTcgEventLog(hugeBuf),
      (err) => err instanceof TcgEventLogError && err.code === "too_large"
    );

    // Parse event.bin to find first event offset
    const parsed = parseTcgEventLog(buf);
    assert.ok(parsed.events.length > 0);
    const evOff = parsed.events[0].offset;

    // Mutate count to larger than Spec ID algorithms -> bad_digest_count
    const badCountBuf = Buffer.from(buf);
    badCountBuf.writeUInt32LE(99, evOff + 8);
    assert.throws(
      () => parseTcgEventLog(badCountBuf),
      (err) => err instanceof TcgEventLogError && err.code === "bad_digest_count"
    );

    // Mutate algId in first event to unknown 0x7777 -> unknown_alg
    const badAlgBuf = Buffer.from(buf);
    badAlgBuf.writeUInt16LE(0x7777, evOff + 12);
    assert.throws(
      () => parseTcgEventLog(badAlgBuf),
      (err) => err instanceof TcgEventLogError && err.code === "unknown_alg"
    );

    // Mutate eventSize in legacy header to 0xFFFFFFFF -> truncated or too_large
    const badEvSizeBuf = Buffer.from(buf);
    badEvSizeBuf.writeUInt32LE(0xffffffff, 28);
    assert.throws(
      () => parseTcgEventLog(badEvSizeBuf),
      (err) => err instanceof TcgEventLogError && (err.code === "truncated" || err.code === "too_large")
    );
  });

  await t.test("8. StartupLocality: synthetic log with NO_ACTION StartupLocality\\0 + 0x03 gives PCR0 initial 00..03", () => {
    // Construct minimal synthetic log
    // 1. Legacy header (32 bytes) + Spec ID event (28 + 4 + 1 = 33 bytes)
    const specBuf = Buffer.alloc(33);
    specBuf.write("Spec ID Event03\0", 0, 16, "latin1");
    specBuf.writeUInt32LE(0, 16); // platformClass
    specBuf.writeUInt8(0, 20); // minor
    specBuf.writeUInt8(2, 21); // major
    specBuf.writeUInt8(0, 22); // errata
    specBuf.writeUInt8(2, 23); // uintnSize
    specBuf.writeUInt32LE(1, 24); // 1 algorithm
    specBuf.writeUInt16LE(0x000b, 28); // sha256
    specBuf.writeUInt16LE(32, 30); // 32 bytes
    specBuf.writeUInt8(0, 32); // vendorInfoSize = 0

    const legHdr = Buffer.alloc(32);
    legHdr.writeUInt32LE(0, 0); // PCR0
    legHdr.writeUInt32LE(3, 4); // EV_NO_ACTION
    legHdr.writeUInt32LE(specBuf.length, 28);

    // 2. StartupLocality event (EV_NO_ACTION on PCR0)
    const locData = Buffer.concat([Buffer.from("StartupLocality\0", "latin1"), Buffer.from([0x03])]);
    const ev1Hdr = Buffer.alloc(12 + 2 + 32 + 4);
    ev1Hdr.writeUInt32LE(0, 0); // PCR0
    ev1Hdr.writeUInt32LE(3, 4); // EV_NO_ACTION
    ev1Hdr.writeUInt32LE(1, 8); // 1 digest
    ev1Hdr.writeUInt16LE(0x000b, 12);
    // 32-byte digest in NO_ACTION is zeros
    ev1Hdr.writeUInt32LE(locData.length, 12 + 2 + 32);
    const ev1 = Buffer.concat([ev1Hdr, locData]);

    // 3. Normal extend event on PCR0
    const mDigest = crypto.createHash("sha256").update("test measurement").digest();
    const ev2Data = Buffer.from("test measurement", "utf8");
    const ev2Hdr = Buffer.alloc(12 + 2 + 32 + 4);
    ev2Hdr.writeUInt32LE(0, 0); // PCR0
    ev2Hdr.writeUInt32LE(0x4, 4); // EV_SEPARATOR
    ev2Hdr.writeUInt32LE(1, 8); // 1 digest
    ev2Hdr.writeUInt16LE(0x000b, 12);
    mDigest.copy(ev2Hdr, 14);
    ev2Hdr.writeUInt32LE(ev2Data.length, 12 + 2 + 32);
    const ev2 = Buffer.concat([ev2Hdr, ev2Data]);

    const syntheticLog = Buffer.concat([legHdr, specBuf, ev1, ev2]);
    const parsed = parseTcgEventLog(syntheticLog);
    const replayed = replayTcgEventLog(parsed, { bank: "sha256", pcrs: [0] });

    assert.strictEqual(replayed.startupLocality, 3);

    // Hand compute expected PCR0:
    // Initial PCR0 = 31 zeros + 0x03
    const initPcr0 = Buffer.alloc(32, 0);
    initPcr0[31] = 0x03;
    const expectedPcr0 = crypto.createHash("sha256").update(Buffer.concat([initPcr0, mDigest])).digest();

    assert.strictEqual(replayed.pcrs[0].toString("hex"), expectedPcr0.toString("hex"));
  });

  await t.test("9. toAppraisalEvents on GCE log: no PCR 8/9/14, no NO_ACTION, count matches eventsPcr0to7", () => {
    const logPath = path.join(FIXTURES_DIR, "tpm2-tools/event-gce-ubuntu-2104-log.bin");
    const buf = fs.readFileSync(logPath);
    const parsed = parseTcgEventLog(buf);

    const appEvents = toAppraisalEvents(parsed, { bank: "sha256", pcrs: [0, 1, 2, 3, 4, 5, 6, 7] });
    const expCount = expectedData.logs["tpm2-tools/event-gce-ubuntu-2104-log.bin"].eventsPcr0to7;

    assert.strictEqual(appEvents.length, expCount);
    for (const ev of appEvents) {
      assert.ok(ev.pcr >= 0 && ev.pcr <= 7, `PCR ${ev.pcr} outside 0..7 in appraisal events`);
      assert.notStrictEqual(ev.type, EV.NO_ACTION, "NO_ACTION found in appraisal events");
      assert.ok(ev.digest && /^[0-9a-f]{64}$/.test(ev.digest));
      assert.ok(typeof ev.desc === "string");
    }
  });

  await t.test("10. checkEventDataDigests returns [] for captured log and GCE log", () => {
    const capBuf = fs.readFileSync(path.join(FIXTURES_DIR, "qemu-edk2-swtpm/ubuntu-noble-arm64-edk2.bin"));
    const gceBuf = fs.readFileSync(path.join(FIXTURES_DIR, "tpm2-tools/event-gce-ubuntu-2104-log.bin"));

    const capBad = checkEventDataDigests(parseTcgEventLog(capBuf));
    assert.deepStrictEqual(capBad, []);

    const gceBad = checkEventDataDigests(parseTcgEventLog(gceBuf));
    assert.deepStrictEqual(gceBad, []);
  });

  await t.test("11. loadReferenceValues returns the same sets for legacy file and zta-rv/1 converted file", () => {
    const legacyPath = path.resolve("fixtures/golden-boot.json");
    const legacyRv = loadReferenceValues(legacyPath);

    // Convert legacy events into zta-rv/1 format
    const legacyEvents = JSON.parse(fs.readFileSync(legacyPath, "utf8"));
    const ztaEvents = {};
    for (const e of legacyEvents) {
      if (!ztaEvents[e.pcr]) ztaEvents[e.pcr] = [];
      ztaEvents[e.pcr].push({
        digest: e.digest,
        type: "LEGACY_EVENT",
        desc: e.desc,
      });
    }

    const ztaRv1 = {
      format: "zta-rv/1",
      name: "converted-golden-boot",
      bank: "sha256",
      pcrs: [0, 1, 2, 3, 4, 5, 6, 7],
      events: ztaEvents,
      compositeDigests: [],
    };

    const tmpZtaPath = path.resolve("/tmp/test-zta-rv1.json");
    fs.writeFileSync(tmpZtaPath, JSON.stringify(ztaRv1, null, 2));

    const ztaLoaded = loadReferenceValues(tmpZtaPath);
    for (let p = 0; p < 8; p++) {
      assert.deepStrictEqual(
        [...(ztaLoaded[p] || [])].sort(),
        [...(legacyRv[p] || [])].sort(),
        `PCR${p} sets mismatch between legacy and zta-rv/1`
      );
    }
    fs.unlinkSync(tmpZtaPath);
  });

  await t.test("12. rv-capture CLI (spawned): union two logs, --print exit 0, bad log exit 2", () => {
    const log1 = path.join(FIXTURES_DIR, "qemu-edk2-swtpm/ubuntu-noble-arm64-edk2.bin");
    const log2 = path.join(FIXTURES_DIR, "tpm2-tools/event-arch-linux.bin");
    const outPath = "/tmp/test-rv-union.json";

    // Two --log inputs -> union
    const r1 = spawnSync(
      process.execPath,
      ["scripts/rv-capture.mjs", "--log", log1, "--log", log2, "--name", "union-test", "--out", outPath],
      { encoding: "utf8" }
    );
    assert.strictEqual(r1.status, 0, `rv-capture failed: ${r1.stderr}`);
    const outData = JSON.parse(fs.readFileSync(outPath, "utf8"));
    assert.strictEqual(outData.source.logs.length, 2);
    assert.strictEqual(outData.compositeDigests.length, 2);
    fs.unlinkSync(outPath);

    // --print exit 0
    const r2 = spawnSync(
      process.execPath,
      ["scripts/rv-capture.mjs", "--log", log1, "--print"],
      { encoding: "utf8" }
    );
    assert.strictEqual(r2.status, 0);
    assert.match(r2.stdout, /PCR Digest Summary/);

    // Bad log -> exit 2 with a message
    const r3 = spawnSync(
      process.execPath,
      ["scripts/rv-capture.mjs", "--log", path.join(FIXTURES_DIR, "tpm2-tools/event-uefi-sha1-log.bin")],
      { encoding: "utf8" }
    );
    assert.strictEqual(r3.status, 2);
    assert.match(r3.stderr, /Error parsing event log/);
  });

  await t.test("13. MeasuredBootManager Linux event log reading: path, auto, off, require", async () => {
    const stubConn = {
      call: async () => ({ pcrValues: [] }),
    };

    const logPath = path.join(FIXTURES_DIR, "qemu-edk2-swtpm/ubuntu-noble-arm64-edk2.bin");
    const originalPath = process.env.TPM_EVENTLOG_PATH;
    const originalMode = process.env.TPM_EVENTLOG;

    try {
      // 1. Success reading fixture
      process.env.TPM_EVENTLOG_PATH = logPath;
      process.env.TPM_EVENTLOG = "auto";
      const mgr = new MeasuredBootManager({ conn: stubConn, deviceType: "linux" });
      await mgr.init();
      const log = mgr.readEventLog();
      assert.ok(log);
      assert.strictEqual(log.format, "tcg2-binary");
      const expectedData = fs.readFileSync(logPath).toString("base64url");
      assert.strictEqual(log.data, expectedData);

      // 2. Mode off -> returns null
      process.env.TPM_EVENTLOG = "off";
      const mgrOff = new MeasuredBootManager({ conn: stubConn, deviceType: "linux" });
      await mgrOff.init();
      assert.strictEqual(mgrOff.readEventLog(), null);

      // 3. Mode auto with unreadable path -> returns null with warning
      process.env.TPM_EVENTLOG = "auto";
      process.env.TPM_EVENTLOG_PATH = "/tmp/non-existent-binary-log";
      const mgrAutoMissing = new MeasuredBootManager({ conn: stubConn, deviceType: "linux" });
      await mgrAutoMissing.init();
      assert.strictEqual(mgrAutoMissing.readEventLog(), null);

      // 4. Mode require with unreadable path -> throws TpmError("EVENTLOG_UNAVAILABLE")
      process.env.TPM_EVENTLOG = "require";
      const mgrReq = new MeasuredBootManager({ conn: stubConn, deviceType: "linux" });
      await mgrReq.init();
      assert.throws(
        () => mgrReq.readEventLog(),
        (err) => {
          assert.ok(err instanceof TpmError);
          assert.strictEqual(err.code, "EVENTLOG_UNAVAILABLE");
          return true;
        }
      );
    } finally {
      if (originalPath !== undefined) process.env.TPM_EVENTLOG_PATH = originalPath;
      else delete process.env.TPM_EVENTLOG_PATH;
      if (originalMode !== undefined) process.env.TPM_EVENTLOG = originalMode;
      else delete process.env.TPM_EVENTLOG;
    }
  });
});
