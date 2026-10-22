import { test, describe, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";
import * as jose from "jose";

import {
  createAuditLog,
  verifyAuditLog,
  signAuditHash,
  verifyAuditSig,
} from "../lib/audit-log.js";
import { canonical, sha256 } from "../lib/canonical.js";

describe("WP4: Signed Audit Log", () => {
  let tmpDir;
  let testKey;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "zta-audit-test-"));
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256", {
      extractable: true,
    });
    const publicJwk = await jose.exportJWK(publicKey);
    publicJwk.alg = "ES256";
    publicJwk.use = "sig";
    testKey = { privateKey, publicJwk };
  });

  afterEach(() => {
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test("3 appends produce a valid, verifiable hash-chained audit log", async () => {
    const logFile = path.join(tmpDir, "pep.log");
    const auditLog = createAuditLog({ file: logFile, key: testKey });

    const r1 = auditLog.append({
      decision: "permit",
      sub: "alice",
      resource: "company.news",
    });
    assert.equal(r1.seq, 1);
    assert.equal(r1.prev, "0".repeat(64));
    assert.ok(r1.hash);
    assert.ok(r1.sig);

    const r2 = auditLog.append({
      decision: "step_up",
      sub: "alice",
      resource: "company.audit",
    });
    assert.equal(r2.seq, 2);
    assert.equal(r2.prev, r1.hash);
    assert.ok(r2.hash);

    const r3 = auditLog.append({
      decision: "deny",
      sub: "bob",
      resource: "company.audit",
    });
    assert.equal(r3.seq, 3);
    assert.equal(r3.prev, r2.hash);
    assert.ok(r3.hash);

    // Verify through library function
    const result = await verifyAuditLog(logFile, { publicJwk: testKey.publicJwk });
    assert.equal(result.valid, true);
    assert.equal(result.count, 3);
  });

  test("editing line 2 is detected as tampering", async () => {
    const logFile = path.join(tmpDir, "pep.log");
    const auditLog = createAuditLog({ file: logFile, key: testKey });

    auditLog.append({ event: "login", user: "alice" });
    auditLog.append({ event: "access", user: "alice", decision: "deny" });
    auditLog.append({ event: "logout", user: "alice" });

    // Read lines
    const lines = fs.readFileSync(logFile, "utf8").trim().split("\n");
    assert.equal(lines.length, 3);

    // Tamper with line 2: change decision from "deny" to "permit"
    const parsedLine2 = JSON.parse(lines[1]);
    parsedLine2.decision = "permit"; // changed payload without re-hashing
    lines[1] = JSON.stringify(parsedLine2);
    fs.writeFileSync(logFile, lines.join("\n") + "\n");

    const result = await verifyAuditLog(logFile, { publicJwk: testKey.publicJwk });
    assert.equal(result.valid, false);
    assert.equal(result.lineNum, 2);
    assert.match(result.error, /Hash tampering detected/);
  });

  test("editing line 2 with forged hash is detected via signature failure and broken chain", async () => {
    const logFile = path.join(tmpDir, "pep.log");
    const auditLog = createAuditLog({ file: logFile, key: testKey });

    auditLog.append({ event: "1" });
    auditLog.append({ event: "2" });
    auditLog.append({ event: "3" });

    const lines = fs.readFileSync(logFile, "utf8").trim().split("\n");
    const parsedLine2 = JSON.parse(lines[1]);
    parsedLine2.event = "tampered_event";
    const { hash, sig, ...rawEntry } = parsedLine2;
    parsedLine2.hash = sha256(canonical(rawEntry), "hex");
    // Signature is still old sig over original hash
    lines[1] = JSON.stringify(parsedLine2);
    fs.writeFileSync(logFile, lines.join("\n") + "\n");

    const result = await verifyAuditLog(logFile, { publicJwk: testKey.publicJwk });
    assert.equal(result.valid, false);
    assert.equal(result.lineNum, 2);
    assert.match(result.error, /Signature verification failed/);
  });

  test("deleting line 2 is detected via sequence and chain disruption", async () => {
    const logFile = path.join(tmpDir, "pep.log");
    const auditLog = createAuditLog({ file: logFile, key: testKey });

    auditLog.append({ step: 1 });
    auditLog.append({ step: 2 });
    auditLog.append({ step: 3 });

    const lines = fs.readFileSync(logFile, "utf8").trim().split("\n");
    assert.equal(lines.length, 3);

    // Delete line 2: lines now has [line1, line3]
    lines.splice(1, 1);
    fs.writeFileSync(logFile, lines.join("\n") + "\n");

    const result = await verifyAuditLog(logFile, { publicJwk: testKey.publicJwk });
    assert.equal(result.valid, false);
    assert.equal(result.lineNum, 2); // line 3 is now evaluated at position 2
    assert.match(result.error, /Sequence mismatch/);
  });

  test("reopening log on restart recovers seq and prev from last entry", async () => {
    const logFile = path.join(tmpDir, "pep.log");
    const log1 = createAuditLog({ file: logFile, key: testKey });
    const r1 = log1.append({ record: "first" });
    const r2 = log1.append({ record: "second" });

    assert.equal(r2.seq, 2);

    // Restart service: create new audit log instance pointing to the same file
    const log2 = createAuditLog({ file: logFile, key: testKey });
    assert.equal(log2.getSeq(), 2);
    assert.equal(log2.getPrev(), r2.hash);

    const r3 = log2.append({ record: "third" });
    assert.equal(r3.seq, 3);
    assert.equal(r3.prev, r2.hash);

    const result = await verifyAuditLog(logFile, { publicJwk: testKey.publicJwk });
    assert.equal(result.valid, true);
    assert.equal(result.count, 3);
  });

  test("scripts/verify-audit.js CLI verifies valid log and fails on invalid log", async () => {
    // Write test key to tmp data directory
    const dataDir = path.join(tmpDir, "data");
    const keysDir = path.join(dataDir, "keys");
    fs.mkdirSync(keysDir, { recursive: true });

    // Persist test audit key in keysDir/audit.jwk
    const privateJwk = await jose.exportJWK(testKey.privateKey);
    privateJwk.kid = "test-audit-kid";
    privateJwk.alg = "ES256";
    privateJwk.use = "sig";
    fs.writeFileSync(path.join(keysDir, "audit.jwk"), JSON.stringify(privateJwk));

    const logFile = path.join(dataDir, "audit", "pep.log");
    const auditLog = createAuditLog({ file: logFile, key: testKey });
    auditLog.append({ action: "test-cli-1" });
    auditLog.append({ action: "test-cli-2" });

    const verifyScript = path.resolve("./scripts/verify-audit.js");

    // Run CLI on valid log
    const outputGood = execFileSync(
      process.execPath,
      [verifyScript, logFile],
      {
        env: { ...process.env, ZTA_DATA_DIR: dataDir },
        encoding: "utf8",
      }
    );
    assert.match(outputGood, /SUCCESS/);

    // Tamper with log
    fs.appendFileSync(logFile, JSON.stringify({ seq: 99, bad: true }) + "\n");

    // Run CLI on invalid log -> expects exit code 1
    assert.throws(
      () => {
        execFileSync(process.execPath, [verifyScript, logFile], {
          env: { ...process.env, ZTA_DATA_DIR: dataDir },
          encoding: "utf8",
        });
      },
      (err) => err.status === 1
    );
  });
});
