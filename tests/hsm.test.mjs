/**
 * @file tests/hsm.test.mjs
 * Signing keys in a PKCS#11 token (SoftHSM): generated inside the token, never extractable,
 * stable across sessions, and usable for JWTs (AR, access token) and the audit log.
 * Skipped when SoftHSM or graphene-pk11 is not installed.
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import * as jose from "jose";

const CANDIDATE_LIBS = [
  process.env.ZTA_PKCS11_LIB,
  "/opt/homebrew/lib/softhsm/libsofthsm2.so",
  "/usr/local/lib/softhsm/libsofthsm2.so",
  "/usr/lib/softhsm/libsofthsm2.so",
  "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
].filter(Boolean);
const LIB = CANDIDATE_LIBS.find((p) => fs.existsSync(p));

let grapheneOk = true;
try {
  await import("graphene-pk11");
} catch {
  grapheneOk = false;
}
let utilOk = true;
try {
  execFileSync("softhsm2-util", ["--version"], { stdio: "ignore" });
} catch {
  utilOk = false;
}
const skip = !LIB || !grapheneOk || !utilOk ? "SoftHSM / graphene-pk11 not installed" : false;

describe("HSM-held signing keys (PKCS#11, SoftHSM)", { skip }, () => {
  let dir;
  let hsm;
  let keys;
  let audit;
  const PIN = "1234";

  before(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "zta-softhsm-"));
    fs.mkdirSync(path.join(dir, "tokens"));
    const conf = path.join(dir, "softhsm2.conf");
    fs.writeFileSync(conf, `directories.tokendir = ${path.join(dir, "tokens")}\nobjectstore.backend = file\n`);
    process.env.SOFTHSM2_CONF = conf;
    execFileSync("softhsm2-util", ["--init-token", "--free", "--label", "zta-test", "--pin", PIN, "--so-pin", "5678"], { stdio: "ignore" });
    process.env.ZTA_HSM = "pkcs11";
    process.env.ZTA_PKCS11_LIB = LIB;
    process.env.ZTA_PKCS11_TOKEN = "zta-test";
    process.env.ZTA_PKCS11_PIN = PIN;
    hsm = await import("../lib/hsm.js");
    keys = await import("../lib/keys.js");
    audit = await import("../lib/audit-log.js");
  });

  after(() => {
    hsm?.closeHsmSessions();
    delete process.env.ZTA_HSM;
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("generates the key inside the token and signs a JWT that verifies with its JWK", async () => {
    const key = await keys.loadOrCreateSigningKey("verifier", { store: "file", dataDir: dir });
    assert.equal(key.hsm, true);
    assert.equal(key.privateKey, undefined, "no private key material outside the token");
    const jwt = await keys.signJwt(key, { alg: "ES256", typ: "ar+jwt", kid: key.kid }, { sub: "dev-1", status: "pass" });
    const { payload, protectedHeader } = await jose.jwtVerify(jwt, await jose.importJWK(key.publicJwk, "ES256"));
    assert.equal(payload.sub, "dev-1");
    assert.equal(protectedHeader.kid, key.kid);
  });

  it("the private key is not extractable", async () => {
    const opts = { lib: LIB, token: "zta-test", pin: PIN };
    assert.deepEqual(await hsm.describeHsmKey("verifier", opts), { extractable: false, sensitive: true, valueReadable: false });
  });

  it("returns the same key (kid) in a new session", async () => {
    const first = await keys.loadOrCreateSigningKey("idp", { store: "file", dataDir: dir });
    hsm.closeHsmSessions();
    const again = await keys.loadOrCreateSigningKey("idp", { store: "file", dataDir: dir });
    assert.equal(again.kid, first.kid);
  });

  it("signs audit-log hashes that verify with the public key", async () => {
    const key = await keys.loadOrCreateSigningKey("audit", { store: "file", dataDir: dir });
    const sig = audit.signAuditHash("abc123", key);
    assert.equal(audit.verifyAuditSig("abc123", sig, key), true);
    assert.equal(audit.verifyAuditSig("abc124", sig, key), false);
  });
});
