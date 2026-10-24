/**
 * @file verify3-regressions.test.mjs
 * Regression tests for the VERIFY3 findings on the real TPM 2.0 backend:
 *  V1 quote appraisal binds the PCR selection (exactly SHA-256 PCR0..7) and needs a non-empty,
 *     golden-covering event log; V2 the X.509 EK certificate is bound to the TPMT_PUBLIC EK;
 *  V3 no TOFU at appraisal time; V4 TPM lost/reset mid-run -> reconnect or 503 tpm_unavailable;
 *  V5 /agent/debug/tamper is dev-only and not reachable by a cross-site simple request.
 * Software-only variants always run; real-TPM variants are skipped when no software TPM is reachable.
 */

import "reflect-metadata";
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import crypto from "node:crypto";
import * as x509 from "@peculiar/x509";

import { SimTpm } from "../lib/sim-tpm/tpm.js";
import { marshalAttest, pcrDigest, replayEventLog, TPM_ST_ATTEST_QUOTE, parseAttest } from "../lib/sim-tpm/attest.js";
import { devIdOf, thumbprintOf } from "../lib/sim-tpm/public-area.js";
import { verifyQuote, startEnrol } from "../lib/verifier/enrol.js";
import { appraiseDevice } from "../lib/verifier/appraise.js";
import { verifyX509EkCert } from "../lib/verifier/ek-cert-x509.js";
import { expectedQn } from "../lib/verifier/evidence.js";
import { addToInventory } from "../lib/verifier/inventory.js";
import { loadReferenceValues } from "../lib/verifier/reference-values.js";
import { createStore } from "../lib/store.js";
import { loadOrCreateSigningKey } from "../lib/keys.js";
import { loadConfig } from "../lib/config.js";
import { parsePublic, publicKeyOf, publicAreaFromTpmt, isStandardEk } from "../lib/tpm2/index.js";
import { RealTpm, tpmReachable } from "../lib/tpm-real/index.js";
import { createApp } from "../tpm-agent.js";

x509.cryptoProvider.set(crypto.webcrypto);

const reachable = await tpmReachable();
const SKIP_REAL = !reachable && "software TPM not running: npm run tpm:sim-server";

const FIXTURES_DIR = path.resolve(import.meta.dirname, "fixtures/tpm2");
const loadFixture = (name) => JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, name), "utf8"));
const GOLDEN_LOG = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, "../fixtures/golden-boot.json"), "utf8"));
const PCR8_15 = [8, 9, 10, 11, 12, 13, 14, 15];

/** Quote signed by a SimTpm AK over an arbitrary selection/digest (what a compromised host can produce). */
function simQuote(tpm, akHandle, nonce, { select, digest }) {
  const ak = tpm.keys.get(akHandle);
  const attest = marshalAttest({
    type: TPM_ST_ATTEST_QUOTE,
    signerName: ak.name,
    extraData: nonce,
    clockInfo: { clock: Date.now(), resetCount: 1, restartCount: 0, safe: 1 },
    firmwareVersion: 1n,
    attested: {
      pcrSelect: { count: 1, hash: 0x000b, sizeofSelect: 3, pcrSelect: Buffer.from(select) },
      pcrDigest: digest,
    },
  });
  const key = crypto.createPrivateKey({ key: { kty: "EC", crv: "P-256", ...ak.privateJwk }, format: "jwk" });
  const sig = crypto.sign("sha256", attest, { key, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return { attest, sig };
}

const zeroPcrsDigest = () => pcrDigest(Array.from({ length: 8 }, () => Buffer.alloc(32, 0)));

async function createDevCa() {
  const caAlg = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
  const caKeys = await crypto.webcrypto.subtle.generateKey(caAlg, true, ["sign", "verify"]);
  const caCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=VERIFY3 Dev TPM Root CA, O=ZTA Lab",
    keys: caKeys,
    signingAlgorithm: caAlg,
    notBefore: new Date(Date.now() - 60000),
    notAfter: new Date(Date.now() + 365 * 864e5),
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });
  return { caKeys, caCert, caAlg };
}

async function issueEkCert(ca, spkiDer) {
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: crypto.randomBytes(8).toString("hex"),
    subject: "",
    issuer: ca.caCert.subject,
    publicKey: new x509.PublicKey(spkiDer),
    signingKey: ca.caKeys.privateKey,
    signingAlgorithm: ca.caAlg,
    notBefore: new Date(Date.now() - 60000),
    notAfter: new Date(Date.now() + 365 * 864e5),
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyEncipherment, true),
    ],
  });
  return Buffer.from(cert.rawData).toString("base64");
}

const spkiOfTpmt = (tpmt) =>
  publicKeyOf(parsePublic(Buffer.from(tpmt, typeof tpmt === "string" && /^[0-9a-f]+$/i.test(tpmt) ? "hex" : "base64url")))
    .export({ type: "spki", format: "der" });

/** TCP proxy for a software TPM (TPM port + platform port) that can be taken down and brought back. */
async function startTpmProxy(target = 2321) {
  const sockets = new Set();
  const servers = [];
  let base;
  const listen = (port, to) =>
    new Promise((resolve, reject) => {
      const srv = net.createServer((c) => {
        const u = net.connect({ host: "127.0.0.1", port: to });
        sockets.add(c);
        sockets.add(u);
        c.pipe(u);
        u.pipe(c);
        const drop = () => {
          c.destroy();
          u.destroy();
          sockets.delete(c);
          sockets.delete(u);
        };
        c.on("error", drop).on("close", drop);
        u.on("error", drop).on("close", drop);
      });
      srv.once("error", reject);
      srv.listen(port, "127.0.0.1", () => resolve(srv));
    });
  const up = async () => {
    servers.push(await listen(base, target), await listen(base + 1, target + 1));
  };
  for (let i = 0; i < 20 && !base; i++) {
    const candidate = 30000 + Math.floor(Math.random() * 20000);
    base = candidate;
    try {
      await up();
    } catch {
      while (servers.length) servers.pop().close();
      base = undefined;
    }
  }
  return {
    port: base,
    up,
    async down() {
      for (const s of sockets) s.destroy();
      sockets.clear();
      await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(() => r()))));
    },
  };
}

describe("VERIFY3 V1: quote must bind SHA-256 PCR0..7 and a golden-covering event log (sim)", () => {
  const rv = loadReferenceValues();
  let tpm;
  let ak;

  before(async () => {
    tpm = new SimTpm();
    ak = await tpm.createAk();
  });

  it("control: honest PCR0..7 quote + golden log is valid", async () => {
    const nonce = crypto.randomBytes(32);
    const q = await tpm.quote(ak.handle, nonce);
    const r = verifyQuote({ quote: q, akPublic: ak.publicArea, expectedNonce: nonce, eventLog: tpm.readEventLog(), referenceValues: rv });
    assert.equal(r.valid, true, r.error);
  });

  it("PCR8..15 selection with an empty log is rejected", () => {
    const nonce = crypto.randomBytes(32);
    const q = simQuote(tpm, ak.handle, nonce, { select: [0x00, 0xff, 0x00], digest: zeroPcrsDigest() });
    const r = verifyQuote({ quote: q, akPublic: ak.publicArea, expectedNonce: nonce, eventLog: [], referenceValues: rv });
    assert.equal(r.valid, false);
    assert.equal(r.akSigned, true);
    assert.match(r.error, /PCR selection/);
  });

  it("PCR8..15 selection is rejected in golden-PCR mode even when the digest is provisioned", () => {
    const nonce = crypto.randomBytes(32);
    const digest = zeroPcrsDigest();
    const q = simQuote(tpm, ak.handle, nonce, { select: [0x00, 0xff, 0x00], digest });
    const r = verifyQuote({
      quote: q,
      akPublic: ak.publicArea,
      expectedNonce: nonce,
      eventLog: null,
      devRecord: { goldenPcrDigests: [digest.toString("hex")] },
    });
    assert.equal(r.valid, false);
    assert.match(r.error, /PCR selection/);
  });

  it("a superset selection (PCR0..8) is rejected", () => {
    const nonce = crypto.randomBytes(32);
    const q = simQuote(tpm, ak.handle, nonce, { select: [0xff, 0x01, 0x00], digest: replayEventLog(GOLDEN_LOG).digest });
    const r = verifyQuote({ quote: q, akPublic: ak.publicArea, expectedNonce: nonce, eventLog: GOLDEN_LOG, referenceValues: rv });
    assert.equal(r.valid, false);
    assert.match(r.error, /PCR selection/);
  });

  it("PCR0..7 selection with an empty log (all-zero PCRs) is rejected", () => {
    const nonce = crypto.randomBytes(32);
    const q = simQuote(tpm, ak.handle, nonce, { select: [0xff, 0x00, 0x00], digest: zeroPcrsDigest() });
    for (const eventLog of [[], undefined]) {
      const r = verifyQuote({ quote: q, akPublic: ak.publicArea, expectedNonce: nonce, eventLog, referenceValues: rv });
      assert.equal(r.valid, false);
      assert.match(r.error, /empty/);
    }
  });

  it("a log that replays but omits golden PCRs (no PCR7 measurement) is rejected", () => {
    const nonce = crypto.randomBytes(32);
    const partial = GOLDEN_LOG.filter((e) => e.pcr !== 7);
    const q = simQuote(tpm, ak.handle, nonce, { select: [0xff, 0x00, 0x00], digest: replayEventLog(partial).digest });
    const r = verifyQuote({ quote: q, akPublic: ak.publicArea, expectedNonce: nonce, eventLog: partial, referenceValues: rv });
    assert.equal(r.valid, false);
    assert.match(r.error, /PCR 7/);
  });

  it("appraiseDevice: tampered device quoting PCR8..15 with [] gets no AR and is suspended", async () => {
    const store = createStore("verifier", { store: "memory" });
    const verifierKey = await loadOrCreateSigningKey("verifier", { store: "memory" });
    const kb = await tpm.createKb();
    const devId = "v1-sim-dev";
    await store.set(`registry/${devId}`, {
      devId,
      akPub: ak.publicArea,
      kbPub: kb.publicArea,
      jkt: await thumbprintOf(kb.publicArea),
      user: "alice",
      status: "active",
    });
    tpm.tamper("rogue bootkit");
    const nonce = crypto.randomBytes(32).toString("base64url");
    await store.set("nonces/n1", { nonceId: "n1", devId, nonce, expiresAt: Date.now() + 60000, used: false });
    const q = simQuote(tpm, ak.handle, Buffer.from(nonce, "base64url"), { select: [0x00, 0xff, 0x00], digest: zeroPcrsDigest() });
    const res = await appraiseDevice({ devId, nonceId: "n1", quote: q, eventLog: [], store, verifierKey });
    assert.equal(res.ok, false);
    assert.equal(res.ar, undefined);
    assert.equal(res.status, 403);
    assert.equal((await store.get(`registry/${devId}`)).status, "suspended");
  });
});

describe("VERIFY3 V3: no TOFU at appraisal time", () => {
  it("VERIFIER_GOLDEN_TOFU=1 does not make a golden-mode appraisal without stored reference values pass", async () => {
    const prev = process.env.VERIFIER_GOLDEN_TOFU;
    process.env.VERIFIER_GOLDEN_TOFU = "1";
    try {
      const tpm = new SimTpm();
      const ak = await tpm.createAk();
      const kb = await tpm.createKb();
      const store = createStore("verifier", { store: "memory" });
      const verifierKey = await loadOrCreateSigningKey("verifier", { store: "memory" });
      const devId = "v3-dev";
      await store.set(`registry/${devId}`, {
        devId,
        akPub: ak.publicArea,
        kbPub: kb.publicArea,
        jkt: await thumbprintOf(kb.publicArea),
        user: "alice",
        status: "active",
      });
      const nonce = crypto.randomBytes(32).toString("base64url");
      await store.set("nonces/n3", { nonceId: "n3", devId, nonce, expiresAt: Date.now() + 60000, used: false });
      tpm.tamper("rogue");
      const q = await tpm.quote(ak.handle, Buffer.from(nonce, "base64url"));
      const res = await appraiseDevice({ devId, nonceId: "n3", quote: q, eventLog: null, store, verifierKey });
      assert.equal(res.ok, false);
      assert.equal(res.ar, undefined);
      assert.match(res.reason, /no reference values/);
    } finally {
      if (prev === undefined) delete process.env.VERIFIER_GOLDEN_TOFU;
      else process.env.VERIFIER_GOLDEN_TOFU = prev;
    }
  });
});

describe("VERIFY3 V2: EK certificate bound to the TPMT_PUBLIC EK (fixtures)", () => {
  const ekRsa = loadFixture("ek-rsa.json");
  const ekEcc = loadFixture("ek-ecc.json");
  const ak = loadFixture("ak.json");
  const srk = loadFixture("srk.json");
  const kb = loadFixture("kb.json");
  let rootsDir;
  let ca;
  let rsaCert;

  before(async () => {
    rootsDir = fs.mkdtempSync(path.join(os.tmpdir(), "v3-ek-roots-"));
    ca = await createDevCa();
    fs.writeFileSync(path.join(rootsDir, "root.pem"), ca.caCert.toString("pem"));
    rsaCert = await issueEkCert(ca, spkiOfTpmt(ekRsa.rawHex));
  });

  after(() => fs.rmSync(rootsDir, { recursive: true, force: true }));

  const opts = { ztaEnv: "development", intermediatesDir: "/nonexistent" };

  it("control: matching tpmtPublic verifies and the result is rebuilt from the bytes", async () => {
    const ekPa = { ...publicAreaFromTpmt(ekRsa.rawHex), injected: "client-controlled" };
    const r = await verifyX509EkCert({ cert: rsaCert, ekPublicArea: ekPa }, rootsDir, opts);
    assert.equal(r.tpmtPublic, ekPa.tpmtPublic);
    assert.equal(r.injected, undefined, "client JSON must not be echoed as the verified EK");
    assert.equal(r.n, publicAreaFromTpmt(ekRsa.rawHex).n);
  });

  it("an ekPublic without tpmtPublic is rejected (no key, or JSON key fields only)", async () => {
    for (const ekPublicArea of [{ note: "no tpmtPublic, no key" }, { ...publicAreaFromTpmt(ekRsa.rawHex), tpmtPublic: undefined }, undefined]) {
      await assert.rejects(
        verifyX509EkCert({ cert: rsaCert, ekPublicArea }, rootsDir, opts),
        /ek_cert_invalid: EK public area \(tpmtPublic\) is required/
      );
    }
  });

  it("a different EK key than the certified one is rejected", async () => {
    await assert.rejects(
      verifyX509EkCert({ cert: rsaCert, ekPublicArea: publicAreaFromTpmt(ekEcc.rawHex) }, rootsDir, opts),
      /does not match EK public area/
    );
  });

  it("isStandardEk ignores plain JSON objects", () => {
    const parsed = parsePublic(Buffer.from(ekEcc.rawHex, "hex"));
    assert.equal(isStandardEk(Buffer.from(ekEcc.rawHex, "hex")), true);
    assert.equal(isStandardEk(parsed), false);
  });

  it("startEnrol: genuine EK cert + ekPublic without tpmtPublic -> 403 ek_cert_invalid, no session", async () => {
    const store = createStore("verifier", { store: "memory" });
    const devId = await devIdOf(publicAreaFromTpmt(ekRsa.rawHex));
    await addToInventory(store, { devId, user: "alice", code: "v2-code" });
    const res = await startEnrol({
      ekCert: rsaCert,
      ekPublic: { kty: "RSA", type: "rsa", n: publicAreaFromTpmt(ekRsa.rawHex).n, e: "AQAB" },
      akPublic: publicAreaFromTpmt(ak.rawHex),
      kbPublic: publicAreaFromTpmt(kb.rawHex),
      srkPublic: publicAreaFromTpmt(srk.rawHex),
      code: "v2-code",
      store,
      ekRootsDir: rootsDir,
      cfg: { ztaEnv: "development" },
    });
    assert.equal(res.ok, false);
    assert.equal(res.status, 403);
    assert.equal(res.error, "ek_cert_invalid");
  });
});

/** PowerOff/PowerOn/NvOn on the software TPM platform port: PCRs reset to 0, TPM needs Startup. */
async function powerCycle(port = 2322) {
  for (const sig of [2, 1, 11]) {
    await new Promise((resolve, reject) => {
      const s = net.connect({ host: "127.0.0.1", port }, () => s.write(Buffer.from([0, 0, 0, sig])));
      s.once("data", () => {
        s.end();
        resolve();
      });
      s.once("error", reject);
    });
  }
}

// The IBM tpm_server serves one client at a time: every test opens and closes its own RealTpm.
describe("VERIFY3 real TPM regressions", { skip: SKIP_REAL }, () => {
  let dir;
  let tpm;
  let ak;
  let akQn;

  async function openFresh() {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "v3-real-"));
    tpm = new RealTpm({ dir, device: "tcp" });
    await tpm.open();
    ak = await tpm.createAk();
    await tpm.createKb();
    akQn = expectedQn(ak.publicArea, await tpm.getSrkPublic());
  }

  async function closeFresh() {
    await tpm?.close();
    tpm = null;
    fs.rmSync(dir, { recursive: true, force: true });
  }

  before(() => powerCycle()); // earlier suites may have tampered PCRs: start from the golden boot

  it("V1: honest PCR0..7 quote is valid; after tamper, PCR8..15 + [] and PCR0..7 + [] are rejected", async () => {
    await openFresh();
    try {
      let nonce = crypto.randomBytes(32).toString("base64url");
      let q = await tpm.quote("ak", nonce);
      const ok = verifyQuote({ quote: q, akPublic: ak.publicArea, expectedNonce: nonce, eventLog: tpm.readEventLog(), akQn });
      assert.equal(ok.valid, true, ok.error);

      await tpm.tamper("v3 rogue bootkit");

      nonce = crypto.randomBytes(32).toString("base64url");
      q = await tpm.quote("ak", nonce, PCR8_15);
      assert.equal(parseAttest(Buffer.from(q.attest)).attested.pcrSelect.pcrSelect.toString("hex"), "00ff00");
      const bypass = verifyQuote({ quote: q, akPublic: ak.publicArea, expectedNonce: nonce, eventLog: [], akQn });
      assert.equal(bypass.valid, false);
      assert.match(bypass.error, /PCR selection/);

      nonce = crypto.randomBytes(32).toString("base64url");
      q = await tpm.quote("ak", nonce);
      const empty = verifyQuote({ quote: q, akPublic: ak.publicArea, expectedNonce: nonce, eventLog: [], akQn });
      assert.equal(empty.valid, false);

      const honest = verifyQuote({ quote: q, akPublic: ak.publicArea, expectedNonce: nonce, eventLog: tpm.readEventLog(), akQn });
      assert.equal(honest.valid, false, "tampered boot must fail appraisal");
    } finally {
      await closeFresh();
    }
  });

  it("V2: a cert for this TPM's EK binds only to its own TPMT_PUBLIC", async () => {
    const rootsDir = fs.mkdtempSync(path.join(os.tmpdir(), "v3-real-roots-"));
    await openFresh();
    try {
      const ca = await createDevCa();
      fs.writeFileSync(path.join(rootsDir, "root.pem"), ca.caCert.toString("pem"));
      const ek = await tpm.getEk();
      const cert = await issueEkCert(ca, spkiOfTpmt(ek.publicArea.tpmtPublic));
      const opts = { ztaEnv: "development", intermediatesDir: "/nonexistent" };

      const r = await verifyX509EkCert({ cert, ekPublicArea: ek.publicArea }, rootsDir, opts);
      assert.equal(r.tpmtPublic, ek.publicArea.tpmtPublic);

      const { tpmtPublic, ...jsonOnly } = ek.publicArea;
      await assert.rejects(verifyX509EkCert({ cert, ekPublicArea: jsonOnly }, rootsDir, opts), /tpmtPublic\) is required/);
      await assert.rejects(verifyX509EkCert({ cert, ekPublicArea: ak.publicArea }, rootsDir, opts), /ek_template_invalid|does not match/);
    } finally {
      await closeFresh();
      fs.rmSync(rootsDir, { recursive: true, force: true });
    }
  });

  it("V4: TPM power-cycle mid-run -> next operation reconnects, replays measured boot and attests", async () => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), "v3-real-pc-"));
    const t = new RealTpm({ dir: d, device: "tcp" });
    try {
      await t.open();
      const a = await t.createAk();
      await t.createKb();
      const qn = expectedQn(a.publicArea, await t.getSrkPublic());
      await t.sign("kb", "before");

      await powerCycle();

      const sig = await t.sign("kb", "after power cycle");
      assert.equal(sig.length, 64);
      const nonce = crypto.randomBytes(32).toString("base64url");
      const q = await t.quote("ak", nonce);
      const r = verifyQuote({ quote: q, akPublic: a.publicArea, expectedNonce: nonce, eventLog: t.readEventLog(), akQn: qn });
      assert.equal(r.valid, true, r.error);
    } finally {
      await t.close();
      fs.rmSync(d, { recursive: true, force: true });
    }
  });

  it("V4: TPM socket lost mid-run -> TPM_UNAVAILABLE, agent 503 + status unavailable, recovers when it is back", async () => {
    const proxy = await startTpmProxy();
    const d = fs.mkdtempSync(path.join(os.tmpdir(), "v3-real-drop-"));
    const t = new RealTpm({ dir: d, device: "tcp", port: proxy.port, timeoutMs: 1000 });
    let server;
    try {
      await t.open();
      await t.createAk();
      await t.createKb();
      await t.sign("kb", "up");

      const app = createApp(loadConfig({ dataDir: d }), { tpm: t });
      await app.locals.tpmReady;
      server = await new Promise((resolve) => {
        const s = app.listen(0, "127.0.0.1", () => resolve(s));
      });
      const base = `http://127.0.0.1:${server.address().port}`;
      const status = async () => (await fetch(`${base}/agent/status`)).json();
      assert.equal((await status()).tpm, "ok");

      await proxy.down();
      await assert.rejects(t.sign("kb", "down"), (err) => err.code === "TPM_UNAVAILABLE");

      const st = await status();
      assert.equal(st.tpm, "unavailable");
      const enrol = await fetch(`${base}/agent/enrol`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: "x" }),
      });
      assert.equal(enrol.status, 503);
      assert.equal((await enrol.json()).error, "tpm_unavailable");

      await proxy.up();
      assert.equal((await status()).tpm, "ok");
      assert.equal((await t.sign("kb", "back")).length, 64);
    } finally {
      if (server) await new Promise((r) => server.close(() => r()));
      await t.close();
      await proxy.down();
      fs.rmSync(d, { recursive: true, force: true });
    }
  });
});

describe("VERIFY3 V5: /agent/debug/tamper is dev-only and not CSRF-able", () => {
  async function withAgent(cfgOverrides, fn) {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), "v3-tamper-"));
    const tpm = new SimTpm({ dir: d });
    // ztaEnv applied after loadConfig, which refuses production with debug (N5)
    const { ztaEnv, ...rest } = cfgOverrides;
    const app = createApp({ ...loadConfig({ dataDir: d, ...rest }), ...(ztaEnv ? { ztaEnv } : {}) }, { tpm });
    const server = await new Promise((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });
    try {
      await fn(`http://127.0.0.1:${server.address().port}/agent/debug/tamper`, tpm);
    } finally {
      await new Promise((r) => server.close(() => r()));
      fs.rmSync(d, { recursive: true, force: true });
    }
  }
  const json = { "Content-Type": "application/json" };

  it("disabled by default (no ZTA_DEBUG) even outside production", async () => {
    await withAgent({ debug: false, ztaEnv: "development" }, async (url, tpm) => {
      const before = tpm.readEventLog().length;
      const r = await fetch(url, { method: "POST", headers: json, body: "{}" });
      assert.equal(r.status, 403);
      assert.equal(tpm.readEventLog().length, before);
    });
  });

  it("with ZTA_DEBUG: cross-site simple request and foreign Origin are refused; local JSON call works", async () => {
    await withAgent({ debug: true, ztaEnv: "development" }, async (url, tpm) => {
      const before = tpm.readEventLog().length;
      const simple = await fetch(url, { method: "POST", headers: { "Content-Type": "text/plain" }, body: "x" });
      assert.equal(simple.status, 415);
      const evil = await fetch(url, { method: "POST", headers: { ...json, Origin: "http://evil.example" }, body: "{}" });
      assert.equal(evil.status, 403);
      assert.equal(tpm.readEventLog().length, before);
      const ok = await fetch(url, { method: "POST", headers: json, body: JSON.stringify({ desc: "local" }) });
      assert.equal(ok.status, 200);
      assert.equal(tpm.readEventLog().length, before + 1);
    });
  });

  it("production refuses to start with ZTA_DEBUG (N5)", () => {
    assert.throws(() => loadConfig({ debug: true, ztaEnv: "production" }), /Refusing to start in production/);
  });

  it("never in production, even with ZTA_DEBUG (config built past loadConfig's refusal)", async () => {
    await withAgent({ debug: true, ztaEnv: "production" }, async (url) => {
      const r = await fetch(url, { method: "POST", headers: json, body: "{}" });
      assert.equal(r.status, 403);
    });
  });
});
