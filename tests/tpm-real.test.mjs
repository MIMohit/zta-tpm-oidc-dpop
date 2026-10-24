/**
 * @file tpm-real.test.mjs
 * Comprehensive test suite for RealTpm backend (WP-T2).
 * Tests all required cases defined in PLAN-TPM.md §3 WP-T2.
 * Skipped gracefully when a TPM 2.0 implementation is not reachable.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import net from "node:net";

import { RealTpm, tpmReachable } from "../lib/tpm-real/index.js";
import { TPMA_OBJECT } from "../lib/sim-tpm/public-area.js";
import { parseAttest, replayEventLog } from "../lib/sim-tpm/attest.js";
import { makeCredentialTpm2, publicKeyOf, nameOfTpmt } from "../lib/tpm2/index.js";

const reachable = await tpmReachable();

function sendPlatformSignal(sig, { host = "127.0.0.1", port = 2322, timeoutMs = 3000 } = {}) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host, port }, () => {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(sig >>> 0);
      s.write(b);
    });
    const t = setTimeout(() => {
      s.destroy();
      reject(new Error("Platform port timeout"));
    }, timeoutMs);
    s.once("data", (d) => {
      clearTimeout(t);
      s.end();
      resolve(d.readUInt32BE(0));
    });
    s.on("error", (e) => {
      clearTimeout(t);
      reject(e);
    });
  });
}

describe("RealTpm", { skip: !reachable && "software TPM not running: npm run tpm:sim-server" }, () => {
  it("getEk is stable across instances", async () => {
    const dir1 = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-real-ek1-"));
    const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-real-ek2-"));

    const tpm1 = new RealTpm({ dir: dir1, device: "tcp" });
    await tpm1.open();
    const ek1 = await tpm1.getEk();
    await tpm1.close();

    const tpm2 = new RealTpm({ dir: dir2, device: "tcp" });
    await tpm2.open();
    const ek2 = await tpm2.getEk();
    await tpm2.close();

    try {
      assert.ok(ek1.publicArea.tpmtPublic, "EK1 must contain tpmtPublic");
      assert.ok(ek2.publicArea.tpmtPublic, "EK2 must contain tpmtPublic");
      assert.equal(
        ek1.publicArea.tpmtPublic,
        ek2.publicArea.tpmtPublic,
        "getEk public area must be deterministic across instances"
      );

      const name1 = nameOfTpmt(ek1.publicArea.tpmtPublic);
      const name2 = nameOfTpmt(ek2.publicArea.tpmtPublic);
      assert.ok(name1.equals(name2), "EK Names must match across instances");
    } finally {
      fs.rmSync(dir1, { recursive: true, force: true });
      fs.rmSync(dir2, { recursive: true, force: true });
    }
  });

  it("AK and K_B attributes", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-real-attrs-"));
    const tpm = new RealTpm({ dir, device: "tcp" });

    try {
      await tpm.open();
      const ak = await tpm.createAk();
      const kb = await tpm.createKb();

      // AK attributes: restricted | sign | fixedTPM | fixedParent | sensitiveDataOrigin (0x00050072)
      assert.ok(
        ak.publicArea.objectAttributes & TPMA_OBJECT.restricted,
        "AK must have restricted attribute"
      );
      assert.ok(
        ak.publicArea.objectAttributes & TPMA_OBJECT.sign,
        "AK must have sign attribute"
      );
      assert.equal(
        ak.publicArea.objectAttributes & 0x00050072,
        0x00050072,
        "AK attributes must contain expected 0x00050072 bits"
      );

      // K_B attributes: sign | fixedTPM | fixedParent | sensitiveDataOrigin (0x00040072, unrestricted)
      assert.equal(
        ak.publicArea.objectAttributes & TPMA_OBJECT.restricted ? 1 : 0,
        1,
        "AK is restricted"
      );
      assert.equal(
        kb.publicArea.objectAttributes & TPMA_OBJECT.restricted,
        0,
        "K_B must NOT have restricted attribute"
      );
      assert.ok(
        kb.publicArea.objectAttributes & TPMA_OBJECT.sign,
        "K_B must have sign attribute"
      );
      assert.equal(
        kb.publicArea.objectAttributes & 0x00040072,
        0x00040072,
        "K_B attributes must contain expected 0x00040072 bits"
      );
    } finally {
      await tpm.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("activate succeeds / fails with the wrong name", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-real-act-"));
    const tpm = new RealTpm({ dir, device: "tcp" });

    try {
      await tpm.open();
      const ek = await tpm.getEk();
      const ak = await tpm.createAk();
      const kb = await tpm.createKb();

      const secret = crypto.randomBytes(32);
      // Valid credential bound to AK name
      const validBlob = makeCredentialTpm2(ek.publicArea, ak.name, secret);

      const recovered = await tpm.activateCredential(ak.handle, validBlob);
      assert.ok(Buffer.isBuffer(recovered), "Recovered secret must be a Buffer");
      assert.ok(recovered.equals(secret), "Recovered secret must match original secret");

      // Negative: credential bound to K_B name instead of AK name
      const badBlob = makeCredentialTpm2(ek.publicArea, kb.name, secret);
      await assert.rejects(
        async () => {
          await tpm.activateCredential(ak.handle, badBlob);
        },
        (err) => {
          assert.equal(err.code, "TPM_RC_INTEGRITY");
          return true;
        },
        "activateCredential must throw TPM_RC_INTEGRITY when activated with wrong key Name"
      );
    } finally {
      await tpm.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("quote verifies with the right nonce and PCR digest", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-real-quote-"));
    const tpm = new RealTpm({ dir, device: "tcp" });

    try {
      await tpm.open();
      const ak = await tpm.createAk();
      const nonce = crypto.randomBytes(32);

      const { attest, sig, pcrs } = await tpm.quote(ak.handle, nonce);

      assert.ok(Buffer.isBuffer(attest), "Attest must be a Buffer");
      assert.equal(typeof sig, "string", "Sig must be a string");
      assert.ok(Array.isArray(pcrs), "PCRs must be an array");

      const parsed = parseAttest(attest);
      assert.equal(parsed.magic, 0xff544347, "Attest magic must equal 0xFF544347");
      assert.equal(parsed.type, 0x8018, "Attest type must equal 0x8018 (QUOTE)");
      assert.ok(parsed.extraData.equals(nonce), "Attest extraData must match nonce");

      // Verify signature over raw attest bytes
      const pubKey = publicKeyOf(Buffer.from(ak.publicArea.tpmtPublic, "base64url"));
      const validSig = crypto.verify(
        "sha256",
        attest,
        { key: pubKey, dsaEncoding: "ieee-p1363" },
        Buffer.from(sig, "base64url")
      );
      assert.ok(validSig, "Quote signature must verify under AK public key");

      // Verify PCR digest matches replayed event log
      const replayed = replayEventLog(tpm.readEventLog());
      assert.ok(parsed.pcrDigest.equals(replayed.digest), "pcrDigest must match replayed event log");
    } finally {
      await tpm.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("certify name", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-real-certify-"));
    const tpm = new RealTpm({ dir, device: "tcp" });

    try {
      await tpm.open();
      const ak = await tpm.createAk();
      const kb = await tpm.createKb();
      const nonce = crypto.randomBytes(32);

      const { attest, sig } = await tpm.certify(kb.handle, ak.handle, nonce);
      assert.ok(Buffer.isBuffer(attest));

      const parsed = parseAttest(attest);
      assert.equal(parsed.magic, 0xff544347);
      assert.equal(parsed.type, 0x8017, "Type must equal 0x8017 (CERTIFY)");
      assert.ok(parsed.extraData.equals(nonce));
      assert.ok(parsed.name.equals(kb.name), "Certified object name must equal K_B Name");

      const pubKey = publicKeyOf(Buffer.from(ak.publicArea.tpmtPublic, "base64url"));
      const validSig = crypto.verify(
        "sha256",
        attest,
        { key: pubKey, dsaEncoding: "ieee-p1363" },
        Buffer.from(sig, "base64url")
      );
      assert.ok(validSig, "Certify signature must verify under AK public key");
    } finally {
      await tpm.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("sign verifies, and AK sign is refused", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-real-sign-"));
    const tpm = new RealTpm({ dir, device: "tcp" });

    try {
      await tpm.open();
      const ak = await tpm.createAk();
      const kb = await tpm.createKb();

      const data = Buffer.from("payload to be signed with K_B");
      const sig = await tpm.sign(kb.handle, data);

      assert.ok(Buffer.isBuffer(sig));
      assert.equal(sig.length, 64, "P-256 signature must be 64 bytes");

      const pubKey = publicKeyOf(Buffer.from(kb.publicArea.tpmtPublic, "base64url"));
      const valid = crypto.verify(
        "sha256",
        data,
        { key: pubKey, dsaEncoding: "ieee-p1363" },
        sig
      );
      assert.ok(valid, "Signature must verify with K_B public key");

      // Negative: AK is restricted key, sign() must be refused
      await assert.rejects(
        async () => {
          await tpm.sign(ak.handle, data);
        },
        (err) => {
          assert.equal(err.code, "TPM_RC_ATTRIBUTES");
          return true;
        },
        "sign() must reject restricted key (AK) with TPM_RC_ATTRIBUTES"
      );
    } finally {
      await tpm.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("extendPcr changes the digest and the event log replays", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-real-pcr-"));
    const tpm = new RealTpm({ dir, device: "tcp" });

    try {
      await tpm.open();
      const ak = await tpm.createAk();
      const nonce = crypto.randomBytes(32);

      const q1 = await tpm.quote(ak.handle, nonce);
      const d1 = parseAttest(q1.attest).pcrDigest;

      const measurement = crypto.randomBytes(32);
      await tpm.extendPcr(4, measurement, "custom kernel module");

      const q2 = await tpm.quote(ak.handle, nonce);
      const d2 = parseAttest(q2.attest).pcrDigest;

      assert.ok(!d1.equals(d2), "PCR digest must change after extendPcr");

      const replayed = replayEventLog(tpm.readEventLog());
      assert.ok(d2.equals(replayed.digest), "New quote PCR digest must match updated event log replay");
    } finally {
      await tpm.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("restart: a new instance reloads blobs and signs with the same K_B", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-real-restart-"));
    const tpm1 = new RealTpm({ dir, device: "tcp" });

    let kbPub;
    try {
      await tpm1.open();
      await tpm1.createAk();
      const kb = await tpm1.createKb();
      kbPub = kb.publicArea;
    } finally {
      await tpm1.close();
    }

    // New instance using the same state dir
    const tpm2 = new RealTpm({ dir, device: "tcp" });
    try {
      await tpm2.open();
      assert.ok(tpm2.keys.has("kb"), "Reopened instance must possess saved K_B");

      const data = Buffer.from("data signed across restart");
      const sig = await tpm2.sign("kb", data);

      const pubKey = publicKeyOf(Buffer.from(kbPub.tpmtPublic, "base64url"));
      const valid = crypto.verify(
        "sha256",
        data,
        { key: pubKey, dsaEncoding: "ieee-p1363" },
        sig
      );
      assert.ok(valid, "Signature from reloaded K_B must verify under original public key");
    } finally {
      await tpm2.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("power-cycle via ctl: emulated boot restores PCRs = replay(golden)", async () => {
    // Perform simulated power cycle on platform port (2322)
    // 2 = SIGNAL_POWER_OFF, 1 = SIGNAL_POWER_ON, 11 = SIGNAL_NV_ON
    await sendPlatformSignal(2);
    await sendPlatformSignal(1);
    await sendPlatformSignal(11);

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-real-powercycle-"));
    const tpm = new RealTpm({ dir, device: "tcp" });

    try {
      await tpm.open();
      const ak = await tpm.createAk();
      const nonce = crypto.randomBytes(32);

      const q = await tpm.quote(ak.handle, nonce);
      const parsed = parseAttest(q.attest);

      const replayed = replayEventLog(tpm.readEventLog());
      assert.ok(
        parsed.pcrDigest.equals(replayed.digest),
        "Emulated boot after power cycle must restore PCRs matching golden boot replay"
      );
    } finally {
      await tpm.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("concurrency: 20 parallel sign plus quote all verify", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-real-concurrency-"));
    const tpm = new RealTpm({ dir, device: "tcp" });

    try {
      await tpm.open();
      const ak = await tpm.createAk();
      const kb = await tpm.createKb();

      const akKey = publicKeyOf(Buffer.from(ak.publicArea.tpmtPublic, "base64url"));
      const kbKey = publicKeyOf(Buffer.from(kb.publicArea.tpmtPublic, "base64url"));

      const tasks = [];
      for (let i = 0; i < 10; i++) {
        const payload = Buffer.from(`concurrent-sign-payload-${i}`);
        const nonce = crypto.randomBytes(32);

        tasks.push(
          tpm.sign("kb", payload).then((sig) => {
            const ok = crypto.verify(
              "sha256",
              payload,
              { key: kbKey, dsaEncoding: "ieee-p1363" },
              sig
            );
            assert.ok(ok, `Concurrent sign ${i} verification failed`);
          })
        );

        tasks.push(
          tpm.quote("ak", nonce).then(({ attest, sig }) => {
            const ok = crypto.verify(
              "sha256",
              attest,
              { key: akKey, dsaEncoding: "ieee-p1363" },
              Buffer.from(sig, "base64url")
            );
            assert.ok(ok, `Concurrent quote ${i} verification failed`);
          })
        );
      }

      await Promise.all(tasks);
    } finally {
      await tpm.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("leak flush: kill without close, then a new instance works", async () => {
    const dir1 = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-real-leak1-"));
    const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-real-leak2-"));

    const tpm1 = new RealTpm({ dir: dir1, device: "tcp" });
    await tpm1.open();
    await tpm1.createAk();
    await tpm1.createKb();
    // Simulate abrupt process termination without close()
    tpm1.conn.device.close();

    // New instance must clean up leaked handles on open()
    const tpm2 = new RealTpm({ dir: dir2, device: "tcp" });
    try {
      await tpm2.open();
      const ak2 = await tpm2.createAk();
      const kb2 = await tpm2.createKb();
      const ek2 = await tpm2.getEk();

      assert.ok(ak2.name);
      assert.ok(kb2.name);
      assert.ok(ek2.publicArea);
    } finally {
      await tpm2.close();
      fs.rmSync(dir1, { recursive: true, force: true });
      fs.rmSync(dir2, { recursive: true, force: true });
    }
  });

  it("missing TPM: new RealTpm({device:'tcp', port: 2399}).open() rejects with code and the process survives", async () => {
    const badTpm = new RealTpm({ device: "tcp", port: 2399, timeoutMs: 500 });
    await assert.rejects(
      async () => {
        await badTpm.open();
      },
      (err) => {
        assert.ok(
          err.code === "ECONNREFUSED" ||
          err.code === "TPM_UNAVAILABLE" ||
          err.code === "TPM_TIMEOUT",
          `Expected connection error code, got ${err.code}`
        );
        return true;
      }
    );
  });
});
