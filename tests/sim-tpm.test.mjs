/**
 * @file sim-tpm.test.mjs
 * Comprehensive unit test suite for Simulated TPM (WP1).
 * Tests all required cases (a) through (i) defined in PLAN.md §3 WP1.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import * as jose from "jose";

import { SimTpm } from "../lib/sim-tpm/tpm.js";
import { makePublicArea, nameOf, jwkOf, TPMA_OBJECT } from "../lib/sim-tpm/public-area.js";
import { marshalAttest, parseAttest, pcrDigest, replayEventLog } from "../lib/sim-tpm/attest.js";
import { makeCredential, activate } from "../lib/sim-tpm/credential.js";
import { createVendorCa, issueEkCert, verifyEkCert } from "../lib/sim-tpm/vendor-ca.js";
import { b64u } from "../lib/canonical.js";

describe("WP1: Simulated TPM 2.0 subset", () => {
  it("(a) activate returns s for the matching AK", async () => {
    const tpm = new SimTpm();
    await tpm.init();
    const { publicArea: ekPub } = await tpm.getEk();
    const ak = await tpm.createAk();

    const secret = crypto.randomBytes(32);
    const blob = makeCredential(ekPub, ak.name, secret);

    const sPrime = await tpm.activateCredential(ak.handle, blob);
    assert.ok(Buffer.isBuffer(sPrime), "Returned secret must be a Buffer");
    assert.deepStrictEqual(sPrime, secret, "Activated secret s' must match original secret s");
  });

  it("(b) activate throws for a different AK name", async () => {
    const tpm = new SimTpm();
    await tpm.init();
    const { publicArea: ekPub } = await tpm.getEk();
    const ak1 = await tpm.createAk();
    const ak2 = await tpm.createAk();

    const secret = crypto.randomBytes(32);
    // Verifier creates credential bound to AK2 name
    const blob = makeCredential(ekPub, ak2.name, secret);

    // TPM attempts to activate credential using AK1 handle (different name)
    await assert.rejects(
      async () => {
        await tpm.activateCredential(ak1.handle, blob);
      },
      (err) => {
        assert.equal(err.code, "TPM_RC_INTEGRITY");
        return true;
      },
      "activateCredential must throw TPM_RC_INTEGRITY when loaded AK name does not match blob"
    );
  });

  it("(c) activate throws when the blob was made for another EK", async () => {
    const tpm1 = new SimTpm();
    await tpm1.init();
    const tpm2 = new SimTpm();
    await tpm2.init();

    const ak1 = await tpm1.createAk();
    const { publicArea: ek2Pub } = await tpm2.getEk();

    const secret = crypto.randomBytes(32);
    // Verifier encrypts under TPM2's EK
    const blob = makeCredential(ek2Pub, ak1.name, secret);

    // TPM1 attempts to activate with its own EK
    await assert.rejects(
      async () => {
        await tpm1.activateCredential(ak1.handle, blob);
      },
      (err) => {
        assert.equal(err.code, "TPM_RC_INTEGRITY");
        return true;
      },
      "activateCredential must throw TPM_RC_INTEGRITY when blob was created for another EK"
    );
  });

  it("(d) quote parses, with magic 0xFF544347, type 0x8018, extraData equal to the nonce, and pcrDigest equal to the replayed event log", async () => {
    const tpm = new SimTpm();
    await tpm.init();
    const ak = await tpm.createAk();

    const nonce = crypto.randomBytes(32);
    const { attest, sig, pcrs } = await tpm.quote(ak.handle, nonce);

    assert.ok(Buffer.isBuffer(attest), "attest must be a binary Buffer");
    assert.equal(typeof sig, "string", "sig must be a base64url string");

    const parsed = parseAttest(attest);
    assert.equal(parsed.magic, 0xff544347, "magic must equal 0xFF544347");
    assert.equal(parsed.type, 0x8018, "type must equal 0x8018 (QUOTE)");
    assert.ok(parsed.extraData.equals(nonce), "extraData must equal the nonce");

    const replayed = replayEventLog(tpm.readEventLog());
    assert.ok(parsed.pcrDigest.equals(replayed.digest), "pcrDigest must match replayed event log digest");

    // Verify ECDSA signature under AK public key
    const akJwk = jwkOf(ak.publicArea);
    const akKey = crypto.createPublicKey({
      key: { kty: "EC", crv: "P-256", x: akJwk.x, y: akJwk.y },
      format: "jwk",
    });
    const validSig = crypto.verify(
      "sha256",
      attest,
      { key: akKey, dsaEncoding: "ieee-p1363" },
      Buffer.from(sig, "base64url")
    );
    assert.ok(validSig, "Quote signature must verify under AK public key");
  });

  it("(e) certify(K_B) attested name equals nameOf(kbPublicArea)", async () => {
    const tpm = new SimTpm();
    await tpm.init();
    const ak = await tpm.createAk();
    const kb = await tpm.createKb();

    const nonce = crypto.randomBytes(32);
    const { attest, sig } = await tpm.certify(kb.handle, ak.handle, nonce);

    const parsed = parseAttest(attest);
    assert.equal(parsed.magic, 0xff544347, "magic must equal 0xFF544347");
    assert.equal(parsed.type, 0x8017, "type must equal 0x8017 (CERTIFY)");
    assert.ok(parsed.extraData.equals(nonce), "extraData must match nonce");

    const expectedName = nameOf(kb.publicArea);
    assert.ok(parsed.name.equals(expectedName), "Certified object name must equal nameOf(kbPublicArea)");
  });

  it("(f) sign(akHandle) throws", async () => {
    const tpm = new SimTpm();
    await tpm.init();
    const ak = await tpm.createAk();

    await assert.rejects(
      async () => {
        await tpm.sign(ak.handle, Buffer.from("payload"));
      },
      (err) => {
        assert.equal(err.code, "TPM_RC_ATTRIBUTES");
        return true;
      },
      "sign() must throw TPM_RC_ATTRIBUTES when called with an AK (restricted key)"
    );
  });

  it("(g) a K_B signature verifies with jose as ES256", async () => {
    const tpm = new SimTpm();
    await tpm.init();
    const kb = await tpm.createKb();

    // Build a compact JWS signed via SimTpm.sign()
    const header = b64u.encode(JSON.stringify({ alg: "ES256", typ: "dpop+jwt" }));
    const payload = b64u.encode(JSON.stringify({ sub: "user-123", htm: "POST", htu: "https://example.com/api" }));
    const signingInput = Buffer.from(`${header}.${payload}`, "utf8");

    const rawSig = await tpm.sign(kb.handle, signingInput);
    assert.ok(Buffer.isBuffer(rawSig), "Raw signature must be a Buffer");
    assert.equal(rawSig.length, 64, "P-256 IEEE-P1363 signature must be 64 bytes");

    const compactJws = `${header}.${payload}.${b64u.encode(rawSig)}`;

    // Verify using jose
    const kbJwk = jwkOf(kb.publicArea);
    const key = await jose.importJWK(kbJwk, "ES256");
    const verified = await jose.compactVerify(compactJws, key);

    assert.ok(verified, "jose.compactVerify must succeed");
    const verifiedPayload = JSON.parse(Buffer.from(verified.payload).toString("utf8"));
    assert.equal(verifiedPayload.sub, "user-123");
    assert.equal(verifiedPayload.htm, "POST");
  });

  it("(h) tamper changes pcrDigest", async () => {
    const tpm = new SimTpm();
    await tpm.init();
    const ak = await tpm.createAk();
    const nonce = crypto.randomBytes(32);

    const { attest: initialAttest } = await tpm.quote(ak.handle, nonce);
    const initialParsed = parseAttest(initialAttest);
    const initialDigest = initialParsed.pcrDigest;

    // Tamper extends PCR4 with a rogue measurement
    tpm.tamper("unauthorized boot measurement");

    const { attest: tamperedAttest } = await tpm.quote(ak.handle, nonce);
    const tamperedParsed = parseAttest(tamperedAttest);
    const tamperedDigest = tamperedParsed.pcrDigest;

    assert.ok(!tamperedDigest.equals(initialDigest), "pcrDigest after tamper() must not equal initial pcrDigest");

    // The tampered quote should match the replayed log including the tamper event
    const replayed = replayEventLog(tpm.readEventLog());
    assert.ok(tamperedDigest.equals(replayed.digest), "tampered pcrDigest must match current event log replay");
  });

  it("(i) the EK cert verifies against the sim CA and fails against the evil CA", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "vendor-ca-test-"));
    const simCaDir = path.join(tempDir, "sim");
    const evilCaDir = path.join(tempDir, "evil");

    const simCa = await createVendorCa(simCaDir, "sim-vendor", "SimTPM Vendor CA");
    const evilCa = await createVendorCa(evilCaDir, "evil", "Untrusted Evil Vendor CA");

    const tpm = new SimTpm({ caKey: simCa });
    await tpm.init();
    const { publicArea: ekPub, cert: ekCert } = await tpm.getEk();

    // 1. Verifies successfully against sim CA trust anchor
    const verifiedPub = await verifyEkCert(ekCert, [simCa.publicJwk]);
    assert.equal(verifiedPub.x, ekPub.x);
    assert.equal(verifiedPub.y, ekPub.y);
    assert.equal(verifiedPub.curve, "P-256");

    // 2. Fails verification against untrusted evil CA
    await assert.rejects(
      async () => {
        await verifyEkCert(ekCert, [evilCa.publicJwk]);
      },
      /verification failed|Untrusted vendor CA/i,
      "verifyEkCert must throw when certificate does not chain to trusted anchor"
    );

    // Clean up temp dir
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  });
});
