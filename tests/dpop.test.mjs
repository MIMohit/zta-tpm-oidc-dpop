import { test, describe } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import * as jose from "jose";

import { createNonceStore } from "../lib/nonce.js";
import { createJtiCache } from "../lib/jti-cache.js";
import {
  DpopError,
  normalizeHtu,
  signProof,
  verifyProof,
} from "../lib/dpop.js";

describe("WP4: DPoP core & nonces", () => {
  // Helper to generate a test ES256 key pair
  async function generateTestKey() {
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256", {
      extractable: true,
    });
    const publicJwk = await jose.exportJWK(publicKey);
    publicJwk.alg = "ES256";
    publicJwk.use = "sig";
    const jkt = await jose.calculateJwkThumbprint(publicJwk, "sha256");
    return { publicKey, privateKey, publicJwk, jkt };
  }

  describe("Nonce store", () => {
    test("issues nonces and rotates every tNonce seconds", () => {
      let now = 1000000;
      const clock = () => now;
      const store = createNonceStore({ tNonce: 60, clock });

      const n1 = store.issue();
      assert.ok(n1, "Issued nonce should be non-empty");
      assert.equal(store.valid(n1), true);

      // Advance by 30s (within tNonce): same nonce
      now += 30000;
      assert.equal(store.issue(), n1);
      assert.equal(store.valid(n1), true);

      // Advance past 60s (elapsed = 65s): rotates to n2
      now += 35000;
      const n2 = store.issue();
      assert.notEqual(n2, n1, "Nonce should rotate after tNonce");

      // Both n2 (current) and n1 (previous) must be valid
      assert.equal(store.valid(n2), true);
      assert.equal(store.valid(n1), true, "Previous nonce must remain valid for <= 2*tNonce");

      // Advance past 120s from start (elapsed = 130s): n1 expires, n2 becomes previous
      now += 65000;
      const n3 = store.issue();
      assert.equal(store.valid(n3), true);
      assert.equal(store.valid(n2), true);
      assert.equal(store.valid(n1), false, "Stale nonce (> 2*tNonce) must be rejected");

      // Invalid inputs
      assert.equal(store.valid(null), false);
      assert.equal(store.valid(""), false);
      assert.equal(store.valid("random-nonce"), false);
    });
  });

  describe("JTI Cache", () => {
    test("detects replays within retention window and sweeps expired entries", () => {
      let now = 1000000;
      const clock = () => now;
      const cache = createJtiCache({ windowMs: 120000, clock });

      const jkt = "test-jkt-1";
      const jti = "test-jti-1";

      // First presentation -> not seen (returns false, adds to cache)
      assert.equal(cache.seen(jkt, jti), false);

      // Second presentation -> seen (returns true, replay!)
      assert.equal(cache.seen(jkt, jti), true);

      // Different jti with same jkt -> not seen
      assert.equal(cache.seen(jkt, "test-jti-2"), false);

      // Different jkt with same jti -> not seen
      assert.equal(cache.seen("test-jkt-2", jti), false);

      // Advance clock past windowMs (120s)
      now += 121000;
      assert.equal(cache.seen(jkt, jti), false, "Expired entry should be purged and re-admitted");
    });
  });

  describe("normalizeHtu", () => {
    test("normalizes scheme, host, path, and strips query and fragment", () => {
      const url1 = "HTTP://LOCALHOST:5173/api/company/audit?param=1&other=2#frag";
      assert.equal(normalizeHtu(url1), "http://localhost:5173/api/company/audit");

      const url2 = "https://API.Example.com:443/resource/";
      assert.equal(normalizeHtu(url2), "https://api.example.com/resource/");

      const url3 = "http://example.com";
      assert.equal(normalizeHtu(url3), "http://example.com/");
    });

    test("throws DpopError with code malformed on invalid URL", () => {
      assert.throws(
        () => normalizeHtu("not-a-url"),
        (err) => err instanceof DpopError && err.code === "malformed"
      );
      assert.throws(
        () => normalizeHtu(""),
        (err) => err instanceof DpopError && err.code === "malformed"
      );
    });
  });

  describe("signProof and verifyProof happy path", () => {
    test("valid proof signed with privateKey passes all checks", async () => {
      const key = await generateTestKey();
      const nonceStore = createNonceStore({ tNonce: 60 });
      const jtiCache = createJtiCache({ windowMs: 120000 });
      const nonce = nonceStore.issue();
      const accessToken = "sample.access.token.12345";
      const htm = "POST";
      const htu = "http://localhost:4001/api/company/audit";

      const proof = await signProof({
        privateKey: key.privateKey,
        publicJwk: key.publicJwk,
        htm,
        htu,
        nonce,
        accessToken,
      });

      const result = await verifyProof({
        proof,
        htm,
        htu,
        accessToken,
        expectedJkt: key.jkt,
        nonceStore,
        jtiCache,
      });

      assert.equal(result.jkt, key.jkt);
      assert.equal(result.payload.htm, "POST");
      assert.equal(result.payload.htu, htu);
      assert.equal(result.payload.nonce, nonce);
    });

    test("valid proof signed with custom signer callback (simulating TPM)", async () => {
      const key = await generateTestKey();
      const htm = "GET";
      const htu = "http://localhost:5173/oauth/token";

      // TPM callback receives raw signing input bytes and returns P1363 sig
      const privKeyObj = crypto.KeyObject.from(key.privateKey);
      const customSigner = (bytes) => {
        return crypto.sign("sha256", bytes, {
          key: privKeyObj,
          dsaEncoding: "ieee-p1363",
        });
      };

      const proof = await signProof({
        signer: customSigner,
        publicJwk: key.publicJwk,
        htm,
        htu,
      });

      const result = await verifyProof({
        proof,
        htm,
        htu,
        expectedJkt: key.jkt,
      });

      assert.equal(result.jkt, key.jkt);
      assert.equal(result.payload.htm, "GET");
    });
  });

  describe("Individual error codes", () => {
    test("error code: missing", async () => {
      await assert.rejects(
        () => verifyProof({ proof: null, htm: "GET", htu: "http://example.com" }),
        (err) => err instanceof DpopError && err.code === "missing"
      );
      await assert.rejects(
        () => verifyProof({ proof: "", htm: "GET", htu: "http://example.com" }),
        (err) => err instanceof DpopError && err.code === "missing"
      );
      await assert.rejects(
        () => verifyProof({ proof: "   ", htm: "GET", htu: "http://example.com" }),
        (err) => err instanceof DpopError && err.code === "missing"
      );
    });

    test("error code: malformed (not 3 segments)", async () => {
      await assert.rejects(
        () => verifyProof({ proof: "a.b", htm: "GET", htu: "http://example.com" }),
        (err) => err instanceof DpopError && err.code === "malformed"
      );
      await assert.rejects(
        () => verifyProof({ proof: "a.b.c.d", htm: "GET", htu: "http://example.com" }),
        (err) => err instanceof DpopError && err.code === "malformed"
      );
    });

    test("error code: malformed (jwk with private key 'd')", async () => {
      const key = await generateTestKey();
      const privateJwk = await jose.exportJWK(key.privateKey);

      const proof = await signProof({
        privateKey: key.privateKey,
        publicJwk: privateJwk,
        htm: "GET",
        htu: "http://example.com/api",
        dangerousIncludeD: true,
      });

      await assert.rejects(
        () => verifyProof({ proof, htm: "GET", htu: "http://example.com/api" }),
        (err) => err instanceof DpopError && err.code === "malformed"
      );
    });

    test("error code: malformed (alg none / HS256)", async () => {
      const key = await generateTestKey();

      // alg: none
      const proofNone = await signProof({
        privateKey: key.privateKey,
        publicJwk: key.publicJwk,
        htm: "GET",
        htu: "http://example.com/api",
        dangerousAlg: "none",
      });

      await assert.rejects(
        () => verifyProof({ proof: proofNone, htm: "GET", htu: "http://example.com/api" }),
        (err) => err instanceof DpopError && err.code === "malformed"
      );

      // alg: HS256
      const proofHs256 = await signProof({
        privateKey: key.privateKey,
        publicJwk: key.publicJwk,
        htm: "GET",
        htu: "http://example.com/api",
        dangerousAlg: "HS256",
      });

      await assert.rejects(
        () => verifyProof({ proof: proofHs256, htm: "GET", htu: "http://example.com/api" }),
        (err) => err instanceof DpopError && err.code === "malformed"
      );
    });

    test("error code: malformed (invalid typ header)", async () => {
      const key = await generateTestKey();
      const proof = await signProof({
        privateKey: key.privateKey,
        publicJwk: key.publicJwk,
        htm: "GET",
        htu: "http://example.com/api",
        dangerousTyp: "JWT",
      });

      await assert.rejects(
        () => verifyProof({ proof, htm: "GET", htu: "http://example.com/api" }),
        (err) => err instanceof DpopError && err.code === "malformed"
      );
    });

    test("error code: bad_sig (tampered signature or payload)", async () => {
      const key = await generateTestKey();
      const proof = await signProof({
        privateKey: key.privateKey,
        publicJwk: key.publicJwk,
        htm: "GET",
        htu: "http://example.com/api",
      });

      const parts = proof.split(".");
      // Tamper signature segment (parts[2])
      const badSig = Buffer.alloc(64, 0x42).toString("base64url");
      const tamperedProof = `${parts[0]}.${parts[1]}.${badSig}`;

      await assert.rejects(
        () => verifyProof({ proof: tamperedProof, htm: "GET", htu: "http://example.com/api" }),
        (err) => err instanceof DpopError && err.code === "bad_sig"
      );
    });

    test("error code: jkt_mismatch (other key vs expectedJkt)", async () => {
      const keyA = await generateTestKey();
      const keyB = await generateTestKey();

      const proofA = await signProof({
        privateKey: keyA.privateKey,
        publicJwk: keyA.publicJwk,
        htm: "GET",
        htu: "http://example.com/api",
      });

      // Verification expects key B's thumbprint
      await assert.rejects(
        () =>
          verifyProof({
            proof: proofA,
            htm: "GET",
            htu: "http://example.com/api",
            expectedJkt: keyB.jkt,
          }),
        (err) => err instanceof DpopError && err.code === "jkt_mismatch"
      );
    });

    test("error code: htm (HTTP method mismatch)", async () => {
      const key = await generateTestKey();
      const proof = await signProof({
        privateKey: key.privateKey,
        publicJwk: key.publicJwk,
        htm: "GET",
        htu: "http://example.com/api",
      });

      await assert.rejects(
        () =>
          verifyProof({
            proof,
            htm: "POST",
            htu: "http://example.com/api",
          }),
        (err) => err instanceof DpopError && err.code === "htm"
      );
    });

    test("error code: htu (HTTP URI mismatch)", async () => {
      const key = await generateTestKey();
      const proof = await signProof({
        privateKey: key.privateKey,
        publicJwk: key.publicJwk,
        htm: "GET",
        htu: "http://example.com/api/news",
      });

      await assert.rejects(
        () =>
          verifyProof({
            proof,
            htm: "GET",
            htu: "http://example.com/api/audit",
          }),
        (err) => err instanceof DpopError && err.code === "htu"
      );
    });

    test("error code: ath (wrong ath / missing ath when accessToken expected)", async () => {
      const key = await generateTestKey();

      // Proof signed with token A
      const proofWithTokenA = await signProof({
        privateKey: key.privateKey,
        publicJwk: key.publicJwk,
        htm: "GET",
        htu: "http://example.com/api",
        accessToken: "token-alpha",
      });

      // Verifying against token B
      await assert.rejects(
        () =>
          verifyProof({
            proof: proofWithTokenA,
            htm: "GET",
            htu: "http://example.com/api",
            accessToken: "token-beta",
          }),
        (err) => err instanceof DpopError && err.code === "ath"
      );

      // Proof signed WITHOUT accessToken
      const proofWithoutToken = await signProof({
        privateKey: key.privateKey,
        publicJwk: key.publicJwk,
        htm: "GET",
        htu: "http://example.com/api",
      });

      // Verifier expects accessToken binding
      await assert.rejects(
        () =>
          verifyProof({
            proof: proofWithoutToken,
            htm: "GET",
            htu: "http://example.com/api",
            accessToken: "token-alpha",
          }),
        (err) => err instanceof DpopError && err.code === "ath"
      );
    });

    test("error code: iat (iat ± 31 s outside δ = 30s skew)", async () => {
      const key = await generateTestKey();
      const nowSec = 1000000;
      const clock = () => nowSec * 1000;

      // iat 31s in the past (now - 31) with skew = 30s
      const stalePastProof = await signProof({
        privateKey: key.privateKey,
        publicJwk: key.publicJwk,
        htm: "GET",
        htu: "http://example.com/api",
        iat: nowSec - 31,
      });

      await assert.rejects(
        () =>
          verifyProof({
            proof: stalePastProof,
            htm: "GET",
            htu: "http://example.com/api",
            skewS: 30,
            clock,
          }),
        (err) => err instanceof DpopError && err.code === "iat"
      );

      // iat 31s in the future (now + 31) with skew = 30s
      const staleFutureProof = await signProof({
        privateKey: key.privateKey,
        publicJwk: key.publicJwk,
        htm: "GET",
        htu: "http://example.com/api",
        iat: nowSec + 31,
      });

      await assert.rejects(
        () =>
          verifyProof({
            proof: staleFutureProof,
            htm: "GET",
            htu: "http://example.com/api",
            skewS: 30,
            clock,
          }),
        (err) => err instanceof DpopError && err.code === "iat"
      );

      // iat 25s in past passes
      const validSkewProof = await signProof({
        privateKey: key.privateKey,
        publicJwk: key.publicJwk,
        htm: "GET",
        htu: "http://example.com/api",
        iat: nowSec - 25,
      });

      const res = await verifyProof({
        proof: validSkewProof,
        htm: "GET",
        htu: "http://example.com/api",
        skewS: 30,
        clock,
      });
      assert.equal(res.jkt, key.jkt);
    });

    test("error code: use_dpop_nonce (missing nonce or invalid nonce)", async () => {
      const key = await generateTestKey();
      const nonceStore = createNonceStore({ tNonce: 60 });
      const currentNonce = nonceStore.issue();

      // Proof without nonce
      const proofNoNonce = await signProof({
        privateKey: key.privateKey,
        publicJwk: key.publicJwk,
        htm: "GET",
        htu: "http://example.com/api",
      });

      await assert.rejects(
        () =>
          verifyProof({
            proof: proofNoNonce,
            htm: "GET",
            htu: "http://example.com/api",
            nonceStore,
          }),
        (err) => err instanceof DpopError && err.code === "use_dpop_nonce"
      );

      // Proof with wrong/expired nonce
      const proofWrongNonce = await signProof({
        privateKey: key.privateKey,
        publicJwk: key.publicJwk,
        htm: "GET",
        htu: "http://example.com/api",
        nonce: "stale-or-unrecognized-nonce",
      });

      await assert.rejects(
        () =>
          verifyProof({
            proof: proofWrongNonce,
            htm: "GET",
            htu: "http://example.com/api",
            nonceStore,
          }),
        (err) => err instanceof DpopError && err.code === "use_dpop_nonce"
      );
    });

    test("error code: replay (jti cache detects replay)", async () => {
      const key = await generateTestKey();
      const jtiCache = createJtiCache({ windowMs: 120000 });
      const jti = "replayed-jti-12345";

      const proof = await signProof({
        privateKey: key.privateKey,
        publicJwk: key.publicJwk,
        htm: "GET",
        htu: "http://example.com/api",
        jti,
      });

      // First verification succeeds
      const first = await verifyProof({
        proof,
        htm: "GET",
        htu: "http://example.com/api",
        jtiCache,
      });
      assert.equal(first.jkt, key.jkt);

      // Replay of same proof fails with 'replay'
      await assert.rejects(
        () =>
          verifyProof({
            proof,
            htm: "GET",
            htu: "http://example.com/api",
            jtiCache,
          }),
        (err) => err instanceof DpopError && err.code === "replay"
      );
    });
  });
});
