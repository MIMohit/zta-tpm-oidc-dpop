/**
 * @file tests/fuzz-regressions.test.mjs
 * Findings of scripts/fuzz (2026-10-23), now rejected:
 *  F1 an EK certificate with bytes after its DER structure verified (X509Certificate ignores them);
 *  F2 a DPoP proof with a non-canonical base64url signature (padding bits, stray characters) verified.
 * Neither changed the signed content, but each gave one object many encodings.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import * as jose from "jose";

import { parseCertInput } from "../lib/verifier/ek-cert-x509.js";
import { signProof, verifyProof, DpopError } from "../lib/dpop.js";

const CERT = fs.readFileSync("tests/fixtures/swtpm/ekcert-p384-nv01c00016.der");

describe("Fuzzing regressions", () => {
  it("F1: an EK certificate must be exactly one DER structure", () => {
    assert.ok(parseCertInput(CERT));
    assert.throws(() => parseCertInput(Buffer.concat([CERT, Buffer.from([0])])), /trailing or missing data/);
    assert.throws(() => parseCertInput(CERT.subarray(0, CERT.length - 1)), /trailing or missing data/);
    assert.throws(() => parseCertInput(Buffer.concat([CERT, Buffer.from([0])]).toString("base64")), /trailing or missing data/);
  });

  it("F2: DPoP proofs must use canonical base64url", async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
    const publicJwk = await jose.exportJWK(publicKey);
    const htu = "https://pep.example/api/company/news";
    const clock = () => 1_800_000_000_000;
    const proof = await signProof({ privateKey, publicJwk, htm: "GET", htu, clock });
    await verifyProof({ proof, htm: "GET", htu, clock });

    const [h, p, sig] = proof.split(".");
    // Same decoded signature, different encoding: flip the unused low bits of the last character
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = alphabet.indexOf(sig.at(-1));
    const sameBits = alphabet[(last & ~0x0f) | ((last + 1) & 0x0f)];
    // Re-encodings of the same signature bytes: rejected as non-canonical
    for (const v of [`${h}.${p}.${sig.slice(0, -1)}${sameBits}`, `${h}.${p}.${sig.slice(0, 10)}\n${sig.slice(10)}`]) {
      await assert.rejects(verifyProof({ proof: v, htm: "GET", htu, clock }), (err) => err instanceof DpopError && /canonical base64url/.test(err.message));
    }
    // An extra character is a canonical encoding of 65 bytes, which the signature check rejects
    await assert.rejects(verifyProof({ proof: `${h}.${p}.${sig}A`, htm: "GET", htu, clock }), (err) => err instanceof DpopError);
  });
});
