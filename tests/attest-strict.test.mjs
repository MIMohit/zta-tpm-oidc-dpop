/**
 * @file tests/attest-strict.test.mjs
 * parseAttest rejects malformed TPMS_ATTEST with its own Error (found by scripts/fuzz):
 * truncation, a TPM2B length past the end, and trailing bytes are never silently accepted.
 */

import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { SimTpm } from "../lib/sim-tpm/tpm.js";
import { parseAttest } from "../lib/sim-tpm/attest.js";

describe("Strict TPMS_ATTEST parsing", () => {
  let quote;
  let certify;

  before(async () => {
    const tpm = new SimTpm({});
    await tpm.init();
    const ak = await tpm.createAk();
    const kb = await tpm.createKb();
    const nonce = crypto.randomBytes(32);
    quote = Buffer.from((await tpm.quote(ak.handle, nonce)).attest);
    certify = Buffer.from((await tpm.certify(kb.handle, ak.handle, nonce)).attest);
  });

  const rejects = (buf, pattern) =>
    assert.throws(() => parseAttest(buf), (err) => err.constructor === Error && pattern.test(err.message));

  it("parses genuine quote and certify structures", () => {
    assert.equal(parseAttest(quote).attested.pcrSelect.count, 1);
    assert.ok(parseAttest(certify).name.length > 0);
  });

  it("rejects every truncation with a parse error, never a RangeError", () => {
    for (const buf of [quote, certify]) {
      for (let len = 6; len < buf.length; len++) rejects(buf.subarray(0, len), /truncated|TPMS_ATTEST/);
    }
  });

  it("rejects a TPM2B length that runs past the end", () => {
    const bad = Buffer.from(quote);
    bad.writeUInt16BE(0xffff, 6); // qualifiedSigner size
    rejects(bad, /truncated reading qualifiedSigner/);
  });

  it("rejects trailing bytes", () => {
    rejects(Buffer.concat([quote, Buffer.from([0])]), /trailing bytes/);
    rejects(Buffer.concat([certify, Buffer.from([0, 0])]), /trailing bytes/);
  });
});
