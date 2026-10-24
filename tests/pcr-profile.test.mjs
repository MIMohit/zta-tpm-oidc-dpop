/**
 * @file tests/pcr-profile.test.mjs
 * Reference-value profiles fix the PCR set a device must quote (M6) and the PCRs its event log
 * is replayed over (M7). Uses real UEFI event logs from the KVM + swtpm fleet: an Ubuntu 24.04
 * golden boot (kernel 6.8) and the tampered image (kernel 7.0). Under shim + GRUB the kernel is
 * measured into PCR8/9, so a PCR0..7 profile cannot see the kernel swap.
 */

import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { SimTpm } from "../lib/sim-tpm/tpm.js";
import { marshalAttest, TPM_ST_ATTEST_QUOTE } from "../lib/sim-tpm/attest.js";
import { verifyQuote, isExpectedPcrSelection, pcrSelectBitmap } from "../lib/verifier/enrol.js";
import { loadReferenceValues, pcrsOf, profileFor, loadRvProfiles, DEFAULT_PCRS } from "../lib/verifier/reference-values.js";
import { parseTcgEventLog, replayTcgEventLog, pcrCompositeDigest } from "../lib/verifier/tcg-eventlog.js";

const LOGS = path.resolve("fixtures/eventlogs/qemu-ubuntu-noble");
const GOLDEN = fs.readFileSync(path.join(LOGS, "golden-grub-6.8.bin"));
const TAMPERED = fs.readFileSync(path.join(LOGS, "tampered-grub-7.0.bin"));
const GRUB_PROFILE = path.resolve("fixtures/rv/ubuntu-noble-grub.json");
const PCR0_9 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

/** What a TPM whose PCRs hold this log would quote over `pcrs`, signed by the AK. */
function quoteOver(ak, log, pcrs, nonce) {
  const { pcrs: values } = replayTcgEventLog(parseTcgEventLog(log), { bank: "sha256", pcrs });
  const attest = marshalAttest({
    type: TPM_ST_ATTEST_QUOTE,
    signerName: ak.name,
    extraData: nonce,
    attested: {
      pcrSelect: { count: 1, hash: 0x000b, sizeofSelect: 3, pcrSelect: pcrSelectBitmap(pcrs) },
      pcrDigest: pcrCompositeDigest(values, pcrs),
    },
  });
  const key = crypto.createPrivateKey({ key: { ...ak.privateJwk, kty: "EC" }, format: "jwk" });
  const sig = crypto.sign("sha256", attest, { key, dsaEncoding: "ieee-p1363" });
  return { attest: attest.toString("base64url"), sig: sig.toString("base64url") };
}

function binaryLog(buf) {
  return { format: "tcg2-binary", data: buf.toString("base64url") };
}

describe("Reference-value PCR profiles on real Ubuntu boot logs", () => {
  let ak;
  let nonce;
  const grubRv = loadReferenceValues(GRUB_PROFILE);
  const pcr07Rv = loadReferenceValues(GRUB_PROFILE);
  for (const p of [8, 9]) delete pcr07Rv[p]; // the old design: same events, PCR0..7 only

  before(async () => {
    const tpm = new SimTpm({});
    await tpm.init();
    const { handle } = await tpm.createAk();
    ak = tpm.keys.get(handle);
    nonce = crypto.randomBytes(32);
  });

  it("the GRUB profile declares PCR0..9; legacy files default to PCR0..7", () => {
    assert.deepEqual(pcrsOf(grubRv), PCR0_9);
    assert.deepEqual(pcrsOf(loadReferenceValues(path.resolve("fixtures/golden-boot.json"))), [...DEFAULT_PCRS]);
  });

  it("the golden boot appraises under the PCR0..9 profile", () => {
    const res = verifyQuote({
      quote: quoteOver(ak, GOLDEN, PCR0_9, nonce),
      akPublic: ak.publicArea,
      expectedNonce: nonce,
      eventLog: binaryLog(GOLDEN),
      referenceValues: grubRv,
    });
    assert.equal(res.valid, true, res.error);
  });

  it("the kernel swap is rejected under the PCR0..9 profile", () => {
    const res = verifyQuote({
      quote: quoteOver(ak, TAMPERED, PCR0_9, nonce),
      akPublic: ak.publicArea,
      expectedNonce: nonce,
      eventLog: binaryLog(TAMPERED),
      referenceValues: grubRv,
    });
    assert.equal(res.valid, false);
    assert.equal(res.fresh, true, "fresh AK-signed failing evidence (suspends the device)");
    assert.match(res.error, /not in reference values/);
  });

  it("regression: a PCR0..7 profile accepts the kernel swap (pitfall P-2 on shim + GRUB)", () => {
    const res = verifyQuote({
      quote: quoteOver(ak, TAMPERED, [...DEFAULT_PCRS], nonce),
      akPublic: ak.publicArea,
      expectedNonce: nonce,
      eventLog: binaryLog(TAMPERED),
      referenceValues: pcr07Rv,
    });
    assert.equal(res.valid, true, "PCR0..7 do not measure the kernel on this boot chain");
  });

  it("a quote that leaves out PCR8/9 is rejected under the PCR0..9 profile (M6)", () => {
    const res = verifyQuote({
      quote: quoteOver(ak, TAMPERED, [...DEFAULT_PCRS], nonce),
      akPublic: ak.publicArea,
      expectedNonce: nonce,
      eventLog: binaryLog(TAMPERED),
      referenceValues: grubRv,
    });
    assert.equal(res.valid, false);
    assert.match(res.error, /Invalid PCR selection.*PCR0,1,2,3,4,5,6,7,8,9/);
  });

  it("selection bitmaps match exactly, not as a superset", () => {
    const sel = (pcrs) => ({ count: 1, hash: 0x000b, sizeofSelect: 3, pcrSelect: pcrSelectBitmap(pcrs) });
    assert.equal(isExpectedPcrSelection(sel(PCR0_9), PCR0_9), true);
    assert.equal(isExpectedPcrSelection(sel([...PCR0_9, 10]), PCR0_9), false);
    assert.equal(isExpectedPcrSelection(sel([...DEFAULT_PCRS])), true);
    assert.equal(isExpectedPcrSelection(sel(PCR0_9)), false);
  });

  it("profileFor picks the named profile and fails closed on an unknown name", () => {
    const profiles = loadRvProfiles(`ubuntu-grub=${GRUB_PROFILE}`);
    assert.deepEqual(pcrsOf(profileFor({ rvProfile: "ubuntu-grub" }, { rvProfiles: profiles })), PCR0_9);
    assert.equal(profileFor({}, { referenceValues: pcr07Rv, rvProfiles: profiles }), pcr07Rv);
    assert.throws(() => profileFor({ rvProfile: "nope" }, { rvProfiles: profiles }), /Unknown reference-value profile/);
  });
});
