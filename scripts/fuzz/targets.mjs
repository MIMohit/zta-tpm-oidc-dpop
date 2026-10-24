/**
 * @file scripts/fuzz/targets.mjs
 * Fuzz targets: the code that parses or verifies attacker-controlled bytes on the verifier
 * and PEP paths. Each target builds seeds from real data and checks one input.
 *
 * check(input) returns "rejected" (clean rejection) or "accepted". It throws on an
 * unchecked failure, which the worker classifies by error type.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import * as jose from "jose";

import { parseTcgEventLog, replayTcgEventLog, toAppraisalEvents, TcgEventLogError } from "../../lib/verifier/tcg-eventlog.js";
import { parseAttest } from "../../lib/sim-tpm/attest.js";
import { parsePublic, publicAreaFromTpmt } from "../../lib/tpm2/marshal.js";
import { verifyX509EkCert } from "../../lib/verifier/ek-cert-x509.js";
import { signProof, verifyProof, DpopError } from "../../lib/dpop.js";
import { verifyQuote } from "../../lib/verifier/enrol.js";
import { SimTpm } from "../../lib/sim-tpm/tpm.js";

const REPO = path.resolve(import.meta.dirname, "../..");
const EVENTLOG_DIRS = ["fixtures/eventlogs/tpm2-tools", "fixtures/eventlogs/qemu-edk2-swtpm", "fixtures/eventlogs/qemu-ubuntu-noble"];
const SWTPM = path.join(REPO, "tests/fixtures/swtpm");

/** Error types a parser throws on purpose to reject input. */
export const CLEAN_ERRORS = new Set(["Error", "TcgEventLogError", "DpopError"]);

function readSeeds(dirs, filter) {
  const out = [];
  for (const d of dirs) {
    const dir = path.join(REPO, d);
    for (const f of fs.readdirSync(dir).sort()) {
      if (filter(f)) out.push({ name: `${d}/${f}`, data: fs.readFileSync(path.join(dir, f)) });
    }
  }
  return out;
}

async function simQuoteFixture() {
  const tpm = new SimTpm({});
  await tpm.init();
  const ak = await tpm.createAk();
  const nonce = crypto.randomBytes(32);
  const quote = await tpm.quote(ak.handle, nonce);
  return { tpm, ak, nonce, quote, eventLog: tpm.readEventLog() };
}

export async function loadTargets() {
  const eventLogs = readSeeds(EVENTLOG_DIRS, (f) => f.endsWith(".bin"));

  const q = await simQuoteFixture();
  const attestBuf = Buffer.isBuffer(q.quote.attest) ? q.quote.attest : Buffer.from(q.quote.attest, "base64url");
  const sigBuf = Buffer.from(q.quote.sig, "base64url");

  const tpmts = readSeeds(["tests/fixtures/swtpm"], (f) => f.endsWith(".tpmt"));
  const p384Tpmt = fs.readFileSync(path.join(SWTPM, "ek-p384-H3.tpmt"));
  const p384Cert = fs.readFileSync(path.join(SWTPM, "ekcert-p384-nv01c00016.der"));
  const issuerPem = fs.readFileSync(path.join(SWTPM, "swtpm-localca-issuer.pem"), "utf8");
  const rootsDir = fs.mkdtempSync(path.join(process.env.TMPDIR || "/tmp", "zta-fuzz-roots-"));
  fs.copyFileSync(path.join(SWTPM, "swtpm-localca-root.pem"), path.join(rootsDir, "root.pem"));
  const ekPublicArea = publicAreaFromTpmt(p384Tpmt);

  const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
  const publicJwk = await jose.exportJWK(publicKey);
  const htu = "https://pep.example/api/company/news";
  const fixedNow = 1_800_000_000_000;
  const proof = await signProof({ privateKey, publicJwk, htm: "GET", htu, clock: () => fixedNow });

  return {
    eventlog: {
      seeds: eventLogs.map((s) => s.data),
      // Parse, then replay and extract events as the verifier does
      check(buf) {
        let parsed;
        try {
          parsed = parseTcgEventLog(buf);
        } catch (err) {
          if (err instanceof TcgEventLogError) return "rejected";
          throw err;
        }
        replayTcgEventLog(parsed, { bank: "sha256", pcrs: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] });
        toAppraisalEvents(parsed, { bank: "sha256", pcrs: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] });
        return "parsed";
      },
    },
    attest: {
      seeds: [attestBuf],
      check(buf) {
        try {
          parseAttest(buf);
          return "parsed";
        } catch (err) {
          if (err.constructor === Error) return "rejected";
          throw err;
        }
      },
    },
    tpmt: {
      seeds: tpmts.map((s) => s.data),
      check(buf) {
        try {
          parsePublic(buf);
          publicAreaFromTpmt(buf);
          return "parsed";
        } catch (err) {
          if (err.constructor === Error) return "rejected";
          throw err;
        }
      },
    },
    x509: {
      seeds: [p384Cert],
      // A mutated certificate must never verify against the real EK
      async check(buf) {
        try {
          await verifyX509EkCert({ cert: buf, ekCertChain: [issuerPem], ekPublicArea }, { rootsDir, ignoreExpiry: true, ztaEnv: "production" });
          return buf.equals(p384Cert) ? "parsed" : "accepted";
        } catch (err) {
          if (/^ek_(cert|template)_invalid/.test(err.message)) return "rejected";
          throw err;
        }
      },
    },
    dpop: {
      seeds: [Buffer.from(proof)],
      // A mutated proof must never verify
      async check(buf) {
        const s = buf.toString("latin1");
        try {
          await verifyProof({ proof: s, htm: "GET", htu, clock: () => fixedNow, checks: {} });
          return s === proof ? "parsed" : "accepted";
        } catch (err) {
          if (err instanceof DpopError) return "rejected";
          throw err;
        }
      },
    },
    quote: {
      // attest || sig, split at the original attest length: mutations hit either half,
      // and a mutated quote must never appraise as valid
      seeds: [Buffer.concat([attestBuf, sigBuf])],
      check(buf) {
        const attest = buf.subarray(0, Math.min(buf.length, attestBuf.length));
        const sig = buf.subarray(attest.length);
        const res = verifyQuote({ quote: { attest, sig }, akPublic: q.ak.publicArea, expectedNonce: q.nonce, eventLog: q.eventLog });
        if (!res.valid) return "rejected";
        return attest.equals(attestBuf) && sig.equals(sigBuf) ? "parsed" : "accepted";
      },
    },
  };
}

