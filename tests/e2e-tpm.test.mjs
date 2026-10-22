/**
 * @file tests/e2e-tpm.test.mjs
 * End-to-end ZTA flow with alice-laptop on a REAL TPM 2.0 (RealTpm over the MS-simulator TCP
 * protocol, i.e. IBM tpm_server via `npm run tpm:sim-server`) and bob-laptop on the SimTpm,
 * in the same in-process stack (WP-T5, PLAN-TPM.md §3).
 *
 * Covers: enrolment with an X.509 EK cert in TPM NV, AR, login, DPoP-bound access with
 * TPM-signed proofs, step-up, revocation, tamper (PCR extend) -> suspension, rogue EK not in
 * inventory, and the E1 stolen-token attack.
 *
 * Skipped (not failed) when no software TPM is reachable. The suite power-cycles the software
 * TPM and temporarily replaces its RSA EK cert NV index (restored afterwards), so do not run it
 * while a live agent is using the same software TPM.
 */

import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import os from "node:os";
import * as jose from "jose";

import { startStack } from "./helpers/harness.js";
import { SoftAuthenticator } from "./helpers/soft-webauthn.js";
import { RealTpm, tpmReachable, readEkCertFromNv } from "../lib/tpm-real/index.js";
import { verifyAttestationResult } from "../lib/verifier/ar.js";
import { publicJwks } from "../lib/keys.js";
import { signProof } from "../lib/dpop.js";
import { thumbprintOf } from "../lib/sim-tpm/public-area.js";

const HOST = process.env.TPM_TCP_HOST || "127.0.0.1";
const PORT = Number(process.env.TPM_TCP_PORT || 2321);
const reachable = await tpmReachable({ host: HOST, port: PORT });

// Platform-port signals (MS simulator protocol)
const SIGNAL_POWER_ON = 1;
const SIGNAL_POWER_OFF = 2;
const SIGNAL_NV_ON = 11;

function platformSignal(sig) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: HOST, port: PORT + 1 }, () => {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(sig >>> 0);
      s.write(b);
    });
    const t = setTimeout(() => {
      s.destroy();
      reject(new Error("platform port timeout"));
    }, 3000);
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

/** Simulated reboot: PCRs back to zero, so the next RealTpm.open() replays the golden boot. */
async function powerCycle() {
  await platformSignal(SIGNAL_POWER_OFF);
  await platformSignal(SIGNAL_POWER_ON);
  await platformSignal(SIGNAL_NV_ON);
}

function tpmOptions(dir) {
  return { device: "tcp", host: HOST, port: PORT, timeoutMs: 3000, ekType: "rsa", dir };
}

const decodeJwt = (jwt) => JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString("utf8"));

describe("E2E on a real TPM 2.0 (software TPM)", { skip: !reachable && "software TPM not running: npm run tpm:sim-server" }, () => {
  let work;
  let ekRootsDir;
  let savedNvCert = null;

  before(async () => {
    // Test-only dev manufacturer CA; its root is the only entry in the stack's EK_ROOTS_DIR.
    const { loadOrCreateDevCa, issueEkCertDer, writeEkCertToNv } = await import("../scripts/tpm-provision-ek-cert.mjs");
    work = fs.mkdtempSync(path.join(os.tmpdir(), "zta-e2e-tpm-"));
    ekRootsDir = path.join(work, "ek-roots");
    fs.mkdirSync(ekRootsDir, { recursive: true });
    const ca = await loadOrCreateDevCa(path.join(work, "ek-ca"));
    fs.writeFileSync(path.join(ekRootsDir, "test-root.pem"), ca.certPem);

    const tpm = new RealTpm(tpmOptions(path.join(work, "provision")));
    await tpm.open();
    try {
      savedNvCert = await readEkCertFromNv(tpm.conn, "rsa");
      const ek = await tpm.getEk();
      const der = await issueEkCertDer(ca, ek.publicArea);
      assert.equal(await writeEkCertToNv(tpm, "rsa", der), true, "EK cert written to NV 0x01C00002");
    } finally {
      await tpm.close();
    }
  });

  after(async () => {
    // Restore the software TPM's previous EK cert (e.g. from `npm run tpm:provision-ek-cert`) and PCRs.
    const { writeEkCertToNv, removeEkCertFromNv } = await import("../scripts/tpm-provision-ek-cert.mjs");
    const tpm = new RealTpm(tpmOptions(path.join(work, "restore")));
    try {
      await tpm.open();
      if (savedNvCert) await writeEkCertToNv(tpm, "rsa", savedNvCert);
      else await removeEkCertFromNv(tpm, "rsa");
    } finally {
      await tpm.close();
    }
    await powerCycle().catch(() => {});
    fs.rmSync(work, { recursive: true, force: true });
  });

  beforeEach(async () => {
    await powerCycle();
  });

  /** Stack with alice-laptop on RealTpm; everyone else on SimTpm. Real wall clock (X.509 validity). */
  async function startTpmStack() {
    return startStack({
      initialTime: Date.now(),
      ekRootsDir,
      tpmFactory: async ({ name, dir }) => {
        if (name !== "alice-laptop") return null;
        const tpm = new RealTpm(tpmOptions(path.join(dir, "tpm")));
        await tpm.open();
        return tpm;
      },
    });
  }

  it("enrol (X.509 EK cert, real MakeCredential/ActivateCredential, QN-checked quote+certify) alongside a SimTpm device", async () => {
    const stack = await startTpmStack();
    try {
      const alice = stack.clients.alice;
      assert.ok(stack.tpms.alice instanceof RealTpm);

      const res = await alice.enrol(stack.codes["alice-laptop"]);
      assert.equal(res.enrolled, true);
      assert.equal(alice.kbPublicArea.format, "tpm2", "K_B public area comes from real TPMT_PUBLIC bytes");
      assert.equal(alice.jkt, await thumbprintOf(alice.kbPublicArea));

      const reg = await (
        await fetch(`${stack.urls.verifierUrl}/v/devices/${alice.devId}`, {
          headers: { "X-ZTA-Internal": stack.cfg.ztaInternalToken },
        })
      ).json();
      assert.equal(reg.status, "active");
      assert.equal(reg.user, "alice");
      assert.equal(reg.jkt, alice.jkt);

      // bob on the simulated TPM enrols in the same stack
      const bobRes = await stack.clients.bob.enrol(stack.codes["bob-laptop"]);
      assert.equal(bobRes.enrolled, true);
      assert.notEqual(stack.clients.bob.devId, alice.devId);

      const pip = await (
        await fetch(`${stack.urls.pipUrl}/pip/device/${alice.devId}`, {
          headers: { "X-ZTA-Internal": stack.cfg.ztaInternalToken },
        })
      ).json();
      assert.equal(pip.status, "active");
    } finally {
      await stack.stop();
    }
  });

  it("AR from a real quote, login, DPoP access with TPM-signed proofs, step-up, then revocation -> 403", async () => {
    const stack = await startTpmStack();
    try {
      const alice = stack.clients.alice;
      await alice.enrol(stack.codes["alice-laptop"]);

      // AR
      const ar = await alice.attest();
      const verified = await verifyAttestationResult(ar, publicJwks(stack.keys.verifier), { clock: stack.clock });
      assert.equal(verified.payload.status, "pass");
      assert.equal(verified.payload.dev, alice.devId);
      assert.equal(verified.payload.jkt, alice.jkt);

      // Login (acr pwd); the DPoP proofs are signed by K_B inside the TPM
      const softAuth = new SoftAuthenticator();
      await softAuth.registerInStore(stack.stores.idp, "alice", alice.devId);
      const { tokens } = await stack.loginUser(alice, { username: "alice", password: "alice-pass" });
      const at = decodeJwt(tokens.access_token);
      assert.equal(at.cnf.jkt, alice.jkt, "access token bound to the TPM-resident K_B");
      assert.equal(at.dev, alice.devId);

      const realSigns = [];
      const origSign = stack.tpms.alice.sign.bind(stack.tpms.alice);
      stack.tpms.alice.sign = async (h, data) => {
        realSigns.push(h);
        return origSign(h, data);
      };

      const news = await alice.request("company.news");
      assert.equal(news.status, 200);
      assert.ok(realSigns.length >= 1, "DPoP proof for the resource request was signed by RealTpm");

      // company.audit with acr=pwd -> RFC 9470 step-up; after WebAuthn step-up -> 200
      const audit1 = await alice.request("company.audit");
      assert.equal(audit1.status, 401);
      assert.equal(audit1.stepUp, true);
      await stack.loginUser(alice, { username: "alice", password: "alice-pass", acrValues: "mfa", softAuth });
      assert.equal(alice.session.acr, "mfa");
      const audit2 = await alice.request("company.audit");
      assert.equal(audit2.status, 200);

      // Admin revokes the device -> next request 403
      const revokeRes = await fetch(`${stack.urls.registryUrl}/registry/${alice.devId}/revoke`, {
        method: "POST",
        headers: { Authorization: `Bearer ${stack.cfg.adminToken}` },
      });
      assert.equal(revokeRes.status, 200);
      const afterRevoke = await alice.request("company.news");
      assert.equal(afterRevoke.status, 403);
    } finally {
      await stack.stop();
    }
  });

  it("tamper: PCR4 extended in the real TPM -> appraisal fails -> device suspended -> 403", async () => {
    const stack = await startTpmStack();
    try {
      const alice = stack.clients.alice;
      await alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(alice, { username: "alice", password: "alice-pass" });
      assert.equal((await alice.request("company.news")).status, 200);

      await alice.tamper("e2e-tpm rogue bootloader");
      await assert.rejects(() => alice.attest());

      const pip = await (
        await fetch(`${stack.urls.pipUrl}/pip/device/${alice.devId}`, {
          headers: { "X-ZTA-Internal": stack.cfg.ztaInternalToken },
        })
      ).json();
      assert.equal(pip.status, "suspended");
      assert.equal((await alice.request("company.news")).status, 403);
    } finally {
      await stack.stop();
    }
  });

  it("rogue: a genuine real EK that IT never put in the inventory is refused (ek_not_in_inventory)", async () => {
    const stack = await startTpmStack();
    try {
      const alice = stack.clients.alice;
      const { publicArea } = await stack.tpms.alice.getEk();
      const { devIdOf } = await import("../lib/sim-tpm/public-area.js");
      const devId = await devIdOf(publicArea);
      await stack.stores.verifier.del(`inventory/${devId}`);

      await assert.rejects(
        () => alice.enrol(stack.codes["alice-laptop"]),
        (err) => /ek_not_in_inventory|inventory|403/.test(err.message)
      );
      assert.equal(alice.enrolled, false);
    } finally {
      await stack.stop();
    }
  });

  it("E1: stolen TPM-bound access token replayed with an attacker key -> 401 jkt_mismatch; as Bearer -> 401", async () => {
    const stack = await startTpmStack();
    try {
      const alice = stack.clients.alice;
      await alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(alice, { username: "alice", password: "alice-pass" });
      const stolenAt = alice.accessToken;

      const attacker = await jose.generateKeyPair("ES256", { extractable: true });
      const newsUrl = `${stack.urls.pepPublicUrl}/api/company/news`;
      const nonce = (await fetch(newsUrl)).headers.get("DPoP-Nonce");
      const proof = await signProof({
        signer: async (data) => crypto.sign("sha256", Buffer.from(data), { key: attacker.privateKey, dsaEncoding: "ieee-p1363" }),
        publicJwk: await jose.exportJWK(attacker.publicKey),
        htm: "GET",
        htu: newsUrl,
        nonce,
        accessToken: stolenAt,
        clock: stack.clock,
      });
      const stolen = await fetch(newsUrl, { headers: { Authorization: `DPoP ${stolenAt}`, DPoP: proof } });
      assert.equal(stolen.status, 401);
      assert.equal((await stolen.json().catch(() => ({}))).error, "jkt_mismatch");

      const bearer = await fetch(newsUrl, { headers: { Authorization: `Bearer ${stolenAt}` } });
      assert.equal(bearer.status, 401);

      // The legitimate holder of the TPM key still gets through
      assert.equal((await alice.request("company.news")).status, 200);
    } finally {
      await stack.stop();
    }
  });
});
