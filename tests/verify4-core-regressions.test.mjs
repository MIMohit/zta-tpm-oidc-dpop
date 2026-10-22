/**
 * @file tests/verify4-core-regressions.test.mjs
 * Regression tests for the VERIFY4 core-code findings:
 *   H4  legacy ablation flags cannot bypass the switchboard (one parser, production refusal)
 *   H1  no hard-coded identity fallbacks in the -M24 WebAuthn branch
 *   M4  M5 covers only the quote; the certify signature/signer checks belong to M8
 *   M5  GET /health on every service reports the live ablation state
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import * as jose from "jose";

import { startStack } from "./helpers/harness.js";
import {
  configureFromEnv,
  resetAblation,
  state,
  withAblation,
  runManifest,
  listCodeFiles,
} from "../lib/ablation.js";
import { loadConfig } from "../lib/config.js";
import { signProof } from "../lib/dpop.js";
import { verifyCertify } from "../lib/verifier/enrol.js";
import { SimTpm } from "../lib/sim-tpm/tpm.js";
import { createVendorCa } from "../lib/sim-tpm/vendor-ca.js";
import { SoftAuthenticator } from "./helpers/soft-webauthn.js";

const repoRoot = path.resolve(import.meta.dirname, "..");

async function stolenAtRequest(stack) {
  const aliceAT = stack.clients.alice.accessToken;
  assert.ok(aliceAT);
  const attackerKp = await jose.generateKeyPair("ES256", { extractable: true });
  const attackerPubJwk = await jose.exportJWK(attackerKp.publicKey);
  const signer = async (data) =>
    crypto.sign("sha256", Buffer.from(data), { key: attackerKp.privateKey, dsaEncoding: "ieee-p1363" });
  const newsUrl = `${stack.urls.pepPublicUrl}/api/company/news`;
  const nonce = (await fetch(newsUrl)).headers.get("DPoP-Nonce");
  const proof = await signProof({
    signer,
    publicJwk: attackerPubJwk,
    htm: "GET",
    htu: newsUrl,
    nonce,
    accessToken: aliceAT,
    clock: stack.clock,
  });
  return fetch(newsUrl, { headers: { Authorization: `DPoP ${aliceAT}`, DPoP: proof } });
}

describe("VERIFY4 H4: legacy ablation flags go through the switchboard only", () => {
  after(() => resetAblation());

  it("configureFromEnv rejects unrecognised truthy legacy values", () => {
    for (const env of [{ ZTA_ABLATE_CNF: "yes" }, { ZTA_ABLATE_NONCE: "on" }, { ZTA_ABLATE_CNF: "2" }]) {
      assert.throws(() => configureFromEnv(env), /Unrecognised ZTA_ABLATE_/);
    }
    assert.equal(state().label, "full");
    assert.equal(configureFromEnv({ ZTA_ABLATE_CNF: "0", ZTA_ABLATE_NONCE: "false" }).label, "full");
    assert.equal(configureFromEnv({ ZTA_ABLATE_CNF: "1" }).label, "-M16");
    assert.equal(configureFromEnv({ ZTA_ABLATE_NONCE: "true" }).label, "-M17");
    resetAblation();
  });

  it("production refuses legacy flags, any value, and baselines", () => {
    for (const prod of [{ ZTA_ENV: "production" }, { NODE_ENV: "production" }]) {
      for (const extra of [{ ZTA_ABLATE_CNF: "1" }, { ZTA_ABLATE_CNF: "yes" }, { ZTA_ABLATE_NONCE: "true" }, { ZTA_BASELINE: "B2" }]) {
        assert.throws(() => configureFromEnv({ ...prod, ...extra }));
      }
    }
    assert.equal(state().label, "full");
  });

  it("loadConfig carries no ablateCnf/ablateNonce keys, even with a legacy env flag set", () => {
    const saved = { cnf: process.env.ZTA_ABLATE_CNF, nonce: process.env.ZTA_ABLATE_NONCE };
    process.env.ZTA_ABLATE_CNF = "yes";
    process.env.ZTA_ABLATE_NONCE = "yes";
    try {
      const cfg = loadConfig({ store: "memory" });
      assert.equal(cfg.ablateCnf, undefined);
      assert.equal(cfg.ablateNonce, undefined);
      assert.equal(cfg.ablation, undefined);
    } finally {
      for (const [k, v] of [["ZTA_ABLATE_CNF", saved.cnf], ["ZTA_ABLATE_NONCE", saved.nonce]]) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });

  it("pep.js reads only the switchboard: a PEP whose cfg has ablateCnf/ablateNonce still enforces C3 when M16 is on", async () => {
    const pepSrc = fs.readFileSync(path.join(repoRoot, "pep.js"), "utf8");
    assert.doesNotMatch(pepSrc, /ablateCnf|ablateNonce|ZTA_ABLATE_CNF|ZTA_ABLATE_NONCE/);

    // The harness maps the legacy override onto the switchboard, so state() and the banner see it
    const stack = await startStack({ ablateCnf: true, ablateNonce: true });
    try {
      assert.equal(state().label, "-M16,-M17");
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(stack.clients.alice, { username: "alice", password: "alice-pass" });

      // Switchboard back to full while every app's cfg still carries the legacy keys
      resetAblation();
      const res = await stolenAtRequest(stack);
      assert.equal(res.status, 401, "stolen AT must be rejected: cfg.ablateCnf must not disable M16");

      // And the ablation is visible when it is real
      await withAblation("-M16", async () => {
        const res2 = await stolenAtRequest(stack);
        assert.equal(res2.status, 200);
      });
    } finally {
      await stack.stop();
    }
    assert.equal(state().label, "full");
  });
});

describe("VERIFY4 H1: -M24 has no hard-coded identity fallbacks", () => {
  it("webauthn.js contains no literal user or device fallback", () => {
    const src = fs.readFileSync(path.join(repoRoot, "lib/idp/webauthn.js"), "utf8");
    assert.doesNotMatch(src, /"alice"|'alice'|"dev-001"|'dev-001'/);
  });

  for (const label of ["full", "-M24"]) {
    it(`ungated txn with no identity in the session, credentials stored for alice (${label})`, async () => {
      const stack = await startStack(label === "full" ? {} : { ablation: label });
      try {
        await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
        // Credentials that the old literal fallbacks would have picked up
        const fakeCred = { credential: { id: "AAAA", publicKey: "AAAA", counter: 0, transports: [] } };
        await stack.stores.idp.set("webauthn/alice/dev-001", fakeCred);
        await stack.stores.idp.set(`webauthn/alice/${stack.clients.alice.devId}`, fakeCred);

        // Ungated OAuth transaction: PAR + authorize, no primary authentication
        const loginStart = await stack.clients.alice.startLogin();
        const authRes = await fetch(loginStart.authorizeUrl);
        const cookie = (authRes.headers.get("set-cookie") || "").split(";")[0];
        assert.ok(cookie, "authorize must set a session cookie");

        const optsRes = await fetch(`${stack.urls.idpIssuer}/mfa/auth/options`, { headers: { Cookie: cookie } });
        const optsBody = await optsRes.json();
        const verifyRes = await fetch(`${stack.urls.idpIssuer}/mfa/verify`, {
          method: "POST",
          headers: { Cookie: cookie, "Content-Type": "application/json" },
          body: JSON.stringify({ id: "AAAA", rawId: "AAAA", type: "public-key", response: {} }),
        });
        const verifyBody = await verifyRes.json();

        if (label === "full") {
          assert.equal(optsRes.status, 403);
          assert.equal(optsBody.error, "unauthorized_transaction");
          assert.equal(verifyRes.status, 403);
          assert.equal(verifyBody.error, "unauthorized_transaction");
        } else {
          // No identity anywhere in the session: the ablated branch must fail, never pick a default user
          assert.equal(optsRes.status, 400, `options must fail without identity, got ${optsRes.status} ${JSON.stringify(optsBody)}`);
          assert.equal(optsBody.error, "no_device_context");
          assert.equal(verifyRes.status, 400);
          assert.equal(verifyBody.error, "no_device_context");
          assert.equal(verifyBody.code, undefined, "no authorization code may be issued");
        }
      } finally {
        await stack.stop();
      }
    });
  }
  for (const label of ["full", "-M24"]) {
    it(`ungated txn in a session with a verified idpUser: code only under -M24 (${label})`, async () => {
      const stack = await startStack(label === "full" ? {} : { ablation: label });
      try {
        const idp = stack.urls.idpIssuer;
        await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
        const softAuth = new SoftAuthenticator();
        await softAuth.registerInStore(stack.stores.idp, "alice", stack.clients.alice.devId);

        // 1. Primary login completes: the session now has a verified idpUser
        const start1 = await stack.clients.alice.startLogin();
        const auth1 = await fetch(start1.authorizeUrl);
        const cookie = (auth1.headers.get("set-cookie") || "").split(";")[0];
        const loginRes = await fetch(`${idp}/oauth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json", Cookie: cookie },
          body: JSON.stringify({ username: "alice", password: "alice-pass" }),
        });
        assert.equal(loginRes.status, 200);

        // 2. A new transaction in the same session that never passes the primary-auth gate
        const start2 = await stack.clients.alice.startLogin({ acrValues: "mfa" });
        const auth2 = await fetch(start2.authorizeUrl, { headers: { Cookie: cookie } });
        assert.equal(auth2.status, 200);

        const optsRes = await fetch(`${idp}/mfa/auth/options`, { headers: { Cookie: cookie } });
        const opts = await optsRes.json();
        if (label === "full") {
          assert.equal(optsRes.status, 403);
          assert.equal(opts.error, "unauthorized_transaction");
          const verifyRes = await fetch(`${idp}/mfa/verify`, {
            method: "POST",
            headers: { "Content-Type": "application/json", Cookie: cookie },
            body: JSON.stringify({}),
          });
          assert.equal(verifyRes.status, 403);
          assert.equal((await verifyRes.json()).error, "unauthorized_transaction");
          return;
        }

        assert.equal(optsRes.status, 200, JSON.stringify(opts));
        const assertion = softAuth.createAuthenticationResponse(opts, { origin: idp, rpID: new URL(idp).hostname });
        const verifyRes = await fetch(`${idp}/mfa/verify`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Cookie: cookie },
          body: JSON.stringify(assertion),
        });
        const verifyBody = await verifyRes.json();
        assert.equal(verifyRes.status, 200, JSON.stringify(verifyBody));
        assert.ok(verifyBody.code, "-M24 must issue a code for the ungated txn (F2 reproduced)");
        assert.equal(verifyBody.acr, "mfa");
      } finally {
        await stack.stop();
      }
    });
  }
});

describe("VERIFY4 M4: certify signature and signer are M8, not M5", () => {
  let tmpDir;
  let simVendorCa;

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "zta-verify4-m4-"));
    simVendorCa = await createVendorCa(path.join(tmpDir, "ca"), "sim-vendor", "SimTPM Vendor CA");
  });
  after(() => {
    resetAblation();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("a certify signed by another AK is rejected under full and -M5, accepted only under -M8", async () => {
    const tpm1 = new SimTpm({ caKey: simVendorCa });
    await tpm1.init();
    const ak1 = await tpm1.createAk();
    const tpm2 = new SimTpm({ caKey: simVendorCa });
    await tpm2.init();
    const ak2 = await tpm2.createAk();
    const kb2 = await tpm2.createKb();
    const nonce = crypto.randomBytes(32).toString("base64url");
    const certify2 = await tpm2.certify(kb2.handle, ak2.handle, nonce);
    const args = { certify: certify2, akPublic: ak1.publicArea, kbPublic: kb2.publicArea, expectedNonce: nonce };

    const full = verifyCertify(args);
    assert.equal(full.valid, false);
    assert.match(full.error, /qualifiedSigner|signature/);

    await withAblation("-M5", () => {
      const r = verifyCertify(args);
      assert.equal(r.valid, false, "-M5 must not weaken the K_B certify check");
      assert.match(r.error, /qualifiedSigner|signature/);
    });

    await withAblation("-M8", () => {
      assert.equal(verifyCertify(args).valid, true);
    });

    // The attested-name check is not part of the ablation: a certify of another key still fails under -M5
    const kbOther = await tpm1.createKb();
    await withAblation("-M5", () => {
      const r = verifyCertify({ ...args, kbPublic: kbOther.publicArea });
      assert.equal(r.valid, false);
    });
    assert.equal(state().label, "full");
  });
});

describe("VERIFY4 M5: GET /health on every service", () => {
  for (const label of ["full", "-M7,-M16"]) {
    it(`reports the live switchboard (${label})`, async () => {
      const stack = await startStack(label === "full" ? {} : { ablation: label });
      try {
        const expected = {
          idpIssuer: "idp",
          pepPublicUrl: "pep",
          pdpUrl: "pdp",
          pipUrl: "pip",
          registryUrl: "registry",
          verifierUrl: "verifier",
        };
        for (const [key, service] of Object.entries(expected)) {
          const res = await fetch(`${stack.urls[key]}/health`);
          assert.equal(res.status, 200, `${service} /health`);
          const body = await res.json();
          assert.equal(body.service, service);
          assert.equal(body.ablation.label, label);
          assert.equal(body.ablation.hash, state().hash);
        }

        // Resource server keeps requireInternal
        const anon = await fetch(`${stack.urls.resourceUrl}/health`);
        assert.equal(anon.status, 401);
        const internal = await fetch(`${stack.urls.resourceUrl}/health`, {
          headers: { "X-ZTA-Internal": stack.cfg.ztaInternalToken },
        });
        assert.equal(internal.status, 200);
        const body = await internal.json();
        assert.equal(body.service, "resource");
        assert.equal(body.ablation.label, label);
      } finally {
        await stack.stop();
      }
    });
  }
});

describe("VERIFY4 M1 (decision c): run manifest identifies the code without git writes", () => {
  it("runManifest().code is a sha256 content hash over source files", () => {
    const m = runManifest();
    assert.match(m.code.sha256, /^[0-9a-f]{64}$/);
    assert.ok(m.code.files > 0);
    assert.equal(m.label, "full");
  });

  it("the no-git directory walk lists the same files as git", (t) => {
    const viaGit = listCodeFiles();
    if (viaGit.source !== "git") {
      t.skip("git is not available in this checkout");
      return;
    }
    assert.deepEqual(listCodeFiles(process.cwd(), { useGit: false }).files, viaGit.files);
  });
});
