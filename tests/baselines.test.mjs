/**
 * @file tests/baselines.test.mjs
 * Ablation baselines (B0–B3) and non-verifier guard HTTP tests (M9–M22, M24–M26) for WP-C1.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import * as jose from "jose";

import { startStack } from "./helpers/harness.js";
import { state, resetAblation } from "../lib/ablation.js";
import { signProof } from "../lib/dpop.js";
import { jwkOf } from "../lib/sim-tpm/public-area.js";

describe("WP-C1: Baselines (B0–B3) and Guard Ablation", () => {

  // -------------------------------------------------------------
  // Baseline B0: OIDC code + PKCE, Bearer
  // -------------------------------------------------------------
  it("B0: login without PAR AR/DPoP -> Bearer AT with no cnf, PEP 200 with Bearer header", async () => {
    const stack = await startStack({ ablation: "B0" });
    try {
      assert.equal(state().baseline, "B0");
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);

      // 1. Initiate PAR without AR and without DPoP header
      const codeVerifier = crypto.randomBytes(32).toString("base64url");
      const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
      const stateParam = crypto.randomBytes(16).toString("base64url");

      const parRes = await fetch(`${stack.urls.idpIssuer}/oauth/par`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: "zta-agent",
          response_type: "code",
          redirect_uri: "http://127.0.0.1:7000/callback",
          code_challenge: codeChallenge,
          code_challenge_method: "S256",
          state: stateParam,
          device_id: stack.clients.alice.devId,
        }),
      });
      assert.equal(parRes.status, 201);
      const { request_uri } = await parRes.json();
      assert.ok(request_uri);

      // 2. Authorize & Login as alice
      const authRes = await fetch(`${stack.urls.idpIssuer}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(request_uri)}`);
      const cookie = (authRes.headers.get("set-cookie") || "").split(";")[0];

      const loginRes = await fetch(`${stack.urls.idpIssuer}/oauth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Cookie: cookie,
        },
        body: JSON.stringify({ username: "alice", password: "alice-pass" }),
      });
      assert.equal(loginRes.status, 200);
      const { code } = await loginRes.json();
      assert.ok(code);

      // 3. Exchange code for Bearer token at /oauth/token (no DPoP header)
      const tokenRes = await fetch(`${stack.urls.idpIssuer}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code,
          redirect_uri: "http://127.0.0.1:7000/callback",
          client_id: "zta-agent",
          code_verifier: codeVerifier,
        }),
      });
      assert.equal(tokenRes.status, 200);
      const tokenData = await tokenRes.json();
      assert.ok(tokenData.access_token);
      assert.equal(tokenData.token_type, "Bearer");

      // Verify AT has no cnf claim
      const atPayload = JSON.parse(Buffer.from(tokenData.access_token.split(".")[1], "base64url").toString("utf8"));
      assert.equal(atPayload.cnf, undefined);

      // 4. Request PEP with Bearer header -> 200 OK
      const pepRes = await fetch(`${stack.urls.pepPublicUrl}/api/company/news`, {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
        },
      });
      assert.equal(pepRes.status, 200);
      const pepData = await pepRes.json();
      assert.ok(pepData);
    } finally {
      await stack.stop();
      assert.equal(state().label, "full");
    }
  });

  // -------------------------------------------------------------
  // Baseline B1: B0 + DPoP with software key (no attestation)
  // -------------------------------------------------------------
  it("B1: DPoP AT bound to a software key with no attestation -> PEP 200; stolen AT with another key -> 401", async () => {
    const stack = await startStack({ ablation: "B1" });
    try {
      assert.equal(state().baseline, "B1");
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);

      // Generate software key for client
      const clientKp = await jose.generateKeyPair("ES256", { extractable: true });
      const clientPubJwk = await jose.exportJWK(clientKp.publicKey);
      const clientJkt = await jose.calculateJwkThumbprint(clientPubJwk);

      const clientSigner = async (data) =>
        crypto.sign("sha256", Buffer.from(data), {
          key: clientKp.privateKey,
          dsaEncoding: "ieee-p1363",
        });

      // 1. PAR without AR (M9 is off in B1), but with DPoP header
      const codeVerifier = crypto.randomBytes(32).toString("base64url");
      const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
      const stateParam = crypto.randomBytes(16).toString("base64url");
      const parUrl = `${stack.urls.idpIssuer}/oauth/par`;

      const parProof = await signProof({
        signer: clientSigner,
        publicJwk: clientPubJwk,
        htm: "POST",
        htu: parUrl,
        clock: stack.clock,
      });

      const parRes = await fetch(parUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          DPoP: parProof,
        },
        body: JSON.stringify({
          client_id: "zta-agent",
          response_type: "code",
          redirect_uri: "http://127.0.0.1:7000/callback",
          code_challenge: codeChallenge,
          code_challenge_method: "S256",
          state: stateParam,
          dpop_jkt: clientJkt,
          device_id: stack.clients.alice.devId,
        }),
      });
      assert.equal(parRes.status, 201);
      const { request_uri } = await parRes.json();

      // 2. Authorize & Login
      const authRes = await fetch(`${stack.urls.idpIssuer}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(request_uri)}`);
      const cookie = (authRes.headers.get("set-cookie") || "").split(";")[0];

      const loginRes = await fetch(`${stack.urls.idpIssuer}/oauth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Cookie: cookie,
        },
        body: JSON.stringify({ username: "alice", password: "alice-pass" }),
      });
      assert.equal(loginRes.status, 200);
      const { code } = await loginRes.json();

      // 3. Token exchange with client DPoP proof (with nonce handshake)
      const tokenUrl = `${stack.urls.idpIssuer}/oauth/token`;
      let tokenProof = await signProof({
        signer: clientSigner,
        publicJwk: clientPubJwk,
        htm: "POST",
        htu: tokenUrl,
        clock: stack.clock,
      });

      let tokenRes = await fetch(tokenUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          DPoP: tokenProof,
        },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code,
          redirect_uri: "http://127.0.0.1:7000/callback",
          client_id: "zta-agent",
          code_verifier: codeVerifier,
        }),
      });

      if (tokenRes.status === 400 && tokenRes.headers.get("DPoP-Nonce")) {
        const nonce = tokenRes.headers.get("DPoP-Nonce");
        tokenProof = await signProof({
          signer: clientSigner,
          publicJwk: clientPubJwk,
          htm: "POST",
          htu: tokenUrl,
          nonce,
          clock: stack.clock,
        });
        tokenRes = await fetch(tokenUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            DPoP: tokenProof,
          },
          body: JSON.stringify({
            grant_type: "authorization_code",
            code,
            redirect_uri: "http://127.0.0.1:7000/callback",
            client_id: "zta-agent",
            code_verifier: codeVerifier,
          }),
        });
      }

      assert.equal(tokenRes.status, 200);
      const tokenData = await tokenRes.json();
      assert.equal(tokenData.token_type, "DPoP");
      const atPayload = JSON.parse(Buffer.from(tokenData.access_token.split(".")[1], "base64url").toString("utf8"));
      assert.equal(atPayload.cnf.jkt, clientJkt);

      // 4. PEP access with valid client key -> 200 OK
      const newsUrl = `${stack.urls.pepPublicUrl}/api/company/news`;
      const clientPepProof = await signProof({
        signer: clientSigner,
        publicJwk: clientPubJwk,
        htm: "GET",
        htu: newsUrl,
        accessToken: tokenData.access_token,
        clock: stack.clock,
      });

      const pepRes = await fetch(newsUrl, {
        headers: {
          Authorization: `DPoP ${tokenData.access_token}`,
          DPoP: clientPepProof,
        },
      });
      assert.equal(pepRes.status, 200);

      // 5. Stolen AT used with attacker's key -> 401 (M16 is on in B1)
      const attackerKp = await jose.generateKeyPair("ES256", { extractable: true });
      const attackerPubJwk = await jose.exportJWK(attackerKp.publicKey);
      const attackerSigner = async (data) =>
        crypto.sign("sha256", Buffer.from(data), {
          key: attackerKp.privateKey,
          dsaEncoding: "ieee-p1363",
        });

      const attackerPepProof = await signProof({
        signer: attackerSigner,
        publicJwk: attackerPubJwk,
        htm: "GET",
        htu: newsUrl,
        accessToken: tokenData.access_token,
        clock: stack.clock,
      });

      const stolenRes = await fetch(newsUrl, {
        headers: {
          Authorization: `DPoP ${tokenData.access_token}`,
          DPoP: attackerPepProof,
        },
      });
      assert.equal(stolenRes.status, 401);
      const stolenData = await stolenRes.json();
      assert.equal(stolenData.reason, "jkt_mismatch");
    } finally {
      await stack.stop();
      assert.equal(state().label, "full");
    }
  });

  // -------------------------------------------------------------
  // Baseline B2: B1 + attestation at login, unbound
  // -------------------------------------------------------------
  it("B2: AR required at PAR but not bound: AR(A) + key(B) succeeds", async () => {
    const stack = await startStack({ ablation: "B2" });
    try {
      assert.equal(state().baseline, "B2");

      // Enrol alice device A
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      const arA = await stack.clients.alice.attest();
      assert.ok(arA);

      // Create software key B
      const keyBKp = await jose.generateKeyPair("ES256", { extractable: true });
      const keyBPubJwk = await jose.exportJWK(keyBKp.publicKey);
      const keyBJkt = await jose.calculateJwkThumbprint(keyBPubJwk);
      const keyBSigner = async (data) =>
        crypto.sign("sha256", Buffer.from(data), {
          key: keyBKp.privateKey,
          dsaEncoding: "ieee-p1363",
        });

      // 1. PAR: submit AR from device A, but dpop_jkt from key B
      const codeVerifier = crypto.randomBytes(32).toString("base64url");
      const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
      const stateParam = crypto.randomBytes(16).toString("base64url");
      const parUrl = `${stack.urls.idpIssuer}/oauth/par`;

      const parProof = await signProof({
        signer: keyBSigner,
        publicJwk: keyBPubJwk,
        htm: "POST",
        htu: parUrl,
        clock: stack.clock,
      });

      const parRes = await fetch(parUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          DPoP: parProof,
        },
        body: JSON.stringify({
          client_id: "zta-agent",
          response_type: "code",
          redirect_uri: "http://127.0.0.1:7000/callback",
          code_challenge: codeChallenge,
          code_challenge_method: "S256",
          state: stateParam,
          dpop_jkt: keyBJkt,
          attestation_result: arA,
        }),
      });
      assert.equal(parRes.status, 201, "PAR must succeed despite jkt mismatch because M10 is ablated in B2");
      const { request_uri } = await parRes.json();

      // 2. Authorize & Login as alice
      const authRes = await fetch(`${stack.urls.idpIssuer}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(request_uri)}`);
      const cookie = (authRes.headers.get("set-cookie") || "").split(";")[0];

      const loginRes = await fetch(`${stack.urls.idpIssuer}/oauth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Cookie: cookie,
        },
        body: JSON.stringify({ username: "alice", password: "alice-pass" }),
      });
      assert.equal(loginRes.status, 200);
      const { code } = await loginRes.json();

      // 3. Token exchange using key B
      const tokenUrl = `${stack.urls.idpIssuer}/oauth/token`;
      let tokenProof = await signProof({
        signer: keyBSigner,
        publicJwk: keyBPubJwk,
        htm: "POST",
        htu: tokenUrl,
        clock: stack.clock,
      });

      let tokenRes = await fetch(tokenUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          DPoP: tokenProof,
        },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code,
          redirect_uri: "http://127.0.0.1:7000/callback",
          client_id: "zta-agent",
          code_verifier: codeVerifier,
        }),
      });

      if (tokenRes.status === 400 && tokenRes.headers.get("DPoP-Nonce")) {
        const nonce = tokenRes.headers.get("DPoP-Nonce");
        tokenProof = await signProof({
          signer: keyBSigner,
          publicJwk: keyBPubJwk,
          htm: "POST",
          htu: tokenUrl,
          nonce,
          clock: stack.clock,
        });
        tokenRes = await fetch(tokenUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            DPoP: tokenProof,
          },
          body: JSON.stringify({
            grant_type: "authorization_code",
            code,
            redirect_uri: "http://127.0.0.1:7000/callback",
            client_id: "zta-agent",
            code_verifier: codeVerifier,
          }),
        });
      }

      assert.equal(tokenRes.status, 200);
      const { access_token } = await tokenRes.json();

      // 4. Access PEP with key B -> 200
      const newsUrl = `${stack.urls.pepPublicUrl}/api/company/news`;
      const pepProof = await signProof({
        signer: keyBSigner,
        publicJwk: keyBPubJwk,
        htm: "GET",
        htu: newsUrl,
        accessToken: access_token,
        clock: stack.clock,
      });

      const pepRes = await fetch(newsUrl, {
        headers: {
          Authorization: `DPoP ${access_token}`,
          DPoP: pepProof,
        },
      });
      assert.equal(pepRes.status, 200);
    } finally {
      await stack.stop();
      assert.equal(state().label, "full");
    }
  });

  // -------------------------------------------------------------
  // Baseline B3: Full binding, no per-request state (M21 off)
  // -------------------------------------------------------------
  it("B3: revoked device's AT still gets 200 at the PEP", async () => {
    const stack = await startStack({ ablation: "B3" });
    try {
      assert.equal(state().baseline, "B3");

      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });

      // Initial request works
      const res1 = await stack.clients.alice.request("company.news");
      assert.equal(res1.status, 200);

      // Revoke the device
      const revokeRes = await fetch(`${stack.urls.registryUrl}/registry/${stack.clients.alice.devId}/revoke`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${stack.cfg.adminToken}`,
        },
      });
      assert.equal(revokeRes.status, 200);

      // Verify PIP shows device is revoked
      const pipRes = await fetch(`${stack.urls.pipUrl}/pip/device/${stack.clients.alice.devId}`, {
        headers: { "X-ZTA-Internal": stack.cfg.ztaInternalToken },
      });
      const pipDev = await pipRes.json();
      assert.equal(pipDev.status, "revoked");

      // In B3, M21 is off: PDP/policy skips statusOk & ageOk!
      // So PEP still returns 200!
      const res2 = await stack.clients.alice.request("company.news");
      assert.equal(res2.status, 200, "In B3, revoked device must still get 200 at PEP because M21 is ablated");
    } finally {
      await stack.stop();
      assert.equal(state().label, "full");
    }
  });

  // -------------------------------------------------------------
  // Individual Guard Ablations (HTTP-level)
  // -------------------------------------------------------------

  it("M9 guard: PAR accepts forged/unverified AR when -M9 is active", async () => {
    const stack = await startStack({ ablation: "-M9" });
    try {
      assert.equal(state().label, "-M9");

      // Forge an invalid AR (signed with arbitrary key)
      const fakeKey = await jose.generateKeyPair("ES256");
      const fakeAr = await new jose.SignJWT({
        status: "pass",
        dev: "forged-dev",
        jkt: "forged-jkt",
      })
        .setProtectedHeader({ alg: "ES256", typ: "ar+jwt" })
        .setIssuedAt(Math.floor(Date.now() / 1000))
        .setExpirationTime(Math.floor(Date.now() / 1000) + 120)
        .sign(fakeKey.privateKey);

      const parRes = await fetch(`${stack.urls.idpIssuer}/oauth/par`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: "zta-agent",
          response_type: "code",
          redirect_uri: "http://127.0.0.1:7000/callback",
          code_challenge: "dummy-challenge",
          code_challenge_method: "S256",
          dpop_jkt: "forged-jkt",
          attestation_result: fakeAr,
          state: "s",
        }),
      });
      assert.equal(parRes.status, 201, "PAR must accept unverified AR when M9 is ablated");
    } finally {
      await stack.stop();
    }
  });

  it("M11 guard: request_uri reuse allowed when -M11 is active", async () => {
    const stack = await startStack({ ablation: "-M11" });
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      const loginStart = await stack.clients.alice.startLogin();

      // First authorize call
      const authRes1 = await fetch(loginStart.authorizeUrl);
      assert.equal(authRes1.status, 200);

      // Second authorize call with same request_uri: on full -> 400; with -M11 -> 200
      const authRes2 = await fetch(loginStart.authorizeUrl);
      assert.equal(authRes2.status, 200, "Second use of request_uri must succeed when M11 is ablated");
    } finally {
      await stack.stop();
    }
  });

  it("M12 guard: login from non-owned device allowed when -M12 is active", async () => {
    const stack = await startStack({ ablation: "-M12" });
    try {
      // Bob's device is enrolled to Bob
      await stack.clients.bob.enrol(stack.codes["bob-laptop"]);

      // Alice tries to log in using Bob's enrolled device
      const loginStart = await stack.clients.bob.startLogin();
      const authRes = await fetch(loginStart.authorizeUrl);
      const cookie = (authRes.headers.get("set-cookie") || "").split(";")[0];

      const loginRes = await fetch(`${stack.urls.idpIssuer}/oauth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Cookie: cookie,
        },
        body: JSON.stringify({ username: "alice", password: "alice-pass" }),
      });
      assert.equal(loginRes.status, 200, "Login from non-owned device must succeed when M12 is ablated");
    } finally {
      await stack.stop();
    }
  });

  it("M16 guard: PEP accepts stolen AT with another key when -M16 is active", async () => {
    const stack = await startStack({ ablation: "-M16" });
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });

      const aliceAT = stack.clients.alice.accessToken;
      assert.ok(aliceAT);

      // Attacker creates own DPoP key
      const attackerKp = await jose.generateKeyPair("ES256", { extractable: true });
      const attackerPubJwk = await jose.exportJWK(attackerKp.publicKey);
      const attackerSigner = async (data) =>
        crypto.sign("sha256", Buffer.from(data), {
          key: attackerKp.privateKey,
          dsaEncoding: "ieee-p1363",
        });

      const newsUrl = `${stack.urls.pepPublicUrl}/api/company/news`;
      const nonce = (await fetch(newsUrl)).headers.get("DPoP-Nonce");

      const attackerProof = await signProof({
        signer: attackerSigner,
        publicJwk: attackerPubJwk,
        htm: "GET",
        htu: newsUrl,
        nonce,
        accessToken: aliceAT,
        clock: stack.clock,
      });

      const res = await fetch(newsUrl, {
        headers: {
          Authorization: `DPoP ${aliceAT}`,
          DPoP: attackerProof,
        },
      });
      assert.equal(res.status, 200, "PEP must accept stolen AT with different key when M16 is ablated");
    } finally {
      await stack.stop();
    }
  });

  it("M17 guard: PEP accepts proof without nonce when -M17 is active", async () => {
    const stack = await startStack({ ablation: "-M17" });
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });

      const aliceAT = stack.clients.alice.accessToken;
      const newsUrl = `${stack.urls.pepPublicUrl}/api/company/news`;
      const kbPub = stack.clients.alice.kbPublicArea || stack.clients.alice.tpm.keys.get(stack.clients.alice.kbHandle).publicArea;
      const publicJwk = jwkOf(kbPub);

      // Proof without nonce
      const proofWithoutNonce = await signProof({
        signer: (data) => stack.clients.alice.tpm.sign(stack.clients.alice.kbHandle, data),
        publicJwk,
        htm: "GET",
        htu: newsUrl,
        accessToken: aliceAT,
        clock: stack.clock,
        // no nonce
      });

      const res = await fetch(newsUrl, {
        headers: {
          Authorization: `DPoP ${aliceAT}`,
          DPoP: proofWithoutNonce,
        },
      });
      assert.equal(res.status, 200, "PEP must accept proof without nonce when M17 is ablated");
    } finally {
      await stack.stop();
    }
  });

  it("M19 guard: PEP accepts proof with mismatched htm/htu when -M19 is active", async () => {
    const stack = await startStack({ ablation: "-M19" });
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });

      const aliceAT = stack.clients.alice.accessToken;
      const newsUrl = `${stack.urls.pepPublicUrl}/api/company/news`;
      const nonce = (await fetch(newsUrl)).headers.get("DPoP-Nonce");
      const kbPub = stack.clients.alice.kbPublicArea || stack.clients.alice.tpm.keys.get(stack.clients.alice.kbHandle).publicArea;
      const publicJwk = jwkOf(kbPub);

      // Proof minted for POST http://other-host/wrong
      const wrongProof = await signProof({
        signer: (data) => stack.clients.alice.tpm.sign(stack.clients.alice.kbHandle, data),
        publicJwk,
        htm: "POST",
        htu: "http://other-host/wrong",
        nonce,
        accessToken: aliceAT,
        clock: stack.clock,
      });

      const res = await fetch(newsUrl, {
        headers: {
          Authorization: `DPoP ${aliceAT}`,
          DPoP: wrongProof,
        },
      });
      assert.equal(res.status, 200, "PEP must accept proof with mismatched htm/htu when M19 is ablated");
    } finally {
      await stack.stop();
    }
  });

  it("M20 guard: PEP merges forged X-ZTA-Role header when -M20 is active", async () => {
    const stack = await startStack({ ablation: "-M20" });
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });

      const aliceAT = stack.clients.alice.accessToken;
      // High resource requires acr=mfa
      const auditUrl = `${stack.urls.pepPublicUrl}/api/company/audit`;
      const nonce = (await fetch(auditUrl)).headers.get("DPoP-Nonce");
      const kbPub = stack.clients.alice.kbPublicArea || stack.clients.alice.tpm.keys.get(stack.clients.alice.kbHandle).publicArea;
      const publicJwk = jwkOf(kbPub);

      const proof = await signProof({
        signer: (data) => stack.clients.alice.tpm.sign(stack.clients.alice.kbHandle, data),
        publicJwk,
        htm: "GET",
        htu: auditUrl,
        nonce,
        accessToken: aliceAT,
        clock: stack.clock,
      });

      // Alice has acr="pwd", but passes X-ZTA-Acr: mfa to bypass step-up requirement
      const res = await fetch(auditUrl, {
        headers: {
          Authorization: `DPoP ${aliceAT}`,
          DPoP: proof,
          "X-ZTA-Acr": "mfa",
        },
      });
      assert.equal(res.status, 200, "PEP must accept forged role/acr headers when M20 is ablated");
    } finally {
      await stack.stop();
    }
  });

  it("M10 guard: AR jkt mismatch allowed when -M10 is active", async () => {
    const stack = await startStack({ ablation: "-M10" });
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      const arA = await stack.clients.alice.attest();

      // Submit PAR with different dpop_jkt
      const parRes = await fetch(`${stack.urls.idpIssuer}/oauth/par`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: "zta-agent",
          response_type: "code",
          redirect_uri: "http://127.0.0.1:7000/callback",
          code_challenge: "challenge",
          code_challenge_method: "S256",
          dpop_jkt: "different-jkt",
          attestation_result: arA,
          state: "s",
        }),
      });
      assert.equal(parRes.status, 201, "PAR must accept mismatched dpop_jkt when M10 is ablated");
    } finally {
      await stack.stop();
    }
  });

  it("M13 guard: token endpoint mints Bearer token without DPoP header when -M13 is active", async () => {
    const stack = await startStack({ ablation: "-M13" });
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      const loginStart = await stack.clients.alice.startLogin();
      const authRes = await fetch(loginStart.authorizeUrl);
      const cookie = (authRes.headers.get("set-cookie") || "").split(";")[0];

      const loginRes = await fetch(`${stack.urls.idpIssuer}/oauth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json", Cookie: cookie },
        body: JSON.stringify({ username: "alice", password: "alice-pass" }),
      });
      const { code } = await loginRes.json();

      // Call /oauth/token without DPoP header using real code_verifier
      const tokenRes = await fetch(`${stack.urls.idpIssuer}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code,
          redirect_uri: "http://127.0.0.1:7000/callback",
          client_id: "zta-agent",
          code_verifier: stack.clients.alice.pendingLogin.codeVerifier,
        }),
      });
      assert.equal(tokenRes.status, 200, "Token endpoint must succeed without DPoP header when M13 is ablated");
      const tokenData = await tokenRes.json();
      assert.equal(tokenData.token_type, "Bearer");
    } finally {
      await stack.stop();
    }
  });

  it("M14 guard: client-supplied role honored when -M14 is active", async () => {
    const stack = await startStack({ ablation: "-M14" });
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      const ar = await stack.clients.alice.attest();
      const codeVerifier = crypto.randomBytes(32).toString("base64url");
      const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

      const kbPub = stack.clients.alice.kbPublicArea || stack.clients.alice.tpm.keys.get(stack.clients.alice.kbHandle).publicArea;
      const publicJwk = jwkOf(kbPub);
      const parUrl = `${stack.urls.idpIssuer}/oauth/par`;
      const parProof = await signProof({
        signer: (data) => stack.clients.alice.tpm.sign(stack.clients.alice.kbHandle, data),
        publicJwk,
        htm: "POST",
        htu: parUrl,
        clock: stack.clock,
      });

      // Pass client role="admin"
      const parRes = await fetch(parUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", DPoP: parProof },
        body: JSON.stringify({
          client_id: "zta-agent",
          response_type: "code",
          redirect_uri: "http://127.0.0.1:7000/callback",
          code_challenge: codeChallenge,
          code_challenge_method: "S256",
          dpop_jkt: stack.clients.alice.jkt,
          attestation_result: ar,
          state: "s",
          role: "admin",
        }),
      });
      assert.equal(parRes.status, 201);
      const { request_uri } = await parRes.json();

      const authRes = await fetch(`${stack.urls.idpIssuer}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(request_uri)}`);
      const cookie = (authRes.headers.get("set-cookie") || "").split(";")[0];

      const loginRes = await fetch(`${stack.urls.idpIssuer}/oauth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json", Cookie: cookie },
        body: JSON.stringify({ username: "alice", password: "alice-pass" }),
      });
      const { code } = await loginRes.json();

      const tokenUrl = `${stack.urls.idpIssuer}/oauth/token`;
      let tokenProof = await signProof({
        signer: (data) => stack.clients.alice.tpm.sign(stack.clients.alice.kbHandle, data),
        publicJwk,
        htm: "POST",
        htu: tokenUrl,
        clock: stack.clock,
      });

      let tokenRes = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", DPoP: tokenProof },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code,
          redirect_uri: "http://127.0.0.1:7000/callback",
          client_id: "zta-agent",
          code_verifier: codeVerifier,
        }),
      });

      if (tokenRes.status === 400 && tokenRes.headers.get("DPoP-Nonce")) {
        const nonce = tokenRes.headers.get("DPoP-Nonce");
        tokenProof = await signProof({
          signer: (data) => stack.clients.alice.tpm.sign(stack.clients.alice.kbHandle, data),
          publicJwk,
          htm: "POST",
          htu: tokenUrl,
          nonce,
          clock: stack.clock,
        });
        tokenRes = await fetch(tokenUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json", DPoP: tokenProof },
          body: JSON.stringify({
            grant_type: "authorization_code",
            code,
            redirect_uri: "http://127.0.0.1:7000/callback",
            client_id: "zta-agent",
            code_verifier: codeVerifier,
          }),
        });
      }

      assert.equal(tokenRes.status, 200);
      const tokenData = await tokenRes.json();
      const atPayload = JSON.parse(Buffer.from(tokenData.access_token.split(".")[1], "base64url").toString("utf8"));
      assert.equal(atPayload.role, "admin", "Client-supplied role must be used when M14 is ablated");
    } finally {
      await stack.stop();
    }
  });

  it("M15 guard: PEP accepts Bearer scheme when -M15,-M16 is active", async () => {
    const stack = await startStack({ ablation: "-M15,-M16" });
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });

      const aliceAT = stack.clients.alice.accessToken;
      const res = await fetch(`${stack.urls.pepPublicUrl}/api/company/news`, {
        headers: {
          Authorization: `Bearer ${aliceAT}`,
        },
      });
      assert.equal(res.status, 200, "PEP must accept Bearer scheme when M15 is ablated");
    } finally {
      await stack.stop();
    }
  });

  it("M18 guard: PEP accepts replayed proof when -M17,-M18 is active", async () => {
    const stack = await startStack({ ablation: "-M17,-M18" });
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });

      const aliceAT = stack.clients.alice.accessToken;
      const newsUrl = `${stack.urls.pepPublicUrl}/api/company/news`;
      const kbPub = stack.clients.alice.kbPublicArea || stack.clients.alice.tpm.keys.get(stack.clients.alice.kbHandle).publicArea;
      const publicJwk = jwkOf(kbPub);

      const proof = await signProof({
        signer: (data) => stack.clients.alice.tpm.sign(stack.clients.alice.kbHandle, data),
        publicJwk,
        htm: "GET",
        htu: newsUrl,
        accessToken: aliceAT,
        clock: stack.clock,
      });

      // First use
      const res1 = await fetch(newsUrl, {
        headers: { Authorization: `DPoP ${aliceAT}`, DPoP: proof },
      });
      assert.equal(res1.status, 200);

      // Replay of exact same proof (same jti)
      const res2 = await fetch(newsUrl, {
        headers: { Authorization: `DPoP ${aliceAT}`, DPoP: proof },
      });
      assert.equal(res2.status, 200, "Replayed proof must succeed when M18 is ablated");
    } finally {
      await stack.stop();
    }
  });

  it("M21 guard: PEP permits access with stale attestation when -M21 is active", async () => {
    const stack = await startStack({ ablation: "-M21" });
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });

      // Set attestation age to 1000s (> 600s max allowed) in PIP
      await fetch(`${stack.urls.pipUrl}/pip/device/${stack.clients.alice.devId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-ZTA-Internal": stack.cfg.ztaInternalToken },
        body: JSON.stringify({ attestation_age_s: 1000 }),
      });

      const res = await stack.clients.alice.request("company.news");
      assert.equal(res.status, 200, "PEP must allow access despite stale attestation when M21 is ablated");
    } finally {
      await stack.stop();
    }
  });

  it("M22 guard: token refresh succeeds for suspended device when -M22 is active", async () => {
    const stack = await startStack({ ablation: "-M22" });
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });

      // Suspend device in PIP
      await fetch(`${stack.urls.pipUrl}/pip/device/${stack.clients.alice.devId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-ZTA-Internal": stack.cfg.ztaInternalToken },
        body: JSON.stringify({ status: "suspended" }),
      });

      // Refresh token
      const refreshResult = await stack.clients.alice.refresh();
      assert.ok(refreshResult.access_token, "Refresh must succeed even if device suspended when M22 is ablated");
    } finally {
      await stack.stop();
    }
  });

  it("M24 guard: WebAuthn auth options allowed without gated transaction when -M24 is active", async () => {
    const stack = await startStack({ ablation: "-M24" });
    try {
      // Direct call without prior gating
      const res = await fetch(`${stack.urls.idpIssuer}/mfa/auth/options`);
      // When M24 is ablated, default fallback user/dev is used, not 403 unauthorized_transaction
      assert.notEqual(res.status, 403, "WebAuthn auth options must not be blocked with 403 when M24 is ablated");
    } finally {
      await stack.stop();
    }
  });

  it("M25 guard: WebAuthn registration allowed during pending transaction when -M25 is active", async () => {
    const stack = await startStack({ ablation: "-M25" });
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      const loginStart = await stack.clients.alice.startLogin();
      const authRes = await fetch(loginStart.authorizeUrl);
      const cookie = (authRes.headers.get("set-cookie") || "").split(";")[0];

      // With an active oauth transaction, try to register
      const res = await fetch(`${stack.urls.idpIssuer}/mfa/register/options`, {
        headers: { Cookie: cookie },
      });
      // When M25 is ablated, does not return 403 registration_forbidden
      const data = await res.json().catch(() => ({}));
      assert.notEqual(data.error, "registration_forbidden", "WebAuthn registration must not be rejected with registration_forbidden when M25 is ablated");
    } finally {
      await stack.stop();
    }
  });

  it("M26 guard: direct access to resource server allowed when -M26 is active", async () => {
    const stack = await startStack({ ablation: "-M26" });
    try {
      // Directly call resource server without X-ZTA-Internal header
      const directRes = await fetch(`${stack.urls.resourceUrl}/company/news`);
      assert.equal(directRes.status, 200, "Resource server must allow direct access without internal token when M26 is ablated");
    } finally {
      await stack.stop();
    }
  });

});
