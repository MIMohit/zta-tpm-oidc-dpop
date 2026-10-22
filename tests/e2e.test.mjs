/**
 * @file tests/e2e.test.mjs
 * End-to-end integration test suite (WP8).
 * Covers all 15 scenarios defined in PLAN.md Section 4.2:
 * 1. Enrolment (E1-E9)
 * 2. AR issuance (L1-L5) and tauAR expiry
 * 3. Login (Alg.2) & low resource access with DPoP binding (Alg.3)
 * 4. Stolen token without key (C3 check) & Bearer downgrade prevention
 * 5. Replayed DPoP proof (C4 check)
 * 6. Wrong jkt in PAR (C2) and token endpoint
 * 7. Client-asserted role ignored (directory role strictly enforced)
 * 8. Step-up path (RFC 9470 challenge -> WebAuthn -> high resource permit)
 * 9. Risk engine at login (Alg.4 impossible travel step-up and threshold deny)
 * 10. Device revocation propagation (delta < 1s) and refresh rejection
 * 11. Re-attestation failure & suspension on boot tamper
 * 12. Stale attestation enforcement (T_max high vs low)
 * 13. Rogue device not in inventory (A4) & evil CA rejection
 * 14. Stolen password without device / cross-device login prevention
 * 15. Hash-chained signed audit log integrity and tamper detection
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import crypto from "node:crypto";
import * as jose from "jose";

import { startStack } from "./helpers/harness.js";
import { SoftAuthenticator } from "./helpers/soft-webauthn.js";
import { publicJwks } from "../lib/keys.js";
import { verifyAttestationResult } from "../lib/verifier/ar.js";
import { signProof } from "../lib/dpop.js";
import { jwkOf } from "../lib/sim-tpm/public-area.js";
import { verifyAuditLog } from "../lib/audit-log.js";

describe("WP8: End-to-End ZTA Integration Scenarios", () => {
  // Scenario 1: Enrolment
  it("1. Enrolment: alice-laptop enrols, registry and PIP active with fresh attestation", async () => {
    const stack = await startStack();
    try {
      const enrolRes = await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      assert.equal(enrolRes.enrolled, true);
      assert.equal(enrolRes.devId, stack.clients.alice.devId);
      assert.equal(enrolRes.jkt, stack.clients.alice.jkt);

      // Query Verifier registry directly
      const regRes = await fetch(`${stack.urls.verifierUrl}/v/devices/${stack.clients.alice.devId}`, {
        headers: { "X-ZTA-Internal": stack.cfg.ztaInternalToken },
      });
      assert.equal(regRes.status, 200);
      const regData = await regRes.json();
      assert.equal(regData.status, "active");
      assert.equal(regData.jkt, stack.clients.alice.jkt);
      assert.equal(regData.user, "alice");

      // Query PIP
      const pipRes = await fetch(`${stack.urls.pipUrl}/pip/device/${stack.clients.alice.devId}`, {
        headers: { "X-ZTA-Internal": stack.cfg.ztaInternalToken },
      });
      assert.equal(pipRes.status, 200);
      const pipData = await pipRes.json();
      assert.equal(pipData.status, "active");
      assert.ok(pipData.last_good_attestation);
      assert.equal(pipData.attestation_age_s, 0);
    } finally {
      await stack.stop();
    }
  });

  // Scenario 2: AR issuance & tauAR
  it("2. AR issuance: attest() returns AR with exp - iat = 120 and jkt; advancing 121s -> PAR 400", async () => {
    const stack = await startStack();
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      const ar = await stack.clients.alice.attest();
      assert.ok(ar);

      const parts = ar.split(".");
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
      assert.equal(header.typ, "ar+jwt");
      assert.equal(header.alg, "ES256");
      assert.equal(payload.status, "pass");
      assert.equal(payload.jkt, stack.clients.alice.jkt);
      assert.equal(payload.dev, stack.clients.alice.devId);
      assert.equal(payload.exp - payload.iat, 120);

      // Cryptographic verification against Verifier JWKS
      const verified = await verifyAttestationResult(ar, publicJwks(stack.keys.verifier), {
        clock: stack.clock,
      });
      assert.equal(verified.payload.dev, stack.clients.alice.devId);

      // Advancing the clock 121 s before submitting this AR to PAR -> 400
      stack.clock.advance(121);
      const parRes = await fetch(`${stack.urls.idpIssuer}/oauth/par`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: "zta-agent",
          response_type: "code",
          redirect_uri: "http://127.0.0.1:7000/callback",
          code_challenge: "test-challenge",
          code_challenge_method: "S256",
          dpop_jkt: stack.clients.alice.jkt,
          attestation_result: ar,
          state: "s",
        }),
      });
      assert.equal(parRes.status, 400);
      const parData = await parRes.json();
      assert.ok(parData.error_description?.includes("expired") || parData.error?.includes("invalid"));
    } finally {
      await stack.stop();
    }
  });

  // Scenario 3: Login and low resource
  it("3. Login and low resource: alice logs in (acr pwd) and company.news returns 200, AT exp - iat = 300", async () => {
    const stack = await startStack();
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      const { tokens } = await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });
      assert.ok(tokens.access_token);

      const parts = tokens.access_token.split(".");
      const atPayload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
      assert.equal(atPayload.exp - atPayload.iat, 300);
      assert.equal(atPayload.cnf.jkt, stack.clients.alice.jkt);
      assert.equal(atPayload.role, "auditor");
      assert.equal(atPayload.acr, "pwd");

      const res = await stack.clients.alice.request("company.news");
      assert.equal(res.status, 200);
      assert.ok(res.data);
    } finally {
      await stack.stop();
    }
  });

  // Scenario 4: Stolen token without key & Bearer downgrade
  it("4. Stolen token without key: attacker copies AT with own key -> 401 jkt_mismatch; Bearer -> 401", async () => {
    const stack = await startStack();
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });

      const aliceAT = stack.clients.alice.accessToken;
      assert.ok(aliceAT);

      const attackerKp = await jose.generateKeyPair("ES256", { extractable: true });
      const attackerPubJwk = await jose.exportJWK(attackerKp.publicKey);

      const newsUrl = `${stack.urls.pepPublicUrl}/api/company/news`;
      const noncePre = (await fetch(newsUrl)).headers.get("DPoP-Nonce");

      const attackerProof = await signProof({
        signer: async (data) => {
          return crypto.sign("sha256", Buffer.from(data), {
            key: attackerKp.privateKey,
            dsaEncoding: "ieee-p1363",
          });
        },
        publicJwk: attackerPubJwk,
        htm: "GET",
        htu: newsUrl,
        nonce: noncePre,
        accessToken: aliceAT,
        clock: stack.clock,
      });

      // Attacker sends Alice's AT with attacker's DPoP proof -> 401 jkt_mismatch
      const stolenRes = await fetch(newsUrl, {
        headers: {
          Authorization: `DPoP ${aliceAT}`,
          DPoP: attackerProof,
        },
      });
      assert.equal(stolenRes.status, 401);
      const stolenBody = await stolenRes.json().catch(() => ({}));
      assert.equal(stolenBody.error, "jkt_mismatch");

      // Presenting AT as Bearer -> 401 invalid_token
      const bearerRes = await fetch(newsUrl, {
        headers: {
          Authorization: `Bearer ${aliceAT}`,
        },
      });
      assert.equal(bearerRes.status, 401);
    } finally {
      await stack.stop();
    }
  });

  // Scenario 5: Replayed DPoP proof
  it("5. Replayed proof: capturing exact (AT, proof) pair and resending -> 401 replay or use_dpop_nonce", async () => {
    const stack = await startStack();
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });

      const newsUrl = `${stack.urls.pepPublicUrl}/api/company/news`;
      const noncePre = (await fetch(newsUrl)).headers.get("DPoP-Nonce");

      const alicePubJwk = jwkOf(stack.clients.alice.kbPublicArea);
      const proof = await signProof({
        signer: (data) => stack.tpms.alice.sign(stack.clients.alice.kbHandle, data),
        publicJwk: alicePubJwk,
        htm: "GET",
        htu: newsUrl,
        nonce: noncePre,
        accessToken: stack.clients.alice.accessToken,
        clock: stack.clock,
      });

      // 1st request -> 200
      const res1 = await fetch(newsUrl, {
        headers: {
          Authorization: `DPoP ${stack.clients.alice.accessToken}`,
          DPoP: proof,
        },
      });
      assert.equal(res1.status, 200);

      // Replay identical request with same DPoP proof -> 401 replay
      const res2 = await fetch(newsUrl, {
        headers: {
          Authorization: `DPoP ${stack.clients.alice.accessToken}`,
          DPoP: proof,
        },
      });
      assert.equal(res2.status, 401);
      const body2 = await res2.json().catch(() => ({}));
      assert.ok(body2.error === "replay" || body2.error === "use_dpop_nonce");
    } finally {
      await stack.stop();
    }
  });

  // Scenario 6: Wrong jkt
  it("6. Wrong jkt: PAR with dpop_jkt of software key -> 400; token request with proof by another key -> 400", async () => {
    const stack = await startStack();
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      const ar = await stack.clients.alice.attest();

      const swKp = await jose.generateKeyPair("ES256", { extractable: true });
      const swPubJwk = await jose.exportJWK(swKp.publicKey);
      const swJkt = await jose.calculateJwkThumbprint(swPubJwk, "sha256");

      // 1. PAR with dpop_jkt = swJkt while AR has alice.jkt -> 400 ar_jkt_mismatch
      const parRes = await fetch(`${stack.urls.idpIssuer}/oauth/par`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: "zta-agent",
          response_type: "code",
          redirect_uri: "http://127.0.0.1:7000/callback",
          code_challenge: "test-code-challenge",
          code_challenge_method: "S256",
          dpop_jkt: swJkt,
          attestation_result: ar,
          state: "state123",
        }),
      });
      assert.equal(parRes.status, 400);
      const parData = await parRes.json();
      assert.equal(parData.error_description, "ar_jkt_mismatch");

      // 2. Token request with proof signed by key != dpop_jkt -> 400
      const loginStart = await stack.clients.alice.startLogin();
      const authRes = await fetch(loginStart.authorizeUrl);
      const cookie = (authRes.headers.get("set-cookie") || "").split(";")[0];
      const loginRes = await fetch(`${stack.urls.idpIssuer}/oauth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json", Cookie: cookie },
        body: JSON.stringify({ username: "alice", password: "alice-pass" }),
      });
      const { code } = await loginRes.json();
      assert.ok(code);

      const tokenUrl = `${stack.urls.idpIssuer}/oauth/token`;
      const tokenNonce = (await (await fetch(tokenUrl, { method: "POST", body: "{}" })).headers.get("DPoP-Nonce"));

      const badProof = await signProof({
        signer: async (data) => {
          return crypto.sign("sha256", Buffer.from(data), {
            key: swKp.privateKey,
            dsaEncoding: "ieee-p1363",
          });
        },
        publicJwk: swPubJwk,
        htm: "POST",
        htu: tokenUrl,
        nonce: tokenNonce,
        clock: stack.clock,
      });

      const tokenRes = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", DPoP: badProof },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code,
          code_verifier: stack.clients.alice.pendingLogin.codeVerifier,
          redirect_uri: "http://127.0.0.1:7000/callback",
          client_id: "zta-agent",
        }),
      });
      assert.equal(tokenRes.status, 400);
    } finally {
      await stack.stop();
    }
  });

  // Scenario 7: Client-asserted role ignored
  it("7. Client-asserted role ignored: bob (employee) sends asserted role=admin/auditor; AT role is employee and company.audit never 200", async () => {
    const stack = await startStack();
    try {
      await stack.clients.bob.enrol(stack.codes["bob-laptop"]);

      const loginStart = await stack.clients.bob.startLogin();
      const authRes = await fetch(loginStart.authorizeUrl);
      const cookie = (authRes.headers.get("set-cookie") || "").split(";")[0];

      const loginRes = await fetch(`${stack.urls.idpIssuer}/oauth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Cookie: cookie,
          "X-Role": "auditor",
        },
        body: JSON.stringify({ username: "bob", password: "bob-pass", role: "admin" }),
      });
      const { code } = await loginRes.json();
      assert.ok(code);

      const tokens = await stack.clients.bob.finishLogin(code, loginStart.state);
      const atParts = tokens.access_token.split(".");
      const atPayload = JSON.parse(Buffer.from(atParts[1], "base64url").toString("utf8"));
      assert.equal(atPayload.role, "employee", "Role MUST come from directory, client-asserted role ignored");

      // Bob accesses company.audit with acr pwd -> 401 step-up
      const req1 = await stack.clients.bob.request("company.audit");
      assert.equal(req1.status, 401);
      assert.equal(req1.stepUp, true);

      // Even if bob steps up to acr=mfa, employee has no permission on company.audit -> 403
      const bobSoftAuth = new SoftAuthenticator();
      await bobSoftAuth.registerInStore(stack.stores.idp, "bob", stack.clients.bob.devId);

      await stack.loginUser(stack.clients.bob, {
        username: "bob",
        password: "bob-pass",
        acrValues: "mfa",
        softAuth: bobSoftAuth,
      });

      const req2 = await stack.clients.bob.request("company.audit");
      assert.equal(req2.status, 403, "Bob cannot access company.audit even after MFA");
      assert.notEqual(req2.status, 200);
    } finally {
      await stack.stop();
    }
  });

  // Scenario 8: Step-up path
  it("8. Step-up path: alice requests company.audit with pwd -> 401 step-up, then acr_values=mfa -> WebAuthn -> AT acr=mfa -> 200", async () => {
    const stack = await startStack();
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);

      const aliceSoftAuth = new SoftAuthenticator();
      await aliceSoftAuth.registerInStore(stack.stores.idp, "alice", stack.clients.alice.devId);

      // Initial login with acr = pwd
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });

      // Request high resource with acr pwd -> 401 insufficient_user_authentication
      const stepUpRes = await stack.clients.alice.request("company.audit");
      assert.equal(stepUpRes.status, 401);
      assert.equal(stepUpRes.stepUp, true);
      assert.equal(stepUpRes.error, "insufficient_user_authentication");

      // Step-up login with acr_values=mfa
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
        acrValues: "mfa",
        softAuth: aliceSoftAuth,
      });

      assert.equal(stack.clients.alice.session.acr, "mfa");

      // Request high resource with acr mfa -> 200
      const auditRes = await stack.clients.alice.request("company.audit");
      assert.equal(auditRes.status, 200);
      assert.ok(auditRes.data);
    } finally {
      await stack.stop();
    }
  });

  // Scenario 9: Risk at login
  it("9. Risk at login: Berlin -> Sydney 30 min later -> rho >= 0.5 step-up; +5 failures -> rho >= 0.85 deny", async () => {
    const stack = await startStack();
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);

      const aliceSoftAuth = new SoftAuthenticator();
      await aliceSoftAuth.registerInStore(stack.stores.idp, "alice", stack.clients.alice.devId);

      // 1. Seed Alice's prior login history in Berlin on an earlier device
      await stack.stores.pip.set("history/alice", [
        {
          sub: "alice",
          dev: "prior-device",
          ip: "192.0.2.10", // Berlin (AS6805)
          t: stack.clock() - 1800 * 1000,
          success: true,
        },
      ]);

      // 2. Login on alice-laptop from Sydney (new ASN + impossible travel + first login -> rho >= 0.5 -> step-up)
      const loginStart2 = await stack.clients.alice.startLogin();
      const authRes2 = await fetch(loginStart2.authorizeUrl);
      const cookie2 = (authRes2.headers.get("set-cookie") || "").split(";")[0];

      const loginRes2 = await fetch(`${stack.urls.idpIssuer}/oauth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Cookie: cookie2,
          "X-ZTA-Sim-IP": "198.51.100.10", // Sydney
        },
        body: JSON.stringify({ username: "alice", password: "alice-pass" }),
      });
      const loginData2 = await loginRes2.json();
      assert.equal(loginData2.redirect, "/stepup.html", "Must redirect to step-up because rho >= 0.5");
      assert.ok(loginData2.risk >= 0.5, `Expected risk >= 0.5, got ${loginData2.risk}`);

      // 3. Add 5 failed login attempts in PIP
      for (let i = 0; i < 5; i++) {
        await fetch(`${stack.urls.pipUrl}/pip/login-event`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-ZTA-Internal": stack.cfg.ztaInternalToken,
          },
          body: JSON.stringify({
            sub: "alice",
            dev: stack.clients.alice.devId,
            ip: "198.51.100.10",
            t: stack.clock() - 60 * 1000 * (i + 1),
            success: false,
          }),
        });
      }

      // Valid password now fails due to high risk (rho >= 0.85)
      const loginStart3 = await stack.clients.alice.startLogin();

      // Re-set attestation age >= 600s in PIP after appraise so f4 = 1 during login
      await fetch(`${stack.urls.pipUrl}/pip/device/${stack.clients.alice.devId}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ZTA-Internal": stack.cfg.ztaInternalToken,
        },
        body: JSON.stringify({
          last_good_attestation: stack.clock() - 601 * 1000,
          attestation_age_s: 601,
        }),
      });

      const authRes3 = await fetch(loginStart3.authorizeUrl);
      const cookie3 = (authRes3.headers.get("set-cookie") || "").split(";")[0];

      const loginRes3 = await fetch(`${stack.urls.idpIssuer}/oauth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Cookie: cookie3,
          "X-ZTA-Sim-IP": "198.51.100.10",
        },
        body: JSON.stringify({ username: "alice", password: "alice-pass" }),
      });
      assert.equal(loginRes3.status, 403, "Must be denied due to rho >= 0.85");
      const loginData3 = await loginRes3.json();
      assert.equal(loginData3.reason, "risk_score_too_high");
      assert.ok(loginData3.risk >= 0.85);
    } finally {
      await stack.stop();
    }
  });

  // Scenario 10: Revocation
  it("10. Revocation: admin revokes alice device -> next request 403 (delta < 1s); refresh -> invalid_grant", async () => {
    const stack = await startStack();
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });

      const res1 = await stack.clients.alice.request("company.news");
      assert.equal(res1.status, 200);

      // Admin revokes device
      const t0 = Date.now();
      const revokeRes = await fetch(`${stack.urls.registryUrl}/registry/${stack.clients.alice.devId}/revoke`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${stack.cfg.adminToken}`,
        },
      });
      assert.equal(revokeRes.status, 200);
      const revokeData = await revokeRes.json();
      assert.equal(revokeData.revoked, true);

      // Next request to PEP
      const res2 = await stack.clients.alice.request("company.news");
      const t1 = Date.now();
      assert.equal(res2.status, 403);
      const deltaMs = t1 - t0;
      console.log(`⏱️ Revocation propagation latency: ${deltaMs} ms`);
      assert.ok(deltaMs < 1000, `Revocation delta must be < 1s, took ${deltaMs} ms`);

      // Refresh token exchange -> 400 invalid_grant ("device_not_active")
      await assert.rejects(
        async () => {
          await stack.clients.alice.refresh();
        },
        (err) => {
          return err.message.includes("device_not_active") || err.message.includes("400");
        }
      );
    } finally {
      await stack.stop();
    }
  });

  // Scenario 11: Re-attestation failure & suspension on tamper
  it("11. Re-attestation failure: tamper() -> attest() 403 suspended -> next request 403", async () => {
    const stack = await startStack();
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });

      const res1 = await stack.clients.alice.request("company.news");
      assert.equal(res1.status, 200);

      // Tamper Alice's TPM measurements
      stack.clients.alice.tamper("Corrupted boot measurement");

      // Re-attestation attempt fails
      await assert.rejects(
        async () => {
          await stack.clients.alice.attest();
        },
        (err) => {
          return (
            err.message.includes("403") ||
            err.message.includes("Appraisal") ||
            err.message.includes("verification failed")
          );
        }
      );

      // Verify status in PIP is suspended
      const pipRes = await fetch(`${stack.urls.pipUrl}/pip/device/${stack.clients.alice.devId}`, {
        headers: { "X-ZTA-Internal": stack.cfg.ztaInternalToken },
      });
      const pipData = await pipRes.json();
      assert.equal(pipData.status, "suspended");

      // Next request to PEP -> 403
      const res2 = await stack.clients.alice.request("company.news");
      assert.equal(res2.status, 403);
    } finally {
      await stack.stop();
    }
  });

  // Scenario 12: Stale attestation
  it("12. Stale attestation: advance clock 331s without re-attesting -> company.audit 403, company.news 200 until 601s", async () => {
    const stack = await startStack();
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);

      const aliceSoftAuth = new SoftAuthenticator();
      await aliceSoftAuth.registerInStore(stack.stores.idp, "alice", stack.clients.alice.devId);

      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
        acrValues: "mfa",
        softAuth: aliceSoftAuth,
      });

      assert.equal((await stack.clients.alice.request("company.audit")).status, 200);
      assert.equal((await stack.clients.alice.request("company.news")).status, 200);

      // Advance clock 331 s (T_max high = 330 s, T_max low = 600 s)
      stack.clock.advance(331);

      // company.audit (high sensitivity) must return 403 due to stale attestation
      const resAudit = await stack.clients.alice.request("company.audit");
      assert.equal(resAudit.status, 403);

      // company.news (low sensitivity) must still be 200
      const resNews1 = await stack.clients.alice.request("company.news");
      assert.equal(resNews1.status, 200);

      // Advance clock past 601 s (total 602 s)
      stack.clock.advance(271);

      // company.news must now also return 403
      const resNews2 = await stack.clients.alice.request("company.news");
      assert.equal(resNews2.status, 403);
    } finally {
      await stack.stop();
    }
  });

  // Scenario 13: Rogue device & untrusted CA
  it("13. Rogue device (A4): rogue TPM tries to enrol -> 403 ek_not_in_inventory; evil-CA TPM -> 403 ek_cert_invalid", async () => {
    const stack = await startStack();
    try {
      // 1. Rogue device: valid vendor CA cert, but omitted from inventory
      await assert.rejects(
        async () => {
          await stack.clients.rogue.enrol("any-dummy-code");
        },
        (err) => {
          return (
            err.message.includes("ek_not_in_inventory") ||
            err.message.includes("inventory") ||
            err.message.includes("403")
          );
        }
      );

      // 2. Evil device: untrusted evil CA cert
      await assert.rejects(
        async () => {
          await stack.clients.evil.enrol("any-dummy-code");
        },
        (err) => {
          return (
            err.message.includes("ek_cert_invalid") ||
            err.message.includes("certificate") ||
            err.message.includes("403")
          );
        }
      );
    } finally {
      await stack.stop();
    }
  });

  // Scenario 14: Stolen password, no device
  it("14. Stolen password, no device: attacker has password but no AR -> PAR rejected; using bob's AR -> deny", async () => {
    const stack = await startStack();
    try {
      await stack.clients.bob.enrol(stack.codes["bob-laptop"]);

      // 1. Attacker has alice's password, attempts PAR without AR
      const parRes = await fetch(`${stack.urls.idpIssuer}/oauth/par`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: "zta-agent",
          response_type: "code",
          redirect_uri: "http://127.0.0.1:7000/callback",
          code_challenge: "challenge",
          code_challenge_method: "S256",
          dpop_jkt: "fake-jkt",
          state: "s",
        }),
      });
      assert.equal(parRes.status, 400);

      // 2. Attacker uses bob's device / bob's valid AR with alice's password
      const bobLoginStart = await stack.clients.bob.startLogin();
      const authRes = await fetch(bobLoginStart.authorizeUrl);
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

      assert.equal(loginRes.status, 403);
      const loginData = await loginRes.json();
      assert.equal(loginData.reason, "device_not_assigned_to_user_or_inactive");
    } finally {
      await stack.stop();
    }
  });

  // Scenario 15: Audit integrity
  it("15. Audit integrity: verify-audit passes; flipping one byte in audit log -> fails", async () => {
    const stack = await startStack();
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });

      // Perform requests to populate the audit log
      await stack.clients.alice.request("company.news");
      await stack.clients.alice.request("company.audit"); // generates step_up audit
      await stack.clients.alice.request("company.news");

      assert.ok(fs.existsSync(stack.auditLogFile));
      const lines = fs.readFileSync(stack.auditLogFile, "utf8").trim().split("\n");
      assert.ok(lines.length >= 3, `Expected at least 3 audit entries, got ${lines.length}`);

      // Verify audit log
      const resClean = await verifyAuditLog(stack.auditLogFile, {
        publicJwk: stack.keys.audit.publicJwk,
        cfg: stack.cfg,
      });
      assert.equal(resClean.valid, true);

      // Tamper audit log: flip a single byte in the log file
      const rawContent = fs.readFileSync(stack.auditLogFile, "utf8");
      const flipIdx = Math.floor(rawContent.length / 2);
      const flippedChar = rawContent[flipIdx] === "X" ? "Y" : "X";
      const tampered = rawContent.slice(0, flipIdx) + flippedChar + rawContent.slice(flipIdx + 1);
      assert.notEqual(rawContent, tampered);
      fs.writeFileSync(stack.auditLogFile, tampered, "utf8");

      const resTampered = await verifyAuditLog(stack.auditLogFile, {
        publicJwk: stack.keys.audit.publicJwk,
        cfg: stack.cfg,
      });
      assert.equal(resTampered.valid, false);
      assert.ok(resTampered.error);
    } finally {
      await stack.stop();
    }
  });

  // Scenario 16: Regression F4
  it("16. Regression F4: Re-attestation timer persists across logout and restarts after login", async () => {
    const stack = await startStack();
    try {
      await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      assert.ok(stack.clients.alice.reattestTimer, "Re-attestation timer must be running after enrolment");

      // Login alice
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });
      assert.ok(stack.clients.alice.reattestTimer, "Re-attestation timer must be running after login");

      // Logout alice
      stack.clients.alice.logout();
      assert.equal(stack.clients.alice.accessToken, null);
      assert.ok(stack.clients.alice.reattestTimer, "Re-attestation timer must NOT be stopped on logout");

      // Manually stop reattestation to simulate stopped state
      stack.clients.alice.stopReattestation();
      assert.equal(stack.clients.alice.reattestTimer, null);

      // Subsequent login MUST restart re-attestation (F4 requirement)
      await stack.loginUser(stack.clients.alice, {
        username: "alice",
        password: "alice-pass",
      });
      assert.ok(stack.clients.alice.reattestTimer, "Re-attestation timer MUST be restarted after login");

      // Verified access works
      const res = await stack.clients.alice.request("company.news");
      assert.equal(res.status, 200);
    } finally {
      await stack.stop();
    }
  });
});

