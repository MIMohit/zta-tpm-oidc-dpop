/**
 * @file scripts/attacks/a12-single-use-violation.mjs
 * Attack A12: Single-use violation: reuse of AR jti, request_uri, or auth code (A2).
 * Variants:
 *   - "ar_jti": reuse same AR in a second PAR request
 *   - "request_uri": reuse same request_uri at /oauth/authorize
 *   - "code": reuse same authorization code at /oauth/token
 * Expected: M11 (single use of AR jti, request_uri and code).
 */

import crypto from "node:crypto";
import { jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";

export default {
  id: "A12",
  title: "Single-use violation (AR jti, request_uri, code)",
  goal: "G2",
  adversary: "A2",
  expected: ["M11"],
  variants: ["ar_jti", "request_uri", "code"],

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    const activeVariant = variant || "ar_jti";
    const client = ctx.clients.alice;
    await client.enrol(ctx.codes["alice-laptop"]);
    const aliceAr = await client.attest();
    const aliceJkt = client.jkt;
    const alicePubJwk = jwkOf(client.kbPublicArea);

    if (activeVariant === "ar_jti") {
      // First PAR request (legitimate)
      const codeVerifier1 = crypto.randomBytes(32).toString("base64url");
      const codeChallenge1 = crypto.createHash("sha256").update(codeVerifier1).digest("base64url");

      const proof1 = await signProof({
        signer: (data) => client.tpm.sign(client.kbHandle, data),
        publicJwk: alicePubJwk,
        htm: "POST",
        htu: `${ctx.urls.idpUrl}/oauth/par`,
        clock: ctx.clock,
      });

      const res1 = await fetch(`${ctx.urls.idpUrl}/oauth/par`, {
        method: "POST",
        headers: { "Content-Type": "application/json", DPoP: proof1 },
        body: JSON.stringify({
          client_id: "zta-agent",
          response_type: "code",
          redirect_uri: "http://127.0.0.1:7000/callback",
          code_challenge: codeChallenge1,
          code_challenge_method: "S256",
          dpop_jkt: aliceJkt,
          attestation_result: aliceAr,
          state: "state1",
        }),
      });

      if (!res1.ok) {
        throw new Error(`Initial PAR request failed with status ${res1.status}`);
      }

      // Replay identical AR in second PAR request
      const codeVerifier2 = crypto.randomBytes(32).toString("base64url");
      const codeChallenge2 = crypto.createHash("sha256").update(codeVerifier2).digest("base64url");

      const proof2 = await signProof({
        signer: (data) => client.tpm.sign(client.kbHandle, data),
        publicJwk: alicePubJwk,
        htm: "POST",
        htu: `${ctx.urls.idpUrl}/oauth/par`,
        clock: ctx.clock,
      });

      const res2 = await fetch(`${ctx.urls.idpUrl}/oauth/par`, {
        method: "POST",
        headers: { "Content-Type": "application/json", DPoP: proof2 },
        body: JSON.stringify({
          client_id: "zta-agent",
          response_type: "code",
          redirect_uri: "http://127.0.0.1:7000/callback",
          code_challenge: codeChallenge2,
          code_challenge_method: "S256",
          dpop_jkt: aliceJkt,
          attestation_result: aliceAr, // Replayed AR with same jti
          state: "state2",
        }),
      });

      if (!res2.ok) {
        const body = await res2.json().catch(() => ({}));
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: res2.status,
            reason: body.error_description || body.error || "AR jti replay rejected at PAR",
          },
          evidence: { variant: activeVariant, status: res2.status },
        };
      }

      // If PAR accepted replayed AR, continue flow to verify if a token can actually be issued
      const { request_uri: reqUri2 } = await res2.json();
      const authRes2 = await fetch(`${ctx.urls.idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${reqUri2}`);
      if (!authRes2.ok && authRes2.status !== 302) {
        const body = await authRes2.json().catch(() => ({}));
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: authRes2.status,
            reason: body.error || "Authorize failed for replayed AR",
          },
          evidence: { variant: activeVariant, status: authRes2.status },
        };
      }

      const cookie2 = (authRes2.headers.get("set-cookie") || "").split(";")[0];
      const loginRes2 = await fetch(`${ctx.urls.idpUrl}/oauth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json", Cookie: cookie2 },
        body: JSON.stringify({ username: "alice", password: "alice-pass" }),
      });
      if (!loginRes2.ok) {
        const body = await loginRes2.json().catch(() => ({}));
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: loginRes2.status,
            reason: body.error || "Login failed for replayed AR",
          },
          evidence: { variant: activeVariant, status: loginRes2.status },
        };
      }

      const { code: code2 } = await loginRes2.json();
      const tokenUrl = `${ctx.urls.idpUrl}/oauth/token`;
      const preRes = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const tokenNonce = preRes.headers.get("DPoP-Nonce") || undefined;
      const proof = await signProof({
        signer: (data) => client.tpm.sign(client.kbHandle, data),
        publicJwk: alicePubJwk,
        htm: "POST",
        htu: tokenUrl,
        nonce: tokenNonce,
        clock: ctx.clock,
      });

      const tokenRes = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", DPoP: proof },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code: code2,
          redirect_uri: "http://127.0.0.1:7000/callback",
          client_id: "zta-agent",
          code_verifier: codeVerifier2,
        }),
      });

      if (!tokenRes.ok) {
        const body = await tokenRes.json().catch(() => ({}));
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: tokenRes.status,
            reason: body.error_description || body.error || "Token redemption failed for replayed AR",
          },
          evidence: { variant: activeVariant, status: tokenRes.status },
        };
      }

      return {
        outcome: "accepted",
        stoppedAt: null,
        evidence: { variant: activeVariant, tokenStatus: tokenRes.status },
      };
    }

    if (activeVariant === "request_uri") {
      const codeVerifier = crypto.randomBytes(32).toString("base64url");
      const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

      const parProof = await signProof({
        signer: (data) => client.tpm.sign(client.kbHandle, data),
        publicJwk: alicePubJwk,
        htm: "POST",
        htu: `${ctx.urls.idpUrl}/oauth/par`,
        clock: ctx.clock,
      });

      const parRes = await fetch(`${ctx.urls.idpUrl}/oauth/par`, {
        method: "POST",
        headers: { "Content-Type": "application/json", DPoP: parProof },
        body: JSON.stringify({
          client_id: "zta-agent",
          response_type: "code",
          redirect_uri: "http://127.0.0.1:7000/callback",
          code_challenge: codeChallenge,
          code_challenge_method: "S256",
          dpop_jkt: aliceJkt,
          attestation_result: aliceAr,
          state: "state-uri",
        }),
      });

      const { request_uri } = await parRes.json();

      // First authorize call (legitimate)
      const authRes1 = await fetch(`${ctx.urls.idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${request_uri}`);
      if (!authRes1.ok && authRes1.status !== 302) {
        throw new Error(`First authorize call failed with status ${authRes1.status}`);
      }

      // Replay authorize call with same request_uri
      const authRes2 = await fetch(`${ctx.urls.idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${request_uri}`);
      if (!authRes2.ok && authRes2.status !== 302) {
        const body = await authRes2.json().catch(() => ({}));
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: authRes2.status,
            reason: body.error_description || body.error || "request_uri reuse rejected at authorize",
          },
          evidence: { variant: activeVariant, status: authRes2.status },
        };
      }

      // If replayed request_uri was accepted at authorize, continue through login to token endpoint
      const cookie2 = (authRes2.headers.get("set-cookie") || "").split(";")[0];
      const loginRes2 = await fetch(`${ctx.urls.idpUrl}/oauth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json", Cookie: cookie2 },
        body: JSON.stringify({ username: "alice", password: "alice-pass" }),
      });

      if (!loginRes2.ok) {
        const body = await loginRes2.json().catch(() => ({}));
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: loginRes2.status,
            reason: body.error || "Login failed after replayed request_uri",
          },
          evidence: { variant: activeVariant, status: loginRes2.status },
        };
      }

      const { code: code2 } = await loginRes2.json();
      const tokenUrl = `${ctx.urls.idpUrl}/oauth/token`;
      const preRes = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const tokenNonce = preRes.headers.get("DPoP-Nonce") || undefined;
      const proof = await signProof({
        signer: (data) => client.tpm.sign(client.kbHandle, data),
        publicJwk: alicePubJwk,
        htm: "POST",
        htu: tokenUrl,
        nonce: tokenNonce,
        clock: ctx.clock,
      });

      const tokenRes = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", DPoP: proof },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code: code2,
          redirect_uri: "http://127.0.0.1:7000/callback",
          client_id: "zta-agent",
          code_verifier: codeVerifier,
        }),
      });

      if (!tokenRes.ok) {
        const body = await tokenRes.json().catch(() => ({}));
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: tokenRes.status,
            reason: body.error_description || body.error || "Token redemption failed for replayed request_uri",
          },
          evidence: { variant: activeVariant, status: tokenRes.status },
        };
      }

      return {
        outcome: "accepted",
        stoppedAt: null,
        evidence: { variant: activeVariant, tokenStatus: tokenRes.status },
      };
    }

    if (activeVariant === "code") {
      // Complete legitimate login up to code redemption
      const loginStart = await client.startLogin();
      const authRes = await fetch(loginStart.authorizeUrl);
      const cookie = (authRes.headers.get("set-cookie") || "").split(";")[0];

      const loginRes = await fetch(`${ctx.urls.idpUrl}/oauth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json", Cookie: cookie },
        body: JSON.stringify({ username: "alice", password: "alice-pass" }),
      });
      const { code } = await loginRes.json();

      // Nonce handshake at token endpoint
      const tokenUrl = `${ctx.urls.idpUrl}/oauth/token`;
      const preRes = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const tokenNonce = preRes.headers.get("DPoP-Nonce") || undefined;

      // First code exchange (legitimate)
      const proof1 = await signProof({
        signer: (data) => client.tpm.sign(client.kbHandle, data),
        publicJwk: alicePubJwk,
        htm: "POST",
        htu: tokenUrl,
        nonce: tokenNonce,
        clock: ctx.clock,
      });

      const tokenRes1 = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", DPoP: proof1 },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code,
          redirect_uri: "http://127.0.0.1:7000/callback",
          client_id: "zta-agent",
          code_verifier: client.pendingLogin.codeVerifier,
        }),
      });

      if (!tokenRes1.ok) {
        throw new Error(`First token redemption failed with status ${tokenRes1.status}`);
      }

      // Replay identical code redemption (with fresh nonce)
      const postNonce = tokenRes1.headers.get("DPoP-Nonce") || tokenNonce;
      const proof2 = await signProof({
        signer: (data) => client.tpm.sign(client.kbHandle, data),
        publicJwk: alicePubJwk,
        htm: "POST",
        htu: tokenUrl,
        nonce: postNonce,
        clock: ctx.clock,
      });

      const tokenRes2 = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", DPoP: proof2 },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code,
          redirect_uri: "http://127.0.0.1:7000/callback",
          client_id: "zta-agent",
          code_verifier: client.pendingLogin.codeVerifier,
        }),
      });

      if (!tokenRes2.ok) {
        const body = await tokenRes2.json().catch(() => ({}));
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: tokenRes2.status,
            reason: body.error_description || body.error || "Code reuse rejected at token endpoint",
          },
          evidence: { variant: activeVariant, status: tokenRes2.status },
        };
      }

      return {
        outcome: "accepted",
        stoppedAt: null,
        evidence: { variant: activeVariant, status: tokenRes2.status },
      };
    }

    return { outcome: "error", stoppedAt: { reason: `Unknown variant ${activeVariant}` } };
  },

  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
