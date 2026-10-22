/**
 * @file scripts/attacks/a10-forged-or-expired-ar.mjs
 * Attack A10: Forged or invalid Attestation Result presented at PAR (A1).
 * Variants:
 *   - "invalid_signature": AR signed by attacker key
 *   - "expired": AR with exp in the past
 *   - "status_fail": AR with status: "fail"
 * Expected: M9 (AR signature, expiry and status at PAR).
 */

import crypto from "node:crypto";
import * as jose from "jose";
import { jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";

export default {
  id: "A10",
  title: "Forged or expired attestation result at PAR",
  goal: "G2",
  adversary: "A1",
  expected: ["M9"],
  variants: ["invalid_signature", "expired", "status_fail"],

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    const activeVariant = variant || "invalid_signature";
    const client = ctx.clients.alice;
    await client.enrol(ctx.codes["alice-laptop"]);
    const aliceDevId = client.devId;
    const aliceJkt = client.jkt;
    const alicePubJwk = jwkOf(client.kbPublicArea);

    let arToken;
    const nowSec = Math.floor(ctx.clock() / 1000);

    if (activeVariant === "invalid_signature") {
      const attackerKp = await jose.generateKeyPair("ES256", { extractable: true });
      arToken = await ctx.forgeAr({
        devId: aliceDevId,
        jkt: aliceJkt,
        status: "pass",
        iat: nowSec,
        exp: nowSec + 120,
        signWithKey: attackerKp.privateKey,
      });
    } else if (activeVariant === "expired") {
      arToken = await ctx.forgeAr({
        devId: aliceDevId,
        jkt: aliceJkt,
        status: "pass",
        iat: nowSec - 200,
        exp: nowSec - 100, // Expired
      });
    } else {
      // status_fail
      arToken = await ctx.forgeAr({
        devId: aliceDevId,
        jkt: aliceJkt,
        status: "fail",
        iat: nowSec,
        exp: nowSec + 120,
      });
    }

    // Attempt PAR with this AR
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
    const stateParam = crypto.randomBytes(16).toString("base64url");

    const parProof = await signProof({
      signer: (data) => client.tpm.sign(client.kbHandle, data),
      publicJwk: alicePubJwk,
      htm: "POST",
      htu: `${ctx.urls.idpUrl}/oauth/par`,
      clock: ctx.clock,
    });

    const parRes = await fetch(`${ctx.urls.idpUrl}/oauth/par`, {
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
        dpop_jkt: aliceJkt,
        attestation_result: arToken,
        state: stateParam,
      }),
    });

    if (!parRes.ok) {
      const body = await parRes.json().catch(() => ({}));
      return {
        outcome: "rejected",
        stoppedAt: {
          service: "idp",
          status: parRes.status,
          reason: body.error_description || body.error || "PAR rejected invalid AR",
        },
        evidence: { variant: activeVariant, parStatus: parRes.status },
      };
    }

    // PAR succeeded; check if full login succeeds and allows accessing PEP
    const parData = await parRes.json();
    const requestUri = parData.request_uri;

    const authRes = await fetch(`${ctx.urls.idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${requestUri}`);
    const cookie = (authRes.headers.get("set-cookie") || "").split(";")[0];

    const loginRes = await fetch(`${ctx.urls.idpUrl}/oauth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Cookie: cookie,
      },
      body: JSON.stringify({ username: "alice", password: "alice-pass" }),
    });

    if (!loginRes.ok) {
      const body = await loginRes.json().catch(() => ({}));
      return {
        outcome: "rejected",
        stoppedAt: {
          service: "idp",
          status: loginRes.status,
          reason: body.error || body.reason || "Login gate rejected invalid AR",
        },
        evidence: { variant: activeVariant, loginStatus: loginRes.status },
      };
    }

    const loginData = await loginRes.json();
    const code = loginData.code;

    // Exchange code at /oauth/token with nonce handshake
    const tokenUrl = `${ctx.urls.idpUrl}/oauth/token`;
    const preTokenRes = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const tokenNonce = preTokenRes.headers.get("DPoP-Nonce") || undefined;

    const tokenProof = await signProof({
      signer: (data) => client.tpm.sign(client.kbHandle, data),
      publicJwk: alicePubJwk,
      htm: "POST",
      htu: tokenUrl,
      nonce: tokenNonce,
      clock: ctx.clock,
    });

    const tokenRes = await fetch(tokenUrl, {
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

    if (!tokenRes.ok) {
      return {
        outcome: "rejected",
        stoppedAt: {
          service: "idp",
          status: tokenRes.status,
          reason: "Token endpoint rejected code exchange",
        },
        evidence: { variant: activeVariant, tokenStatus: tokenRes.status },
      };
    }

    const tokenData = await tokenRes.json();
    const accessToken = tokenData.access_token;

    // Use token at PEP
    const pepUrl = `${ctx.urls.pepUrl}/api/company/news`;
    const pepNonceRes = await fetch(pepUrl);
    const pepNonce = pepNonceRes.headers.get("DPoP-Nonce") || undefined;

    const pepProof = await signProof({
      signer: (data) => client.tpm.sign(client.kbHandle, data),
      publicJwk: alicePubJwk,
      htm: "GET",
      htu: pepUrl,
      nonce: pepNonce,
      accessToken,
      clock: ctx.clock,
    });

    const pepRes = await fetch(pepUrl, {
      headers: {
        Authorization: `DPoP ${accessToken}`,
        DPoP: pepProof,
      },
    });

    if (pepRes.status === 200) {
      return {
        outcome: "accepted",
        stoppedAt: null,
        evidence: { variant: activeVariant, pepStatus: 200 },
      };
    }

    return {
      outcome: "rejected",
      stoppedAt: {
        service: "pep",
        status: pepRes.status,
        reason: "PEP rejected access",
      },
      evidence: { variant: activeVariant, pepStatus: pepRes.status },
    };
  },
  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
