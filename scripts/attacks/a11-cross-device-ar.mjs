/**
 * @file scripts/attacks/a11-cross-device-ar.mjs
 * Attack A11: Cross-device AR injection (AR of Alice + DPoP key of Bob) (A4).
 * Expected: M10 (C2: AR.jkt = dpop_jkt).
 */

import crypto from "node:crypto";
import { jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";

export default {
  id: "A11",
  title: "Cross-device AR injection (AR.jkt != dpop_jkt)",
  goal: "G2",
  adversary: "A4",
  expected: ["M10"],
  variants: null,

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    // Alice enrols device and gets genuine AR
    const clientAlice = ctx.clients.alice;
    await clientAlice.enrol(ctx.codes["alice-laptop"]);
    const aliceAr = await clientAlice.attest();

    // Bob enrols device to obtain second key
    const clientBob = ctx.clients.bob;
    await clientBob.enrol(ctx.codes["bob-laptop"]);
    const bobJkt = clientBob.jkt;
    const bobPubJwk = jwkOf(clientBob.kbPublicArea);

    // Attacker initiates PAR with Alice's AR but Bob's K_B / dpop_jkt
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
    const stateParam = crypto.randomBytes(16).toString("base64url");

    const parProof = await signProof({
      signer: (data) => clientBob.tpm.sign(clientBob.kbHandle, data),
      publicJwk: bobPubJwk,
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
        dpop_jkt: bobJkt,
        attestation_result: aliceAr,
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
          reason: body.error_description || body.error || "PAR rejected mismatched dpop_jkt",
        },
        evidence: { parStatus: parRes.status },
      };
    }

    // If PAR accepted it, complete login for alice (owner of the device)
    const parData = await parRes.json();
    const requestUri = parData.request_uri;

    const authResAuth = await ctx.authorize(`${ctx.urls.idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${requestUri}`);
    const authRes = authResAuth.res;
    const cookie = authResAuth.cookie;

    const loginRes = await ctx.primaryLogin({ auth: authResAuth, username: "alice", password: "alice-pass" });

    if (!loginRes.ok) {
      const body = await loginRes.json().catch(() => ({}));
      return {
        outcome: "rejected",
        stoppedAt: {
          service: "idp",
          status: loginRes.status,
          reason: body.error || body.reason || "Login gate rejected cross-device AR",
        },
        evidence: { loginStatus: loginRes.status },
      };
    }

    const { code } = await loginRes.json();

    // Redeem code with Bob's key, using token nonce handshake
    const tokenUrl = `${ctx.urls.idpUrl}/oauth/token`;
    const preTokenRes = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const tokenNonce = preTokenRes.headers.get("DPoP-Nonce") || undefined;

    const tokenProof = await signProof({
      signer: (data) => clientBob.tpm.sign(clientBob.kbHandle, data),
      publicJwk: bobPubJwk,
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
          reason: "Token endpoint rejected code redemption",
        },
        evidence: { tokenStatus: tokenRes.status },
      };
    }

    const { access_token } = await tokenRes.json();

    // Test PEP access with Bob's key proof
    const pepUrl = `${ctx.urls.pepUrl}/api/company/news`;
    const pepNonceRes = await fetch(pepUrl);
    const pepNonce = pepNonceRes.headers.get("DPoP-Nonce") || undefined;

    const pepProof = await signProof({
      signer: (data) => clientBob.tpm.sign(clientBob.kbHandle, data),
      publicJwk: bobPubJwk,
      htm: "GET",
      htu: pepUrl,
      nonce: pepNonce,
      accessToken: access_token,
      clock: ctx.clock,
    });

    const pepRes = await fetch(pepUrl, {
      headers: {
        Authorization: `DPoP ${access_token}`,
        DPoP: pepProof,
      },
    });

    if (pepRes.status === 200) {
      return {
        outcome: "accepted",
        stoppedAt: null,
        evidence: { pepStatus: 200 },
      };
    }

    return {
      outcome: "rejected",
      stoppedAt: {
        service: "pep",
        status: pepRes.status,
        reason: "PEP rejected access",
      },
      evidence: { pepStatus: pepRes.status },
    };
  },
  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
