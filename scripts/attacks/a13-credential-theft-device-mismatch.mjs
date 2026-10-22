/**
 * @file scripts/attacks/a13-credential-theft-device-mismatch.mjs
 * Attack A13: Credential theft without enrolled device (Alice password + Bob device) (A3).
 * Expected: M12 (Device owner and status checked at login).
 */

import crypto from "node:crypto";
import { jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";

export default {
  id: "A13",
  title: "Credential theft without enrolled device",
  goal: "G2",
  adversary: "A3",
  expected: ["M12"],
  variants: null,

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    // Bob enrols his device legitimately
    const clientBob = ctx.clients.bob;
    await clientBob.enrol(ctx.codes["bob-laptop"]);
    const bobAr = await clientBob.attest();
    const bobJkt = clientBob.jkt;
    const bobPubJwk = jwkOf(clientBob.kbPublicArea);

    // Attacker initiates PAR using Bob's device & DPoP key
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
        attestation_result: bobAr,
        state: stateParam,
      }),
    });

    if (!parRes.ok) {
      throw new Error(`PAR with Bob's device unexpectedly failed: ${parRes.status}`);
    }

    const { request_uri } = await parRes.json();
    const authRes = await fetch(`${ctx.urls.idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(request_uri)}`);
    const cookie = (authRes.headers.get("set-cookie") || "").split(";")[0];

    // Attacker submits Alice's stolen password from Bob's device session
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
          reason: body.reason || body.error || "Login rejected: device not owned by user",
        },
        evidence: { loginStatus: loginRes.status },
      };
    }

    // Login accepted (M12 ablated); exchange code and verify PEP access
    const { code } = await loginRes.json();

    const tokenUrl = `${ctx.urls.idpUrl}/oauth/token`;
    const preRes = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const tokenNonce = preRes.headers.get("DPoP-Nonce") || undefined;

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
          reason: "Token exchange failed",
        },
        evidence: { tokenStatus: tokenRes.status },
      };
    }

    const { access_token } = await tokenRes.json();

    return {
      outcome: "accepted",
      stoppedAt: null,
      evidence: { loginStatus: loginRes.status, tokenStatus: tokenRes.status, hasToken: Boolean(access_token) },
    };
  },

  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
