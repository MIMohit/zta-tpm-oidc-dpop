/**
 * @file scripts/attacks/a14-code-redemption-key-mismatch.mjs
 * Attack A14: Stolen authorization code redeemed with attacker DPoP key (A2).
 * Expected: M13 (Token-endpoint DPoP: nonce, and proof key = code.jkt).
 */

import crypto from "node:crypto";
import * as jose from "jose";
import { signProof } from "../../lib/dpop.js";

export default {
  id: "A14",
  title: "Stolen authorization code redeemed with attacker DPoP key",
  goal: "G2",
  adversary: "A2",
  expected: ["M13"],
  variants: null,

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    const client = ctx.clients.alice;
    await client.enrol(ctx.codes["alice-laptop"]);

    // Alice performs login up to obtaining authorization code
    const loginStart = await client.startLogin();
    const authResAuth = await ctx.authorize(loginStart.authorizeUrl);
    const authRes = authResAuth.res;
    const cookie = authResAuth.cookie;

    const loginRes = await ctx.primaryLogin({ auth: authResAuth, username: "alice", password: "alice-pass" });

    const { code } = await loginRes.json();
    const codeVerifier = client.pendingLogin.codeVerifier;

    // Attacker intercepts code and redeems it with attacker's own DPoP keypair
    const attackerKp = await jose.generateKeyPair("ES256", { extractable: true });
    const attackerPubJwk = await jose.exportJWK(attackerKp.publicKey);

    // Get nonce from token endpoint
    const preRes = await fetch(`${ctx.urls.idpUrl}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const tokenNonce = preRes.headers.get("DPoP-Nonce") || undefined;

    const attackerProof = await signProof({
      signer: async (data) =>
        crypto.sign("sha256", Buffer.from(data), {
          key: attackerKp.privateKey,
          dsaEncoding: "ieee-p1363",
        }),
      publicJwk: attackerPubJwk,
      htm: "POST",
      htu: `${ctx.urls.idpUrl}/oauth/token`,
      nonce: tokenNonce,
      clock: ctx.clock,
    });

    const tokenRes = await fetch(`${ctx.urls.idpUrl}/oauth/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        DPoP: attackerProof,
      },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
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
          reason: body.error_description || body.error || "Token endpoint rejected mismatched DPoP key",
        },
        evidence: { tokenStatus: tokenRes.status },
      };
    }

    // Token was minted for attacker; verify PEP access
    const tokenData = await tokenRes.json();
    const accessToken = tokenData.access_token;

    const pepUrl = `${ctx.urls.pepUrl}/api/company/news`;
    const pepNonceRes = await fetch(pepUrl);
    const pepNonce = pepNonceRes.headers.get("DPoP-Nonce") || undefined;

    const pepProof = await signProof({
      signer: async (data) =>
        crypto.sign("sha256", Buffer.from(data), {
          key: attackerKp.privateKey,
          dsaEncoding: "ieee-p1363",
        }),
      publicJwk: attackerPubJwk,
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
