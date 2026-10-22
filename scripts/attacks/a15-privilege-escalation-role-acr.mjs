/**
 * @file scripts/attacks/a15-privilege-escalation-role-acr.mjs
 * Attack A15: Privilege escalation via client-asserted role/acr (A1).
 * Bob attempts to access /api/company/audit by injecting role=auditor in PAR and X-ZTA-Role at PEP.
 * Expected: M14 (directory role), M20 (AT claims only at PEP/PDP).
 */

import crypto from "node:crypto";
import { jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";
import { SoftAuthenticator } from "../../tests/helpers/soft-webauthn.js";

export default {
  id: "A15",
  title: "Privilege escalation via client-asserted role/acr",
  goal: "G2",
  adversary: "A1",
  expected: ["M14", "M20"],
  variants: null,

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    const client = ctx.clients.bob;
    await client.enrol(ctx.codes["bob-laptop"]);
    const bobAr = await client.attest();
    const bobJkt = client.jkt;
    const bobPubJwk = jwkOf(client.kbPublicArea);

    // Register WebAuthn authenticator for Bob to allow step-up MFA
    const softAuth = new SoftAuthenticator();
    await softAuth.registerInStore(ctx.stores.idp, "bob", client.devId);

    // 1. Bob attempts to inject role=auditor and acr=mfa in PAR request
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
    const stateParam = crypto.randomBytes(16).toString("base64url");

    const parProof = await signProof({
      signer: (data) => client.tpm.sign(client.kbHandle, data),
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
        role: "auditor",
        acr: "mfa",
        acr_values: "mfa",
      }),
    });

    if (!parRes.ok) {
      throw new Error(`PAR unexpectedly failed: ${parRes.status}`);
    }

    const { request_uri } = await parRes.json();
    const authRes = await fetch(`${ctx.urls.idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${request_uri}`);
    const cookie = (authRes.headers.get("set-cookie") || "").split(";")[0];

    const loginRes = await fetch(`${ctx.urls.idpUrl}/oauth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Cookie: cookie,
      },
      body: JSON.stringify({ username: "bob", password: "bob-pass" }),
    });

    const loginData = await loginRes.json();
    let code = loginData.code;

    if (loginData.redirect === "/stepup.html" || loginData.redirect?.includes("stepup")) {
      const authOptsRes = await fetch(`${ctx.urls.idpUrl}/mfa/auth/options`, {
        headers: { Cookie: cookie },
      });
      const authOpts = await authOptsRes.json();
      const assertion = softAuth.createAuthenticationResponse(authOpts, {
        origin: ctx.urls.idpUrl,
        rpID: new URL(ctx.urls.idpUrl).hostname,
      });

      const verifyRes = await fetch(`${ctx.urls.idpUrl}/mfa/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: cookie },
        body: JSON.stringify(assertion),
      });
      const verifyData = await verifyRes.json();
      code = verifyData.code;
    }

    const preRes = await fetch(`${ctx.urls.idpUrl}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const tokenNonce = preRes.headers.get("DPoP-Nonce") || undefined;

    const tokenProof = await signProof({
      signer: (data) => client.tpm.sign(client.kbHandle, data),
      publicJwk: bobPubJwk,
      htm: "POST",
      htu: `${ctx.urls.idpUrl}/oauth/token`,
      nonce: tokenNonce,
      clock: ctx.clock,
    });

    const tokenRes = await fetch(`${ctx.urls.idpUrl}/oauth/token`, {
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

    const { access_token } = await tokenRes.json();

    // 2. Bob requests high-privilege resource /api/company/audit (which requires auditor role)
    // and sends X-ZTA-Role: auditor header
    const auditUrl = `${ctx.urls.pepUrl}/api/company/audit`;
    const pepNonceRes = await fetch(auditUrl);
    const pepNonce = pepNonceRes.headers.get("DPoP-Nonce") || undefined;

    const pepProof = await signProof({
      signer: (data) => client.tpm.sign(client.kbHandle, data),
      publicJwk: bobPubJwk,
      htm: "GET",
      htu: auditUrl,
      nonce: pepNonce,
      accessToken: access_token,
      clock: ctx.clock,
    });

    const pepRes = await fetch(auditUrl, {
      headers: {
        Authorization: `DPoP ${access_token}`,
        DPoP: pepProof,
        "X-ZTA-Role": "auditor",
        "X-ZTA-Acr": "mfa",
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
        reason: "Access denied to auditor endpoint (privilege escalation blocked)",
      },
      evidence: { pepStatus: pepRes.status },
    };
  },
  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
