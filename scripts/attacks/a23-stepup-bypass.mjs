/**
 * @file scripts/attacks/a23-stepup-bypass.mjs
 * Attack A23: Step-up bypass / rogue credential injection (A3).
 * Variants:
 *   - "ungated_stepup": Step-up attempted through an ungated transaction (M24)
 *   - "race_registration": WebAuthn credential registration while step-up is gated (M25)
 * Expected: M24 (gated step-up), M25 (controlled credential policy).
 */

import * as jose from "jose";
import { jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";
import { SoftAuthenticator } from "../../tests/helpers/soft-webauthn.js";

export default {
  id: "A23",
  title: "Step-up bypass / rogue credential injection",
  goal: "G2",
  adversary: "A3",
  expected: ["M24", "M25"],
  variants: ["ungated_stepup", "race_registration"],

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    const activeVariant = variant || "ungated_stepup";
    const client = ctx.clients.alice;
    await client.enrol(ctx.codes["alice-laptop"]);

    if (activeVariant === "ungated_stepup") {
      // Register legitimate credential for Alice under her actual deviceId (no literal dev-001 fallback)
      const softAuth = new SoftAuthenticator();
      await ctx.seedWebauthn(softAuth, { user: "alice", client, password: ctx.passwords.alice });

      // 1. Establish an authenticated idpUser session via legitimate primary password login
      const initLogin = await client.startLogin();
      const initAuthResAuth = await ctx.authorize(initLogin.authorizeUrl);
      const initAuthRes = initAuthResAuth.res;
      let cookie = initAuthResAuth.cookie;

      const initPwdRes = await ctx.primaryLogin({ auth: initAuthResAuth, username: "alice", password: "alice-pass" });
      if (!initPwdRes.ok) {
        throw new Error(`Initial primary password authentication failed: ${initPwdRes.status}`);
      }
      cookie = initAuthResAuth.cookie; // the gate session (updated by the Keycloak flow)
      const newCookie = initPwdRes.headers.get("set-cookie");
      if (newCookie) {
        cookie = newCookie.split(";")[0];
      }

      // 2. Start a new OAuth transaction requiring MFA step-up in the same session
      const stepupStart = await client.startLogin({ acrValues: "mfa" });
      // The attacker stops at the gate: no primary authentication (local or Keycloak) for this txn
      const stepupAuthRes = await fetch(stepupStart.authorizeUrl, {
        headers: { Cookie: cookie },
        redirect: "manual",
      });
      const stepupCookie = stepupAuthRes.headers.get("set-cookie");
      if (stepupCookie) {
        cookie = stepupCookie.split(";")[0];
      }

      // 3. Attacker bypasses primary password gate for this new txn and calls /mfa/auth/options directly
      const mfaOptsRes = await fetch(`${ctx.urls.idpUrl}/mfa/auth/options`, {
        headers: { Cookie: cookie },
      });

      if (!mfaOptsRes.ok) {
        const body = await mfaOptsRes.json().catch(() => ({}));
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: mfaOptsRes.status,
            reason: body.error || body.message || "unauthorized_transaction",
          },
          evidence: { variant: activeVariant, status: mfaOptsRes.status },
        };
      }

      // Under -M24, options succeed. Attacker produces WebAuthn assertion and posts to /mfa/verify
      const mfaOpts = await mfaOptsRes.json();
      const assertion = softAuth.createAuthenticationResponse(mfaOpts, {
        origin: ctx.urls.idpUrl,
        rpID: new URL(ctx.urls.idpUrl).hostname,
      });

      const verifyRes = await fetch(`${ctx.urls.idpUrl}/mfa/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: cookie },
        body: JSON.stringify(assertion),
      });

      if (!verifyRes.ok) {
        const body = await verifyRes.json().catch(() => ({}));
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: verifyRes.status,
            reason: body.error || body.message || "MFA verification failed",
          },
          evidence: { variant: activeVariant, status: verifyRes.status },
        };
      }

      const verifyData = await verifyRes.json();
      const code = verifyData.code;
      if (!code) {
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: 400,
            reason: "no_code_issued",
          },
          evidence: { variant: activeVariant, verifyData },
        };
      }

      // 4. Redeem code at /oauth/token and verify returned AT has acr=mfa
      const tokenUrl = `${ctx.urls.idpUrl}/oauth/token`;
      const preRes = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const tokenNonce = preRes.headers.get("DPoP-Nonce") || undefined;

      const tokenProof = await signProof({
        signer: (data) => client.tpm.sign(client.kbHandle, data),
        publicJwk: jwkOf(client.kbPublicArea),
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
          code_verifier: client.pendingLogin?.codeVerifier,
        }),
      });

      if (!tokenRes.ok) {
        const body = await tokenRes.json().catch(() => ({}));
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: tokenRes.status,
            reason: body.error_description || body.error || "Token exchange failed",
          },
          evidence: { variant: activeVariant, tokenStatus: tokenRes.status },
        };
      }

      const tokenData = await tokenRes.json();
      const atPayload = jose.decodeJwt(tokenData.access_token);
      if (atPayload.acr !== "mfa") {
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: 200,
            reason: `Access token acr '${atPayload.acr}' is not mfa`,
          },
          evidence: { variant: activeVariant, atPayload },
        };
      }

      return {
        outcome: "accepted",
        stoppedAt: null,
        evidence: { variant: activeVariant, acr: atPayload.acr },
      };
    }

    if (activeVariant === "race_registration") {
      // 1. Register legitimate authenticator 1 for Alice
      const softAuth1 = new SoftAuthenticator();
      await ctx.seedWebauthn(softAuth1, { user: "alice", client, password: ctx.passwords.alice });

      // 2. Establish authenticated idpUser session via normal login
      const initLogin = await client.startLogin();
      const initAuthResAuth = await ctx.authorize(initLogin.authorizeUrl);
      const initAuthRes = initAuthResAuth.res;
      let cookie = initAuthResAuth.cookie;

      const initPwdRes = await ctx.primaryLogin({ auth: initAuthResAuth, username: "alice", password: "alice-pass" });
      cookie = initAuthResAuth.cookie; // the gate session (updated by the Keycloak flow)
      const newCookie = initPwdRes.headers.get("set-cookie");
      if (newCookie) {
        cookie = newCookie.split(";")[0];
      }

      // 3. Start step-up login transaction with acr=mfa and submit password to enter gated step-up state
      const stepupLogin = await client.startLogin({ acrValues: "mfa" });
      // A second transaction in the same session; the password (local or Keycloak) gates it into step-up
      const stepupAuth = await ctx.authorize(stepupLogin.authorizeUrl, { cookie });
      cookie = stepupAuth.cookie || cookie;

      // Submit password to enter gated step-up
      const loginRes = await ctx.primaryLogin({ auth: stepupAuth, username: "alice", password: "alice-pass" });
      cookie = stepupAuth.cookie || cookie;

      if (!loginRes.ok) {
        throw new Error(`Password submission failed: ${loginRes.status}`);
      }

      // 4. While transaction is gated (pending step-up), attempt to register a new WebAuthn credential
      const regOptsRes = await fetch(`${ctx.urls.idpUrl}/mfa/register/options`, {
        headers: { Cookie: cookie },
      });

      if (!regOptsRes.ok) {
        const body = await regOptsRes.json().catch(() => ({}));
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: regOptsRes.status,
            reason: body.error || body.message || "registration_forbidden",
          },
          evidence: { variant: activeVariant, status: regOptsRes.status },
        };
      }

      // 5. Complete registration with a second credential (softAuth2)
      const regOpts = await regOptsRes.json();
      const softAuth2 = new SoftAuthenticator();
      const regResponse = softAuth2.createRegistrationResponse(regOpts, {
        origin: ctx.urls.idpUrl,
        rpID: new URL(ctx.urls.idpUrl).hostname,
      });

      const regVerifyRes = await fetch(`${ctx.urls.idpUrl}/mfa/register/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: cookie },
        body: JSON.stringify(regResponse),
      });

      if (!regVerifyRes.ok) {
        const body = await regVerifyRes.json().catch(() => ({}));
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: regVerifyRes.status,
            reason: body.error || "registration_verify_failed",
          },
          evidence: { variant: activeVariant, status: regVerifyRes.status },
        };
      }

      // 6. Accepted only if this second stored credential then passes step-up
      const authOptsRes = await fetch(`${ctx.urls.idpUrl}/mfa/auth/options`, {
        headers: { Cookie: cookie },
      });
      if (!authOptsRes.ok) {
        const body = await authOptsRes.json().catch(() => ({}));
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: authOptsRes.status,
            reason: body.error || "mfa_auth_options_failed",
          },
          evidence: { variant: activeVariant, status: authOptsRes.status },
        };
      }

      const authOpts = await authOptsRes.json();
      const assertion = softAuth2.createAuthenticationResponse(authOpts, {
        origin: ctx.urls.idpUrl,
        rpID: new URL(ctx.urls.idpUrl).hostname,
      });

      const stepupVerifyRes = await fetch(`${ctx.urls.idpUrl}/mfa/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: cookie },
        body: JSON.stringify(assertion),
      });

      if (!stepupVerifyRes.ok) {
        const body = await stepupVerifyRes.json().catch(() => ({}));
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: stepupVerifyRes.status,
            reason: body.error || "second_credential_stepup_failed",
          },
          evidence: { variant: activeVariant, status: stepupVerifyRes.status },
        };
      }

      const verifyData = await stepupVerifyRes.json();
      if (!verifyData.code) {
        return {
          outcome: "rejected",
          stoppedAt: {
            service: "idp",
            status: 400,
            reason: "no_code_after_second_credential_stepup",
          },
          evidence: { variant: activeVariant, verifyData },
        };
      }

      return {
        outcome: "accepted",
        stoppedAt: null,
        evidence: { variant: activeVariant, code: verifyData.code, acr: verifyData.acr },
      };
    }

    return { outcome: "error", stoppedAt: { reason: `Unknown variant ${variant}` } };
  },

  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
