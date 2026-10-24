/**
 * @file scripts/attacks/a21-revocation-enforcement.mjs
 * Attack A21: Continued use and refresh after device revocation (A2).
 * Variants:
 *   - "at_revoked": AT presentation to PEP after revocation
 *   - "refresh_revoked": Token refresh at IdP after revocation
 * Expected: M21 (per-request device status), M22 (refresh PIP status check).
 */

import { jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";

export default {
  id: "A21",
  title: "Continued use and refresh after device revocation",
  goal: "G4",
  adversary: "A2",
  expected: ["M21", "M22"],
  variants: ["at_revoked", "refresh_revoked"],

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    const activeVariant = variant || "at_revoked";
    const client = ctx.clients.alice;
    await client.enrol(ctx.codes["alice-laptop"]);

    const loginResult = await ctx.loginWithDevice(client, {
      username: "alice",
      password: "alice-pass",
    });

    const aliceAT = client.accessToken;
    const refreshToken = loginResult.tokens?.refresh_token || client.refreshToken;

    // Revoke the device
    await ctx.revoke(client.devId);

    if (activeVariant === "at_revoked") {
      // Presentation of AT to PEP after revocation
      const newsUrl = `${ctx.urls.pepUrl}/api/company/news`;
      const alicePubJwk = jwkOf(client.kbPublicArea);
      const noncePre = (await fetch(newsUrl)).headers.get("DPoP-Nonce");

      const proof = await signProof({
        signer: (data) => client.tpm.sign(client.kbHandle, data),
        publicJwk: alicePubJwk,
        htm: "GET",
        htu: newsUrl,
        nonce: noncePre,
        accessToken: aliceAT,
        clock: ctx.clock,
      });

      const res = await fetch(newsUrl, {
        headers: {
          Authorization: `DPoP ${aliceAT}`,
          DPoP: proof,
        },
      });

      if (res.status === 200) {
        return {
          outcome: "accepted",
          stoppedAt: null,
          evidence: { variant, pepStatus: 200 },
        };
      }

      const body = await res.json().catch(() => ({}));
      return {
        outcome: "rejected",
        stoppedAt: {
          service: "pep",
          status: res.status,
          reason: body.reason || body.error || "PEP/PDP rejected revoked device access",
        },
        evidence: { variant, pepStatus: res.status },
      };
    }

    if (activeVariant === "refresh_revoked") {
      // Attempt token refresh after revocation
      const tokenUrl = `${ctx.urls.idpUrl}/oauth/token`;
      const alicePubJwk = jwkOf(client.kbPublicArea);

      // Pre-flight nonce from token endpoint
      const preRes = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const tokenNonce = preRes.headers.get("DPoP-Nonce") || undefined;

      const refreshProof = await signProof({
        signer: (data) => client.tpm.sign(client.kbHandle, data),
        publicJwk: alicePubJwk,
        htm: "POST",
        htu: tokenUrl,
        nonce: tokenNonce,
        clock: ctx.clock,
      });

      const refreshRes = await fetch(tokenUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          DPoP: refreshProof,
        },
        body: JSON.stringify({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: "zta-agent",
        }),
      });

      if (refreshRes.ok) {
        return {
          outcome: "accepted",
          stoppedAt: null,
          evidence: { variant, refreshStatus: refreshRes.status },
        };
      }

      const body = await refreshRes.json().catch(() => ({}));
      return {
        outcome: "rejected",
        stoppedAt: {
          service: "idp",
          status: refreshRes.status,
          reason: body.error_description || body.error || "IdP rejected refresh for revoked device",
        },
        evidence: { variant, refreshStatus: refreshRes.status },
      };
    }

    return { outcome: "error", stoppedAt: { reason: `Unknown variant ${variant}` } };
  },
  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
