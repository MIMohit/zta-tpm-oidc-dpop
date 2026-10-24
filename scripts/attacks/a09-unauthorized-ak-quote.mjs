/**
 * @file scripts/attacks/a09-unauthorized-ak-quote.mjs
 * Attack A09: Quote signed by unauthorized AK (different AK of the same TPM) (A4).
 * Expected: M5 (Quote signature under AKpub and qualifiedSigner).
 */

import { jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";

export default {
  id: "A09",
  title: "Quote signed by unauthorized AK (different AK of the same TPM)",
  goal: "G1",
  adversary: "A4",
  expected: ["M5"],
  variants: null,

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    const client = ctx.clients.alice;
    await client.enrol(ctx.codes["alice-laptop"]);

    // Request appraisal nonce for enrolled device (registered with AK1)
    const nonceRes = await fetch(`${ctx.urls.verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: client.devId }),
    });

    if (!nonceRes.ok) {
      return {
        outcome: "rejected",
        stoppedAt: { service: "verifier", status: nonceRes.status, reason: "Appraisal nonce failed" },
      };
    }
    const { nonceId, nonce } = await nonceRes.json();

    // Create a second, unauthorized AK2 on the same TPM
    const unauthorizedAk = await client.tpm.createAk();

    // Sign quote with AK2 instead of registered AK1
    const quote = await client.tpm.quote(unauthorizedAk.handle, nonce);
    const eventLog = client.tpm.readEventLog();

    const appraiseRes = await fetch(`${ctx.urls.verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: client.devId,
        nonceId,
        quote,
        eventLog,
      }),
    });

    if (!appraiseRes.ok) {
      const body = await appraiseRes.json().catch(() => ({}));
      return {
        outcome: "rejected",
        stoppedAt: {
          service: "verifier",
          status: appraiseRes.status,
          reason: body.reason || body.error || "Unauthorized AK quote signature rejected",
        },
        evidence: { appraiseStatus: appraiseRes.status },
      };
    }

    // If M5 is OFF, signature check and qualifiedSigner checks are skipped
    const { ar } = await appraiseRes.json();
    client.latestAr = ar;

    try {
      await ctx.loginWithDevice(client, {
        username: "alice",
        password: "alice-pass",
      });
    } catch (err) {
      return {
        outcome: "rejected",
        stoppedAt: { service: "idp", status: err.status || 403, reason: err.message || "Login failed" },
      };
    }

    const newsUrl = `${ctx.urls.pepUrl}/api/company/news`;
    const preRes = await fetch(newsUrl);
    const pepNonce = preRes.headers.get("DPoP-Nonce") || undefined;
    const pubJwk = jwkOf(client.kbPublicArea);

    const proof = await signProof({
      signer: (data) => client.tpm.sign(client.kbHandle, data),
      publicJwk: pubJwk,
      htm: "GET",
      htu: newsUrl,
      nonce: pepNonce,
      accessToken: client.accessToken,
      clock: ctx.clock,
    });

    let pepRes = await fetch(newsUrl, {
      headers: {
        Authorization: `DPoP ${client.accessToken}`,
        DPoP: proof,
      },
    });

    if (pepRes.status !== 200) {
      pepRes = await fetch(newsUrl, {
        headers: {
          Authorization: `Bearer ${client.accessToken}`,
        },
      });
    }

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
        reason: "PEP access rejected",
      },
      evidence: { pepStatus: pepRes.status },
    };
  },
  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
