/**
 * @file scripts/attacks/a20-proof-method-uri-mismatch.mjs
 * Attack A20: Proof minted for different HTTP method/URI (htm/htu mismatch) (A2).
 * Expected: M19 (htm, htu and ath binding).
 */

import { jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";

export default {
  id: "A20",
  title: "Proof minted for different HTTP method/URI (htm/htu mismatch)",
  goal: "G3",
  adversary: "A2",
  expected: ["M19"],
  variants: null,

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    const client = ctx.clients.alice;
    await client.enrol(ctx.codes["alice-laptop"]);

    await ctx.loginWithDevice(client, {
      username: "alice",
      password: "alice-pass",
    });

    const aliceAT = client.accessToken;
    const targetUrl = `${ctx.urls.pepUrl}/api/company/news`;
    const alicePubJwk = jwkOf(client.kbPublicArea);

    const noncePre = (await fetch(targetUrl)).headers.get("DPoP-Nonce");

    // Proof minted with htm: "POST", but used on GET request (or htu mismatch)
    const mismatchedProof = await signProof({
      signer: (data) => client.tpm.sign(client.kbHandle, data),
      publicJwk: alicePubJwk,
      htm: "POST", // Mismatch with actual GET method
      htu: targetUrl,
      nonce: noncePre,
      accessToken: aliceAT,
      clock: ctx.clock,
    });

    const res = await fetch(targetUrl, {
      method: "GET",
      headers: {
        Authorization: `DPoP ${aliceAT}`,
        DPoP: mismatchedProof,
      },
    });

    if (res.status === 200) {
      return {
        outcome: "accepted",
        stoppedAt: null,
        evidence: { pepStatus: 200 },
      };
    }

    const body = await res.json().catch(() => ({}));
    return {
      outcome: "rejected",
      stoppedAt: {
        service: "pep",
        status: res.status,
        reason: body.message || body.reason || "PEP rejected mismatched htm/htu",
      },
      evidence: { pepStatus: res.status },
    };
  },
  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
