/**
 * @file scripts/attacks/a18-dpop-proof-no-nonce.mjs
 * Attack A18: DPoP proof pre-computed without server nonce (A2).
 * Expected: M17 (PEP server nonce).
 */

import { jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";

export default {
  id: "A18",
  title: "DPoP proof pre-computed without server nonce",
  goal: "G3",
  adversary: "A2",
  expected: ["M17"],
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
    const newsUrl = `${ctx.urls.pepUrl}/api/company/news`;
    const alicePubJwk = jwkOf(client.kbPublicArea);

    // Proof minted in advance without server nonce
    const proofNoNonce = await signProof({
      signer: (data) => client.tpm.sign(client.kbHandle, data),
      publicJwk: alicePubJwk,
      htm: "GET",
      htu: newsUrl,
      nonce: undefined,
      accessToken: aliceAT,
      clock: ctx.clock,
    });

    const res = await fetch(newsUrl, {
      headers: {
        Authorization: `DPoP ${aliceAT}`,
        DPoP: proofNoNonce,
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
        reason: body.reason || body.error || "PEP nonce check rejection (use_dpop_nonce)",
      },
      evidence: { pepStatus: res.status },
    };
  },
  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
