/**
 * @file scripts/attacks/a19-proof-replay.mjs
 * Attack A19: Replay of captured (AT, DPoP proof) pair (A2).
 * Expected: M18 (jti replay cache), M17 (server nonce).
 */

import { jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";

export default {
  id: "A19",
  title: "Replay of captured (AT, DPoP proof) pair",
  goal: "G3",
  adversary: "A2",
  expected: ["M18", "M17"],
  variants: ["immediate", "delayed"],

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    const activeVariant = variant || "immediate";
    const client = ctx.clients.alice;
    await client.enrol(ctx.codes["alice-laptop"]);

    await ctx.loginWithDevice(client, {
      username: "alice",
      password: "alice-pass",
    });

    const aliceAT = client.accessToken;
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

    // 1. Legitimate request
    const legitimateRes = await fetch(newsUrl, {
      headers: {
        Authorization: `DPoP ${aliceAT}`,
        DPoP: proof,
      },
    });

    if (legitimateRes.status !== 200) {
      throw new Error(`Legitimate initial request failed with status ${legitimateRes.status}`);
    }

    // 2. Replay captured request:
    // - immediate: 5s later, inside nonce validity window and iat skew (M18 necessary)
    // - delayed: 130s later, past nonce window and iat skew (M17 and M18 give defence-in-depth)
    if (activeVariant === "immediate") {
      if (typeof ctx.clock?.advance === "function") {
        ctx.clock.advance(5);
      }
    } else {
      if (typeof ctx.clock?.advance === "function") {
        ctx.clock.advance(130);
      }
    }

    const replayRes = await fetch(newsUrl, {
      headers: {
        Authorization: `DPoP ${aliceAT}`,
        DPoP: proof,
      },
    });

    if (replayRes.status === 200) {
      return {
        outcome: "accepted",
        stoppedAt: null,
        evidence: { variant: activeVariant, replayStatus: 200 },
      };
    }

    const body = await replayRes.json().catch(() => ({}));
    return {
      outcome: "rejected",
      stoppedAt: {
        service: "pep",
        status: replayRes.status,
        reason: body.message || body.reason || "PEP jti replay / nonce check rejection",
      },
      evidence: { variant: activeVariant, replayStatus: replayRes.status },
    };
  },

  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
