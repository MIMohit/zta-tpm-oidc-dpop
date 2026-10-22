/**
 * @file scripts/attacks/a08-stale-quote-replay.mjs
 * Attack A08: Replay of an earlier genuine quote against a new appraisal nonce (A1).
 * Expected: M4 (Nonce freshness: extraData == n_V).
 */

import { jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";

export default {
  id: "A08",
  title: "Replay of an earlier genuine quote against a new appraisal nonce",
  goal: "G1",
  adversary: "A1",
  expected: ["M4"],
  variants: null,

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    const client = ctx.clients.alice;
    await client.enrol(ctx.codes["alice-laptop"]);

    // 1. Legitimate quote at T1 over nonce1
    const nonce1Res = await fetch(`${ctx.urls.verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: client.devId }),
    });
    const { nonce: nonce1 } = await nonce1Res.json();
    const genuineQuote1 = await client.tpm.quote(client.akHandle, nonce1);
    const genuineLog1 = client.tpm.readEventLog();

    // 2. Attacker requests fresh appraisal nonce2 at T2
    const nonce2Res = await fetch(`${ctx.urls.verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: client.devId }),
    });
    const { nonceId: nonceId2 } = await nonce2Res.json();

    // 3. Replay earlier quote1 against new nonceId2
    const appraiseRes = await fetch(`${ctx.urls.verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: client.devId,
        nonceId: nonceId2,
        quote: genuineQuote1,
        eventLog: genuineLog1,
      }),
    });

    if (!appraiseRes.ok) {
      const body = await appraiseRes.json().catch(() => ({}));
      return {
        outcome: "rejected",
        stoppedAt: {
          service: "verifier",
          status: appraiseRes.status,
          reason: body.reason || body.error || "Stale quote rejected",
        },
        evidence: { appraiseStatus: appraiseRes.status },
      };
    }

    // If M4 is OFF, stale quote extraData check is skipped and fresh AR is issued
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
