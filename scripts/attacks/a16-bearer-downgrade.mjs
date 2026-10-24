/**
 * @file scripts/attacks/a16-bearer-downgrade.mjs
 * Attack A16: Access token presented without DPoP proof (Bearer downgrade) (A2).
 * Expected: M15 (DPoP scheme required).
 */

export default {
  id: "A16",
  title: "Access token presented without DPoP proof (Bearer downgrade)",
  goal: "G3",
  adversary: "A2",
  expected: ["M15"],
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

    // Attacker presents stolen AT as Bearer token without DPoP header
    const res = await fetch(newsUrl, {
      headers: {
        Authorization: `Bearer ${aliceAT}`,
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
        reason: body.message || body.reason || "PEP rejected Bearer scheme",
      },
      evidence: { pepStatus: res.status },
    };
  },
  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
