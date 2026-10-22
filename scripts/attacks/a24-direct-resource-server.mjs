/**
 * @file scripts/attacks/a24-direct-resource-server.mjs
 * Attack A24: Direct call to Resource Server bypassing PEP (A1).
 * Expected: M26 (Resource server reachable only from the PEP).
 */

export default {
  id: "A24",
  title: "Direct call to Resource Server bypassing PEP",
  goal: "G3",
  adversary: "A1",
  expected: ["M26"],
  variants: null,

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    // Attacker bypasses the PEP and calls the backend Resource Server directly
    // without the internal service token header (X-ZTA-Internal)
    const directUrl = `${ctx.urls.resourceUrl}/company/news`;

    const res = await fetch(directUrl);

    if (res.status === 200) {
      return {
        outcome: "accepted",
        stoppedAt: null,
        evidence: { status: 200 },
      };
    }

    const body = await res.json().catch(() => ({}));
    return {
      outcome: "rejected",
      stoppedAt: {
        service: "resource-server",
        status: res.status,
        reason: body.message || body.error || "Resource server requireInternal rejection",
      },
      evidence: { status: res.status },
    };
  },
  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
