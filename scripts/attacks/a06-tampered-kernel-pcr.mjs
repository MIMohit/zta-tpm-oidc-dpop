/**
 * @file scripts/attacks/a06-tampered-kernel-pcr.mjs
 * Attack A06: Boot with a modified kernel (tampered boot state) (A5).
 * Expected: M7 (Boot-state appraisal against reference values).
 */

import { jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";

export default {
  id: "A06",
  title: "Boot with a modified kernel (tampered boot state)",
  goal: "G1",
  adversary: "A5",
  expected: ["M7"],
  variants: null,

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    const client = ctx.clients.alice;
    await client.enrol(ctx.codes["alice-laptop"]);

    // Tamper device boot measurements (simulates boot with a compromised/tampered kernel)
    if (typeof client.tpm.tamper === "function") {
      client.tpm.tamper("modified-compromised-kernel");
    }

    // Attempt appraisal with tampered state
    let ar;
    try {
      ar = await client.attest();
    } catch (err) {
      return {
        outcome: "rejected",
        stoppedAt: {
          service: "verifier",
          status: 403,
          reason: err.message || "Appraisal rejected tampered kernel measurements",
        },
        evidence: { attestError: err.message },
      };
    }

    // If M7 is OFF, appraisal succeeded and gave an AR.
    // Verify adversary goal: complete login and verify access token at PEP.
    try {
      await ctx.loginWithDevice(client, {
        username: "alice",
        password: "alice-pass",
      });
    } catch (err) {
      return {
        outcome: "rejected",
        stoppedAt: {
          service: "idp",
          status: err.status || 403,
          reason: err.message || "Login failed",
        },
        evidence: { loginError: err.message },
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
