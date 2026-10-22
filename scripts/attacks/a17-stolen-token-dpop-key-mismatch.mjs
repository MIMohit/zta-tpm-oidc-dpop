/**
 * @file scripts/attacks/a17-stolen-token-dpop-key-mismatch.mjs
 * Attack A17: Stolen access token presented with attacker DPoP key (A2).
 * Expected: M16 (C3: Thumb(proof key) = AT.cnf.jkt).
 */

import crypto from "node:crypto";
import * as jose from "jose";
import { signProof } from "../../lib/dpop.js";

export default {
  id: "A17",
  title: "Stolen access token presented with attacker DPoP key",
  goal: "G3",
  adversary: "A2",
  expected: ["M16"],
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

    // Attacker generates own keypair and obtains fresh server nonce
    const attackerKp = await jose.generateKeyPair("ES256", { extractable: true });
    const attackerPubJwk = await jose.exportJWK(attackerKp.publicKey);

    const noncePre = (await fetch(newsUrl)).headers.get("DPoP-Nonce");

    const proof = await signProof({
      signer: async (data) =>
        crypto.sign("sha256", Buffer.from(data), {
          key: attackerKp.privateKey,
          dsaEncoding: "ieee-p1363",
        }),
      publicJwk: attackerPubJwk,
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
        evidence: { pepStatus: 200 },
      };
    }

    const body = await res.json().catch(() => ({}));
    return {
      outcome: "rejected",
      stoppedAt: {
        service: "pep",
        status: res.status,
        reason: body.message || body.reason || "PEP C3 thumbprint mismatch rejection",
      },
      evidence: { pepStatus: res.status },
    };
  },
  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
