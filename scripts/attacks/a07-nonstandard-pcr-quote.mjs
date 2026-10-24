/**
 * @file scripts/attacks/a07-nonstandard-pcr-quote.mjs
 * Attack A07: Quote over nonstandard PCR selection (PCR8-15) with empty event log (A5).
 * Expected: M6 (PCR selection check) and M7 (Event log coverage & non-empty check).
 */

import crypto from "node:crypto";
import { marshalAttest, TPM_ST_ATTEST_QUOTE, pcrDigest } from "../../lib/sim-tpm/attest.js";
import { jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";

export default {
  id: "A07",
  title: "Quote over nonstandard PCR selection (PCR8-15) with empty log",
  goal: "G1",
  adversary: "A5",
  expected: ["M6", "M7"],
  variants: null,

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    const client = ctx.clients.alice;
    await client.enrol(ctx.codes["alice-laptop"]);

    // Request appraisal nonce
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

    // Quote over PCR 8..15 (selection [0x00, 0xff, 0x00]), which the boot never extended
    const ak = client.tpm.keys.get(client.akHandle);
    let quote;
    if (!ak?.privateJwk) {
      // Real TPM: the compromised host simply asks its genuine TPM for this selection
      quote = await client.tpm.quote(client.akHandle, nonce, [8, 9, 10, 11, 12, 13, 14, 15]);
    } else {
      // Simulator: it models PCR0..7 only, so build the same TPMS_ATTEST and sign it with the AK
      const zeroDigest = pcrDigest(Array.from({ length: 8 }, () => Buffer.alloc(32, 0)));
      const attest = marshalAttest({
        type: TPM_ST_ATTEST_QUOTE,
        signerName: ak.name,
        extraData: Buffer.from(nonce, "base64url"),
        clockInfo: { clock: Date.now(), resetCount: 1, restartCount: 0, safe: 1 },
        firmwareVersion: 1n,
        attested: {
          pcrSelect: { count: 1, hash: 0x000b, sizeofSelect: 3, pcrSelect: Buffer.from([0x00, 0xff, 0x00]) },
          pcrDigest: zeroDigest,
        },
      });
      const key = crypto.createPrivateKey({ key: { kty: "EC", crv: "P-256", ...ak.privateJwk }, format: "jwk" });
      const sig = crypto.sign("sha256", attest, { key, dsaEncoding: "ieee-p1363" }).toString("base64url");
      quote = { attest, sig };
    }

    // Submit with empty event log
    const appraiseRes = await fetch(`${ctx.urls.verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: client.devId,
        nonceId,
        quote,
        eventLog: [],
      }),
    });

    if (!appraiseRes.ok) {
      const body = await appraiseRes.json().catch(() => ({}));
      return {
        outcome: "rejected",
        stoppedAt: {
          service: "verifier",
          status: appraiseRes.status,
          reason: body.reason || body.error || "Nonstandard PCR quote rejected",
        },
        evidence: { appraiseStatus: appraiseRes.status },
      };
    }

    // Both M6 and M7 are OFF: appraise succeeded! Complete login and PEP request.
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
