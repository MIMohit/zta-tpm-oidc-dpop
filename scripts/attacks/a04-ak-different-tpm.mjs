/**
 * @file scripts/attacks/a04-ak-different-tpm.mjs
 * Attack A04: AK created on a different TPM than the certified EK (A4).
 * Expected: M3 (Credential activation secret check: s' == s).
 */

import crypto from "node:crypto";
import { jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";

export default {
  id: "A04",
  title: "AK created on a different TPM than the certified EK",
  goal: "G1",
  adversary: "A4",
  expected: ["M3"],
  variants: null,

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    // Alice's legitimate EK and cert
    const { publicArea: aliceEkPub, cert: aliceEkCert } = await ctx.tpms.alice.getEk();
    const aliceCode = ctx.codes["alice-laptop"] || ctx.codes.alice;

    // Attacker generates AK and KB on Rogue's TPM
    const rogueTpm = ctx.tpms.rogue;
    const ak = await rogueTpm.createAk();
    const kb = await rogueTpm.createKb();

    // Start enrolment with Alice's EK cert and code, but Rogue's AK
    const startRes = await fetch(`${ctx.urls.verifierUrl}/v/enrol/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: aliceCode,
        ekCert: aliceEkCert,
        akPublic: ak.publicArea,
        kbPublic: kb.publicArea,
        user: "alice",
      }),
    });

    if (!startRes.ok) {
      const body = await startRes.json().catch(() => ({}));
      return {
        outcome: "rejected",
        stoppedAt: {
          service: "verifier",
          status: startRes.status,
          reason: body.message || body.error || "Enrol start failed",
        },
        evidence: { startStatus: startRes.status },
      };
    }

    const { sessionId, nonce } = await startRes.json();

    // The blob was encrypted with Alice's EK, so Rogue's TPM cannot decrypt it.
    // The attacker supplies a random fake secret instead.
    const fakeSecret = crypto.randomBytes(32).toString("hex");
    const quote = await rogueTpm.quote(ak.handle, nonce);
    const certify = await rogueTpm.certify(kb.handle, ak.handle, nonce);
    const eventLog = typeof rogueTpm.readEventLog === "function" ? await rogueTpm.readEventLog() : null;

    const finishRes = await fetch(`${ctx.urls.verifierUrl}/v/enrol/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId,
        secret: fakeSecret,
        quote,
        certify,
        eventLog,
      }),
    });

    if (!finishRes.ok) {
      const body = await finishRes.json().catch(() => ({}));
      return {
        outcome: "rejected",
        stoppedAt: {
          service: "verifier",
          status: finishRes.status,
          reason: body.message || body.error || "Credential activation secret mismatch",
        },
        evidence: { finishStatus: finishRes.status },
      };
    }

    // If M3 is OFF, wrong secret is accepted and enrolment finishes
    const finishBody = await finishRes.json();
    const client = ctx.clients.rogue;
    client.enrolled = true;
    client.devId = finishBody.devId;
    client.akHandle = ak.handle;
    client.kbHandle = kb.handle;
    client.jkt = finishBody.jkt;
    client.kbPublicArea = kb.publicArea;

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
