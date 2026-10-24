/**
 * @file scripts/attacks/a02-untrusted-ca-ek.mjs
 * Attack A02: Untrusted CA EK certificate presented at enrolment (A4).
 * Expected: M1 (EK certificate chain to a vendor root).
 */

import crypto from "node:crypto";
import { devIdOf, jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";
import { enrolExtras } from "./lib/enrol-extras.mjs";

export default {
  id: "A02",
  title: "Untrusted CA EK certificate presented at enrolment",
  goal: "G1",
  adversary: "A4",
  expected: ["M1"],
  variants: null,

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    const client = ctx.clients.evil;
    const { publicArea: ekPub, cert: ekCert } = await client.tpm.getEk();
    const evilDevId = await devIdOf(ekPub);

    // Pre-seed evil device in inventory for alice so M2 (inventory check) passes,
    // isolating M1 (vendor CA certificate verification).
    const code = "a02-evil-code";
    await ctx.seedInventory({ devId: evilDevId, user: "alice", code });

    const ak = await client.tpm.createAk();
    const kb = await client.tpm.createKb();

    const startRes = await fetch(`${ctx.urls.verifierUrl}/v/enrol/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code,
        ekCert,
        akPublic: ak.publicArea,
        kbPublic: kb.publicArea,
        user: "alice",
        ...(await enrolExtras(client.tpm)),
      }),
    });

    if (!startRes.ok) {
      const body = await startRes.json().catch(() => ({}));
      return {
        outcome: "rejected",
        stoppedAt: {
          service: "verifier",
          status: startRes.status,
          reason: body.message || body.error || "Untrusted CA EK certificate rejected",
        },
        evidence: { startStatus: startRes.status },
      };
    }

    // If M1 is OFF, untrusted CA cert is accepted
    const { sessionId, blob, nonce } = await startRes.json();
    const secret = await client.tpm.activateCredential(ak.handle, blob);
    const quote = await client.tpm.quote(ak.handle, nonce);
    const certify = await client.tpm.certify(kb.handle, ak.handle, nonce);
    const eventLog = typeof client.tpm.readEventLog === "function" ? await client.tpm.readEventLog() : null;

    const finishRes = await fetch(`${ctx.urls.verifierUrl}/v/enrol/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId,
        secret: Buffer.isBuffer(secret) ? secret.toString("hex") : String(secret),
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
          reason: body.message || body.error || "Enrol finish failed",
        },
        evidence: { finishStatus: finishRes.status },
      };
    }

    const finishBody = await finishRes.json();
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
          reason: err.message || "Login failed for evil device",
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
