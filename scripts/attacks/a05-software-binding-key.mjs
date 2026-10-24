/**
 * @file scripts/attacks/a05-software-binding-key.mjs
 * Attack A05: Software binding key (uncertified K_B) (A4).
 * Expected: M8 (Binding key certification: CertifyOK).
 */

import crypto from "node:crypto";
import * as jose from "jose";
import { signProof } from "../../lib/dpop.js";
import { enrolExtras } from "./lib/enrol-extras.mjs";

export default {
  id: "A05",
  title: "Software binding key (uncertified K_B)",
  goal: "G1",
  adversary: "A4",
  expected: ["M8"],
  variants: ["dummy_certify", "genuine_certify_different_key"],

  applicable(cfgState, mode) {
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    const activeVariant = variant || "dummy_certify";
    const tpm = ctx.tpms.alice;
    const { cert: ekCert } = await tpm.getEk();
    const aliceCode = ctx.codes["alice-laptop"] || ctx.codes.alice;

    // Legitimate TPM Attestation Key
    const ak = await tpm.createAk();

    // Software Binding Key K_B (not generated or stored in TPM)
    const swKp = await jose.generateKeyPair("ES256", { extractable: true });
    const swPubJwk = await jose.exportJWK(swKp.publicKey);

    const kbPublic = {
      type: "ecc",
      curve: "P-256",
      x: swPubJwk.x,
      y: swPubJwk.y,
    };

    const startRes = await fetch(`${ctx.urls.verifierUrl}/v/enrol/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: aliceCode,
        ekCert,
        akPublic: ak.publicArea,
        kbPublic,
        user: "alice",
        ...(await enrolExtras(tpm)),
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
        evidence: { variant: activeVariant, startStatus: startRes.status },
      };
    }

    const { sessionId, blob, nonce } = await startRes.json();
    const secret = await tpm.activateCredential(ak.handle, blob);
    const quote = await tpm.quote(ak.handle, nonce);
    const eventLog = typeof tpm.readEventLog === "function" ? await tpm.readEventLog() : null;

    let certify;
    if (activeVariant === "genuine_certify_different_key") {
      // Genuine TPM2_Certify produced by AK over a real TPM key, presented alongside software K_B
      const genuineTpmKey = await tpm.createKb();
      certify = await tpm.certify(genuineTpmKey.handle, ak.handle, nonce);
    } else {
      // Forged/dummy certify structure
      certify = {
        attest: Buffer.from("dummy-attest").toString("base64url"),
        sig: Buffer.from("dummy-sig").toString("base64url"),
      };
    }

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
          reason: body.message || body.error || "Certify verification failed",
        },
        evidence: { finishStatus: finishRes.status },
      };
    }

    // If M8 is OFF, software K_B is accepted without certification
    const finishBody = await finishRes.json();
    const devId = finishBody.devId;

    // Use software key for DPoP and TPM for appraisal
    // 1. Appraise device to get fresh AR
    const nonceRes = await fetch(`${ctx.urls.verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId }),
    });
    if (!nonceRes.ok) {
      return {
        outcome: "rejected",
        stoppedAt: { service: "verifier", status: nonceRes.status, reason: "Appraisal nonce failed" },
      };
    }
    const { nonceId: appraiseNonceId, nonce: appraiseNonce } = await nonceRes.json();
    const appraiseQuote = await tpm.quote(ak.handle, appraiseNonce);
    const appraiseLog = typeof tpm.readEventLog === "function" ? await tpm.readEventLog() : null;

    const appraiseRes = await fetch(`${ctx.urls.verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId,
        nonceId: appraiseNonceId,
        quote: appraiseQuote,
        eventLog: appraiseLog,
      }),
    });
    if (!appraiseRes.ok) {
      return {
        outcome: "rejected",
        stoppedAt: { service: "verifier", status: appraiseRes.status, reason: "Appraisal failed" },
      };
    }
    const { ar } = await appraiseRes.json();

    // 2. PAR with software key DPoP proof
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
    const stateParam = crypto.randomBytes(16).toString("base64url");
    const swJkt = await jose.calculateJwkThumbprint(swPubJwk);

    const swSigner = async (data) =>
      crypto.sign("sha256", Buffer.from(data), {
        key: swKp.privateKey,
        dsaEncoding: "ieee-p1363",
      });

    const parProof = await signProof({
      signer: swSigner,
      publicJwk: swPubJwk,
      htm: "POST",
      htu: `${ctx.urls.idpUrl}/oauth/par`,
      clock: ctx.clock,
    });

    const parRes = await fetch(`${ctx.urls.idpUrl}/oauth/par`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        DPoP: parProof,
      },
      body: JSON.stringify({
        client_id: "zta-agent",
        response_type: "code",
        redirect_uri: "http://127.0.0.1:7000/callback",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        dpop_jkt: swJkt,
        attestation_result: ar,
        state: stateParam,
      }),
    });
    if (!parRes.ok) {
      const body = await parRes.json().catch(() => ({}));
      return {
        outcome: "rejected",
        stoppedAt: { service: "idp", status: parRes.status, reason: body.error || "PAR failed" },
      };
    }

    const { request_uri } = await parRes.json();
    const authResAuth = await ctx.authorize(`${ctx.urls.idpUrl}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(request_uri)}`);
    const authRes = authResAuth.res;
    const cookie = authResAuth.cookie;

    const loginRes = await ctx.primaryLogin({ auth: authResAuth, username: "alice", password: "alice-pass" });
    if (!loginRes.ok) {
      return {
        outcome: "rejected",
        stoppedAt: { service: "idp", status: loginRes.status, reason: "Login failed" },
      };
    }
    const { code } = await loginRes.json();

    // 3. Redeem code at token endpoint
    const tokenUrl = `${ctx.urls.idpUrl}/oauth/token`;
    const preTokenRes = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const tokenNonce = preTokenRes.headers.get("DPoP-Nonce") || undefined;

    const tokenProof = await signProof({
      signer: swSigner,
      publicJwk: swPubJwk,
      htm: "POST",
      htu: tokenUrl,
      nonce: tokenNonce,
      clock: ctx.clock,
    });

    const tokenRes = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", DPoP: tokenProof },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        redirect_uri: "http://127.0.0.1:7000/callback",
        client_id: "zta-agent",
        code_verifier: codeVerifier,
      }),
    });
    if (!tokenRes.ok) {
      return {
        outcome: "rejected",
        stoppedAt: { service: "idp", status: tokenRes.status, reason: "Token exchange failed" },
      };
    }
    const { access_token } = await tokenRes.json();

    // 4. Access PEP with software key DPoP proof
    const newsUrl = `${ctx.urls.pepUrl}/api/company/news`;
    const preRes = await fetch(newsUrl);
    const pepNonce = preRes.headers.get("DPoP-Nonce") || undefined;

    const pepProof = await signProof({
      signer: swSigner,
      publicJwk: swPubJwk,
      htm: "GET",
      htu: newsUrl,
      nonce: pepNonce,
      accessToken: access_token,
      clock: ctx.clock,
    });

    let pepRes = await fetch(newsUrl, {
      headers: {
        Authorization: `DPoP ${access_token}`,
        DPoP: pepProof,
      },
    });

    if (pepRes.status !== 200) {
      pepRes = await fetch(newsUrl, {
        headers: {
          Authorization: `Bearer ${access_token}`,
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
