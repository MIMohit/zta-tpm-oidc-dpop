/**
 * @file scripts/attacks/a03-ek-cert-pub-mismatch.mjs
 * Attack A03: EK certificate / public area mismatch (tampered cert payload or SPKI mismatch) (A4).
 * Variants:
 *   - "jws": Tampered JWS cert payload (chain/signature half of M1)
 *   - "x509": Valid X.509 cert of TPM 1 presented with ekPublic of TPM 2 (SPKI = EK half of M1)
 * Expected: M1 (EK certificate chain to a vendor root, and SPKI = EK).
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { devIdOf, jwkOf } from "../../lib/sim-tpm/public-area.js";
import { signProof } from "../../lib/dpop.js";
import { classifyEkTemplate, kdfa, kdfe, publicAreaFromTpmt } from "../../lib/tpm2/index.js";
import { enrolExtras } from "./lib/enrol-extras.mjs";

export default {
  id: "A03",
  title: "EK certificate / public area mismatch",
  goal: "G1",
  adversary: "A4",
  expected: ["M1"],
  variants: ["jws", "x509"],

  applicable(cfgState, mode, { tpm, variant } = {}) {
    if (tpm === "swtpm" && (variant || "jws") === "jws") {
      return "JWS EK certificates exist only on the simulated TPM";
    }
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    const activeVariant = variant || "jws";

    if (activeVariant === "x509") {
      let presentedCert;
      let presentedChain;
      let pa2;
      let ecdh;
      let ekX;
      if (ctx.tpm === "swtpm") {
        // Bob's genuine lab-CA certificate next to the EK of the TPM the attacker holds (rogue):
        // the chain verifies, only the certificate-to-EK binding (M1) can catch it
        const bobEk = await ctx.tpms.bob.getEk();
        presentedCert = bobEk.cert;
        presentedChain = bobEk.chain;
        pa2 = (await ctx.tpms.rogue.getEk()).publicArea;
      } else {
        const swtpmFixturesDir = path.resolve("tests/fixtures/swtpm");
        const p384CertDer = fs.readFileSync(path.join(swtpmFixturesDir, "ekcert-p384-nv01c00016.der"));
        const issuerPem = fs.readFileSync(path.join(swtpmFixturesDir, "swtpm-localca-issuer.pem"), "utf8");

        // Generate TPM 2 P-384 key pair (different from TPM 1 certified in ekcert-p384)
        ecdh = crypto.createECDH("secp384r1");
        ecdh.generateKeys();
        const pubPt = ecdh.getPublicKey();
        ekX = pubPt.subarray(1, 49);
        const ekY = pubPt.subarray(49, 97);
        const authPolicy = Buffer.from(
          "b26e7d28d11a50bc53d882bcf5fd3a1a074148bb35d3b4e4cb1c0ad9bde419cacb47ba09699646150f9fc000f3f80e12",
          "hex"
        );
        const hdr = Buffer.alloc(10);
        hdr.writeUInt16BE(0x0023, 0); // TPM_ALG_ECC
        hdr.writeUInt16BE(0x000c, 2); // TPM_ALG_SHA384
        hdr.writeUInt32BE(0x000300f2, 4); // TPMA_OBJECT
        hdr.writeUInt16BE(authPolicy.length, 8);
        const parms = Buffer.alloc(12);
        parms.writeUInt16BE(0x0006, 0); // AES
        parms.writeUInt16BE(256, 2); // 256 bits
        parms.writeUInt16BE(0x0043, 4); // CFB
        parms.writeUInt16BE(0x0010, 6); // NULL scheme
        parms.writeUInt16BE(0x0004, 8); // NIST P-384
        parms.writeUInt16BE(0x0010, 10); // NULL kdf
        const u16 = (n) => {
          const b = Buffer.alloc(2);
          b.writeUInt16BE(n);
          return b;
        };
        const tpmtPub2 = Buffer.concat([hdr, authPolicy, parms, u16(ekX.length), ekX, u16(ekY.length), ekY]);
        pa2 = publicAreaFromTpmt(tpmtPub2);
        presentedCert = p384CertDer.toString("base64url");
        presentedChain = [issuerPem];
      }
      const devId2 = await devIdOf(pa2);

      const code = "a03-x509-code";
      await ctx.seedInventory({ devId: devId2, user: "alice", code });

      const client = ctx.clients.rogue;
      const ak = await client.tpm.createAk();
      const kb = await client.tpm.createKb();

      const startRes = await fetch(`${ctx.urls.verifierUrl}/v/enrol/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code,
          ekCert: presentedCert,
          ekCertChain: presentedChain,
          akPublic: ak.publicArea,
          kbPublic: kb.publicArea,
          ekPublic: pa2,
          srkPublic: (await enrolExtras(client.tpm)).srkPublic,
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
            reason: body.message || body.error || "EK cert signature/SPKI invalid",
          },
          evidence: { variant: activeVariant, startStatus: startRes.status },
        };
      }

      // Under -M1, unverified ekPublic is accepted; recover secret using TPM 2 private key
      const startData = await startRes.json();
      let recoveredSecret;
      if (ctx.tpm === "swtpm") {
        // The attacker's own TPM holds the presented EK, so it activates the credential itself
        recoveredSecret = await client.tpm.activateCredential(ak.handle, startData.blob);
      } else {
        const cred = startData.blob;
        const credIdObj = Buffer.from(cred.credentialBlob, "base64url");
        const credEncSec = Buffer.from(cred.secret, "base64url");
        const ephXLen = credEncSec.readUInt16BE(0);
        const ephX = credEncSec.subarray(2, 2 + ephXLen);
        const ephYLen = credEncSec.readUInt16BE(2 + ephXLen);
        const ephY = credEncSec.subarray(4 + ephXLen, 4 + ephXLen + ephYLen);
        const ephPtRaw = Buffer.concat([Buffer.from([4]), ephX, ephY]);
        const z = ecdh.computeSecret(ephPtRaw);
        const recoveredSeed = kdfe("sha384", z, "IDENTITY", ephX, ekX, 48 * 8);
        const akName = ak.name ? (Buffer.isBuffer(ak.name) ? ak.name : Buffer.from(ak.name, "hex")) : Buffer.alloc(34);
        const recoveredSymKey = kdfa("sha384", recoveredSeed, "STORAGE", akName, Buffer.alloc(0), 256);
        const integrityLen = credIdObj.readUInt16BE(0);
        const encIdentity = credIdObj.subarray(2 + integrityLen);
        const decipher = crypto.createDecipheriv("aes-256-cfb", recoveredSymKey, Buffer.alloc(16));
        const decIdentity = Buffer.concat([decipher.update(encIdentity), decipher.final()]);
        const credLen = decIdentity.readUInt16BE(0);
        recoveredSecret = decIdentity.subarray(2, 2 + credLen);
      }

      const quote = await client.tpm.quote(ak.handle, startData.nonce);
      const certify = await client.tpm.certify(kb.handle, ak.handle, startData.nonce);
      const eventLog = typeof client.tpm.readEventLog === "function" ? await client.tpm.readEventLog() : null;

      const finishRes = await fetch(`${ctx.urls.verifierUrl}/v/enrol/finish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sessionId: startData.sessionId,
          secret: Buffer.isBuffer(recoveredSecret) ? recoveredSecret.toString("hex") : String(recoveredSecret),
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
          evidence: { variant: activeVariant, finishStatus: finishRes.status },
        };
      }

      const finishBody = await finishRes.json();
      client.enrolled = true;
      client.devId = devId2;
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
          evidence: { variant: activeVariant, loginError: err.message },
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
          evidence: { variant: activeVariant, pepStatus: 200 },
        };
      }

      return {
        outcome: "rejected",
        stoppedAt: {
          service: "pep",
          status: pepRes.status,
          reason: "PEP access rejected",
        },
        evidence: { variant: activeVariant, pepStatus: pepRes.status },
      };
    }

    // Default variant: "jws" (tampered JWS payload)
    const client = ctx.clients.rogue;
    const { publicArea: rogueEkPub } = await client.tpm.getEk();
    const rogueDevId = await devIdOf(rogueEkPub);

    // Get Bob's legitimate EK cert signed by Vendor CA
    const { cert: bobCert } = await ctx.tpms.bob.getEk();

    // Pre-seed rogue devId in inventory for alice so M2 passes,
    // isolating M1 (certificate signature integrity / SPKI = EK binding).
    const code = "a03-rogue-code";
    await ctx.seedInventory({ devId: rogueDevId, user: "alice", code });

    // Tamper Bob's JWS cert: replace ek_pub with rogue's EK public area
    // but keep Bob's header and signature (invalidating the JWS signature under Vendor CA)
    const parts = bobCert.split(".");
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    payload.ek_pub = rogueEkPub;
    const tamperedPayloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const tamperedCert = `${parts[0]}.${tamperedPayloadB64}.${parts[2]}`;

    const ak = await client.tpm.createAk();
    const kb = await client.tpm.createKb();

    const startRes = await fetch(`${ctx.urls.verifierUrl}/v/enrol/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code,
        ekCert: tamperedCert,
        akPublic: ak.publicArea,
        kbPublic: kb.publicArea,
        ekPublic: rogueEkPub,
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
          reason: body.message || body.error || "EK cert signature invalid",
        },
        evidence: { variant: activeVariant, startStatus: startRes.status },
      };
    }

    // If M1 is OFF, unverified payload EK is accepted
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
        evidence: { variant: activeVariant, finishStatus: finishRes.status },
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
          reason: err.message || "Login failed",
        },
        evidence: { variant: activeVariant, loginError: err.message },
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
        evidence: { variant: activeVariant, pepStatus: 200 },
      };
    }

    return {
      outcome: "rejected",
      stoppedAt: {
        service: "pep",
        status: pepRes.status,
        reason: "PEP access rejected",
      },
      evidence: { variant: activeVariant, pepStatus: pepRes.status },
    };
  },

  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
