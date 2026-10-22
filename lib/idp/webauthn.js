/**
 * @file lib/idp/webauthn.js
 * WebAuthn step-up and credential registration ported to @simplewebauthn/server v13 API.
 * Credentials keyed by (u, dev) from session.
 * Store namespace: idp
 * Path: webauthn/<u>/<devId> = { credential: { id, publicKey, counter, transports } }
 */

import crypto from "node:crypto";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { internalFetch } from "../internal-auth.js";
import { on } from "../ablation.js";

function getExpectedOrigins(req, cfg) {
  const list = [];
  const rawHost = req.get("host");
  if (rawHost) {
    list.push(`${req.protocol}://${rawHost}`);
  }
  if (cfg?.idpIssuer) {
    list.push(cfg.idpIssuer);
  }
  list.push("http://localhost:5173", "http://127.0.0.1:5173");
  return Array.from(new Set(list.filter(Boolean)));
}

function getExpectedRPID(req, cfg) {
  if (cfg?.rpID) return cfg.rpID;
  if (req.hostname) return req.hostname;
  if (cfg?.idpIssuer) {
    try {
      return new URL(cfg.idpIssuer).hostname;
    } catch {}
  }
  return "localhost";
}

function getExpectedRPIDs(req, cfg) {
  const list = [];
  if (cfg?.rpID) list.push(cfg.rpID);
  if (req.hostname) list.push(req.hostname);
  if (cfg?.idpIssuer) {
    try {
      list.push(new URL(cfg.idpIssuer).hostname);
    } catch {}
  }
  list.push("localhost", "127.0.0.1");
  return Array.from(new Set(list.filter(Boolean)));
}

// N3: A successful assertion grants credential replacement for this long only
const REPLACEMENT_WINDOW_MS = 120 * 1000;

function isReplacementAllowed(session, u, dev, cfg) {
  const grant = session.webauthnReplacementAllowed;
  if (!grant || grant.u !== u || grant.dev !== dev) return false;
  const nowMs = cfg?.clock ? cfg.clock() : Date.now();
  return typeof grant.at === "number" && nowMs - grant.at <= REPLACEMENT_WINDOW_MS;
}

/**
 * GET /mfa/register/options
 */
export async function handleRegisterOptions(req, res, { store, cfg }) {
  try {
    // F1/N2: Reject only while a gated step-up (oauthTxn.gated) is in progress
    if (on("M25") && req.session.oauthTxn?.gated) {
      return res.status(403).json({
        error: "registration_forbidden",
        message: "WebAuthn registration not allowed while an OAuth transaction is pending",
      });
    }

    // F1: Strictly from completed idpUser session
    const u = req.session.idpUser?.u;
    const dev = req.session.idpUser?.dev;

    if (!u || !dev) {
      return res.status(401).json({
        error: "unauthenticated",
        message: "Active IdP session required for WebAuthn registration",
      });
    }

    // F1: Only for first enrolment of (u, dev), or replacement after assertion with existing credential
    const existing = await store.get(`webauthn/${u}/${dev}`);
    if (on("M25") && existing && existing.credential) {
      const replacementAllowed = isReplacementAllowed(req.session, u, dev, cfg);

      if (!replacementAllowed) {
        return res.status(403).json({
          error: "credential_exists",
          message: "Credential already exists for this device; replacement requires an assertion with the existing credential within the last 120 s",
        });
      }
    }

    const rpID = getExpectedRPID(req, cfg);
    const options = await generateRegistrationOptions({
      rpName: "Zero-Trust Portal",
      rpID,
      userID: Buffer.from(u),
      userName: u,
      userDisplayName: u,
      attestationType: "none",
      authenticatorSelection: {
        userVerification: "preferred",
        residentKey: "preferred",
      },
    });

    req.session.webauthnChallenge = options.challenge;
    req.session.webauthnUser = u;
    req.session.webauthnDev = dev;

    return res.json(options);
  } catch (err) {
    console.error("❌ [/mfa/register/options] Error:", err);
    return res.status(500).json({ error: err.message });
  }
}

/**
 * POST /mfa/register/verify
 */
export async function handleRegisterVerify(req, res, { store, cfg }) {
  try {
    // F1/N2: Reject only while a gated step-up (oauthTxn.gated) is in progress
    if (on("M25") && req.session.oauthTxn?.gated) {
      return res.status(403).json({
        error: "registration_forbidden",
        message: "WebAuthn registration not allowed while an OAuth transaction is pending",
      });
    }

    // F1: Strictly from completed idpUser session
    const u = req.session.idpUser?.u;
    const dev = req.session.idpUser?.dev;

    if (!u || !dev) {
      return res.status(401).json({
        error: "unauthenticated",
        message: "No user/device session found for registration verification",
      });
    }

    // F1: Check existing credential & replacement authorization
    const existing = await store.get(`webauthn/${u}/${dev}`);
    if (on("M25") && existing && existing.credential) {
      const replacementAllowed = isReplacementAllowed(req.session, u, dev, cfg);

      if (!replacementAllowed) {
        return res.status(403).json({
          error: "credential_exists",
          message: "Credential already exists for this device; replacement requires an assertion with the existing credential within the last 120 s",
        });
      }
    }

    const expectedChallenge = req.session.webauthnChallenge;
    if (!expectedChallenge) {
      return res.status(400).json({ error: "missing_challenge" });
    }

    const expectedOrigin = getExpectedOrigins(req, cfg);
    const expectedRPID = getExpectedRPIDs(req, cfg);

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
    });

    if (verification.verified) {
      const { registrationInfo } = verification;
      const { credential } = registrationInfo;

      const credentialData = {
        id: credential.id,
        publicKey: Buffer.from(credential.publicKey).toString("base64url"),
        counter: credential.counter,
        transports: req.body.response?.transports || credential.transports || [],
        enrolled_at: new Date(cfg.clock ? cfg.clock() : Date.now()).toISOString(),
      };

      await store.set(`webauthn/${u}/${dev}`, {
        user_id: u,
        device_id: dev,
        credential: credentialData,
      });

      delete req.session.webauthnChallenge;
      delete req.session.webauthnUser;
      delete req.session.webauthnDev;
      delete req.session.mfa_enroll_required;
      delete req.session.webauthnReplacementAllowed;

      return res.json({ enrolled: true, verified: true });
    } else {
      return res.status(400).json({ error: "Registration verification failed" });
    }
  } catch (err) {
    console.error("❌ [/mfa/register/verify] Error:", err);
    return res.status(500).json({ error: err.message });
  }
}

/**
 * GET /mfa/auth/options
 */
export async function handleAuthOptions(req, res, { store, cfg }) {
  try {
    let u, dev;
    if (req.session.oauthTxn) {
      const txn = req.session.oauthTxn;
      // F2: If oauthTxn exists, require txn.u (set only by gateAfterPrimaryAuth) and explicit txn.gated
      if (on("M24")) {
        if (!txn.gated || !txn.u || !txn.dev) {
          return res.status(403).json({
            error: "unauthorized_transaction",
            message: "OAuth transaction has not passed primary authentication gate",
          });
        }
        u = txn.u;
        dev = txn.dev;
      } else {
        // M24 off (reproduces F2): identity from the gate if any, else the verified idpUser session; never a default
        u = txn.u || req.session.idpUser?.u;
        dev = txn.dev || req.session.idpUser?.dev;
      }
    } else if (req.session.idpUser?.u && req.session.idpUser?.dev) {
      // Standalone assertion from authenticated idpUser (e.g. to enable replacement)
      u = req.session.idpUser.u;
      dev = req.session.idpUser.dev;
    } else {
      if (on("M24")) {
        return res.status(400).json({
          error: "no_device_context",
          message: "No active user/device session found for step-up authentication",
        });
      }
    }

    if (!u || !dev) {
      return res.status(400).json({
        error: "no_device_context",
        message: "No active user/device session found for step-up authentication",
      });
    }

    const storedRecord = await store.get(`webauthn/${u}/${dev}`);
    if (!storedRecord || !storedRecord.credential) {
      return res.status(404).json({
        error: "mfa_not_enrolled",
        message: `MFA not enrolled for user ${u} on device ${dev}`,
      });
    }

    const stored = storedRecord.credential;
    const rpID = getExpectedRPID(req, cfg);

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: [
        {
          id: stored.id,
          type: "public-key",
          transports: stored.transports || [],
        },
      ],
      userVerification: "preferred",
    });

    req.session.webauthnChallenge = options.challenge;
    req.session.webauthnAuthUser = u;
    req.session.webauthnAuthDev = dev;
    req.session.mfaStart = cfg.clock ? cfg.clock() : Date.now();

    return res.json(options);
  } catch (err) {
    console.error("❌ [/mfa/auth/options] Error:", err);
    return res.status(500).json({ error: err.message });
  }
}

/**
 * POST /mfa/verify
 */
export async function handleAuthVerify(req, res, { store, cfg }) {
  try {
    let u, dev;
    const txn = req.session.oauthTxn;
    if (txn) {
      // F2: If oauthTxn exists, require txn.u (set only by gateAfterPrimaryAuth) and explicit txn.gated
      // Take u/dev ONLY from txn; NO fallback to idpUser or webauthnUser
      if (on("M24")) {
        if (!txn.gated || !txn.u || !txn.dev) {
          return res.status(403).json({
            error: "unauthorized_transaction",
            message: "OAuth transaction has not passed primary authentication gate",
          });
        }
        // N4: Re-check txn expiry (as /oauth/login does)
        const nowMs = cfg.clock ? cfg.clock() : Date.now();
        if (txn.expires_at && nowMs > txn.expires_at) {
          delete req.session.oauthTxn;
          return res.status(400).json({
            error: "invalid_request",
            error_description: "OAuth transaction has expired. Please re-authenticate.",
          });
        }
        u = txn.u;
        dev = txn.dev;
      } else {
        // M24 off (reproduces F2): identity from the gate if any, else the verified idpUser session; never a default
        u = txn.u || req.session.idpUser?.u;
        dev = txn.dev || req.session.idpUser?.dev;
      }
    } else if (req.session.idpUser?.u && req.session.idpUser?.dev) {
      u = req.session.idpUser.u;
      dev = req.session.idpUser.dev;
    } else {
      if (on("M24")) {
        return res.status(400).json({
          error: "no_device_context",
          message: "Missing session context for MFA verification",
        });
      }
    }

    if (!u || !dev) {
      return res.status(400).json({
        error: "no_device_context",
        message: "Missing session context for MFA verification",
      });
    }

    if (req.session.webauthnAuthUser && req.session.webauthnAuthUser !== u) {
      return res.status(403).json({ error: "user_mismatch" });
    }

    const expectedChallenge = req.session.webauthnChallenge;
    if (!expectedChallenge) {
      return res.status(400).json({ error: "missing_challenge" });
    }

    const storedRecord = await store.get(`webauthn/${u}/${dev}`);
    if (!storedRecord || !storedRecord.credential) {
      return res.status(403).json({ error: "MFA not enrolled" });
    }

    const stored = storedRecord.credential;
    const expectedOrigin = getExpectedOrigins(req, cfg);
    const expectedRPID = getExpectedRPIDs(req, cfg);

    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      credential: {
        id: stored.id,
        publicKey: Buffer.from(stored.publicKey, "base64url"),
        counter: stored.counter,
        transports: stored.transports || [],
      },
    });

    if (verification.verified) {
      stored.counter = verification.authenticationInfo.newCounter;
      await store.set(`webauthn/${u}/${dev}`, storedRecord);
      delete req.session.webauthnChallenge;
      delete req.session.webauthnAuthUser;
      delete req.session.webauthnAuthDev;

      const nowMs = cfg.clock ? cfg.clock() : Date.now();
      const mfaDelay = nowMs - (req.session.mfaStart || nowMs);
      console.log("⏱️ MFA verification delay:", mfaDelay, "ms");

      // Successful assertion unlocks credential replacement for (u, dev)
      req.session.webauthnReplacementAllowed = {
        u,
        dev,
        at: nowMs,
      };

      // F2: Code issuance ONLY for an oauthTxn that passed gateAfterPrimaryAuth (M24 off: any txn)
      if (txn && (txn.gated || !on("M24"))) {
        txn.acr = "mfa";
        const nowS = Math.floor(nowMs / 1000);

        // Record successful step-up login event in PIP
        try {
          const pipUrl = cfg.pipUrl || "http://localhost:4003";
          await internalFetch(
            `${pipUrl}/pip/login-event`,
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                sub: u,
                dev,
                ip: txn.ip || "127.0.0.1",
                t: nowMs,
                success: true,
              }),
            },
            cfg
          );
        } catch (err) {
          console.warn("⚠️ [MFA] Could not update PIP login event:", err.message);
        }

        req.session.idpUser = {
          u,
          dev,
          acr: "mfa",
          auth_time: nowS,
        };

        // Issue authorization code bound to dpop_jkt
        // F11: Carry upstream role into the code record
        const code = crypto.randomBytes(32).toString("base64url");
        const codeRecord = {
          code,
          u,
          dev,
          jkt: txn.dpop_jkt,
          role: txn.role || undefined,
          acr: "mfa",
          auth_time: nowS,
          code_challenge: txn.code_challenge,
          code_challenge_method: txn.code_challenge_method,
          redirect_uri: txn.redirect_uri,
          client_id: txn.client_id,
          expires_at: nowMs + (cfg.codeLifetime || 60) * 1000,
        };

        await store.set(`codes/${code}`, codeRecord);
        delete req.session.oauthTxn;

        const redirectUrl = `${txn.redirect_uri}?code=${code}&state=${encodeURIComponent(txn.state || "")}`;

        return res.json({
          success: true,
          redirect: redirectUrl,
          code,
          acr: "mfa",
          mfa_delay_ms: mfaDelay,
        });
      }

      req.session.mfa_passed = true;
      return res.json({
        success: true,
        mfa_delay_ms: mfaDelay,
      });
    } else {
      return res.status(403).json({ error: "MFA failed" });
    }
  } catch (err) {
    console.error("❌ [/mfa/verify] Error:", err);
    return res.status(500).json({ error: err.message });
  }
}

export default {
  handleRegisterOptions,
  handleRegisterVerify,
  handleAuthOptions,
  handleAuthVerify,
};
