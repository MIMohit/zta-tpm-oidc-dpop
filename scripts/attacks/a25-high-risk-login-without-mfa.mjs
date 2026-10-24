/**
 * @file scripts/attacks/a25-high-risk-login-without-mfa.mjs
 * Attack A25: Stolen device used from far away without the owner's WebAuthn factor (A3).
 * The device binding cannot stop this attacker (it is the right device); only the risk checks can.
 *
 * Variants (every client request carries the client's simulated location):
 *   new_login     - the owner logs in from Berlin; a minute later the attacker logs in from Sydney
 *                   with the device and the password. New ASN + impossible travel give
 *                   rho >= theta_login, so the gate demands WebAuthn (M27). M28 does not cover this
 *                   case: the attacker's own login enters the history the per-request score uses.
 *   moved_session - the attacker takes the unlocked device with the owner's session and uses it
 *                   from Sydney after the step-up grace period T_su, refreshing the token with the
 *                   device's key; no new login happens, so only the PDP's per-request check (M28) can
 *                   demand a step-up.
 * Whether the score flags such logins in practice is measured separately (E6); this attack checks
 * that a high score is enforced.
 */

import { SoftAuthenticator } from "../../tests/helpers/soft-webauthn.js";

// Documentation addresses mapped in fixtures/geo.json
const OWNER_IP = "192.0.2.10"; // Berlin, AS6805
const ATTACKER_IP = "198.51.100.7"; // Sydney, AS1221

/** The PEP's reason for refusing a request (WWW-Authenticate or the JSON body), if any. */
async function refusal(res) {
  const www = res.headers?.get?.("WWW-Authenticate");
  const body = await res.json?.().catch(() => null);
  return [www, body?.reason || body?.error].filter(Boolean).join("; ");
}

export default {
  id: "A25",
  title: "Stolen device and password used from far away without the WebAuthn factor",
  goal: "G2",
  adversary: "A3",
  expected: ["M27", "M28"],
  variants: ["new_login", "moved_session"],

  applicable() {
    return true;
  },

  async run(ctx, { variant = "new_login" } = {}) {
    const client = ctx.clients.alice;
    await client.enrol(ctx.codes["alice-laptop"]);

    // The owner has WebAuthn registered for this device and logs in from home
    const ownerFactor = new SoftAuthenticator();
    await ctx.seedWebauthn(ownerFactor, { user: "alice", client, password: ctx.passwords.alice });
    await ctx.loginWithDevice(client, { username: "alice", password: ctx.passwords.alice, simIp: OWNER_IP, softAuth: ownerFactor });

    if (variant === "moved_session") {
      // Past the step-up grace period (T_su = 300 s) and the token lifetime; the session continues
      await ctx.advance(360);
      client.simIp = ATTACKER_IP;
      try {
        await client.refresh();
      } catch (err) {
        return { outcome: "rejected", stoppedAt: { service: "idp", status: err.status ?? 401, reason: `refresh refused: ${err.message}` }, evidence: {} };
      }
      const moved = await client.request("/api/company/news");
      if (moved.status === 200) return { outcome: "accepted", stoppedAt: null, evidence: { status: 200 } };
      return {
        outcome: "rejected",
        stoppedAt: { service: "pep", status: moved.status, reason: (await refusal(moved)) || "resource request refused" },
        evidence: { status: moved.status },
      };
    }

    // One minute later (Berlin to Sydney in a minute is impossible travel)
    await ctx.advance(60);

    // The attacker: same device, same password, another continent, no WebAuthn factor
    try {
      await ctx.loginWithDevice(client, { username: "alice", password: ctx.passwords.alice, simIp: ATTACKER_IP });
    } catch (err) {
      return {
        outcome: "rejected",
        stoppedAt: {
          service: "idp",
          status: err.status ?? 401,
          reason: err.stepUpRequired ? `step-up required (risk ${err.risk})` : err.body?.reason || err.message,
        },
        evidence: { risk: err.risk ?? err.body?.risk ?? null },
      };
    }

    const res = await client.request("/api/company/news");
    if (res.status === 200) {
      return { outcome: "accepted", stoppedAt: null, evidence: { status: 200 } };
    }
    return {
      outcome: "rejected",
      stoppedAt: { service: "pep", status: res.status, reason: (await refusal(res)) || "resource request refused" },
      evidence: { status: res.status },
    };
  },

  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
