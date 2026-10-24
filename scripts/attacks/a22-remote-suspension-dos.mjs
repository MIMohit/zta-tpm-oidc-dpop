/**
 * @file scripts/attacks/a22-remote-suspension-dos.mjs
 * Attack A22: Remote device suspension via stale quote replay DoS (A1).
 * Adversary goal: abuse replayed quote to transition victim device to 'suspended'.
 * Expected: M23 (Only fresh, AK-signed failing evidence suspends device).
 */

export default {
  id: "A22",
  title: "Remote device suspension via stale quote replay DoS",
  goal: "G4",
  adversary: "A1",
  expected: ["M23"],
  variants: null,

  applicable(cfgState, mode) {
    if (cfgState?.baseline === "B0" || cfgState?.baseline === "B1") {
      return `n/a: baseline ${cfgState.baseline} has no attestation verifier`;
    }
    if (cfgState?.off?.includes("M4")) {
      return "n/a: M4 off, a replayed quote is appraised as fresh (no suspension path)";
    }
    return true;
  },

  async run(ctx, { variant = null } = {}) {
    // Victim enrols legitimate device
    const client = ctx.clients.alice;
    await client.enrol(ctx.codes["alice-laptop"]);

    // Attacker sniffs Alice's genuine quote over nonce1 at T1
    const n1Res = await fetch(`${ctx.urls.verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: client.devId }),
    });
    const { nonce: nonce1 } = await n1Res.json();
    const sniffedQuote = await client.tpm.quote(client.akHandle, nonce1);
    const sniffedLog = client.tpm.readEventLog();

    // Attacker requests new nonce2 at T2
    const n2Res = await fetch(`${ctx.urls.verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: client.devId }),
    });
    const { nonceId: nonceId2 } = await n2Res.json();

    // Attacker replays sniffed quote against nonceId2 to attempt remote suspension DoS
    const appraiseRes = await fetch(`${ctx.urls.verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: client.devId,
        nonceId: nonceId2,
        quote: sniffedQuote,
        eventLog: sniffedLog,
      }),
    });

    // Check device status in registry via internal endpoint
    const devRes = await fetch(`${ctx.urls.verifierUrl}/v/devices/${client.devId}`, {
      headers: { "X-ZTA-Internal": ctx.ztaInternalToken },
    });
    const devData = await devRes.json();
    const isSuspended = devData.status === "suspended";

    if (isSuspended) {
      // Adversary goal G4 achieved: victim device was remotely suspended
      return {
        outcome: "accepted",
        stoppedAt: null,
        evidence: {
          appraiseStatus: appraiseRes.status,
          deviceStatus: devData.status,
        },
      };
    }

    if (appraiseRes.ok) {
      return {
        outcome: "rejected",
        stoppedAt: {
          service: "verifier",
          status: appraiseRes.status,
          reason: "appraised_ok_replay_accepted",
        },
        evidence: {
          appraiseStatus: appraiseRes.status,
          deviceStatus: devData.status,
        },
      };
    }

    // Defense held (M23 ON): device was not suspended
    const body = await appraiseRes.json().catch(() => ({}));
    return {
      outcome: "rejected",
      stoppedAt: {
        service: "verifier",
        status: appraiseRes.status,
        reason: body.reason || body.error || "quote_not_fresh (no state change)",
      },
      evidence: {
        appraiseStatus: appraiseRes.status,
        deviceStatus: devData.status,
      },
    };
  },

  async runLive(ctx, options) {
    return this.run(ctx, options);
  },
};
