import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { risk, geo, haversineDistance, matchCidr, ipToLong } from "../lib/risk.js";
import { loadConfig } from "../lib/config.js";

describe("Risk Engine (Algorithm 4)", () => {
  const cfg = loadConfig();

  it("Weights sum to 1", () => {
    const weights = cfg.risk.weights;
    assert.equal(weights.length, 6);
    const sum = weights.reduce((acc, w) => acc + w, 0);
    assert(Math.abs(sum - 1.0) < 1e-9, `Weights sum to ${sum}, expected 1.0`);

    const namedSum =
      cfg.risk.w1 +
      cfg.risk.w2 +
      cfg.risk.w3 +
      cfg.risk.w4 +
      cfg.risk.w5 +
      cfg.risk.w6;
    assert(Math.abs(namedSum - 1.0) < 1e-9, `Named weights sum to ${namedSum}, expected 1.0`);
  });

  it("No history → ρ = w1·1 + w6·1 + w4·f4", () => {
    const now = 1700000000000;
    const testCases = [
      { ad: 0, expectedF4: 0 },
      { ad: 300, expectedF4: 0.5 },
      { ad: 600, expectedF4: 1.0 },
      { ad: 900, expectedF4: 1.0 },
    ];

    for (const tc of testCases) {
      const res = risk({
        history: [],
        device: { attestation_age_s: tc.ad, devId: "dev-1" },
        ctx: { ip: "192.0.2.1", t: now, sub: "alice", dev: "dev-1" },
        cfg,
      });

      assert.equal(res.f[0], 1, "f1 should be 1 (ASN not seen)");
      assert.equal(res.f[1], 0, "f2 should be 0 (no history)");
      assert.equal(res.f[2], 0, "f3 should be 0 (fewer than 10 logins)");
      assert(
        Math.abs(res.f[3] - tc.expectedF4) < 1e-6,
        `f4 should be ${tc.expectedF4}, got ${res.f[3]}`
      );
      assert.equal(res.f[4], 0, "f5 should be 0 (0 failures)");
      assert.equal(res.f[5], 1, "f6 should be 1 (first login on dev)");

      const expectedRho =
        cfg.risk.w1 * 1 +
        cfg.risk.w6 * 1 +
        cfg.risk.w4 * tc.expectedF4;
      assert(
        Math.abs(res.rho - expectedRho) < 1e-6,
        `ρ should be ${expectedRho}, got ${res.rho}`
      );
    }
  });

  it("Berlin → Sydney within 1 h → f2 = 1", () => {
    const t0 = 1700000000000;
    const t1 = t0 + 3600 * 1000; // 1 hour later

    const berlinIp = "192.0.2.10";
    const sydneyIp = "198.51.100.20";

    const history = [
      { sub: "alice", dev: "dev-1", ip: berlinIp, t: t0, success: true },
    ];

    const res = risk({
      history,
      device: { attestation_age_s: 0, devId: "dev-1" },
      ctx: { sub: "alice", dev: "dev-1", ip: sydneyIp, t: t1 },
      cfg,
    });

    assert.equal(res.f[1], 1, `f2 should be 1 (speed > 900 km/h), got ${res.f[1]}`);
  });

  it("5 failures → f5 = 1", () => {
    const now = 1700000000000;
    const history = [];

    // Add 5 failures in the last 15 minutes
    for (let i = 1; i <= 5; i++) {
      history.push({
        sub: "alice",
        dev: "dev-1",
        ip: "127.0.0.1",
        t: now - i * 60 * 1000,
        success: false,
      });
    }

    const res = risk({
      history,
      device: { attestation_age_s: 0, devId: "dev-1" },
      ctx: { sub: "alice", dev: "dev-1", ip: "127.0.0.1", t: now },
      cfg,
    });

    assert.equal(res.f[4], 1, `f5 should be 1 for 5 failures, got ${res.f[4]}`);

    // Test partial failures: 3 failures -> 3/5 = 0.6
    const resPartial = risk({
      history: history.slice(0, 3),
      device: { attestation_age_s: 0, devId: "dev-1" },
      ctx: { sub: "alice", dev: "dev-1", ip: "127.0.0.1", t: now },
      cfg,
    });
    assert(Math.abs(resPartial.f[4] - 0.6) < 1e-6, `f5 should be 0.6, got ${resPartial.f[4]}`);
  });

  it("f1: ASN seen in last Ndays vs outside Ndays", () => {
    const now = 1700000000000;
    const berlinIp = "192.0.2.1";

    // Successful login 10 days ago (within 30 days)
    const historyRecent = [
      { sub: "alice", dev: "dev-1", ip: berlinIp, t: now - 10 * 86400 * 1000, success: true },
    ];
    const resRecent = risk({
      history: historyRecent,
      device: { attestation_age_s: 0, devId: "dev-1" },
      ctx: { sub: "alice", dev: "dev-1", ip: berlinIp, t: now },
      cfg,
    });
    assert.equal(resRecent.f[0], 0, "f1 should be 0 when ASN was seen within Ndays");

    // Successful login 35 days ago (outside 30 days)
    const historyOld = [
      { sub: "alice", dev: "dev-1", ip: berlinIp, t: now - 35 * 86400 * 1000, success: true },
    ];
    const resOld = risk({
      history: historyOld,
      device: { attestation_age_s: 0, devId: "dev-1" },
      ctx: { sub: "alice", dev: "dev-1", ip: berlinIp, t: now },
      cfg,
    });
    assert.equal(resOld.f[0], 1, "f1 should be 1 when ASN was not seen in last Ndays");
  });

  it("f3: Login hours percentiles with >= 10 logins", () => {
    // Construct 20 logins during normal business hours (UTC 9:00 - 17:00)
    const baseDay = new Date("2026-05-01T00:00:00Z").getTime();
    const history = [];
    for (let i = 0; i < 20; i++) {
      const hour = 9 + (i % 8); // 9 to 16
      history.push({
        sub: "alice",
        dev: "dev-1",
        ip: "127.0.0.1",
        t: baseDay + i * 86400 * 1000 + hour * 3600 * 1000,
        success: true,
      });
    }

    const testTimeNormal = baseDay + 25 * 86400 * 1000 + 12 * 3600 * 1000; // 12:00 UTC
    const resNormal = risk({
      history,
      device: { attestation_age_s: 0, devId: "dev-1" },
      ctx: { sub: "alice", dev: "dev-1", ip: "127.0.0.1", t: testTimeNormal },
      cfg,
    });
    assert.equal(resNormal.f[2], 0, "f3 should be 0 for typical hour (12:00)");

    const testTimeUnusual = baseDay + 25 * 86400 * 1000 + 3 * 3600 * 1000; // 03:00 UTC
    const resUnusual = risk({
      history,
      device: { attestation_age_s: 0, devId: "dev-1" },
      ctx: { sub: "alice", dev: "dev-1", ip: "127.0.0.1", t: testTimeUnusual },
      cfg,
    });
    assert.equal(resUnusual.f[2], 1, "f3 should be 1 for unusual hour (03:00)");
  });

  it("f6: prior successful login on device sets f6 = 0", () => {
    const now = 1700000000000;
    const history = [
      { sub: "alice", dev: "laptop-1", ip: "127.0.0.1", t: now - 3600 * 1000, success: true },
    ];

    const resSameDev = risk({
      history,
      device: { devId: "laptop-1", attestation_age_s: 0 },
      ctx: { sub: "alice", dev: "laptop-1", ip: "127.0.0.1", t: now },
      cfg,
    });
    assert.equal(resSameDev.f[5], 0, "f6 should be 0 when device has prior successful login");

    const resNewDev = risk({
      history,
      device: { devId: "laptop-2", attestation_age_s: 0 },
      ctx: { sub: "alice", dev: "laptop-2", ip: "127.0.0.1", t: now },
      cfg,
    });
    assert.equal(resNewDev.f[5], 1, "f6 should be 1 when device is new for user");
  });

  it("Geolocation resolution and CIDR matching", () => {
    const local = geo("127.0.0.1");
    assert.equal(local.asn, "AS0");
    assert.equal(local.city, "LOCAL");

    const berlin = geo("192.0.2.55");
    assert.equal(berlin.asn, "AS6805");
    assert.equal(berlin.city, "Berlin");

    const sydney = geo("198.51.100.99");
    assert.equal(sydney.asn, "AS1221");
    assert.equal(sydney.city, "Sydney");

    const ny = geo("203.0.113.12");
    assert.equal(ny.asn, "AS701");
    assert.equal(ny.city, "New York");

    const dist = haversineDistance(52.52, 13.405, -33.8688, 151.2093);
    assert(dist > 15000 && dist < 17000, `Expected distance ~16000 km, got ${dist}`);
  });
});
