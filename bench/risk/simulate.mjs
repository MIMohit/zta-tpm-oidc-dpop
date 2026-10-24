#!/usr/bin/env node
/**
 * @file bench/risk/simulate.mjs
 * E6 (synthetic): behaviour of the adaptive-MFA policy on simulated login traffic.
 *
 * Every login is scored with the real risk function (lib/risk.js, the code the gate uses)
 * against that user's history so far. Legitimate traffic and five attack scenarios are
 * generated from the parameters below (stated in the paper); results show how the policy
 * trades step-ups of legitimate users against detected attacks. This is not a measurement of
 * real-world detection rates.
 *
 * Attacks are logins on the victim's enrolled device with the victim's password (device and
 * password stolen): the case device binding cannot stop and only the step-up can.
 *
 * Usage: node bench/risk/simulate.mjs [--users 1000] [--days 30] [--seed 1] [--out results/e6-risk]
 */

import fs from "node:fs";
import path from "node:path";
import process from "node:process";

import { risk } from "../../lib/risk.js";

// Locations known to the risk engine (fixtures/geo.json); one IP range each
const PLACES = {
  berlin: { ip: (n) => `192.0.2.${10 + (n % 200)}`, lat: 52.52, lon: 13.405 },
  newyork: { ip: (n) => `203.0.113.${10 + (n % 200)}`, lat: 40.7128, lon: -74.006 },
  sydney: { ip: (n) => `198.51.100.${10 + (n % 200)}`, lat: -33.8688, lon: 151.2093 },
};
const HOMES = ["berlin", "newyork"];

export const PARAMS = {
  loginsPerWorkday: 2.5, // mean
  workStartUtc: [6, 9], // range of users' usual first hour (UTC)
  workLengthH: 9,
  typoRate: 0.05, // a login preceded by one failed attempt
  travelUserRate: 0.03, // users who take one trip in the period
  secondDeviceRate: 0.05, // users who enrol a second device mid-period
  flightKmh: 800,
  airportHours: 3,
  attestationPeriodS: 300, // T_RA: attestation age is uniform in [0, T_RA]
  attacksPerScenario: 300,
  burnInDays: 7, // history is built but not scored, so no user is measured on a cold start
};

export const SCENARIOS = {
  S1_same_network: "stolen device and password, used from the victim's own network at usual hours",
  S2_impossible_travel: "used from another continent within 1 h of the owner's last login",
  S3_abroad_next_day: "used from another continent 24-48 h after the owner's last login",
  S4_after_guessing: "used from another continent after 5 failed attempts in 15 min",
  S5_abroad_off_hours: "used from another continent outside the owner's usual hours, 6-12 h later",
};

const FEATURES = ["f1 new ASN", "f2 travel speed", "f3 unusual hour", "f4 attestation age", "f5 recent failures", "f6 new device"];
const DEFAULT_WEIGHTS = [0.25, 0.25, 0.1, 0.15, 0.15, 0.1];

function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function poisson(rnd, mean) {
  const L = Math.exp(-mean);
  let k = 0;
  let p = 1;
  do {
    k++;
    p *= rnd();
  } while (p > L);
  return k - 1;
}

const HOUR = 3600e3;
const DAY = 24 * HOUR;

function distanceKm(a, b) {
  const R = 6371;
  const dLat = ((b.lat - a.lat) * Math.PI) / 180;
  const dLon = ((b.lon - a.lon) * Math.PI) / 180;
  const h = Math.sin(dLat / 2) ** 2 + Math.cos((a.lat * Math.PI) / 180) * Math.cos((b.lat * Math.PI) / 180) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.atan2(Math.sqrt(h), Math.sqrt(1 - h));
}

/** Legitimate login events for all users, in time order per user. */
function legitimateTraffic(rnd, users, days, t0) {
  const out = [];
  for (let u = 0; u < users; u++) {
    const home = HOMES[Math.floor(rnd() * HOMES.length)];
    const start = PARAMS.workStartUtc[0] + Math.floor(rnd() * (PARAMS.workStartUtc[1] - PARAMS.workStartUtc[0] + 1));
    const user = { id: `u${u}`, home, start, devices: [`d${u}a`] };
    const secondDeviceDay = rnd() < PARAMS.secondDeviceRate ? 5 + Math.floor(rnd() * (days - 10)) : null;
    let trip = null;
    if (rnd() < PARAMS.travelUserRate) {
      const dest = home === "berlin" ? (rnd() < 0.5 ? "newyork" : "sydney") : rnd() < 0.5 ? "berlin" : "sydney";
      const departDay = 3 + Math.floor(rnd() * (days - 10));
      const flightH = distanceKm(PLACES[home], PLACES[dest]) / PARAMS.flightKmh + PARAMS.airportHours;
      trip = { dest, from: t0 + departDay * DAY, arrive: t0 + departDay * DAY + flightH * HOUR, back: t0 + (departDay + 5) * DAY };
    }
    const events = [];
    for (let d = 0; d < days; d++) {
      const weekday = d % 7 < 5;
      const n = poisson(rnd, weekday ? PARAMS.loginsPerWorkday : 0.4);
      for (let k = 0; k < n; k++) {
        const t = t0 + d * DAY + (start + rnd() * PARAMS.workLengthH) * HOUR;
        let place = home;
        if (trip && t >= trip.from && t < trip.arrive) continue; // in the air
        if (trip && t >= trip.arrive && t < trip.back) place = trip.dest;
        let dev = user.devices[0];
        if (secondDeviceDay !== null && d >= secondDeviceDay && rnd() < 0.5) dev = `d${u}b`;
        const ip = PLACES[place].ip(u);
        if (rnd() < PARAMS.typoRate) events.push({ user, t: t - 60e3, ip, dev, success: false, label: "typo" });
        events.push({ user, t, ip, dev, success: true, label: "legit" });
      }
    }
    events.sort((a, b) => a.t - b.t);
    out.push({ user, events });
  }
  return out;
}

/** Attack login events (plus guessing failures), each attached to a victim. */
function attacks(rnd, perUser, scoreFrom) {
  const pick = (arr) => arr[Math.floor(rnd() * arr.length)];
  const out = [];
  const abroadOf = (home) => (home === "berlin" ? "sydney" : "berlin");
  for (const scenario of Object.keys(SCENARIOS)) {
    for (let i = 0; i < PARAMS.attacksPerScenario; i++) {
      let victim;
      let anchor;
      do {
        victim = pick(perUser);
        anchor = pick(victim.events.filter((e) => e.success && e.t >= scoreFrom));
      } while (!anchor);
      const u = victim.user;
      const dev = u.devices[0];
      const extra = [];
      let t;
      let place;
      switch (scenario) {
        case "S1_same_network":
          t = anchor.t + (1 + rnd() * 3) * HOUR;
          place = u.home;
          break;
        case "S2_impossible_travel":
          t = anchor.t + rnd() * HOUR;
          place = abroadOf(u.home);
          break;
        case "S3_abroad_next_day":
          t = anchor.t + (24 + rnd() * 24) * HOUR;
          place = abroadOf(u.home);
          break;
        case "S4_after_guessing":
          t = anchor.t + (24 + rnd() * 24) * HOUR;
          place = abroadOf(u.home);
          for (let k = 0; k < 5; k++) extra.push({ t: t - (10 - k) * 60e3, ip: PLACES[place].ip(7), dev, success: false });
          break;
        case "S5_abroad_off_hours":
          t = anchor.t + (6 + rnd() * 6) * HOUR;
          place = abroadOf(u.home);
          break;
      }
      out.push({ victim, scenario, t, ip: PLACES[place].ip(7), dev, extra });
    }
  }
  return out;
}

function historyBefore(events, t, extra = []) {
  return [...events.filter((e) => e.t < t), ...extra].map((e) => ({ t: e.t, ip: e.ip, dev: e.dev, success: e.success }));
}

function scoreAll({ perUser, attackList, weights, rnd, scoreFrom }) {
  const cfg = { risk: { weights } };
  const ageS = () => rnd() * PARAMS.attestationPeriodS;
  const legit = [];
  for (const { events } of perUser) {
    for (const e of events) {
      if (!e.success || e.t < scoreFrom) continue;
      const r = risk({ history: historyBefore(events, e.t), device: { attestation_age_s: ageS() }, ctx: { ip: e.ip, t: e.t, dev: e.dev }, cfg });
      legit.push({ rho: r.rho, f: r.f });
    }
  }
  const atk = [];
  for (const a of attackList) {
    const r = risk({
      history: historyBefore(a.victim.events, a.t, a.extra),
      device: { attestation_age_s: ageS() },
      ctx: { ip: a.ip, t: a.t, dev: a.dev },
      cfg,
    });
    atk.push({ scenario: a.scenario, rho: r.rho, f: r.f });
  }
  return { legit, atk };
}

function rates(scored, theta) {
  const legitStepUp = scored.legit.filter((x) => x.rho >= theta).length / scored.legit.length;
  const perScenario = {};
  for (const s of Object.keys(SCENARIOS)) {
    const xs = scored.atk.filter((x) => x.scenario === s);
    perScenario[s] = xs.filter((x) => x.rho >= theta).length / xs.length;
  }
  const allAtk = scored.atk.filter((x) => x.rho >= theta).length / scored.atk.length;
  return { theta, legitStepUp, attacksCaught: allAtk, perScenario };
}

function pct(x) {
  return `${(100 * x).toFixed(1)}%`;
}

export async function main(argv = process.argv.slice(2)) {
  const opt = (k, d) => (argv.includes(k) ? argv[argv.indexOf(k) + 1] : d);
  const users = Number(opt("--users", "1000"));
  const days = Number(opt("--days", "30"));
  const seed = Number(opt("--seed", "1"));
  const outDir = path.resolve(opt("--out", "results/e6-risk"));
  const t0 = Date.UTC(2026, 0, 5); // a Monday

  const rnd = prng(seed);
  const perUser = legitimateTraffic(rnd, users, days, t0);
  const scoreFrom = t0 + PARAMS.burnInDays * DAY;
  const attackList = attacks(rnd, perUser, scoreFrom);
  const scoreRnd = prng(seed + 1);
  const base = scoreAll({ perUser, attackList, weights: DEFAULT_WEIGHTS, rnd: scoreRnd, scoreFrom });

  const thetas = Array.from({ length: 21 }, (_, i) => Math.round(i * 5) / 100);
  const sweep = thetas.map((th) => rates(base, th));
  const atDefault = rates(base, 0.5);
  const atDeny = rates(base, 0.85);

  const ablation = FEATURES.map((name, i) => {
    const w = DEFAULT_WEIGHTS.map((v, j) => (j === i ? 0 : v));
    const r = rates(scoreAll({ perUser, attackList, weights: w, rnd: prng(seed + 1), scoreFrom }), 0.5);
    return { removed: name, ...r };
  });

  const nLegit = base.legit.length;
  const policies = [
    { policy: "No MFA (B5 = M27 and M28 off)", legitStepUp: 0, attacksCaught: 0 },
    { policy: "Adaptive (theta_login = 0.5)", legitStepUp: atDefault.legitStepUp, attacksCaught: atDefault.attacksCaught },
    { policy: "Static MFA (B4)", legitStepUp: 1, attacksCaught: 1 },
  ];

  const report = { at: new Date().toISOString(), seed, users, days, params: PARAMS, scenarios: SCENARIOS, weights: DEFAULT_WEIGHTS, legitLogins: nLegit, attacks: base.atk.length, atDefault, atDeny, sweep, ablation, policies };
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, `e6-risk-seed${seed}.json`), JSON.stringify(report, null, 2));
  fs.writeFileSync(
    path.join(outDir, `e6-sweep-seed${seed}.csv`),
    ["theta,legit_stepup," + Object.keys(SCENARIOS).join(",") + ",all_attacks", ...sweep.map((r) => [r.theta, r.legitStepUp, ...Object.values(r.perScenario), r.attacksCaught].join(","))].join("\n") + "\n"
  );

  console.log(`E6 synthetic: ${users} users x ${days} days, ${nLegit} legitimate logins, ${base.atk.length} attack logins (seed ${seed})`);
  console.log(`\nAt theta_login = 0.5: legitimate logins stepped up ${pct(atDefault.legitStepUp)}, attacks caught ${pct(atDefault.attacksCaught)}`);
  for (const [s, v] of Object.entries(atDefault.perScenario)) console.log(`  ${s.padEnd(22)} ${pct(v).padStart(6)}  ${SCENARIOS[s]}`);
  console.log(`At theta_deny = 0.85: legitimate denied ${pct(atDeny.legitStepUp)}, attacks denied ${pct(atDeny.attacksCaught)}`);
  console.log(`\nThreshold sweep (theta: legit step-up / attacks caught):`);
  console.log("  " + sweep.filter((r) => [0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6].includes(r.theta)).map((r) => `${r.theta}: ${pct(r.legitStepUp)}/${pct(r.attacksCaught)}`).join("  "));
  console.log(`\nFeature ablation at theta = 0.5 (legit step-up / attacks caught):`);
  for (const a of ablation) console.log(`  without ${a.removed.padEnd(20)} ${pct(a.legitStepUp).padStart(6)} / ${pct(a.attacksCaught).padStart(6)}`);
  console.log(`\nPolicies (legit step-up / attacks caught):`);
  for (const p of policies) console.log(`  ${p.policy.padEnd(34)} ${pct(p.legitStepUp).padStart(6)} / ${pct(p.attacksCaught).padStart(6)}`);
  console.log(`\nReport: ${path.join(outDir, `e6-risk-seed${seed}.json`)}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
