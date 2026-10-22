/**
 * @file tests/attacks-smoke.test.mjs
 * Smoke tests for Attack Suite v2 (WP-D1).
 * Tests fast subset to verify:
 *  - Full config: every applicable attack is rejected
 *  - -M16 -> A17 accepted
 *  - -M17 -> A18 accepted, and A19 stays rejected (DiD)
 *  - B1 -> A11 accepted, A22 n/a
 *  - JSONL rows validate against the schema
 *  - The shim's exit code is 0 for full and 1 with --ablate cnf
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { ATTACKS, getAttack } from "../scripts/attacks/index.mjs";
import { createContext } from "../scripts/attacks/lib/context.mjs";
import { normaliseResult } from "../scripts/attacks/lib/result.mjs";
import { parseConfigLabel } from "../lib/ablation.js";

describe("WP-D1: Attack Suite v2 Smoke Tests", () => {
  it("Full config: every applicable attack is rejected", async () => {
    // Test a representative set of implemented attacks under full config
    const testIds = ["A10", "A11", "A12", "A13", "A14", "A15", "A16", "A17", "A18", "A19", "A20", "A21", "A23", "A24"];

    for (const id of testIds) {
      const attackDef = getAttack(id);
      assert.ok(attackDef, `Attack ${id} should exist`);
      const ctx = await createContext({ mode: "inproc", config: "full" });
      try {
        const res = await attackDef.module.run(ctx, { variant: null });
        assert.equal(res.outcome, "rejected", `Attack ${id} must be rejected under full config`);
        assert.ok(res.stoppedAt, `Attack ${id} must report stoppedAt`);
      } finally {
        await ctx.cleanup();
      }
    }
  });

  it("-M16 -> A17 is accepted", async () => {
    const a17 = getAttack("A17");
    const ctx = await createContext({ mode: "inproc", config: "-M16" });
    try {
      const res = await a17.module.run(ctx, { variant: null });
      assert.equal(res.outcome, "accepted", "A17 must be accepted under -M16");
      assert.equal(res.stoppedAt, null);
    } finally {
      await ctx.cleanup();
    }
  });

  it("-M17 -> A18 is accepted, and A19 stays rejected (Defense-in-Depth)", async () => {
    const a18 = getAttack("A18");
    const a19 = getAttack("A19");

    const ctx18 = await createContext({ mode: "inproc", config: "-M17" });
    try {
      const res18 = await a18.module.run(ctx18, { variant: null });
      assert.equal(res18.outcome, "accepted", "A18 must be accepted under -M17");
    } finally {
      await ctx18.cleanup();
    }

    const ctx19 = await createContext({ mode: "inproc", config: "-M17" });
    try {
      const res19 = await a19.module.run(ctx19, { variant: null });
      assert.equal(res19.outcome, "rejected", "A19 must stay rejected under -M17 due to DiD (M18 jti cache)");
    } finally {
      await ctx19.cleanup();
    }
  });

  it("B1 -> A11 is accepted, and A22 is n/a", async () => {
    const a11 = getAttack("A11");
    const a22 = getAttack("A22");

    const ctx = await createContext({ mode: "inproc", config: "B1" });
    try {
      const res11 = await a11.module.run(ctx, { variant: null });
      assert.equal(res11.outcome, "accepted", "A11 must be accepted under B1 (M10 is off)");

      const parsedB1 = parseConfigLabel("B1");
      const app22 = a22.module.applicable(parsedB1, "inproc");
      assert.ok(typeof app22 === "string" && app22.startsWith("n/a"), "A22 must be n/a under B1");
    } finally {
      await ctx.cleanup();
    }
  });

  it("JSONL rows validate against zta-attack/1 schema", () => {
    const sample = {
      runId: "run_sample",
      ts: new Date().toISOString(),
      mode: "inproc",
      config: "-M16",
      baseline: null,
      mechanismsOff: ["M16"],
      attack: "A17",
      variant: null,
      rep: 1,
      goal: "G3",
      adversary: "A2",
      expected: ["M16"],
      outcome: "accepted",
      stoppedAt: null,
      durationMs: 15,
      manifestHash: "abcd",
    };

    const row = normaliseResult(sample);
    assert.equal(row.schema, "zta-attack/1");
    assert.equal(row.runId, "run_sample");
    assert.equal(row.attack, "A17");
    assert.equal(row.outcome, "accepted");
    assert.equal(row.stoppedAt, null);
    assert.equal(row.predicted, "accepted");
  });

  it("Shim scripts/attack-e1.mjs exit code is 0 for full and 1 with --ablate cnf", () => {
    // Full run -> exit 0
    const outFull = execSync("node scripts/attack-e1.mjs", { encoding: "utf8" });
    assert.ok(outFull.includes("All attacks successfully REJECTED"));

    // Ablate cnf -> exit 1
    let failed = false;
    try {
      execSync("node scripts/attack-e1.mjs --ablate cnf", { encoding: "utf8", stdio: "pipe" });
    } catch (err) {
      failed = true;
      assert.equal(err.status, 1, "Exit code must be 1 when attack accepted under ablation");
    }
    assert.ok(failed, "attack-e1 with --ablate cnf must exit with code 1");
  });
});
