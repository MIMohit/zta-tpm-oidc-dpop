import { describe, it } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { execSync } from "node:child_process";
import { decide, defaultPolicyData } from "../lib/policy.js";
import { createApp as createPipApp } from "../pip.js";
import { createApp as createPdpApp } from "../pdp.js";
import { loadConfig } from "../lib/config.js";

describe("Policy Decision Engine & PDP (Rego-equivalent)", () => {
  const data = defaultPolicyData;
  const now_s = 1700000500;

  it("Policy truth table: 12+ rows covering all decision branches", () => {
    const truthTable = [
      // 1. Inactive device: suspended -> deny
      {
        name: "Inactive device (suspended)",
        input: {
          resource: "company.news",
          op: "GET",
          now_s,
          risk: 0.1,
          device: { status: "suspended", attestation_age_s: 10, owner: "alice" },
          token: { sub: "alice", role: "employee", acr: "pwd", auth_time: now_s - 10 },
        },
        expected: "deny",
      },
      // 2. Inactive device: revoked -> deny
      {
        name: "Inactive device (revoked)",
        input: {
          resource: "company.news",
          op: "GET",
          now_s,
          risk: 0.1,
          device: { status: "revoked", attestation_age_s: 10, owner: "alice" },
          token: { sub: "alice", role: "employee", acr: "pwd", auth_time: now_s - 10 },
        },
        expected: "deny",
      },
      // 3. Inactive device: unknown -> deny
      {
        name: "Inactive device (unknown)",
        input: {
          resource: "company.news",
          op: "GET",
          now_s,
          risk: 0.1,
          device: { status: "unknown", attestation_age_s: 10, owner: "alice" },
          token: { sub: "alice", role: "employee", acr: "pwd", auth_time: now_s - 10 },
        },
        expected: "deny",
      },
      // 4. Stale attestation on low sensitivity (> 600 s) -> deny
      {
        name: "Stale attestation on low resource (601 s)",
        input: {
          resource: "company.news",
          op: "GET",
          now_s,
          risk: 0.1,
          device: { status: "active", attestation_age_s: 601, owner: "alice" },
          token: { sub: "alice", role: "employee", acr: "pwd", auth_time: now_s - 10 },
        },
        expected: "deny",
      },
      // 5. Stale attestation on high sensitivity (> 330 s) -> deny
      {
        name: "Stale attestation on high resource (331 s)",
        input: {
          resource: "company.audit",
          op: "GET",
          now_s,
          risk: 0.1,
          device: { status: "active", attestation_age_s: 331, owner: "alice" },
          token: { sub: "alice", role: "auditor", acr: "mfa", auth_time: now_s - 10 },
        },
        expected: "deny",
      },
      // 6. Owner mismatch -> deny
      {
        name: "Device owner mismatch (owner bob vs sub alice)",
        input: {
          resource: "company.news",
          op: "GET",
          now_s,
          risk: 0.1,
          device: { status: "active", attestation_age_s: 50, owner: "bob" },
          token: { sub: "alice", role: "employee", acr: "pwd", auth_time: now_s - 10 },
        },
        expected: "deny",
      },
      // 7. Low sensitivity + acr pwd + risk < 0.5 + employee role -> permit
      {
        name: "Low sensitivity + pwd + low risk + employee -> permit",
        input: {
          resource: "company.news",
          op: "GET",
          now_s,
          risk: 0.2,
          device: { status: "active", attestation_age_s: 50, owner: "bob" },
          token: { sub: "bob", role: "employee", acr: "pwd", auth_time: now_s - 50 },
        },
        expected: "permit",
      },
      // 8. Low sensitivity + acr pwd + risk >= 0.5 -> step_up
      {
        name: "Low sensitivity + pwd + elevated risk (0.6) -> step_up",
        input: {
          resource: "company.news",
          op: "GET",
          now_s,
          risk: 0.6,
          device: { status: "active", attestation_age_s: 50, owner: "bob" },
          token: { sub: "bob", role: "employee", acr: "pwd", auth_time: now_s - 50 },
        },
        expected: "step_up",
      },
      // 9. High sensitivity + acr pwd -> step_up
      {
        name: "High sensitivity + pwd (even with low risk) -> step_up",
        input: {
          resource: "company.audit",
          op: "GET",
          now_s,
          risk: 0.05,
          device: { status: "active", attestation_age_s: 50, owner: "alice" },
          token: { sub: "alice", role: "auditor", acr: "pwd", auth_time: now_s - 10 },
        },
        expected: "step_up",
      },
      // 10. High sensitivity + acr mfa + recent auth (<= 300 s) with risk >= 0.3 -> permit
      {
        name: "High sensitivity + mfa + recent auth covering risk 0.4 -> permit",
        input: {
          resource: "company.audit",
          op: "GET",
          now_s,
          risk: 0.4,
          device: { status: "active", attestation_age_s: 50, owner: "alice" },
          token: { sub: "alice", role: "auditor", acr: "mfa", auth_time: now_s - 150 },
        },
        expected: "permit",
      },
      // 11. High sensitivity + acr mfa + stale auth (> 300 s) with risk >= 0.3 -> step_up
      {
        name: "High sensitivity + mfa + stale auth (350 s) with risk 0.35 -> step_up",
        input: {
          resource: "company.audit",
          op: "GET",
          now_s,
          risk: 0.35,
          device: { status: "active", attestation_age_s: 50, owner: "alice" },
          token: { sub: "alice", role: "auditor", acr: "mfa", auth_time: now_s - 350 },
        },
        expected: "step_up",
      },
      // 12. High sensitivity + acr mfa + stale auth with risk < 0.3 -> permit
      {
        name: "High sensitivity + mfa + stale auth with risk 0.2 < 0.3 -> permit",
        input: {
          resource: "company.audit",
          op: "GET",
          now_s,
          risk: 0.2,
          device: { status: "active", attestation_age_s: 50, owner: "alice" },
          token: { sub: "alice", role: "auditor", acr: "mfa", auth_time: now_s - 350 },
        },
        expected: "permit",
      },
      // 13. Wrong role: employee accessing company.audit -> deny
      {
        name: "Wrong role (employee on company.audit) -> deny",
        input: {
          resource: "company.audit",
          op: "GET",
          now_s,
          risk: 0.1,
          device: { status: "active", attestation_age_s: 50, owner: "bob" },
          token: { sub: "bob", role: "employee", acr: "mfa", auth_time: now_s - 10 },
        },
        expected: "deny",
      },
      // 14. Unknown resource -> deny
      {
        name: "Unknown resource -> deny",
        input: {
          resource: "company.secret",
          op: "GET",
          now_s,
          risk: 0.1,
          device: { status: "active", attestation_age_s: 50, owner: "alice" },
          token: { sub: "alice", role: "auditor", acr: "mfa", auth_time: now_s - 10 },
        },
        expected: "deny",
      },
      // 15. Unsupported HTTP method -> deny
      {
        name: "Unsupported HTTP method (POST on company.news) -> deny",
        input: {
          resource: "company.news",
          op: "POST",
          now_s,
          risk: 0.1,
          device: { status: "active", attestation_age_s: 50, owner: "alice" },
          token: { sub: "alice", role: "auditor", acr: "mfa", auth_time: now_s - 10 },
        },
        expected: "deny",
      },
    ];

    assert(truthTable.length >= 12, "Truth table must contain at least 12 rows");

    for (const row of truthTable) {
      const res = decide(row.input, data);
      assert.equal(
        res.decision,
        row.expected,
        `[${row.name}] Expected '${row.expected}', got '${res.decision}' (reason: ${res.reason})`
      );
      assert(typeof res.reason === "string" && res.reason.length > 0, "Reason must be non-empty string");
    }
  });

  it("Mutual exclusivity: exactly one outcome for every generated combination", () => {
    const statuses = ["active", "revoked", "suspended"];
    const ages = [50, 400, 700];
    const owners = ["alice", "bob"];
    const resources = ["company.news", "company.audit"];
    const acrs = ["pwd", "mfa"];
    const authAges = [50, 400]; // <= 300 vs > 300
    const risks = [0.1, 0.4, 0.7]; // < 0.3, [0.3, 0.5), >= 0.5
    const roles = ["auditor", "employee", "unknown"];
    const ops = ["GET", "POST"];

    let count = 0;

    for (const status of statuses) {
      for (const age of ages) {
        for (const owner of owners) {
          for (const resource of resources) {
            for (const acr of acrs) {
              for (const authAge of authAges) {
                for (const risk of risks) {
                  for (const role of roles) {
                    for (const op of ops) {
                      count++;
                      const input = {
                        resource,
                        op,
                        now_s,
                        risk,
                        device: { status, attestation_age_s: age, owner },
                        token: { sub: "alice", role, acr, auth_time: now_s - authAge },
                      };

                      const sens = data.resources[resource].sensitivity;
                      const statusOk = status === "active";
                      const ageOk = age <= data.max_age_s[sens];
                      const ownerOk = owner === "alice";
                      const device_ok = statusOk && ageOk && ownerOk;

                      const acr_ok = sens === "low" || acr === "mfa";
                      const theta = data.theta[sens];
                      const recentMfa = acr === "mfa" && authAge <= data.t_su_s;
                      const risk_ok = risk < theta || recentMfa;

                      const perms = data.permissions[role] || [];
                      const role_ok = perms.some((p) => p.resource === resource && p.ops.includes(op));

                      const rule1 = !device_ok;
                      const rule2 = device_ok && !acr_ok;
                      const rule3 = device_ok && acr_ok && !risk_ok;
                      const rule4 = device_ok && acr_ok && risk_ok && role_ok;
                      const rule5 = device_ok && acr_ok && risk_ok && !role_ok;

                      // Mutual exclusivity and completeness: exactly 1 rule must be true
                      const activeRules = [rule1, rule2, rule3, rule4, rule5].filter(Boolean).length;
                      assert.equal(
                        activeRules,
                        1,
                        `Rules are not mutually exclusive for input ${JSON.stringify(input)}`
                      );

                      let expectedDecision = "deny";
                      if (rule1) expectedDecision = "deny";
                      else if (rule2 || rule3) expectedDecision = "step_up";
                      else if (rule4) expectedDecision = "permit";
                      else if (rule5) expectedDecision = "deny";

                      const actual = decide(input, data);
                      assert.equal(
                        actual.decision,
                        expectedDecision,
                        `Decision mismatch for input: ${JSON.stringify(input)}`
                      );
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    assert(count > 2000, `Evaluated ${count} combinations`);
  });

  it("If opa is on PATH, opa eval agrees with decide (skipped otherwise)", () => {
    let hasOpa = false;
    try {
      execSync("which opa", { stdio: "ignore" });
      hasOpa = true;
    } catch {
      hasOpa = false;
    }

    if (!hasOpa) {
      // Skipped otherwise
      return;
    }

    const testInput = {
      resource: "company.news",
      op: "GET",
      now_s,
      risk: 0.1,
      device: { status: "active", attestation_age_s: 50, owner: "alice" },
      token: { sub: "alice", role: "employee", acr: "pwd", auth_time: now_s - 50 },
    };

    const decideRes = decide(testInput, data);

    const inputJson = JSON.stringify(testInput);
    const cmd = `opa eval -d policy/ -i '${inputJson.replace(/'/g, "'\\''")}' "data.zta.authz.decision" --format raw`;
    const opaOutput = execSync(cmd, { encoding: "utf8" }).trim();

    assert.equal(opaOutput, decideRes.decision, `OPA decision (${opaOutput}) must match decide (${decideRes.decision})`);
  });

  it("In-process PIP & PDP HTTP integration", async () => {
    const testCfg = loadConfig({
      store: "memory",
      ztaInternalToken: "test-token-12345",
      clock: () => now_s * 1000,
    });

    // Start PIP
    const pipApp = createPipApp(testCfg);
    const pipServer = http.createServer(pipApp);
    await new Promise((resolve) => pipServer.listen(0, "127.0.0.1", resolve));
    const pipPort = pipServer.address().port;
    testCfg.pipUrl = `http://127.0.0.1:${pipPort}`;

    // Start PDP
    const pdpApp = createPdpApp(testCfg);
    const pdpServer = http.createServer(pdpApp);
    await new Promise((resolve) => pdpServer.listen(0, "127.0.0.1", resolve));
    const pdpPort = pdpServer.address().port;

    try {
      // 1. Enroll/update device in PIP
      const enrollRes = await fetch(`${testCfg.pipUrl}/pip/device/dev-100`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ZTA-Internal": testCfg.ztaInternalToken,
        },
        body: JSON.stringify({
          user: "alice",
          status: "active",
          jkt: "test-jkt",
          last_good_attestation: now_s * 1000 - 10000, // 10s ago
        }),
      });
      assert.equal(enrollRes.status, 200);

      // 2. Query PIP device
      const getDevRes = await fetch(`${testCfg.pipUrl}/pip/device/dev-100`, {
        headers: { "X-ZTA-Internal": testCfg.ztaInternalToken },
      });
      assert.equal(getDevRes.status, 200);
      const devData = await getDevRes.json();
      assert.equal(devData.user, "alice");
      assert.equal(devData.status, "active");
      assert.equal(devData.attestation_age_s, 10);

      // 3. Record login events
      const loginEventRes = await fetch(`${testCfg.pipUrl}/pip/login-event`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ZTA-Internal": testCfg.ztaInternalToken,
        },
        body: JSON.stringify({
          sub: "alice",
          dev: "dev-100",
          ip: "127.0.0.1",
          t: now_s * 1000 - 5000,
          success: true,
        }),
      });
      assert.equal(loginEventRes.status, 200);

      // 4. Query PIP context
      const ctxRes = await fetch(`${testCfg.pipUrl}/pip/context`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ZTA-Internal": testCfg.ztaInternalToken,
        },
        body: JSON.stringify({
          sub: "alice",
          dev: "dev-100",
          ip: "127.0.0.1",
          now: now_s,
        }),
      });
      assert.equal(ctxRes.status, 200);
      const ctxData = await ctxRes.json();
      assert.equal(ctxData.status, "active");
      assert.equal(ctxData.owner, "alice");
      assert.equal(ctxData.attestation_age_s, 10);
      assert(typeof ctxData.risk === "number");

      // 5. Evaluate via PDP: permit case (alice accessing company.news with pwd)
      const pdpPermitRes = await fetch(`http://127.0.0.1:${pdpPort}/pdp/evaluate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ZTA-Internal": testCfg.ztaInternalToken,
        },
        body: JSON.stringify({
          token: {
            sub: "alice",
            role: "employee",
            acr: "pwd",
            dev: "dev-100",
            auth_time: now_s - 10,
          },
          resource: "company.news",
          op: "GET",
          ip: "127.0.0.1",
        }),
      });
      assert.equal(pdpPermitRes.status, 200);
      const pdpPermitData = await pdpPermitRes.json();
      assert.equal(pdpPermitData.decision, "permit");
      assert.equal(pdpPermitData.pip.status, "active");

      // 6. Evaluate via PDP: step_up case (alice accessing company.audit with pwd)
      const pdpStepUpRes = await fetch(`http://127.0.0.1:${pdpPort}/pdp/evaluate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ZTA-Internal": testCfg.ztaInternalToken,
        },
        body: JSON.stringify({
          token: {
            sub: "alice",
            role: "auditor",
            acr: "pwd",
            dev: "dev-100",
            auth_time: now_s - 10,
          },
          resource: "company.audit",
          op: "GET",
          ip: "127.0.0.1",
        }),
      });
      assert.equal(pdpStepUpRes.status, 200);
      const pdpStepUpData = await pdpStepUpRes.json();
      assert.equal(pdpStepUpData.decision, "step_up");

      // 7. Evaluate via PDP: deny case (unknown / mismatch device)
      const pdpDenyRes = await fetch(`http://127.0.0.1:${pdpPort}/pdp/evaluate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-ZTA-Internal": testCfg.ztaInternalToken,
        },
        body: JSON.stringify({
          token: {
            sub: "alice",
            role: "auditor",
            acr: "mfa",
            dev: "non-existent-device",
            auth_time: now_s - 10,
          },
          resource: "company.audit",
          op: "GET",
          ip: "127.0.0.1",
        }),
      });
      assert.equal(pdpDenyRes.status, 200);
      const pdpDenyData = await pdpDenyRes.json();
      assert.equal(pdpDenyData.decision, "deny");
    } finally {
      await new Promise((r) => pipServer.close(r));
      await new Promise((r) => pdpServer.close(r));
    }
  });
});
