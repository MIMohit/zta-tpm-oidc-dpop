/**
 * @file tests/tpm-factory.test.mjs
 * Unit tests for lib/tpm-factory.js and agent integration (WP-T4).
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

import { createTpmBackend } from "../lib/tpm-factory.js";
import { createApp } from "../tpm-agent.js";
import { SimTpm } from "../lib/sim-tpm/tpm.js";
import { WindowsEkTpm } from "../lib/sim-tpm/windows-ek.js";

async function listenApp(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      resolve({
        server,
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise((res) => server.close(res)),
      });
    });
  });
}

describe("WP-T4: TPM Factory & Agent Wiring", () => {
  it("creates SimTpm backend when TPM_BACKEND=sim", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-fact-sim-"));
    try {
      const res = await createTpmBackend({ tpmBackend: "sim" }, { agentDir: tmpDir });
      assert.equal(res.kind, "sim");
      assert.equal(res.tpmBackend, "sim");
      assert.equal(res.available, true);
      assert.ok(res.tpm instanceof SimTpm);
      assert.equal(res.tpm.kind, "sim");
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("sim and auto-fallback reuse the persisted SimTpm EK (tpm.json is loaded, never regenerated)", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-fact-persist-"));
    try {
      const { devIdOf } = await import("../lib/sim-tpm/public-area.js");
      const seeded = new SimTpm({ dir: tmpDir });
      await seeded.init();
      const devId = await devIdOf((await seeded.getEk()).publicArea);

      for (const cfg of [
        { tpmBackend: "sim" },
        { tpmBackend: "sim" },
        { tpmBackend: "auto", tpmDevice: "tcp", tpmTcpPort: 2499, tpmConnectTimeoutMs: 200 },
      ]) {
        const res = await createTpmBackend(cfg, { agentDir: tmpDir });
        assert.equal(await devIdOf((await res.tpm.getEk()).publicArea), devId);
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("creates WindowsEkTpm backend when TPM_BACKEND=windows-ek", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-fact-win-"));
    try {
      const res = await createTpmBackend({ tpmBackend: "windows-ek" }, { agentDir: tmpDir });
      assert.equal(res.kind, "windows-ek");
      assert.equal(res.tpmBackend, "windows-ek");
      assert.equal(res.available, true);
      assert.ok(res.tpm instanceof WindowsEkTpm);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("TPM_BACKEND=auto falls back to SimTpm with warning banner when TPM is unreachable", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-fact-auto-"));
    try {
      const res = await createTpmBackend(
        {
          tpmBackend: "auto",
          tpmDevice: "tcp",
          tpmTcpHost: "127.0.0.1",
          tpmTcpPort: 2499, // Unused port to guarantee failure
          tpmConnectTimeoutMs: 200,
        },
        { agentDir: tmpDir }
      );

      assert.equal(res.kind, "sim-fallback");
      assert.equal(res.tpmBackend, "auto");
      assert.equal(res.available, true);
      assert.equal(res.fallback, true);
      assert.ok(res.reason, "Should provide failure reason");
      assert.ok(res.tpm instanceof SimTpm);
      assert.equal(res.tpm.kind, "sim-fallback");
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("TPM_BACKEND=tpm never throws on unreachable TPM and returns available=false", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-fact-tpm-"));
    try {
      const res = await createTpmBackend(
        {
          tpmBackend: "tpm",
          tpmDevice: "tcp",
          tpmTcpHost: "127.0.0.1",
          tpmTcpPort: 2499, // Unused port to guarantee failure
          tpmConnectTimeoutMs: 200,
        },
        { agentDir: tmpDir }
      );

      assert.equal(res.kind, "tpm");
      assert.equal(res.tpmBackend, "tpm");
      assert.equal(res.available, false);
      assert.ok(res.reason, "Should capture connection error reason");
      assert.equal(typeof res.reconnect, "function");
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("Agent HTTP routes when TPM_BACKEND=tpm is unreachable return 503 and status shows unavailable", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-agent-tpm-"));
    let srv = null;
    try {
      const cfg = {
        tpmBackend: "tpm",
        tpmDevice: "tcp",
        tpmTcpHost: "127.0.0.1",
        tpmTcpPort: 2499,
        tpmConnectTimeoutMs: 200,
      };
      const app = createApp(cfg, { agentDir: tmpDir });
      srv = await listenApp(app);

      // GET /agent/status: returns 200 with tpm: "unavailable"
      const statusRes = await fetch(`${srv.url}/agent/status`);
      assert.equal(statusRes.status, 200);
      const statusBody = await statusRes.json();
      assert.equal(statusBody.tpm, "unavailable");
      assert.equal(statusBody.backend, "tpm");
      assert.equal(statusBody.kind, "tpm");
      assert.ok(statusBody.reason);

      // POST /agent/enrol: returns 503 tpm_unavailable
      const enrolRes = await fetch(`${srv.url}/agent/enrol`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: "test-code" }),
      });
      assert.equal(enrolRes.status, 503);
      const enrolBody = await enrolRes.json();
      assert.equal(enrolBody.error, "tpm_unavailable");

      // POST /agent/login: returns 503 tpm_unavailable
      const loginRes = await fetch(`${srv.url}/agent/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      assert.equal(loginRes.status, 503);
      const loginBody = await loginRes.json();
      assert.equal(loginBody.error, "tpm_unavailable");

      // GET /agent/resource/company.news: returns 503 tpm_unavailable
      const resRes = await fetch(`${srv.url}/agent/resource/company.news`);
      assert.equal(resRes.status, 503);
      const resBody = await resRes.json();
      assert.equal(resBody.error, "tpm_unavailable");
    } finally {
      if (srv) await srv.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("Agent HTTP routes when TPM_BACKEND=auto without server falls back and serves requests", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tpm-agent-auto-"));
    let srv = null;
    try {
      const cfg = {
        tpmBackend: "auto",
        tpmDevice: "tcp",
        tpmTcpHost: "127.0.0.1",
        tpmTcpPort: 2499,
        tpmConnectTimeoutMs: 200,
      };
      const app = createApp(cfg, { agentDir: tmpDir });
      srv = await listenApp(app);

      const statusRes = await fetch(`${srv.url}/agent/status`);
      assert.equal(statusRes.status, 200);
      const statusBody = await statusRes.json();
      assert.equal(statusBody.tpmBackend, "auto");
      assert.equal(statusBody.kind, "sim-fallback");
      assert.equal(statusBody.backend, "sim");
      assert.equal(statusBody.enrolled, false);
    } finally {
      if (srv) await srv.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
