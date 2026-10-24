/**
 * @file tests/tls.test.mjs
 * Requirements S2/S4: every service can listen with TLS (lib/tls.js); clients verify the server
 * certificate against the testbed CA, and the production guard refuses plain HTTP (see
 * tests/production-safety.test.mjs).
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import express from "express";

import { listen, tlsServerOptions } from "../lib/tls.js";

const REPO = path.resolve(import.meta.dirname, "..");

function get(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { agent: false, ...opts }, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => resolve({ status: res.statusCode, body, protocol: res.socket.getProtocol?.() ?? req.socket?.getProtocol?.() }));
    });
    req.on("error", reject);
  });
}

describe("TLS listener (S2, S4)", () => {
  let dir;
  const saved = {};

  before(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "zta-tls-"));
    execFileSync(path.join(REPO, "testbed", "tls.sh"), [], { env: { ...process.env, ZTA_TLS_DIR: dir, ZTA_PUBLIC_HOST: "127.0.0.1" }, stdio: "ignore" });
    for (const k of ["ZTA_TLS_CERT", "ZTA_TLS_KEY"]) saved[k] = process.env[k];
  });

  after(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const app = () => {
    const a = express();
    a.get("/health", (_req, res) => res.json({ ok: true, secure: _req.secure }));
    return a;
  };

  it("listens with plain HTTP when no certificate is configured", async () => {
    delete process.env.ZTA_TLS_CERT;
    delete process.env.ZTA_TLS_KEY;
    assert.equal(tlsServerOptions(), null);
    const server = await new Promise((resolve) => {
      const s = listen(app(), 0, "127.0.0.1", () => resolve(s));
    });
    const res = await fetch(`http://127.0.0.1:${server.address().port}/health`, { headers: { connection: "close" } });
    assert.equal(res.status, 200);
    server.closeAllConnections();
    server.close();
  });

  it("serves HTTPS (TLS 1.3) that a client trusting the testbed CA accepts", async () => {
    process.env.ZTA_TLS_CERT = path.join(dir, "server.pem");
    process.env.ZTA_TLS_KEY = path.join(dir, "server.key");
    const server = await new Promise((resolve) => {
      const s = listen(app(), 0, "127.0.0.1", () => resolve(s));
    });
    const url = `https://127.0.0.1:${server.address().port}/health`;
    const res = await get(url, { ca: fs.readFileSync(path.join(dir, "ca.pem")) });
    assert.equal(res.status, 200);
    assert.equal(JSON.parse(res.body).secure, true);
    assert.equal(res.protocol, "TLSv1.3");
    server.closeAllConnections();
    server.close();
  });

  it("is rejected by a client that does not trust the CA (verification is never disabled)", async () => {
    process.env.ZTA_TLS_CERT = path.join(dir, "server.pem");
    process.env.ZTA_TLS_KEY = path.join(dir, "server.key");
    const server = await new Promise((resolve) => {
      const s = listen(app(), 0, "127.0.0.1", () => resolve(s));
    });
    await assert.rejects(get(`https://127.0.0.1:${server.address().port}/health`), /self[- ]signed|unable to verify|UNABLE_TO_VERIFY|SELF_SIGNED/i);
    server.closeAllConnections();
    server.close();
  });

  it("refuses a certificate without its key", () => {
    process.env.ZTA_TLS_CERT = path.join(dir, "server.pem");
    delete process.env.ZTA_TLS_KEY;
    assert.throws(() => tlsServerOptions(), /must be set together/);
  });
});
