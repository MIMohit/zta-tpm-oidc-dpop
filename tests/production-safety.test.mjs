/**
 * @file tests/production-safety.test.mjs
 * VERIFY5 N5: in production, settings outside the ablation switchboard that weaken the
 * system, and development or fallback secrets, stop the service from starting.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { loadConfig } from "../lib/config.js";

const strong = () => crypto.randomBytes(32).toString("hex");
const prod = (extra = {}) => ({
  ztaEnv: "production",
  ztaInternalToken: strong(),
  adminToken: strong(),
  sessionSecret: strong(),
  dataDir: "/nonexistent-zta-test",
  tlsCert: "/etc/zta/tls/server.pem",
  tlsKey: "/etc/zta/tls/server.key",
  idpIssuer: "https://idp.example",
  verifierUrl: "https://verifier.example",
  pipUrl: "https://pip.internal.example",
  pdpUrl: "https://pdp.internal.example",
  pepPublicUrl: "https://api.example",
  resourceUrl: "https://rs.internal.example",
  ...extra,
});

describe("Production refusal of unsafe settings (N5)", () => {
  it("starts with strong secrets and no evaluation switches", () => {
    assert.doesNotThrow(() => loadConfig(prod()));
  });

  for (const [name, extra] of [
    ["the simulated-IP header", { simIpHeader: true }],
    ["golden-PCR trust on first use", { verifierGoldenTofu: true }],
    ["ignoring EK certificate expiry", { ekCertIgnoreExpiry: true }],
    ["debug mode", { debug: true }],
    ["a simulated TPM backend", { tpmBackend: "sim" }],
    ["the fallback internal token", { ztaInternalToken: "dev-internal-zta-secret-token" }],
    ["the .env.example session secret", { sessionSecret: "dev-session-secret-change-in-production" }],
    ["a plain-HTTP listener (no TLS certificate)", { tlsCert: null, tlsKey: null }],
    ["an http issuer", { idpIssuer: "http://idp.example" }],
    ["an http service-to-service URL", { pdpUrl: "http://127.0.0.1:4002" }],
    ["an http Keycloak issuer in keycloak mode", { idpMode: "keycloak", keycloakIssuer: "http://kc.example/realms/zta-realm" }],
  ]) {
    it(`refuses ${name}`, () => {
      assert.throws(() => loadConfig(prod(extra)), /Refusing to start in production/);
    });
  }

  it("development mode is unaffected", () => {
    assert.doesNotThrow(() => loadConfig({ ztaEnv: "development", simIpHeader: true, debug: true }));
  });
});
