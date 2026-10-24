/**
 * @file tests/keycloak-upstream.test.mjs
 * Keycloak upstream callback (IDP_MODE=keycloak): the gate accepts a user only from an ID token
 * Keycloak signed for this client, in the browser session that started the login (state), for
 * this login request (nonce). VERIFY5 N4.
 */

import { describe, it, before, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as jose from "jose";

import { redirectToKeycloak, handleKeycloakCallback } from "../lib/idp/keycloak-upstream.js";

const ISSUER = "http://kc.test/realms/zta-realm";
const CLIENT_ID = "zta-gate";

function fakeRes() {
  const res = { statusCode: 200, body: null, location: null };
  res.status = (c) => ((res.statusCode = c), res);
  res.send = (b) => ((res.body = b), res);
  res.json = (b) => ((res.body = b), res);
  res.redirect = (url) => ((res.location = url), res);
  return res;
}

describe("Keycloak upstream callback (N4)", () => {
  let kcKey;
  let otherKey;
  let cfg;
  let realFetch;
  let idTokenToReturn;
  let gateCalls;

  before(async () => {
    kcKey = await jose.generateKeyPair("RS256");
    otherKey = await jose.generateKeyPair("RS256");
    const jwk = { ...(await jose.exportJWK(kcKey.publicKey)), kid: "kc-1", alg: "RS256" };
    cfg = {
      keycloakIssuer: ISSUER,
      keycloakClientId: CLIENT_ID,
      idpIssuer: "http://gate.test",
      keycloakJwks: jose.createLocalJWKSet({ keys: [jwk] }),
    };
  });

  beforeEach(() => {
    realFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response(JSON.stringify({ id_token: idTokenToReturn }), { status: 200 });
    gateCalls = [];
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  async function startLogin() {
    const req = { session: {} };
    const res = fakeRes();
    await redirectToKeycloak(req, res, { request_uri: "urn:test:1" }, cfg);
    const url = new URL(res.location);
    return { session: req.session, state: url.searchParams.get("state"), nonce: url.searchParams.get("nonce") };
  }

  async function idToken({ key = kcKey.privateKey, aud = CLIENT_ID, iss = ISSUER, nonce, user = "alice", roles = ["auditor"] }) {
    return new jose.SignJWT({ preferred_username: user, realm_access: { roles }, nonce })
      .setProtectedHeader({ alg: "RS256", kid: "kc-1" })
      .setIssuer(iss)
      .setAudience(aud)
      .setSubject(`sub-${user}`)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(key);
  }

  async function callback(session, query) {
    const req = { session, query, socket: { remoteAddress: "127.0.0.1" } };
    const res = fakeRes();
    const gate = async (_req, _res, txn, user, _ctx, opts) => {
      gateCalls.push({ txn, user, role: opts.role });
      return _res.status(200).json({ ok: true });
    };
    await handleKeycloakCallback(req, res, { store: {}, cfg, gateAfterPrimaryAuth: gate });
    return res;
  }

  it("the redirect carries a fresh random state and nonce, not the request_uri", async () => {
    const a = await startLogin();
    const b = await startLogin();
    assert.ok(a.state && a.nonce);
    assert.notEqual(a.state, "urn:test:1");
    assert.notEqual(a.state, b.state);
    assert.notEqual(a.nonce, b.nonce);
  });

  it("accepts a Keycloak-signed ID token for this client, session and request", async () => {
    const { session, state, nonce } = await startLogin();
    idTokenToReturn = await idToken({ nonce });
    const res = await callback(session, { code: "c1", state });
    assert.equal(res.statusCode, 200, JSON.stringify(res.body));
    assert.deepEqual(gateCalls.map((c) => [c.user, c.role]), [["alice", "auditor"]]);
  });

  it("rejects a callback whose state does not match the session", async () => {
    const { session, nonce } = await startLogin();
    idTokenToReturn = await idToken({ nonce });
    const res = await callback(session, { code: "c1", state: "attacker-state" });
    assert.equal(res.statusCode, 400);
    assert.equal(gateCalls.length, 0);
  });

  it("rejects a replayed callback (state is single use)", async () => {
    const { session, state, nonce } = await startLogin();
    idTokenToReturn = await idToken({ nonce });
    session.oauthTxn = session.oauthTxn || { request_uri: "urn:test:1" };
    const first = await callback(session, { code: "c1", state });
    assert.equal(first.statusCode, 200);
    const replay = await callback(session, { code: "c1", state });
    assert.equal(replay.statusCode, 400);
    assert.equal(gateCalls.length, 1);
  });

  it("rejects an ID token not signed by Keycloak", async () => {
    const { session, state, nonce } = await startLogin();
    idTokenToReturn = await idToken({ nonce, key: otherKey.privateKey });
    const res = await callback(session, { code: "c1", state });
    assert.equal(res.statusCode, 401);
    assert.equal(gateCalls.length, 0);
  });

  it("rejects an ID token issued to another client", async () => {
    const { session, state, nonce } = await startLogin();
    idTokenToReturn = await idToken({ nonce, aud: "some-other-client" });
    const res = await callback(session, { code: "c1", state });
    assert.equal(res.statusCode, 401);
    assert.equal(gateCalls.length, 0);
  });

  it("rejects an ID token minted for a different login request (nonce)", async () => {
    const { session, state } = await startLogin();
    idTokenToReturn = await idToken({ nonce: "nonce-of-another-login" });
    const res = await callback(session, { code: "c1", state });
    assert.equal(res.statusCode, 401);
    assert.equal(gateCalls.length, 0);
  });
});
