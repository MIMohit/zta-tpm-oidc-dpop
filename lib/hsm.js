/**
 * @file lib/hsm.js
 * Signing keys held in a PKCS#11 token (SoftHSM in the testbed). The verifier's AR key, the
 * IdP's token key and the audit key are generated inside the token as non-extractable P-256
 * keys; only their public halves leave it (JWKS). Enabled with ZTA_HSM=pkcs11.
 *
 * Settings: ZTA_PKCS11_LIB (module path), ZTA_PKCS11_TOKEN (token label),
 * ZTA_PKCS11_PIN (user PIN; else data/secrets.json PKCS11_PIN).
 */

import crypto from "node:crypto";

let graphene = null;
const sessions = new Map(); // lib|token -> { module, session }

async function loadGraphene() {
  if (!graphene) {
    try {
      graphene = await import("graphene-pk11");
    } catch (err) {
      throw new Error(`ZTA_HSM=pkcs11 needs the optional dependency graphene-pk11: ${err.message}`);
    }
  }
  return graphene;
}

async function openSession({ lib, token, pin }) {
  const id = `${lib}|${token}`;
  if (sessions.has(id)) return sessions.get(id);
  const g = await loadGraphene();
  const mod = g.Module.load(lib, "pkcs11");
  mod.initialize();
  const slots = mod.getSlots(true);
  let slot = null;
  for (let i = 0; i < slots.length; i++) {
    const s = slots.items(i);
    if (s.getToken().label.trim() === token) {
      slot = s;
      break;
    }
  }
  if (!slot) {
    mod.finalize();
    throw new Error(`PKCS#11 token "${token}" not found in ${lib}`);
  }
  const session = slot.open(g.SessionFlag.SERIAL_SESSION | g.SessionFlag.RW_SESSION);
  session.login(pin, g.UserType.USER);
  const entry = { mod, session };
  sessions.set(id, entry);
  return entry;
}

/** First object of a search, or null (graphene's items(0) returns a stub for an empty result). */
function firstOf(collection) {
  return collection.length > 0 ? collection.items(0) : null;
}

/** EC point (DER OCTET STRING around 04||x||y) to a P-256 public JWK. */
function pointToJwk(ecPoint) {
  let p = Buffer.from(ecPoint);
  if (p[0] === 0x04 && p.length === 67 && p[1] === 0x41) p = p.subarray(2); // DER-wrapped
  if (p[0] !== 0x04 || p.length !== 65) throw new Error("Unexpected EC point encoding from token");
  return { kty: "EC", crv: "P-256", x: p.subarray(1, 33).toString("base64url"), y: p.subarray(33, 65).toString("base64url") };
}

function thumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return crypto.createHash("sha256").update(canonical).digest("base64url");
}

/**
 * Loads (or generates inside the token) the signing key labelled zta-<name>.
 * @param {string} name - "verifier" | "idp" | "audit"
 * @param {{ lib: string, token: string, pin: string }} opts
 * @returns {Promise<{ hsm: true, kid: string, publicJwk: Object, sign: (data: Buffer) => Buffer }>}
 */
export async function loadOrCreateHsmKey(name, opts) {
  const g = await loadGraphene();
  const { session } = await openSession(opts);
  const label = `zta-${name}`;

  const findKeys = () => ({
    priv: firstOf(session.find({ class: g.ObjectClass.PRIVATE_KEY, label })),
    pub: firstOf(session.find({ class: g.ObjectClass.PUBLIC_KEY, label })),
  });
  let { priv, pub } = findKeys();
  if (!priv || !pub) {
    session.generateKeyPair(
      g.KeyGenMechanism.EC,
      { keyType: g.KeyType.EC, token: true, verify: true, label, paramsEC: g.NamedCurve.getByName("secp256r1").value },
      { keyType: g.KeyType.EC, token: true, sign: true, sensitive: true, extractable: false, private: true, label }
    );
    ({ priv, pub } = findKeys()); // handles from find() are what later attribute reads expect
  }

  const publicJwk = pointToJwk(pub.getAttribute({ pointEC: null }).pointEC);
  const kid = thumbprint(publicJwk);
  Object.assign(publicJwk, { kid, alg: "ES256", use: "sig" });

  return {
    hsm: true,
    kid,
    publicJwk,
    /** ES256 over data: the token signs SHA-256(data) with CKM_ECDSA (raw r||s). */
    sign(data) {
      const digest = crypto.createHash("sha256").update(data).digest();
      return Buffer.from(session.createSign("ECDSA", priv).once(digest));
    },
  };
}

/**
 * Security-relevant attributes of the private key zta-<name> (for tests and the artifact).
 * @returns {Promise<{ extractable: boolean, sensitive: boolean, valueReadable: boolean }>}
 */
export async function describeHsmKey(name, opts) {
  const g = await loadGraphene();
  const { session } = await openSession(opts);
  const priv = firstOf(session.find({ class: g.ObjectClass.PRIVATE_KEY, label: `zta-${name}` }));
  if (!priv) throw new Error(`No key zta-${name} in the token`);
  const { extractable, sensitive } = priv.getAttribute({ extractable: null, sensitive: null });
  let valueReadable = true;
  try {
    priv.getAttribute({ value: null });
  } catch {
    valueReadable = false;
  }
  return { extractable, sensitive, valueReadable };
}

/** Logs out and finalises every open PKCS#11 module (tests, shutdown). */
export function closeHsmSessions() {
  for (const { mod, session } of sessions.values()) {
    try {
      session.logout();
      session.close();
    } catch {}
    try {
      mod.finalize();
    } catch {}
  }
  sessions.clear();
}
