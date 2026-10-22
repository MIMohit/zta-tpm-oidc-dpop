import fs from "node:fs";
import path from "node:path";
import * as jose from "jose";
import { loadConfig } from "./config.js";

// In-memory key store when STORE=memory
const memoryKeys = new Map();

/**
 * Loads an existing ES256 signing key from disk/memory or generates a new one.
 * Persists to $ZTA_DATA_DIR/keys/<name>.jwk with mode 0600 (or keeps in memory when STORE=memory).
 *
 * @param {string} name - Name of the key (e.g. 'verifier', 'idp', 'audit')
 * @param {Record<string, any>} [cfg] - Configuration overrides
 * @returns {Promise<{ privateKey: any, publicJwk: Record<string, any>, kid: string }>}
 */
export async function loadOrCreateSigningKey(name, cfg) {
  const effectiveCfg = cfg?.store ? cfg : loadConfig(cfg);
  const backend = (effectiveCfg.store || effectiveCfg.STORE || "file").toLowerCase();

  if (backend === "memory") {
    if (memoryKeys.has(name)) {
      return memoryKeys.get(name);
    }
    const { privateKey, publicKey } = await jose.generateKeyPair("ES256", { extractable: true });
    const publicJwk = await jose.exportJWK(publicKey);
    const kid = await jose.calculateJwkThumbprint(publicJwk, "sha256");
    publicJwk.kid = kid;
    publicJwk.alg = "ES256";
    publicJwk.use = "sig";

    const keyObj = { privateKey, publicJwk, kid };
    memoryKeys.set(name, keyObj);
    return keyObj;
  }

  const dataDir = path.resolve(effectiveCfg.dataDir || effectiveCfg.ZTA_DATA_DIR || "./data");
  const keysDir = path.join(dataDir, "keys");
  fs.mkdirSync(keysDir, { recursive: true, mode: 0o700 });
  const keyPath = path.join(keysDir, `${name}.jwk`);

  if (fs.existsSync(keyPath)) {
    const raw = fs.readFileSync(keyPath, "utf8");
    const parsedJwk = JSON.parse(raw);
    const privateKey = await jose.importJWK(parsedJwk, "ES256");
    const { d, ...pub } = parsedJwk;
    const kid = parsedJwk.kid || (await jose.calculateJwkThumbprint(pub, "sha256"));
    pub.kid = kid;
    pub.alg = "ES256";
    pub.use = "sig";

    return {
      privateKey,
      publicJwk: pub,
      kid,
    };
  }

  // Generate new ES256 key pair
  const { privateKey, publicKey } = await jose.generateKeyPair("ES256", { extractable: true });
  const privateJwk = await jose.exportJWK(privateKey);
  const publicJwk = await jose.exportJWK(publicKey);
  const kid = await jose.calculateJwkThumbprint(publicJwk, "sha256");

  privateJwk.kid = kid;
  privateJwk.alg = "ES256";
  privateJwk.use = "sig";

  publicJwk.kid = kid;
  publicJwk.alg = "ES256";
  publicJwk.use = "sig";

  fs.writeFileSync(keyPath, JSON.stringify(privateJwk, null, 2), {
    encoding: "utf8",
    mode: 0o600,
  });
  // Ensure strict permissions
  try {
    fs.chmodSync(keyPath, 0o600);
  } catch {
    // Ignore chmod errors on systems that don't support POSIX modes
  }

  return {
    privateKey,
    publicJwk,
    kid,
  };
}

/**
 * Builds a JWKS object from one or more keys or public JWKs.
 * @param {...(Record<string, any>|{ publicJwk: Record<string, any> })} keys
 * @returns {{ keys: Record<string, any>[] }}
 */
export function publicJwks(...keys) {
  const result = [];
  for (const k of keys) {
    if (!k) continue;
    if (k.publicJwk) {
      result.push(k.publicJwk);
    } else if (k.kty) {
      result.push(k);
    } else if (Array.isArray(k)) {
      for (const item of k) {
        if (!item) continue;
        result.push(item.publicJwk || item);
      }
    }
  }
  return { keys: result };
}

export default {
  loadOrCreateSigningKey,
  publicJwks,
};
