/**
 * @file lib/idp/directory.js
 * Local user directory for IdP authentication (IDP_MODE=local).
 * Uses PBKDF2 password hashes via mfa-crypto.js.
 * Store namespace: idp
 * Path: users/<u> = { pwdHash, role }
 */

import { hashAnswer, verifyAnswer } from "../../mfa-crypto.js";

// Pre-computed default hashes for quick fallback and zero-configuration dev/test runs
const DEFAULT_USERS = {
  alice: {
    pwdHash: hashAnswer("alice-pass"),
    role: "auditor",
  },
  bob: {
    pwdHash: hashAnswer("bob-pass"),
    role: "employee",
  },
};

/**
 * Retrieves a user record from the store (or fallback defaults).
 * @param {string} username
 * @param {Object} [store] - idp store instance
 * @returns {Promise<{ u: string, pwdHash: string, role: string }|null>}
 */
export async function getUser(username, store) {
  if (!username || typeof username !== "string") return null;
  const u = username.trim().toLowerCase();

  if (store && typeof store.get === "function") {
    const fromStore = await store.get(`users/${u}`);
    if (fromStore) {
      return { u, ...fromStore };
    }
  }

  if (DEFAULT_USERS[u]) {
    return { u, ...DEFAULT_USERS[u] };
  }

  return null;
}

/**
 * Sets or updates a user record in the store.
 * @param {string} username
 * @param {{ pwdHash?: string, password?: string, role: string }} data
 * @param {Object} store - idp store instance
 * @returns {Promise<{ u: string, pwdHash: string, role: string }>}
 */
export async function setUser(username, data, store) {
  if (!username) throw new Error("username is required");
  const u = username.trim().toLowerCase();

  let pwdHash = data.pwdHash;
  if (!pwdHash && data.password) {
    pwdHash = hashAnswer(data.password);
  }
  if (!pwdHash) {
    throw new Error("pwdHash or password is required");
  }

  const record = {
    pwdHash,
    role: data.role || "employee",
  };

  if (store && typeof store.set === "function") {
    await store.set(`users/${u}`, record);
  }

  return { u, ...record };
}

/**
 * Verifies a user's password using constant-time PBKDF2 comparison.
 * @param {string} username
 * @param {string} password
 * @param {Object} [store] - idp store instance
 * @returns {Promise<boolean>}
 */
export async function verifyPassword(username, password, store) {
  if (!username || !password) return false;
  const user = await getUser(username, store);
  if (!user || !user.pwdHash) return false;

  try {
    return verifyAnswer(password, user.pwdHash);
  } catch (err) {
    console.error("Password verification error:", err);
    return false;
  }
}

/**
 * Returns the role for a user (e.g. 'auditor', 'employee').
 * Defaults to 'employee' if user exists but has no role, or null if user not found.
 * @param {string} username
 * @param {Object} [store] - idp store instance
 * @returns {Promise<string|null>}
 */
export async function roleOf(username, store) {
  const user = await getUser(username, store);
  return user?.role || null;
}

export default {
  getUser,
  setUser,
  verifyPassword,
  roleOf,
};
