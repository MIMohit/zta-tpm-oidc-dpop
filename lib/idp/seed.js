/**
 * @file lib/idp/seed.js
 * Seed step for IdP directory.
 * Seeds alice (alice-pass, auditor) and bob (bob-pass, employee).
 * Store namespace: idp
 */

import { loadConfig } from "../config.js";
import { createStore } from "../store.js";
import { setUser } from "./directory.js";

/**
 * Seeds the IdP user directory.
 *
 * @param {Record<string, any>} [cfg]
 * @returns {Promise<Record<string, { username: string, role: string }>>}
 */
export async function seed(cfg = {}) {
  const effectiveCfg = cfg?.dataDir ? cfg : loadConfig(cfg);
  const store = effectiveCfg.storeInstance || createStore("idp", effectiveCfg);

  console.log("👤 [seed-idp] Seeding IdP user accounts...");

  const alice = await setUser("alice", { password: "alice-pass", role: "auditor" }, store);
  const bob = await setUser("bob", { password: "bob-pass", role: "employee" }, store);

  console.log("├─ User: alice (role: auditor, password: alice-pass)");
  console.log("└─ User: bob   (role: employee, password: bob-pass)");
  console.log("✅ [seed-idp] Dev IdP users initialized successfully.");

  return {
    alice: { username: "alice", role: alice.role },
    bob: { username: "bob", role: bob.role },
  };
}

export default seed;
