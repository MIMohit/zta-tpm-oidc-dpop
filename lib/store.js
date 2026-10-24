import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { loadConfig } from "./config.js";

/**
 * Splits path into cleaned segments.
 * @param {string|string[]} p
 * @returns {string[]}
 */
function parsePath(p) {
  if (!p) return [];
  if (Array.isArray(p)) return p;
  return String(p).split("/").filter(Boolean);
}

/**
 * Retrieves nested value by path segments from an object.
 */
function getByPath(root, parts) {
  if (parts.length === 0) return root;
  let curr = root;
  for (const part of parts) {
    if (curr == null || typeof curr !== "object") return undefined;
    curr = curr[part];
  }
  return curr;
}

/**
 * Sets nested value by path segments into an object.
 */
function setByPath(root, parts, val) {
  if (parts.length === 0) {
    if (val && typeof val === "object" && !Array.isArray(val)) {
      for (const k of Object.keys(root)) delete root[k];
      Object.assign(root, val);
    }
    return root;
  }
  let curr = root;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (curr[part] == null || typeof curr[part] !== "object") {
      curr[part] = {};
    }
    curr = curr[part];
  }
  curr[parts[parts.length - 1]] = val;
  return root;
}

/**
 * Updates nested object by path segments.
 */
function updateByPath(root, parts, obj) {
  if (parts.length === 0) {
    Object.assign(root, obj);
    return root;
  }
  let curr = root;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (curr[part] == null || typeof curr[part] !== "object") {
      curr[part] = {};
    }
    curr = curr[part];
  }
  const last = parts[parts.length - 1];
  if (curr[last] == null || typeof curr[last] !== "object") {
    curr[last] = {};
  }
  Object.assign(curr[last], obj);
  return root;
}

/**
 * Deletes key by path segments from an object.
 */
function delByPath(root, parts) {
  if (parts.length === 0) {
    for (const k of Object.keys(root)) delete root[k];
    return true;
  }
  let curr = root;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (curr == null || typeof curr !== "object") return false;
    curr = curr[part];
  }
  if (curr && typeof curr === "object") {
    delete curr[parts[parts.length - 1]];
    return true;
  }
  return false;
}

/**
 * Formats a node's children as a list of items.
 */
function formatList(node) {
  if (node == null || typeof node !== "object") return [];
  const result = [];
  for (const [k, v] of Object.entries(node)) {
    if (v != null && typeof v === "object" && !Array.isArray(v)) {
      const item = { ...v };
      if (item.key === undefined) item.key = k;
      if (item.id === undefined) item.id = k;
      Object.defineProperty(item, "value", { value: v, enumerable: false, writable: true });
      item[Symbol.iterator] = function* () {
        yield k;
        yield v;
      };
      result.push(item);
    } else {
      const item = {
        key: k,
        id: k,
        value: v,
        [Symbol.iterator]: function* () {
          yield k;
          yield v;
        },
      };
      result.push(item);
    }
  }
  return result;
}

// In-memory store registry for namespace reuse across the process
const memoryStores = new Map();

/**
 * Creates an in-memory store.
 * @param {string} ns
 */
function createMemoryStore(ns) {
  if (!memoryStores.has(ns)) {
    memoryStores.set(ns, {});
  }
  const data = memoryStores.get(ns);

  return {
    async get(pathStr) {
      const parts = parsePath(pathStr);
      return getByPath(data, parts);
    },
    async set(pathStr, v) {
      const parts = parsePath(pathStr);
      setByPath(data, parts, v);
      return v;
    },
    async update(pathStr, obj) {
      const parts = parsePath(pathStr);
      updateByPath(data, parts, obj);
      return getByPath(data, parts);
    },
    async del(pathStr) {
      const parts = parsePath(pathStr);
      return delByPath(data, parts);
    },
    async list(prefix) {
      const parts = parsePath(prefix);
      const node = getByPath(data, parts);
      return formatList(node);
    },
  };
}

/**
 * Creates a file-backed store with in-memory cache and atomic tmp+rename writes.
 * @param {string} ns
 * @param {Record<string, any>} cfg
 */
function createFileStore(ns, cfg) {
  const dataDir = path.resolve(cfg?.dataDir || cfg?.ZTA_DATA_DIR || "./data");
  fs.mkdirSync(dataDir, { recursive: true });
  const filePath = path.join(dataDir, `${ns}.json`);

  let cache = {};
  if (fs.existsSync(filePath)) {
    try {
      cache = JSON.parse(fs.readFileSync(filePath, "utf8"));
    } catch (err) {
      console.warn(`⚠️ [store:${ns}] Failed to parse ${filePath}, initializing empty store:`, err.message);
      cache = {};
    }
  }

  let writeQueue = Promise.resolve();
  function flush() {
    writeQueue = writeQueue.then(async () => {
      const tmpPath = `${filePath}.${Date.now()}.${Math.random().toString(36).slice(2)}.tmp`;
      const serialized = JSON.stringify(cache, null, 2);
      await fs.promises.writeFile(tmpPath, serialized, "utf8");
      await fs.promises.rename(tmpPath, filePath);
    });
    return writeQueue;
  }

  return {
    async get(pathStr) {
      const parts = parsePath(pathStr);
      return getByPath(cache, parts);
    },
    async set(pathStr, v) {
      const parts = parsePath(pathStr);
      setByPath(cache, parts, v);
      await flush();
      return v;
    },
    async update(pathStr, obj) {
      const parts = parsePath(pathStr);
      updateByPath(cache, parts, obj);
      await flush();
      return getByPath(cache, parts);
    },
    async del(pathStr) {
      const parts = parsePath(pathStr);
      const res = delByPath(cache, parts);
      await flush();
      return res;
    },
    async list(prefix) {
      const parts = parsePath(prefix);
      const node = getByPath(cache, parts);
      return formatList(node);
    },
  };
}

/**
 * Creates a Firebase Realtime Database-backed store.
 * @param {string} ns
 * @param {Record<string, any>} cfg
 */
function createFirebaseStore(ns, cfg) {
  let dbPromise = null;

  async function getDb() {
    if (!dbPromise) {
      dbPromise = (async () => {
        const adminModule = await import("firebase-admin");
        const admin = adminModule.default || adminModule;
        if (!admin.apps.length) {
          admin.initializeApp({
            credential: admin.credential.cert({
              projectId: process.env.FIREBASE_PROJECT_ID,
              clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
              privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
            }),
            databaseURL: process.env.FIREBASE_DATABASE_URL,
          });
        }
        return admin.database();
      })();
    }
    return dbPromise;
  }

  async function getRef(pathStr) {
    const db = await getDb();
    const parts = parsePath(pathStr);
    const subPath = parts.join("/");
    return subPath ? db.ref(`${ns}/${subPath}`) : db.ref(ns);
  }

  return {
    async get(pathStr) {
      const ref = await getRef(pathStr);
      const snap = await ref.once("value");
      return snap.exists() ? snap.val() : undefined;
    },
    async set(pathStr, v) {
      const ref = await getRef(pathStr);
      await ref.set(v);
      return v;
    },
    async update(pathStr, obj) {
      const ref = await getRef(pathStr);
      await ref.update(obj);
      const snap = await ref.once("value");
      return snap.val();
    },
    async del(pathStr) {
      const ref = await getRef(pathStr);
      await ref.remove();
      return true;
    },
    async list(prefix) {
      const ref = await getRef(prefix);
      const snap = await ref.once("value");
      return formatList(snap.exists() ? snap.val() : null);
    },
  };
}

/**
 * Factory creating a namespace store.
 * @param {string} ns - Store namespace (e.g. 'verifier', 'idp', 'pip', 'resource')
 * @param {Record<string, any>} [cfg] - Configuration overrides
 * @returns {{ get: Function, set: Function, update: Function, del: Function, list: Function }}
 */
export function createStore(ns, cfg) {
  const effectiveCfg = cfg?.store ? cfg : loadConfig(cfg);
  const backend = (effectiveCfg.store || effectiveCfg.STORE || "file").toLowerCase();

  if (backend === "memory") {
    return createMemoryStore(ns);
  }

  if (backend === "firebase") {
    const hasCreds =
      process.env.FIREBASE_PROJECT_ID &&
      process.env.FIREBASE_CLIENT_EMAIL &&
      process.env.FIREBASE_PRIVATE_KEY &&
      process.env.FIREBASE_DATABASE_URL;

    if (hasCreds) {
      return createFirebaseStore(ns, effectiveCfg);
    }
    console.warn("⚠️ STORE=firebase requested but FIREBASE_* env vars not fully configured; falling back to file store");
  }

  return createFileStore(ns, effectiveCfg);
}

export default { createStore };
