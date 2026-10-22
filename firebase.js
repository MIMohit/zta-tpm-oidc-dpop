import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Always load .env from project root if present
dotenv.config({
  path: path.join(__dirname, ".env"),
  quiet: true,
});

let _cachedDb = null;
let _initAttempted = false;

/**
 * Returns Firebase Realtime Database instance if configured, or null if not configured.
 * Lazy and non-throwing.
 * @returns {Promise<any|null>}
 */
export async function getFirebaseDb() {
  if (_cachedDb) return _cachedDb;
  if (_initAttempted) return null;

  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY;
  const databaseURL = process.env.FIREBASE_DATABASE_URL;

  if (!projectId || !clientEmail || !privateKey || !databaseURL) {
    _initAttempted = true;
    return null;
  }

  try {
    const adminModule = await import("firebase-admin");
    const admin = adminModule.default || adminModule;

    if (!admin.apps || admin.apps.length === 0) {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId,
          clientEmail,
          privateKey: privateKey.replace(/\\n/g, "\n"),
        }),
        databaseURL,
      });
    }

    _cachedDb = admin.database();
    return _cachedDb;
  } catch (err) {
    console.warn("⚠️ [firebase] Failed to initialize Firebase:", err.message);
    _initAttempted = true;
    return null;
  }
}

/**
 * Compatibility proxy export for `db`.
 * Does not throw at import time, but throws a clear error if legacy code attempts to use it.
 */
export const db = new Proxy(
  {},
  {
    get(target, prop) {
      throw new Error(
        `Firebase 'db.${String(prop)}' was accessed, but Firebase is not configured or deprecated. Migrate to lib/store.js or configure FIREBASE_* environment variables.`
      );
    },
    apply() {
      throw new Error("Firebase 'db' is deprecated. Migrate to lib/store.js.");
    },
  }
);

export default {
  getFirebaseDb,
  db,
};
