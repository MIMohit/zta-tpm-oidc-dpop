/**
 * Creates an in-memory JTI cache to detect and prevent DPoP proof replays.
 * Keyed by `${jkt}:${jti}` as required by RFC 9449 §4.3 and Table 5 (W_J = 120s).
 *
 * NOTE: This JTI cache is in-memory only. A production multi-instance PEP
 * deployment requires a shared, distributed cache (such as Redis or Memcached)
 * to detect replays across distributed instances.
 *
 * @param {object} [options={}]
 * @param {number} [options.windowMs=120000] - Cache retention window in milliseconds
 * @param {number} [options.wJti] - Table 5 window in seconds (overrides windowMs if provided)
 * @param {() => number} [options.clock] - Clock returning current epoch timestamp in ms
 * @returns {{ seen: (keyOrJkt: string, maybeJti?: string) => boolean, has: (keyOrJkt: string, maybeJti?: string) => boolean, add: (keyOrJkt: string, maybeJti?: string) => void, sweep: () => number, clear: () => void, size: () => number }}
 */
export function createJtiCache(options = {}) {
  const windowMs = Number(
    options.windowMs ?? (options.wJti !== undefined ? options.wJti * 1000 : 120000)
  );
  const clock = options.clock || (() => Date.now());

  // Map of key -> expirationTimestampMs
  const cache = new Map();

  function formatKey(keyOrJkt, maybeJti) {
    if (maybeJti !== undefined) {
      return `${keyOrJkt}:${maybeJti}`;
    }
    return String(keyOrJkt);
  }

  function sweep() {
    const now = clock();
    let purged = 0;
    for (const [key, expiresAt] of cache.entries()) {
      if (expiresAt <= now) {
        cache.delete(key);
        purged++;
      }
    }
    return purged;
  }

  return {
    /**
     * Checks if a key has been seen. If already seen and not expired, returns true.
     * Otherwise, adds the key with the retention window and returns false.
     *
     * @param {string} keyOrJkt - Either full "jkt:jti" or jkt
     * @param {string} [maybeJti] - Optional jti if first argument is jkt
     * @returns {boolean} true if seen (replay), false if first time seen (added)
     */
    seen(keyOrJkt, maybeJti) {
      if (!keyOrJkt) return false;
      const key = formatKey(keyOrJkt, maybeJti);
      const now = clock();
      sweep();

      const expiresAt = cache.get(key);
      if (expiresAt !== undefined && expiresAt > now) {
        return true;
      }

      cache.set(key, now + windowMs);
      return false;
    },

    /**
     * Checks if a key exists and has not expired, without adding it.
     * @param {string} keyOrJkt
     * @param {string} [maybeJti]
     * @returns {boolean}
     */
    has(keyOrJkt, maybeJti) {
      const key = formatKey(keyOrJkt, maybeJti);
      const now = clock();
      const expiresAt = cache.get(key);
      return expiresAt !== undefined && expiresAt > now;
    },

    /**
     * Explicitly records a key in the cache.
     * @param {string} keyOrJkt
     * @param {string} [maybeJti]
     */
    add(keyOrJkt, maybeJti) {
      const key = formatKey(keyOrJkt, maybeJti);
      const now = clock();
      cache.set(key, now + windowMs);
    },

    /**
     * Sweeps expired entries from the cache.
     * @returns {number} number of purged entries
     */
    sweep,

    /**
     * Clears all entries from the cache.
     */
    clear() {
      cache.clear();
    },

    /**
     * Returns the count of active (unexpired) entries.
     * @returns {number}
     */
    size() {
      sweep();
      return cache.size;
    },
  };
}

export default { createJtiCache };
