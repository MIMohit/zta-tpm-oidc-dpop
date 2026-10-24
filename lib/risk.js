import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Load default fixtures/geo.json
let defaultGeo = {};
try {
  const geoPath = path.resolve(__dirname, "../fixtures/geo.json");
  if (fs.existsSync(geoPath)) {
    defaultGeo = JSON.parse(fs.readFileSync(geoPath, "utf8"));
  }
} catch {
  defaultGeo = {};
}

/**
 * Converts an IPv4 string to a 32-bit unsigned integer.
 * Handles loopback and IPv4-mapped IPv6.
 * @param {string} ip
 * @returns {number|null}
 */
export function ipToLong(ip) {
  if (!ip || typeof ip !== "string") return null;
  let cleanIp = ip.trim();
  if (cleanIp === "::1" || cleanIp === "localhost") {
    cleanIp = "127.0.0.1";
  }
  if (cleanIp.startsWith("::ffff:")) {
    cleanIp = cleanIp.slice(7);
  }
  const parts = cleanIp.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return null;
  }
  return (((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0);
}

/**
 * Checks if an IP address matches a CIDR prefix (e.g. "192.0.2.0/24").
 * @param {string} ip
 * @param {string} cidr
 * @returns {boolean}
 */
export function matchCidr(ip, cidr) {
  if (!cidr.includes("/")) {
    return ip === cidr;
  }
  const [prefix, bitsStr] = cidr.split("/");
  const bits = bitsStr !== undefined ? parseInt(bitsStr, 10) : 32;
  const ipLong = ipToLong(ip);
  const prefixLong = ipToLong(prefix);
  if (ipLong === null || prefixLong === null) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipLong & mask) === (prefixLong & mask);
}

/**
 * Resolves geolocation and ASN for an IP address against a geo database.
 * @param {string} ip
 * @param {Record<string, any>} [geoDb]
 * @returns {{asn: string|null, lat: number|null, lon: number|null, city: string}}
 */
export function geo(ip, geoDb = defaultGeo) {
  if (!ip) {
    return { asn: null, lat: null, lon: null, city: "Unknown" };
  }
  let cleanIp = ip.trim();
  if (cleanIp === "::1" || cleanIp === "localhost") {
    cleanIp = "127.0.0.1";
  }
  if (cleanIp.startsWith("::ffff:")) {
    cleanIp = cleanIp.slice(7);
  }

  // Exact match
  if (geoDb[cleanIp]) {
    return geoDb[cleanIp];
  }

  // Check CIDRs
  for (const [cidr, info] of Object.entries(geoDb)) {
    if (matchCidr(cleanIp, cidr)) {
      return info;
    }
  }

  return { asn: null, lat: null, lon: null, city: "Unknown" };
}

/**
 * Great-circle distance between two points in km (Haversine formula).
 * @param {number} lat1
 * @param {number} lon1
 * @param {number} lat2
 * @param {number} lon2
 * @returns {number} Distance in kilometers
 */
export function haversineDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // Earth radius in km
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) ** 2;

  return 2 * R * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

/**
 * Helper to convert timestamp (seconds or milliseconds) to milliseconds.
 * @param {number|string|Date} t
 * @returns {number}
 */
function toMs(t) {
  if (t instanceof Date) return t.getTime();
  if (typeof t === "string") {
    const parsed = Date.parse(t);
    if (!isNaN(parsed)) return parsed;
    t = Number(t);
  }
  if (typeof t === "number") {
    return t < 1e11 ? t * 1000 : t;
  }
  return Date.now();
}

/**
 * Pure function implementing Algorithm 4 (Contextual risk score).
 *
 * @param {object} params
 * @param {Array<object>} [params.history=[]] User login history
 * @param {object} [params.device] Device information (devId, attestation_age_s, last_good_attestation)
 * @param {object} [params.ctx={}] Current context (ip, t, user/sub, dev)
 * @param {object} [params.cfg] Config overrides
 * @returns {{rho: number, f: [number, number, number, number, number, number]}}
 */
export function risk({ history = [], device, ctx = {}, cfg } = {}) {
  const weights = cfg?.risk?.weights || [0.25, 0.25, 0.10, 0.15, 0.15, 0.10];
  const w1 = cfg?.risk?.w1 ?? weights[0] ?? 0.25;
  const w2 = cfg?.risk?.w2 ?? weights[1] ?? 0.25;
  const w3 = cfg?.risk?.w3 ?? weights[2] ?? 0.10;
  const w4 = cfg?.risk?.w4 ?? weights[3] ?? 0.15;
  const w5 = cfg?.risk?.w5 ?? weights[4] ?? 0.15;
  const w6 = cfg?.risk?.w6 ?? weights[5] ?? 0.10;

  const vMax = cfg?.risk?.vMax ?? 900;
  const fNormalizer = cfg?.risk?.fNormalizer ?? 5;
  const nDays = cfg?.risk?.nDays ?? 30;
  const tMax = cfg?.risk?.tMax ?? 600;

  const nowMs = ctx?.t !== undefined ? toMs(ctx.t) : (cfg?.clock ? cfg.clock() : Date.now());
  const d = ctx?.dev ?? ctx?.deviceId ?? device?.devId ?? device?.id;

  // --- f1: ASN not seen for u in the last Ndays ---
  const currentGeo = geo(ctx?.ip);
  const currentAsn = currentGeo?.asn;
  let f1 = 1;
  if (currentAsn) {
    const cutoffMs = nowMs - nDays * 24 * 60 * 60 * 1000;
    let asnSeen = false;
    for (const e of history) {
      const eTime = toMs(e.t);
      const isSuccess = (e.success === undefined || e.success === true) && !e.failed;
      if (isSuccess && eTime >= cutoffMs && eTime <= nowMs) {
        const eGeo = geo(e.ip);
        if (eGeo?.asn && eGeo.asn === currentAsn) {
          asnSeen = true;
          break;
        }
      }
    }
    f1 = asnSeen ? 0 : 1;
  }

  // --- f2: min(1, v / vmax) from the last successful login ---
  let lastLogin = null;
  for (const e of history) {
    const eTime = toMs(e.t);
    const isSuccess = (e.success === undefined || e.success === true) && !e.failed;
    if (isSuccess && eTime < nowMs) {
      if (!lastLogin || eTime > toMs(lastLogin.t)) {
        lastLogin = e;
      }
    }
  }

  let f2 = 0;
  if (lastLogin && ctx?.ip) {
    const lastTime = toMs(lastLogin.t);
    const dtMs = nowMs - lastTime;
    if (dtMs > 0) {
      const dtHours = dtMs / (1000 * 60 * 60);
      const gLast = geo(lastLogin.ip);
      const gCurr = geo(ctx.ip);
      if (
        gLast?.lat != null &&
        gLast?.lon != null &&
        gCurr?.lat != null &&
        gCurr?.lon != null
      ) {
        const distKm = haversineDistance(gLast.lat, gLast.lon, gCurr.lat, gCurr.lon);
        const v = distKm / dtHours;
        f2 = Math.min(1, Math.max(0, v / vMax));
      }
    }
  }

  // --- f3: hour(t) outside the 5th-95th percentile of u's login hours ---
  const successfulLogins = history.filter((e) => {
    const isSuccess = (e.success === undefined || e.success === true) && !e.failed;
    return isSuccess && toMs(e.t) <= nowMs;
  });

  let f3 = 0;
  if (successfulLogins.length >= 10) {
    const hours = successfulLogins
      .map((e) => {
        if (typeof e.hour === "number") return e.hour;
        return new Date(toMs(e.t)).getUTCHours();
      })
      .sort((a, b) => a - b);

    const getPercentile = (arr, p) => {
      const idx = (p / 100) * (arr.length - 1);
      const lower = Math.floor(idx);
      const upper = Math.ceil(idx);
      const weight = idx - lower;
      return arr[lower] * (1 - weight) + arr[upper] * weight;
    };

    const p5 = getPercentile(hours, 5);
    const p95 = getPercentile(hours, 95);
    const currentHour =
      typeof ctx?.hour === "number"
        ? ctx.hour
        : new Date(nowMs).getUTCHours();

    f3 = currentHour < p5 || currentHour > p95 ? 1 : 0;
  }

  // --- f4: min(1, ad / Tmax) with Tmax = 600 ---
  let ad = 600;
  if (typeof device?.attestation_age_s === "number") {
    ad = device.attestation_age_s;
  } else if (typeof device?.ad === "number") {
    ad = device.ad;
  } else if (device?.last_good_attestation !== undefined) {
    const lastGoodMs = toMs(device.last_good_attestation);
    ad = Math.max(0, Math.floor((nowMs - lastGoodMs) / 1000));
  }
  const f4 = Math.min(1, Math.max(0, ad / tMax));

  // --- f5: min(1, failures15min / F) ---
  const window15Min = 15 * 60 * 1000;
  const windowStart = nowMs - window15Min;
  let failures15min = 0;
  for (const e of history) {
    const eTime = toMs(e.t);
    const isFailed = e.success === false || e.failed === true;
    if (isFailed && eTime >= windowStart && eTime <= nowMs) {
      failures15min++;
    }
  }
  const f5 = Math.min(1, Math.max(0, failures15min / fNormalizer));

  // --- f6: first successful login of u on d ---
  let f6 = 1;
  if (d) {
    const priorLoginOnDevice = history.some((e) => {
      const isSuccess = (e.success === undefined || e.success === true) && !e.failed;
      const devMatch = e.dev === d || e.deviceId === d || e.device === d;
      return isSuccess && devMatch && toMs(e.t) < nowMs;
    });
    if (priorLoginOnDevice) {
      f6 = 0;
    }
  }

  const rawRho = w1 * f1 + w2 * f2 + w3 * f3 + w4 * f4 + w5 * f5 + w6 * f6;
  const rho = Math.min(1, Math.max(0, Math.round(rawRho * 1e9) / 1e9));

  return {
    rho,
    f: [f1, f2, f3, f4, f5, f6]
  };
}

export default { risk, geo, haversineDistance, matchCidr, ipToLong };
