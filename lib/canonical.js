import crypto from "node:crypto";

/**
 * Deterministically stringifies a value with recursively sorted object keys.
 * Arrays retain element order, undefined object properties are omitted.
 * @param {*} val
 * @returns {string}
 */
export function canonicalJson(val) {
  if (val === null || typeof val !== "object") {
    return JSON.stringify(val);
  }
  if (Array.isArray(val)) {
    return "[" + val.map((item) => canonicalJson(item) ?? "null").join(",") + "]";
  }
  const keys = Object.keys(val).sort();
  const entries = [];
  for (const key of keys) {
    const v = val[key];
    if (v !== undefined && typeof v !== "function" && typeof v !== "symbol") {
      entries.push(JSON.stringify(key) + ":" + canonicalJson(v));
    }
  }
  return "{" + entries.join(",") + "}";
}

export const canonical = canonicalJson;

/**
 * Base64url encode and decode helpers.
 */
export const b64u = function (input) {
  return b64u.encode(input);
};

b64u.encode = function (input) {
  const buf = typeof input === "string" ? Buffer.from(input, "utf8") : Buffer.from(input);
  return buf.toString("base64url");
};

b64u.decode = function (str) {
  return Buffer.from(str, "base64url");
};

b64u.decodeString = function (str, encoding = "utf8") {
  return Buffer.from(str, "base64url").toString(encoding);
};

export const b64uEncode = b64u.encode;
export const b64uDecode = b64u.decode;

/**
 * Computes SHA-256 digest of input.
 * When encoding is passed ('hex', 'base64url', etc.), returns string.
 * When encoding is omitted, returns a Buffer with toJSON/toString defaulting to hex.
 * @param {string|Buffer|Uint8Array} data
 * @param {string} [encoding]
 * @returns {Buffer|string}
 */
export function sha256(data, encoding) {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
  const digest = crypto.createHash("sha256").update(buf).digest();
  if (encoding) {
    return digest.toString(encoding);
  }
  // Wrap digest buffer so toString() defaults to 'hex' and toJSON() serializes to hex string
  const wrapped = Buffer.from(digest);
  wrapped.toString = function (enc = "hex", start, end) {
    return Buffer.prototype.toString.call(this, enc, start, end);
  };
  wrapped.toJSON = function () {
    return this.toString("hex");
  };
  return wrapped;
}

export function sha256Hex(data) {
  return sha256(data, "hex");
}

export function sha256Buf(data) {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
  return crypto.createHash("sha256").update(buf).digest();
}

export function sha256B64u(data) {
  return sha256(data, "base64url");
}

export default {
  canonicalJson,
  canonical,
  b64u,
  b64uEncode,
  b64uDecode,
  sha256,
  sha256Hex,
  sha256Buf,
  sha256B64u,
};
