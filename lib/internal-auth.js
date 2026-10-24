import crypto from "node:crypto";
import { loadConfig } from "./config.js";

/**
 * Constant-time string equality check.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Express middleware requiring a valid X-ZTA-Internal header.
 * Can be called as requireInternal(cfg) returning middleware,
 * or directly as (req, res, next).
 *
 * @param {Record<string, any>|import('express').Request} cfgOrReq
 * @param {import('express').Response} [res]
 * @param {import('express').NextFunction} [next]
 */
export function requireInternal(cfgOrReq, res, next) {
  // If invoked as a middleware factory: requireInternal(cfg) -> (req, res, next)
  if (typeof res === "undefined" && typeof next === "undefined") {
    const cfg = cfgOrReq;
    return (req, r, n) => requireInternalHandler(req, r, n, cfg);
  }
  // Invoked directly as (req, res, next)
  return requireInternalHandler(cfgOrReq, res, next);
}

function requireInternalHandler(req, res, next, cfg) {
  const effectiveCfg = cfg?.ztaInternalToken ? cfg : loadConfig(cfg);
  const expectedToken =
    effectiveCfg?.ztaInternalToken ||
    effectiveCfg?.ZTA_INTERNAL_TOKEN ||
    process.env.ZTA_INTERNAL_TOKEN;

  const headerVal = req.headers["x-zta-internal"];
  if (!headerVal || !expectedToken || !safeEqual(headerVal, expectedToken)) {
    return res.status(401).json({
      error: "unauthorized",
      message: "Missing or invalid X-ZTA-Internal token",
    });
  }

  next();
}

/**
 * Global fetch wrapper injecting the X-ZTA-Internal header.
 *
 * @param {string|URL} url
 * @param {RequestInit} [opts={}]
 * @param {Record<string, any>} [cfg]
 * @returns {Promise<Response>}
 */
export async function internalFetch(url, opts = {}, cfg) {
  const effectiveCfg = cfg?.ztaInternalToken ? cfg : loadConfig(cfg);
  const token =
    effectiveCfg?.ztaInternalToken ||
    effectiveCfg?.ZTA_INTERNAL_TOKEN ||
    process.env.ZTA_INTERNAL_TOKEN;

  const headers = new Headers(opts.headers || {});
  if (token) {
    headers.set("X-ZTA-Internal", token);
  }

  return globalThis.fetch(url, {
    ...opts,
    headers,
  });
}

/**
 * Express middleware requiring a valid Authorization: Bearer $ADMIN_TOKEN.
 * Can be called as requireAdmin(cfg) returning middleware,
 * or directly as (req, res, next).
 *
 * @param {Record<string, any>|import('express').Request} cfgOrReq
 * @param {import('express').Response} [res]
 * @param {import('express').NextFunction} [next]
 */
export function requireAdmin(cfgOrReq, res, next) {
  if (typeof res === "undefined" && typeof next === "undefined") {
    const cfg = cfgOrReq;
    return (req, r, n) => requireAdminHandler(req, r, n, cfg);
  }
  return requireAdminHandler(cfgOrReq, res, next);
}

function requireAdminHandler(req, res, next, cfg) {
  const effectiveCfg = cfg?.adminToken ? cfg : loadConfig(cfg);
  const expectedToken =
    effectiveCfg?.adminToken ||
    effectiveCfg?.ADMIN_TOKEN ||
    process.env.ADMIN_TOKEN;

  const authHeader = req.headers["authorization"] || "";
  let token = "";
  if (authHeader.startsWith("Bearer ") || authHeader.startsWith("bearer ")) {
    token = authHeader.slice(7).trim();
  }

  if (!token || !expectedToken || !safeEqual(token, expectedToken)) {
    return res.status(401).json({
      error: "unauthorized",
      message: "Missing or invalid admin token",
    });
  }

  next();
}

export default {
  safeEqual,
  requireInternal,
  internalFetch,
  requireAdmin,
};
