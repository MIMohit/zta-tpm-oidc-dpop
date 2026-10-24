/**
 * @file lib/idp/client-ip.js
 * Client IP used as risk input at login.
 */

/**
 * Extracts client IP respecting ZTA_SIM_IP_HEADER if enabled.
 *
 * @param {import('express').Request} req
 * @param {Record<string, any>} cfg
 * @returns {string}
 */
export function getClientIp(req, cfg) {
  if (cfg.simIpHeader && req.headers?.["x-zta-sim-ip"]) {
    return req.headers["x-zta-sim-ip"];
  }
  return req.socket?.remoteAddress || req.ip || "127.0.0.1";
}
