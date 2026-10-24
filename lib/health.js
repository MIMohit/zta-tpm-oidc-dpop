/**
 * @file lib/health.js
 * GET /health contract shared by every service (VERIFY4 M5):
 * 200 JSON { service, ablation: state() }, so a live run can confirm the remote switchboard.
 */

import { state } from "./ablation.js";

/**
 * Mounts GET /health on an express app.
 * @param {import('express').Express} app
 * @param {string} service
 */
export function mountHealth(app, service) {
  app.get("/health", (req, res) => {
    res.json({ service, ablation: state() });
  });
}

export default { mountHealth };
