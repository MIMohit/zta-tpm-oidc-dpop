import express from "express";
import { loadConfig } from "./lib/config.js";
import { isMain } from "./lib/main.js";

/**
 * Creates the retired Decision Controller Express application.
 * Returns HTTP 410 Gone for all routes directing clients to the single PEP.
 *
 * @param {Record<string, any>} [cfg]
 * @returns {import('express').Express}
 */
export function createApp(cfg = loadConfig()) {
  const app = express();
  const pepUrl = (cfg.pepPublicUrl || cfg.PEP_PUBLIC_URL || "http://localhost:4001").replace(/\/+$/, "");

  app.use((req, res) => {
    res.status(410).json({
      error: "decision_controller_retired",
      use: `${pepUrl}/api/company/audit`,
    });
  });

  return app;
}

if (isMain(import.meta.url)) {
  const cfg = loadConfig();
  const PORT = process.env.PORT || 4000;
  createApp(cfg).listen(PORT, () =>
    console.log(`🎯 Decision Controller retired; returning 410 on http://localhost:${PORT}`)
  );
}

export default { createApp };
