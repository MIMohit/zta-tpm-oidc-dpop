import express from "express";
import { loadConfig } from "../lib/config.js";
import { createStore } from "../lib/store.js";
import { requireInternal } from "../lib/internal-auth.js";
import { isMain } from "../lib/main.js";
import { on, printBannerOnce } from "../lib/ablation.js";
import { mountHealth } from "../lib/health.js";
import { listen } from "../lib/tls.js";

const DEFAULT_AUDIT_DATA = {
  confidential_metrics: {
    revenue_growth: "+12.4%",
    active_vpn_tunnels: 42,
    security_incidents_resolved: 100,
  },
  system_status: "All systems nominal",
};

const DEFAULT_NEWS_DATA = {
  headline: "Quarterly Zero Trust Architecture Rollout",
  articles: [
    {
      id: 1,
      title: "Quarterly Security Update",
      summary: "Zero trust architecture migration progressing smoothly.",
      published_at: "2026-10-01",
    },
    {
      id: 2,
      title: "All-Hands Meeting Next Week",
      summary: "Company-wide all-hands meeting scheduled for Thursday.",
      published_at: "2026-10-01",
    },
  ],
};

/**
 * Ensures initial fixture data is seeded into the resource store.
 * @param {ReturnType<typeof import('../lib/store.js').createStore>} store
 */
async function ensureSeeded(store) {
  try {
    const existingAudit = await store.get("audit_reports/company");
    if (!existingAudit) {
      await store.set("audit_reports/company", DEFAULT_AUDIT_DATA);
    }
    const existingNews = await store.get("company/news");
    if (!existingNews) {
      await store.set("company/news", DEFAULT_NEWS_DATA);
    }
  } catch (err) {
    console.warn("⚠️ [resource-server] Could not check or seed fixtures:", err.message);
  }
}

/**
 * Creates the Protected Resource Server Express application.
 * Locked down to require internal authentication (X-ZTA-Internal) on all routes.
 *
 * @param {Record<string, any>} [cfg]
 * @returns {import('express').Express}
 */
export function createApp(cfg = loadConfig()) {
  const app = express();
  app.use(express.json());

  // Require internal service token on all routes
  if (on("M26")) {
    app.use(requireInternal(cfg));
  }
  mountHealth(app, "resource"); // behind requireInternal, like every resource route

  const store = cfg.storeInstance || createStore("resource", cfg);
  const seedPromise = ensureSeeded(store);

  app.get("/company/audit", async (req, res) => {
    try {
      await seedPromise;
      let audit = await store.get("audit_reports/company");
      if (!audit) {
        audit = await store.get("company/audit");
      }
      if (!audit) {
        audit = DEFAULT_AUDIT_DATA;
      }

      const generated_at = new Date(cfg.clock ? cfg.clock() : Date.now()).toISOString();
      res.json({
        data: audit,
        generated_at,
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch audit data" });
    }
  });

  app.get("/company/news", async (req, res) => {
    try {
      await seedPromise;
      let news = await store.get("company/news");
      if (!news) {
        news = await store.get("news");
      }
      if (!news) {
        news = DEFAULT_NEWS_DATA;
      }

      const generated_at = new Date(cfg.clock ? cfg.clock() : Date.now()).toISOString();
      res.json({
        data: news,
        generated_at,
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch news data" });
    }
  });

  return app;
}

if (isMain(import.meta.url)) {
  printBannerOnce("resource-server");
  const cfg = loadConfig();
  const PORT = process.env.PORT || 5001;
  const HOST = "127.0.0.1";
  listen(createApp(cfg), PORT, HOST, (url) => console.log(`📊 Resource Server running on ${url}`));
}

export default { createApp };
