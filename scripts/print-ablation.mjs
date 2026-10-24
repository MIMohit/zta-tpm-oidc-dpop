#!/usr/bin/env node
import { configureFromEnv, configureAblation, parseConfigLabel, banner, runManifest } from "../lib/ablation.js";

const arg = process.argv[2];
if (arg) {
  const { off, baseline } = parseConfigLabel(arg);
  configureAblation({ off, baseline, source: "cli" });
} else {
  configureFromEnv();
}

console.log(banner());
console.log(JSON.stringify(runManifest(), null, 2));
