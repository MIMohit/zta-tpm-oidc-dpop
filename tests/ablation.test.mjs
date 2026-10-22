import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  MECHANISMS,
  MECHANISM_MAP,
  HYGIENE,
  BASELINES,
  parseConfigLabel,
  allConfigs,
  configureAblation,
  configureFromEnv,
  on,
  state,
  resetAblation,
  withAblation,
  banner,
  printBannerOnce,
  runManifest,
  writeRunManifest,
} from "../lib/ablation.js";

describe("WP-C1: Ablation Switchboard Core", () => {
  beforeEach(() => {
    delete process.env.ZTA_ENV;
    delete process.env.NODE_ENV;
    delete process.env.ZTA_ABLATE;
    delete process.env.ZTA_BASELINE;
    delete process.env.ZTA_ABLATE_CNF;
    delete process.env.ZTA_ABLATE_NONCE;
    resetAblation();
  });

  it("registry has exactly 26 mechanisms with expected schema", () => {
    assert.equal(MECHANISMS.length, 26);
    assert.equal(MECHANISM_MAP.size, 26);
    for (let i = 1; i <= 26; i++) {
      const id = `M${i}`;
      assert.ok(MECHANISM_MAP.has(id), `Missing mechanism ${id}`);
      const m = MECHANISM_MAP.get(id);
      assert.equal(m.id, id);
      assert.ok(typeof m.layer === "string" && m.layer.length > 0);
      assert.ok(typeof m.title === "string" && m.title.length > 0);
      assert.ok(Array.isArray(m.modules) && m.modules.length > 0);
      assert.ok(Array.isArray(m.attacks) && m.attacks.length > 0);
    }
  });

  it("allConfigs() returns exactly 31 configurations", () => {
    const configs = allConfigs();
    assert.equal(configs.length, 31);
    assert.equal(configs[0], "full");
    for (let i = 1; i <= 26; i++) {
      assert.equal(configs[i], `-M${i}`);
    }
    assert.deepEqual(configs.slice(27), ["B0", "B1", "B2", "B3"]);
  });

  it("hygiene mechanisms are present in all baselines", () => {
    assert.deepEqual(HYGIENE, ["M11", "M14", "M20", "M24", "M25", "M26"]);
    for (const [bKey, baseDef] of Object.entries(BASELINES)) {
      for (const hId of HYGIENE) {
        assert.ok(
          !baseDef.off.includes(hId),
          `Hygiene mechanism ${hId} should NOT be off in baseline ${bKey}`
        );
      }
    }
  });

  it("parseConfigLabel correctly parses full, baselines, and individual mechanisms", () => {
    assert.deepEqual(parseConfigLabel("full"), { off: [], baseline: null });
    assert.deepEqual(parseConfigLabel(""), { off: [], baseline: null });
    assert.deepEqual(parseConfigLabel(null), { off: [], baseline: null });

    const b0 = parseConfigLabel("B0");
    assert.equal(b0.baseline, "B0");
    assert.ok(b0.off.includes("M1"));
    assert.ok(!b0.off.includes("M11"));

    const b3 = parseConfigLabel("B3");
    assert.equal(b3.baseline, "B3");
    assert.deepEqual(b3.off, ["M21"]);

    const single = parseConfigLabel("-M7");
    assert.deepEqual(single, { off: ["M7"], baseline: null });

    const multiple = parseConfigLabel("-M16,-M7");
    assert.deepEqual(multiple, { off: ["M7", "M16"], baseline: null });

    const withoutHyphen = parseConfigLabel("M7, M3");
    assert.deepEqual(withoutHyphen, { off: ["M3", "M7"], baseline: null });
  });

  it("unknown mechanism ID throws in on() and parseConfigLabel()", () => {
    assert.throws(() => on("M99"), /Unknown mechanism id/);
    assert.throws(() => on("XYZ"), /Unknown mechanism id/);
    assert.throws(() => parseConfigLabel("-M99"), /Unknown mechanism id/);
    assert.throws(() => configureAblation({ off: ["M0"] }), /Unknown mechanism id/);
    assert.throws(() => configureAblation({ baseline: "B99" }), /Unknown baseline/);
  });

  it("configureFromEnv parses ZTA_ABLATE, ZTA_BASELINE and legacy aliases", () => {
    configureFromEnv({ ZTA_ABLATE: "-M7" });
    assert.deepEqual(state().off, ["M7"]);
    assert.equal(on("M7"), false);
    assert.equal(on("M6"), true);

    resetAblation();
    configureFromEnv({ ZTA_BASELINE: "B3" });
    assert.equal(state().label, "B3");
    assert.equal(on("M21"), false);
    assert.equal(on("M16"), true);

    resetAblation();
    configureFromEnv({ ZTA_ABLATE_CNF: "1", ZTA_ABLATE_NONCE: "true" });
    assert.deepEqual(state().off, ["M16", "M17"]);
    assert.equal(on("M16"), false);
    assert.equal(on("M17"), false);
    assert.equal(on("M7"), true);
  });

  it("refuses ablation in production when any mechanism is disabled", () => {
    process.env.ZTA_ENV = "production";
    // Full design in production is allowed
    assert.doesNotThrow(() => configureAblation({ off: [] }));
    assert.equal(state().label, "full");

    // Any ablated mechanism must throw
    assert.throws(() => configureAblation({ off: ["M7"] }), /forbidden in production/);
    assert.throws(() => configureAblation({ baseline: "B0" }), /forbidden in production/);
  });

  it("state() provides correct label, off, on, and deterministic sha256 hash", () => {
    resetAblation();
    const fullSt = state();
    assert.equal(fullSt.label, "full");
    assert.equal(fullSt.off.length, 0);
    assert.equal(fullSt.on.length, 26);
    assert.ok(typeof fullSt.hash === "string" && fullSt.hash.length === 64);

    configureAblation({ off: ["M7", "M16"] });
    const ablateSt = state();
    assert.equal(ablateSt.label, "-M7,-M16");
    assert.deepEqual(ablateSt.off, ["M7", "M16"]);
    assert.equal(ablateSt.on.length, 24);
    assert.ok(!ablateSt.on.includes("M7"));
    assert.ok(!ablateSt.on.includes("M16"));
    assert.ok(typeof ablateSt.hash === "string" && ablateSt.hash.length === 64);
  });

  it("withAblation runs callback with specified config and always resets", async () => {
    assert.equal(state().label, "full");
    assert.equal(on("M7"), true);

    await withAblation("-M7", async () => {
      assert.equal(on("M7"), false);
      assert.equal(state().label, "-M7");
    });

    assert.equal(state().label, "full");
    assert.equal(on("M7"), true);

    // Verify reset even if callback throws
    await assert.rejects(
      withAblation("-M16", async () => {
        assert.equal(on("M16"), false);
        throw new Error("simulated test error");
      }),
      /simulated test error/
    );

    assert.equal(state().label, "full");
    assert.equal(on("M16"), true);
  });

  it("banner text matches full and ablated formats", () => {
    resetAblation();
    const fullBanner = banner();
    assert.ok(fullBanner.includes("ablation: full design (26/26 mechanisms)"));

    configureAblation({ off: ["M7"] });
    const ablateBanner = banner();
    assert.ok(ablateBanner.includes("⚠️ ABLATION ACTIVE [-M7]: off = M7"));
    assert.ok(ablateBanner.includes("Boot-state appraisal"));

    // Check service-prefixed banner
    const pepBanner = banner("pep");
    assert.ok(pepBanner.startsWith("[pep]"));

    // printBannerOnce does not throw
    assert.doesNotThrow(() => printBannerOnce("test-service"));
    assert.doesNotThrow(() => printBannerOnce("test-service"));
  });

  it("runManifest and writeRunManifest produce valid zta-run-manifest/1 structures", () => {
    configureAblation({ off: ["M16"] });
    const manifest = runManifest({ testRun: true });
    assert.equal(manifest.schema, "zta-run-manifest/1");
    assert.ok(manifest.runId);
    assert.ok(manifest.startedAt);
    assert.equal(manifest.label, "-M16");
    assert.deepEqual(manifest.off, ["M16"]);
    assert.ok(Array.isArray(manifest.on));
    assert.ok(manifest.hash);
    assert.ok(manifest.git);
    assert.equal(typeof manifest.git.commit, "string");
    assert.equal(typeof manifest.git.dirty, "boolean");
    assert.equal(manifest.node, process.version);
    assert.equal(manifest.platform, process.platform);
    assert.equal(manifest.arch, process.arch);
    assert.equal(typeof manifest.cpus, "number");
    assert.ok(manifest.env);
    assert.equal(manifest.testRun, true);

    const tmpFile = path.join(os.tmpdir(), `manifest-${Date.now()}.json`);
    try {
      writeRunManifest(tmpFile, { fromTest: 123 });
      const read = JSON.parse(fs.readFileSync(tmpFile, "utf8"));
      assert.equal(read.schema, "zta-run-manifest/1");
      assert.equal(read.fromTest, 123);
    } finally {
      if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
    }
  });
});
