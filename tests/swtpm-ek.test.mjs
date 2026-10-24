/**
 * @file tests/swtpm-ek.test.mjs
 * Live gated end-to-end integration tests for swtpm transport, P-384 EK,
 * high-range NV indices, and TPM-side ActivateCredential (WP-B).
 *
 * Gated: automatically skipped if swtpm or swtpm_setup are not on PATH.
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { execSync, spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import net from "node:net";
import crypto from "node:crypto";

import { RealTpm } from "../lib/tpm-real/backend.js";
import { classifyEkTemplate } from "../lib/tpm2/ek-template.js";
import { startStack } from "./helpers/harness.js";
import { addToInventory } from "../lib/verifier/inventory.js";
import { devIdOf } from "../lib/sim-tpm/public-area.js";

function hasBinary(bin) {
  try {
    execSync(`which ${bin}`, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const canRunSwtpm = hasBinary("swtpm") && hasBinary("swtpm_setup");

async function getFreePort() {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

const suite = canRunSwtpm ? describe : describe.skip;

suite("WP-B: swtpm EK & ActivateCredential Live Integration", () => {
  let tmpDir;
  let localca1;
  let rootsDir;
  let dataPort1;
  let ctrlPort1;
  let proc1;
  let issuerPem1;

  let dataPort2;
  let ctrlPort2;
  let proc2;

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "swtpm-test-suite-"));
    const tpmstate1 = path.join(tmpDir, "state1");
    localca1 = path.join(tmpDir, "localca1");
    rootsDir = path.join(tmpDir, "roots");
    fs.mkdirSync(tpmstate1);
    fs.mkdirSync(localca1);
    fs.mkdirSync(rootsDir);

    const caConf1 = path.join(tmpDir, "swtpm-localca1.conf");
    fs.writeFileSync(
      caConf1,
      `statedir = ${localca1}
signingkey = ${localca1}/signkey.pem
issuercert = ${localca1}/issuercert.pem
certserial = ${localca1}/certserial
`
    );

    const caOpts1 = path.join(tmpDir, "swtpm-localca1.options");
    fs.writeFileSync(
      caOpts1,
      `--platform-manufacturer ZTA-Lab
--platform-version 2.1
--platform-model QEMU
`
    );

    const setupConf1 = path.join(tmpDir, "swtpm_setup1.conf");
    fs.writeFileSync(
      setupConf1,
      `create_certs_tool = swtpm_localca
create_certs_tool_config = ${caConf1}
create_certs_tool_options = ${caOpts1}
active_pcr_banks = sha256
`
    );

    execSync(
      `swtpm_setup --tpm2 --tpmstate ${tpmstate1} --create-ek-cert --create-platform-cert --pcr-banks sha256 --config ${setupConf1}`,
      { stdio: "ignore" }
    );

    // Copy root CA cert into isolated rootsDir for Verifier trust anchor
    fs.copyFileSync(
      path.join(localca1, "swtpm-localca-rootca-cert.pem"),
      path.join(rootsDir, "swtpm-localca-rootca-cert.pem")
    );
    issuerPem1 = fs.readFileSync(path.join(localca1, "issuercert.pem"), "utf8");

    // Spawn swtpm instance 1
    dataPort1 = await getFreePort();
    ctrlPort1 = await getFreePort();
    proc1 = spawn("swtpm", [
      "socket",
      "--tpm2",
      "--server",
      `type=tcp,port=${dataPort1}`,
      "--ctrl",
      `type=tcp,port=${ctrlPort1}`,
      "--flags",
      "not-need-init,startup-clear",
      "--tpmstate",
      `dir=${tpmstate1}`,
    ]);

    // Setup swtpm instance 2 (for A04 cross-TPM binding test)
    const tpmstate2 = path.join(tmpDir, "state2");
    fs.mkdirSync(tpmstate2);
    // Same lab CA as instance 1: the system default CA dir (/var/lib/swtpm-localca on Arch) is not user-writable
    execSync(
      `swtpm_setup --tpm2 --tpmstate ${tpmstate2} --create-ek-cert --pcr-banks sha256 --config ${setupConf1}`,
      { stdio: "ignore" }
    );

    dataPort2 = await getFreePort();
    ctrlPort2 = await getFreePort();
    proc2 = spawn("swtpm", [
      "socket",
      "--tpm2",
      "--server",
      `type=tcp,port=${dataPort2}`,
      "--ctrl",
      `type=tcp,port=${ctrlPort2}`,
      "--flags",
      "not-need-init,startup-clear",
      "--tpmstate",
      `dir=${tpmstate2}`,
    ]);

    // Give both daemon instances time to bind sockets
    await new Promise((r) => setTimeout(r, 500));
  });

  after(async () => {
    if (proc1) proc1.kill("SIGKILL");
    if (proc2) proc2.kill("SIGKILL");
    if (tmpDir) {
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch {}
    }
  });

  it("RealTpm({device:'swtpm', ekType:'ecc384'}): getEk() reads cert from NV 0x01C00016 and classifies as H-3", async () => {
    const tpm = new RealTpm({
      device: "swtpm",
      host: "127.0.0.1",
      port: dataPort1,
      ekType: "ecc384",
      ekCertChain: [issuerPem1],
    });
    await tpm.init();
    try {
      const ek = await tpm.getEk();
      assert.ok(ek.cert, "Must have read EK cert");
      assert.equal(ek.nvIndex, 0x01c00016, "Must have read certificate from NV index 0x01C00016");
      assert.equal(ek.publicArea.curve, "P-384");
      assert.equal(ek.publicArea.nameAlg, "sha384");

      const classified = classifyEkTemplate(ek.publicArea);
      assert.ok(classified, "Must classify EK template");
      assert.equal(classified.id, "H-3");
      assert.equal(classified.nameAlg, "sha384");
      assert.equal(classified.symKeyBits, 256);
      assert.equal(classified.curve, "P-384");
      assert.equal(classified.userWithAuth, true);
    } finally {
      await tpm.close();
    }
  });

  it("Full enrolment through startStack for alice with P-384 EK (exercises TPM-side ActivateCredential)", async () => {
    let aliceTpm;
    const stack = await startStack({
      ekRootsDir: rootsDir,
      initialTime: Date.now(),
      verifierGoldenTofu: true,
      tpmFactory: async ({ name, dir }) => {
        if (name === "alice-laptop") {
          aliceTpm = new RealTpm({
            device: "swtpm",
            host: "127.0.0.1",
            port: dataPort1,
            ekType: "ecc384",
            dir,
            ekCertChain: [issuerPem1],
          });
          await aliceTpm.init();
          return aliceTpm;
        }
        return null;
      },
    });

    try {
      const enrolRes = await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      assert.equal(enrolRes.enrolled, true);
      assert.equal(enrolRes.devId, stack.clients.alice.devId);
      assert.equal(enrolRes.jkt, stack.clients.alice.jkt);

      // Verify active in Verifier registry
      const regRes = await fetch(`${stack.urls.verifierUrl}/v/devices/${stack.clients.alice.devId}`, {
        headers: { "X-ZTA-Internal": stack.cfg.ztaInternalToken },
      });
      assert.equal(regRes.status, 200);
      const regData = await regRes.json();
      assert.equal(regData.status, "active");
      assert.equal(regData.user, "alice");
      // VERIFY4 L5: the EK was trusted through the X.509 chain, and the TCG SAN was recorded
      assert.equal(regData.ekTrust, "cert");
      assert.equal(typeof regData.san, "string", "registry record must carry the EK cert SAN");
      assert.match(regData.san, /tcg-at-tpmManufacturer=id:00001014/);
      assert.match(regData.san, /tcg-at-tpmModel=swtpm/);
    } finally {
      await stack.stop();
    }
  });

  it("Full enrolment through startStack with ekType:'rsa' (L-1 at 0x01C00002 on the same TPM)", async () => {
    let aliceTpmRsa;
    const stack = await startStack({
      ekRootsDir: rootsDir,
      initialTime: Date.now(),
      verifierGoldenTofu: true,
      tpmFactory: async ({ name, dir }) => {
        if (name === "alice-laptop") {
          aliceTpmRsa = new RealTpm({
            device: "swtpm",
            host: "127.0.0.1",
            port: dataPort1,
            ekType: "rsa",
            dir,
            ekCertChain: [issuerPem1],
          });
          await aliceTpmRsa.init();
          return aliceTpmRsa;
        }
        return null;
      },
    });

    try {
      const ek = await aliceTpmRsa.getEk();
      assert.equal(ek.nvIndex, 0x01c00002, "Must read RSA cert from NV 0x01C00002");
      const classified = classifyEkTemplate(ek.publicArea);
      assert.equal(classified.id, "L-1");

      const enrolRes = await stack.clients.alice.enrol(stack.codes["alice-laptop"]);
      assert.equal(enrolRes.enrolled, true);
      assert.equal(enrolRes.devId, stack.clients.alice.devId);
    } finally {
      await stack.stop();
    }
  });

  it("A04 shape negative: AK from a second swtpm with the first one's EK fails activation with secret_mismatch", async () => {
    const tpm1 = new RealTpm({
      device: "swtpm",
      host: "127.0.0.1",
      port: dataPort1,
      ekType: "ecc384",
      ekCertChain: [issuerPem1],
    });
    const tpm2 = new RealTpm({
      device: "swtpm",
      host: "127.0.0.1",
      port: dataPort2,
      ekType: "ecc384",
    });

    await tpm1.init();
    await tpm2.init();

    const stack = await startStack({
      ekRootsDir: rootsDir,
      initialTime: Date.now(),
      verifierGoldenTofu: true,
    });

    try {
      const ek1 = await tpm1.getEk();
      const devId1 = await devIdOf(ek1.publicArea);
      const inv = await addToInventory(stack.stores.verifier, {
        devId: devId1,
        user: "alice",
        clock: stack.clock,
      });
      const code = inv.code;
      const ak2 = await tpm2.createAk();
      const kb2 = await tpm2.createKb();

      // Start enrolment: present EK1 from instance 1, but AK2 & KB2 from instance 2
      const extras1 = await tpm1.getEnrolExtras();
      const startRes = await fetch(`${stack.urls.verifierUrl}/v/enrol/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code,
          ekCert: ek1.cert,
          akPublic: ak2.publicArea,
          kbPublic: kb2.publicArea,
          ...extras1,
        }),
      });
      const startBody = await startRes.json();
      assert.equal(startRes.status, 200);
      const { sessionId, blob, nonce } = startBody;

      // Instance 2 attempts to activate the credential encrypted for EK1
      let activatedSecret = null;
      try {
        activatedSecret = await tpm2.activateCredential(ak2.handle, blob);
      } catch (err) {
        // Expected hardware TPM failure because TPM2 lacks TPM1's private EK
        activatedSecret = crypto.randomBytes(32);
      }

      const quote = await tpm2.quote(ak2.handle, nonce);
      const certify = await tpm2.certify(kb2.handle, ak2.handle, nonce);

      // Finish enrolment with the failed/random secret
      const finishRes = await fetch(`${stack.urls.verifierUrl}/v/enrol/finish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sessionId,
          secret: activatedSecret.toString("hex"),
          quote,
          certify,
        }),
      });

      assert.equal(finishRes.status, 403);
      const finishBody = await finishRes.json();
      assert.equal(finishBody.error, "secret_mismatch");
    } finally {
      await tpm1.close();
      await tpm2.close();
      await stack.stop();
    }
  });
});
