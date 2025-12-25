import { execFile } from "child_process";
import fs from "fs/promises";
import crypto from "crypto";
import os from "os";
import path from "path";

const MODULE = "/usr/lib/softhsm/libsofthsm2.so";
const PIN = "1234";
const KEY_ID = "01";

export async function hsmHmacEK(ekHashHex) {
  const tmpDir = os.tmpdir();
  const tmpIn = path.join(tmpDir, "ek.bin");
  const tmpOut = path.join(tmpDir, "ek.hmac");

  await fs.writeFile(tmpIn, Buffer.from(ekHashHex, "hex"));

  await new Promise((resolve, reject) => {
    execFile(
      "pkcs11-tool",
      [
        "--module", MODULE,
        "--login",
        "--pin", PIN,
        "--sign",
        "--mechanism", "SHA256-HMAC",
        "--id", KEY_ID,
        "--input-file", tmpIn,
        "--output-file", tmpOut
      ],
      (err) => (err ? reject(err) : resolve())
    );
  });

  const hmac = await fs.readFile(tmpOut);
  return hmac.toString("hex");
}

export function timingSafeEq(a, b) {
  return crypto.timingSafeEqual(
    Buffer.from(a, "hex"),
    Buffer.from(b, "hex")
  );
}
