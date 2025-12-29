import crypto from "crypto";

export function hashAnswer(answer) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(
    answer.toLowerCase().trim(),
    salt,
    100000,
    64,
    "sha512"
  ).toString("hex");

  return `${salt}:${hash}`;
}

export function verifyAnswer(input, stored) {
  const [salt, hash] = stored.split(":");

  const inputHash = crypto.pbkdf2Sync(
    input.toLowerCase().trim(),
    salt,
    100000,
    64,
    "sha512"
  ).toString("hex");

  return crypto.timingSafeEqual(
    Buffer.from(hash, "hex"),
    Buffer.from(inputHash, "hex")
  );
}
