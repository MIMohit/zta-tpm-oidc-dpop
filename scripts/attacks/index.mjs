/**
 * @file scripts/attacks/index.mjs
 * Registry of all 24 attacks (A01–A24) across the 4 security goals (G1–G4).
 * Stubs (A01–A09, A22) point to WP-D2 placeholder modules.
 * Attacks A10–A21, A23, A24 are fully implemented for WP-D1.
 */

import a01 from "./a01-rogue-ek-not-in-inventory.mjs";
import a02 from "./a02-untrusted-ca-ek.mjs";
import a03 from "./a03-ek-cert-pub-mismatch.mjs";
import a04 from "./a04-ak-different-tpm.mjs";
import a05 from "./a05-software-binding-key.mjs";
import a06 from "./a06-tampered-kernel-pcr.mjs";
import a07 from "./a07-nonstandard-pcr-quote.mjs";
import a08 from "./a08-stale-quote-replay.mjs";
import a09 from "./a09-unauthorized-ak-quote.mjs";
import a10 from "./a10-forged-or-expired-ar.mjs";
import a11 from "./a11-cross-device-ar.mjs";
import a12 from "./a12-single-use-violation.mjs";
import a13 from "./a13-credential-theft-device-mismatch.mjs";
import a14 from "./a14-code-redemption-key-mismatch.mjs";
import a15 from "./a15-privilege-escalation-role-acr.mjs";
import a16 from "./a16-bearer-downgrade.mjs";
import a17 from "./a17-stolen-token-dpop-key-mismatch.mjs";
import a18 from "./a18-dpop-proof-no-nonce.mjs";
import a19 from "./a19-proof-replay.mjs";
import a20 from "./a20-proof-method-uri-mismatch.mjs";
import a21 from "./a21-revocation-enforcement.mjs";
import a22 from "./a22-remote-suspension-dos.mjs";
import a23 from "./a23-stepup-bypass.mjs";
import a24 from "./a24-direct-resource-server.mjs";

export const ATTACKS = [
  { id: "A01", title: a01.title, goal: a01.goal, adversary: a01.adversary, expected: a01.expected, module: a01 },
  { id: "A02", title: a02.title, goal: a02.goal, adversary: a02.adversary, expected: a02.expected, module: a02 },
  { id: "A03", title: a03.title, goal: a03.goal, adversary: a03.adversary, expected: a03.expected, module: a03 },
  { id: "A04", title: a04.title, goal: a04.goal, adversary: a04.adversary, expected: a04.expected, module: a04 },
  { id: "A05", title: a05.title, goal: a05.goal, adversary: a05.adversary, expected: a05.expected, module: a05 },
  { id: "A06", title: a06.title, goal: a06.goal, adversary: a06.adversary, expected: a06.expected, module: a06 },
  { id: "A07", title: a07.title, goal: a07.goal, adversary: a07.adversary, expected: a07.expected, module: a07 },
  { id: "A08", title: a08.title, goal: a08.goal, adversary: a08.adversary, expected: a08.expected, module: a08 },
  { id: "A09", title: a09.title, goal: a09.goal, adversary: a09.adversary, expected: a09.expected, module: a09 },
  { id: "A10", title: a10.title, goal: a10.goal, adversary: a10.adversary, expected: a10.expected, module: a10 },
  { id: "A11", title: a11.title, goal: a11.goal, adversary: a11.adversary, expected: a11.expected, module: a11 },
  { id: "A12", title: a12.title, goal: a12.goal, adversary: a12.adversary, expected: a12.expected, module: a12 },
  { id: "A13", title: a13.title, goal: a13.goal, adversary: a13.adversary, expected: a13.expected, module: a13 },
  { id: "A14", title: a14.title, goal: a14.goal, adversary: a14.adversary, expected: a14.expected, module: a14 },
  { id: "A15", title: a15.title, goal: a15.goal, adversary: a15.adversary, expected: a15.expected, module: a15 },
  { id: "A16", title: a16.title, goal: a16.goal, adversary: a16.adversary, expected: a16.expected, module: a16 },
  { id: "A17", title: a17.title, goal: a17.goal, adversary: a17.adversary, expected: a17.expected, module: a17 },
  { id: "A18", title: a18.title, goal: a18.goal, adversary: a18.adversary, expected: a18.expected, module: a18 },
  { id: "A19", title: a19.title, goal: a19.goal, adversary: a19.adversary, expected: a19.expected, module: a19 },
  { id: "A20", title: a20.title, goal: a20.goal, adversary: a20.adversary, expected: a20.expected, module: a20 },
  { id: "A21", title: a21.title, goal: a21.goal, adversary: a21.adversary, expected: a21.expected, module: a21 },
  { id: "A22", title: a22.title, goal: a22.goal, adversary: a22.adversary, expected: a22.expected, module: a22 },
  { id: "A23", title: a23.title, goal: a23.goal, adversary: a23.adversary, expected: a23.expected, module: a23 },
  { id: "A24", title: a24.title, goal: a24.goal, adversary: a24.adversary, expected: a24.expected, module: a24 },
];

export const ATTACK_MAP = new Map(ATTACKS.map((a) => [a.id, a]));

export function getAttack(id) {
  const norm = String(id || "").toUpperCase().trim();
  return ATTACK_MAP.get(norm) || null;
}
