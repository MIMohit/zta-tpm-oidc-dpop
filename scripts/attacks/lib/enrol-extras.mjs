/**
 * @file scripts/attacks/lib/enrol-extras.mjs
 * Evidence the agent sends to /v/enrol/start next to the EK certificate (lib/agent-client.js):
 * the EK public area, the EK certificate chain and the SRK public area. Attacks that build
 * enrolment requests by hand send the same, so a rejection comes from the check under test and
 * not from evidence a genuine agent would have supplied. The simulated TPM has no such extras
 * (its JWS EK certificates are self-contained).
 *
 * @param {Object} tpm - TPM backend
 * @returns {Promise<{ ekPublic?: Object, ekCertChain?: string[], srkPublic?: Object }>}
 */
export async function enrolExtras(tpm) {
  return typeof tpm.getEnrolExtras === "function" ? await tpm.getEnrolExtras() : {};
}
