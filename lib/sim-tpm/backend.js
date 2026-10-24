/**
 * @file backend.js
 * Interface definition for TPM backend implementations.
 * Conforms to WP1 specification for Simulated TPM and future tpm2-tools backend.
 */

/**
 * @typedef {Object} EkResult
 * @property {Record<string, any>} publicArea - TPM 2.0 public area for EK
 * @property {string} cert - Compact JWS EK certificate from vendor CA
 *
 * @typedef {Object} KeyResult
 * @property {string|number} handle - Handle identifying the key in the TPM
 * @property {Record<string, any>} publicArea - Public area of the key
 * @property {Buffer} name - TPM Name of the key (0x000B || SHA256(canonical(publicArea)))
 *
 * @typedef {Object} CredentialBlob
 * @property {string} credentialBlob - Base64url encoded integrity || encIdentity
 * @property {string} secret - Base64url encoded ephemeral public key
 *
 * @typedef {Object} QuoteResult
 * @property {Buffer} attest - Binary TPMS_ATTEST structure
 * @property {string} sig - ECDSA-P256-SHA256 signature in IEEE-P1363 format (base64url)
 * @property {string[]} pcrs - Hex digests of PCR0..7
 *
 * @typedef {Object} CertifyResult
 * @property {Buffer} attest - Binary TPMS_ATTEST structure
 * @property {string} sig - ECDSA-P256-SHA256 signature in IEEE-P1363 format (base64url)
 *
 * @typedef {Object} EventLogEntry
 * @property {number} pcr - PCR index (0..7)
 * @property {string} digest - SHA-256 measurement digest in hex
 * @property {string} desc - Event description
 */

export class TpmBackend {
  /**
   * Returns the Endorsement Key (EK) public area and vendor certificate.
   * @returns {Promise<EkResult>}
   */
  async getEk() {
    throw new Error("Method getEk() must be implemented by subclass");
  }

  /**
   * Creates an Attestation Key (AK) with attributes: restricted | sign | fixedTPM | fixedParent | sensitiveDataOrigin.
   * @returns {Promise<KeyResult>}
   */
  async createAk() {
    throw new Error("Method createAk() must be implemented by subclass");
  }

  /**
   * Creates a Binding Key (K_B) with attributes: sign | fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth.
   * K_B is unrestricted (neither restricted nor decrypt).
   * @returns {Promise<KeyResult>}
   */
  async createKb() {
    throw new Error("Method createKb() must be implemented by subclass");
  }

  /**
   * Activates credential blob for the specified AK handle.
   * Recomputes keys using EK private key and loaded AK's Name, verifies HMAC, and decrypts secret.
   * @param {string|number} akHandle
   * @param {CredentialBlob} blob
   * @returns {Promise<Buffer>} The recovered secret s
   */
  async activateCredential(akHandle, blob) {
    throw new Error("Method activateCredential() must be implemented by subclass");
  }

  /**
   * Produces a TPM2_Quote over selected PCRs and qualifying data (nonce), signed by AK.
   * @param {string|number} akHandle
   * @param {Buffer|string} nonce
   * @param {number[]} [pcrSel=[0, 1, 2, 3, 4, 5, 6, 7]]
   * @returns {Promise<QuoteResult>}
   */
  async quote(akHandle, nonce, pcrSel = [0, 1, 2, 3, 4, 5, 6, 7]) {
    throw new Error("Method quote() must be implemented by subclass");
  }

  /**
   * Produces a TPM2_Certify of an object (K_B) by the AK over qualifying data (nonce).
   * @param {string|number} objHandle
   * @param {string|number} akHandle
   * @param {Buffer|string} nonce
   * @returns {Promise<CertifyResult>}
   */
  async certify(objHandle, akHandle, nonce) {
    throw new Error("Method certify() must be implemented by subclass");
  }

  /**
   * Signs data with K_B key (ES256 P1363). Refuses AK or any restricted key.
   * @param {string|number} kbHandle
   * @param {Buffer|Uint8Array|string} data
   * @returns {Promise<Buffer>} 64-byte IEEE-P1363 signature (r || s)
   */
  async sign(kbHandle, data) {
    throw new Error("Method sign() must be implemented by subclass");
  }

  /**
   * Reads the current measured boot event log.
   * @returns {EventLogEntry[]}
   */
  readEventLog() {
    throw new Error("Method readEventLog() must be implemented by subclass");
  }

  /**
   * Extends a PCR measurement and records an event in the log.
   * @param {number} pcr
   * @param {Buffer|string} digest
   * @param {string} desc
   */
  extendPcr(pcr, digest, desc) {
    throw new Error("Method extendPcr() must be implemented by subclass");
  }
}

export default TpmBackend;
