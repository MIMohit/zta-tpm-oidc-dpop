/**
 * @file tests/helpers/soft-webauthn.js
 * Software WebAuthn platform authenticator (ECC P-256, fmt: "none").
 * Implements clientDataJSON, authenticatorData with COSE key, and CBOR attestationObject.
 */

import crypto from "node:crypto";
import { encodeCBOR } from "@levischuck/tiny-cbor";

export class SoftAuthenticator {
  constructor(options = {}) {
    this.namedCurve = options.namedCurve || "prime256v1";
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: this.namedCurve,
    });
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    this.counter = 0;
    this.credId = options.credId || crypto.randomBytes(16);
  }

  /**
   * Returns CBOR-encoded COSE EC2 public key bytes for this authenticator.
   * @returns {Buffer}
   */
  getCosePublicKey() {
    const jwk = this.publicKey.export({ format: "jwk" });
    const x = Buffer.from(jwk.x, "base64url");
    const y = Buffer.from(jwk.y, "base64url");

    const coseKey = new Map();
    coseKey.set(1, 2); // 1 = kty : 2 (EC2)
    coseKey.set(3, -7); // 3 = alg : -7 (ES256)
    coseKey.set(-1, 1); // -1 = crv : 1 (P-256)
    coseKey.set(-2, x); // -2 = x coordinate
    coseKey.set(-3, y); // -3 = y coordinate
    return Buffer.from(encodeCBOR(coseKey));
  }

  /**
   * Generates a registration response for @simplewebauthn/server verifyRegistrationResponse.
   *
   * @param {Object} options - Registration options from server (generateRegistrationOptions)
   * @param {Object} [ctx]
   * @param {string} [ctx.origin="http://localhost:5173"]
   * @param {string} [ctx.rpID="localhost"]
   * @returns {Object}
   */
  createRegistrationResponse(options, ctx = {}) {
    const origin = ctx.origin || "http://localhost:5173";
    const rpID = ctx.rpID || options.rp?.id || "localhost";
    const challenge = options.challenge;

    const jwk = this.publicKey.export({ format: "jwk" });
    const x = Buffer.from(jwk.x, "base64url");
    const y = Buffer.from(jwk.y, "base64url");

    // COSE EC2 Key Map
    const coseKey = new Map();
    coseKey.set(1, 2); // 1 = kty : 2 (EC2)
    coseKey.set(3, -7); // 3 = alg : -7 (ES256)
    coseKey.set(-1, 1); // -1 = crv : 1 (P-256)
    coseKey.set(-2, x); // -2 = x coordinate
    coseKey.set(-3, y); // -3 = y coordinate
    const coseKeyBytes = encodeCBOR(coseKey);

    const rpIdHash = crypto.createHash("sha256").update(rpID).digest();
    const flags = Buffer.from([0x45]); // UP (0x01) | UV (0x04) | AT (0x40)
    const signCount = Buffer.alloc(4);
    signCount.writeUInt32BE(this.counter, 0);
    const aaguid = Buffer.alloc(16);
    const credIdLen = Buffer.alloc(2);
    credIdLen.writeUInt16BE(this.credId.length, 0);

    const authData = Buffer.concat([
      rpIdHash,
      flags,
      signCount,
      aaguid,
      credIdLen,
      this.credId,
      Buffer.from(coseKeyBytes),
    ]);

    const attestationMap = new Map();
    attestationMap.set("fmt", "none");
    attestationMap.set("attStmt", new Map());
    attestationMap.set("authData", authData);
    const attestationObject = Buffer.from(encodeCBOR(attestationMap));

    const clientDataObj = {
      type: "webauthn.create",
      challenge,
      origin,
      crossOrigin: false,
    };
    const clientDataJSON = Buffer.from(JSON.stringify(clientDataObj));

    return {
      id: this.credId.toString("base64url"),
      rawId: this.credId.toString("base64url"),
      response: {
        attestationObject: attestationObject.toString("base64url"),
        clientDataJSON: clientDataJSON.toString("base64url"),
        transports: ["internal"],
      },
      type: "public-key",
      clientExtensionResults: {},
    };
  }

  /**
   * Generates an authentication response for @simplewebauthn/server verifyAuthenticationResponse.
   *
   * @param {Object} options - Authentication options from server (generateAuthenticationOptions)
   * @param {Object} [ctx]
   * @param {string} [ctx.origin="http://localhost:5173"]
   * @param {string} [ctx.rpID="localhost"]
   * @returns {Object}
   */
  createAuthenticationResponse(options, ctx = {}) {
    const origin = ctx.origin || "http://localhost:5173";
    const rpID = ctx.rpID || options.rpId || "localhost";
    const challenge = options.challenge;

    this.counter += 1;

    const rpIdHash = crypto.createHash("sha256").update(rpID).digest();
    const flags = Buffer.from([0x05]); // UP (0x01) | UV (0x04)
    const signCount = Buffer.alloc(4);
    signCount.writeUInt32BE(this.counter, 0);
    const authData = Buffer.concat([rpIdHash, flags, signCount]);

    const clientDataObj = {
      type: "webauthn.get",
      challenge,
      origin,
      crossOrigin: false,
    };
    const clientDataJSON = Buffer.from(JSON.stringify(clientDataObj));

    const clientDataHash = crypto.createHash("sha256").update(clientDataJSON).digest();
    const sigPayload = Buffer.concat([authData, clientDataHash]);

    // DER encoded signature for WebAuthn
    const signature = crypto.sign("sha256", sigPayload, {
      key: this.privateKey,
      dsaEncoding: "der",
    });

    return {
      id: this.credId.toString("base64url"),
      rawId: this.credId.toString("base64url"),
      response: {
        authenticatorData: authData.toString("base64url"),
        clientDataJSON: clientDataJSON.toString("base64url"),
        signature: signature.toString("base64url"),
      },
      type: "public-key",
      clientExtensionResults: {},
    };
  }

  /**
   * Directly registers this authenticator's credential in the IdP store for (user, devId).
   *
   * @param {Object} store - IdP store instance
   * @param {string} user - Username
   * @param {string} devId - Device ID
   * @returns {Promise<Object>}
   */
  async registerInStore(store, user, devId) {
    const credData = {
      id: this.credId.toString("base64url"),
      publicKey: this.getCosePublicKey().toString("base64url"),
      counter: 0,
      transports: ["internal"],
    };
    return store.set(`webauthn/${user}/${devId}`, {
      user_id: user,
      device_id: devId,
      credential: credData,
    });
  }
}

export default SoftAuthenticator;
