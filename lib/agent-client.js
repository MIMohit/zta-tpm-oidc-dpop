/**
 * @file lib/agent-client.js
 * Client Agent core implementation (ZtaClient).
 * Holds Simulated TPM backend and Binding Key K_B; manages enrolment (E1–E9),
 * attestation (L1–L5), PKCE/PAR/DPoP login flow, protected resource requests with
 * DPoP ath and nonce handshake, step-up detection, and periodic re-attestation (T_RA).
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { loadConfig } from "./config.js";
import { devIdOf, thumbprintOf, jwkOf } from "./sim-tpm/public-area.js";
import { signProof } from "./dpop.js";

export class ZtaClient {
  /**
   * @param {Object} [options]
   * @param {import('./sim-tpm/backend.js').TpmBackend} [options.tpm] - TPM backend instance
   * @param {Record<string, any>} [options.cfg] - ZTA configuration
   * @param {typeof fetch} [options.fetch] - Custom fetch implementation
   */
  constructor(options = {}) {
    this.tpm = options.tpm || null;
    this.cfg = options.cfg || loadConfig();
    this.fetch = options.fetch || globalThis.fetch.bind(globalThis);
    this.clock = this.cfg.clock || (() => Date.now());

    // Nonce cache: origin/URL -> last seen DPoP-Nonce
    this.cachedDpopNonces = new Map();

    // Client state
    this.enrolled = false;
    this.devId = null;
    this.akHandle = null;
    this.kbHandle = null;
    this.jkt = null;
    this.kbPublicArea = null;

    this.lastAttestation = null;
    this.latestAr = null;

    // Tokens in memory
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiresAt = null;
    this.session = null;

    // Pending login transaction
    this.pendingLogin = null;

    // Reattestation interval timer
    this.reattestTimer = null;

    // Restore state from disk if available
    if (this.tpm) {
      this._loadClientState();
    }
  }

  /**
   * Loads persisted client credentials from <tpm.dir>/client.json if present.
   * @private
   */
  _loadClientState() {
    if (!this.tpm?.dir) return;
    const stateFile = path.join(this.tpm.dir, "client.json");
    if (!fs.existsSync(stateFile)) return;

    try {
      const data = JSON.parse(fs.readFileSync(stateFile, "utf8"));
      const currentKind = this.tpm?.kind || this.tpmKind || (this.tpm?.constructor?.name === "RealTpm" ? "tpm" : "sim");
      if (data.tpmKind) {
        const isSimKind = (k) => k === "sim" || k === "sim-fallback";
        if (isSimKind(data.tpmKind) !== isSimKind(currentKind)) {
          console.warn(
            `⚠️ [ZtaClient] Persisted state tpmKind '${data.tpmKind}' does not match current TPM backend '${currentKind}'. Treating as not enrolled.`
          );
          return;
        }
      }

      if (data.devId && data.akHandle && data.kbHandle && data.jkt) {
        this.devId = data.devId;
        this.akHandle = data.akHandle;
        this.kbHandle = data.kbHandle;
        this.jkt = data.jkt;
        this.lastAttestation = data.lastAttestation || null;

        if (data.kbPublicArea) {
          this.kbPublicArea = data.kbPublicArea;
        } else if (this.tpm.keys?.has(data.kbHandle)) {
          this.kbPublicArea = this.tpm.keys.get(data.kbHandle).publicArea;
        }

        this.enrolled = true;
      }
    } catch (err) {
      console.warn("⚠️ [ZtaClient] Could not read client.json:", err.message);
    }
  }

  /**
   * Persists client state to <tpm.dir>/client.json.
   * @private
   */
  _persistClientState() {
    if (!this.tpm?.dir) return;
    try {
      fs.mkdirSync(this.tpm.dir, { recursive: true, mode: 0o700 });
      const stateFile = path.join(this.tpm.dir, "client.json");
      const tpmKind = this.tpm?.kind || this.tpmKind || (this.tpm?.constructor?.name === "RealTpm" ? "tpm" : "sim");
      const state = {
        tpmKind,
        devId: this.devId,
        akHandle: this.akHandle,
        kbHandle: this.kbHandle,
        jkt: this.jkt,
        kbPublicArea: this.kbPublicArea,
        lastAttestation: this.lastAttestation,
      };
      fs.writeFileSync(stateFile, JSON.stringify(state, null, 2), {
        encoding: "utf8",
        mode: 0o600,
      });
      try {
        fs.chmodSync(stateFile, 0o600);
      } catch {}
    } catch (err) {
      console.warn("⚠️ [ZtaClient] Error writing client.json:", err.message);
    }
  }

  /**
   * Returns current agent status representation.
   * @returns {{ enrolled: boolean, devId: string|null, jkt: string|null, lastAttestation: number|null, session: any }}
   */
  getStatus() {
    return {
      enrolled: Boolean(this.enrolled),
      devId: this.devId || null,
      jkt: this.jkt || null,
      lastAttestation: this.lastAttestation || null,
      session: this.session
        ? {
            user: this.session.user,
            acr: this.session.acr,
            exp: this.session.exp,
            role: this.session.role,
            dev: this.session.dev,
          }
        : null,
    };
  }

  /**
   * Executes device enrolment protocol (E1–E9).
   * Generates AK and K_B, validates with Verifier, executes MakeCredential / ActivateCredential,
   * quotes and certifies evidence, and completes binding.
   *
   * @param {string} code - One-time enrolment code
   * @returns {Promise<{ devId: string, jkt: string, enrolled: boolean }>}
   */
  async enrol(code) {
    if (!code || typeof code !== "string") {
      throw new Error("Missing enrolment code");
    }
    if (!this.tpm) {
      throw new Error("No TPM backend configured on ZtaClient");
    }

    // E1: Read EK identity
    const { publicArea: ekPub, cert: ekCert } = await this.tpm.getEk();
    const devId = await devIdOf(ekPub);

    // E1: Create Attestation Key (AK) and Binding Key (K_B)
    const ak = await this.tpm.createAk();
    const kb = await this.tpm.createKb();
    const jkt = await thumbprintOf(kb.publicArea);

    const verifierUrl = this.cfg.verifierUrl || "http://localhost:4005";

    // E3: Start enrolment with verifier
    const extras = typeof this.tpm.getEnrolExtras === "function"
      ? await this.tpm.getEnrolExtras()
      : {};

    const startRes = await this.fetch(`${verifierUrl}/v/enrol/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: code.trim(),
        ekCert,
        akPublic: ak.publicArea,
        kbPublic: kb.publicArea,
        ...extras,
      }),
    });

    if (!startRes.ok) {
      const err = await startRes.json().catch(() => ({}));
      throw new Error(err.message || err.error || `Enrol start failed (${startRes.status})`);
    }

    const { sessionId, blob, nonce } = await startRes.json();

    // E4–E6: Activate credential and generate TPM evidence
    const secret = await this.tpm.activateCredential(ak.handle, blob);
    const quote = await this.tpm.quote(ak.handle, nonce);
    const certify = await this.tpm.certify(kb.handle, ak.handle, nonce);
    const eventLog = typeof this.tpm.readEventLog === "function"
      ? await this.tpm.readEventLog()
      : null;

    // E7–E8: Submit evidence to complete enrolment
    const finishRes = await this.fetch(`${verifierUrl}/v/enrol/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId,
        secret: Buffer.isBuffer(secret) ? secret.toString("hex") : String(secret),
        quote,
        certify,
        eventLog,
      }),
    });

    if (!finishRes.ok) {
      const err = await finishRes.json().catch(() => ({}));
      throw new Error(err.message || err.error || `Enrol finish failed (${finishRes.status})`);
    }

    const finishBody = await finishRes.json();

    // Persist enrolled state
    this.enrolled = true;
    this.devId = finishBody.devId || devId;
    this.akHandle = ak.handle;
    this.kbHandle = kb.handle;
    this.jkt = finishBody.jkt || jkt;
    this.kbPublicArea = kb.publicArea;
    this.lastAttestation = this.clock();

    this._persistClientState();
    this.startReattestation();

    return {
      devId: this.devId,
      jkt: this.jkt,
      enrolled: true,
    };
  }

  /**
   * Executes device appraisal protocol (L1–L5).
   * Requests appraisal nonce from verifier, quotes boot measurements, and receives AR.
   *
   * @returns {Promise<string>} Attestation Result (AR) compact JWS
   */
  async attest() {
    if (!this.enrolled || !this.devId || !this.akHandle) {
      throw new Error("Device is not enrolled");
    }
    if (!this.tpm) {
      throw new Error("No TPM backend configured on ZtaClient");
    }

    const verifierUrl = this.cfg.verifierUrl || "http://localhost:4005";

    // L2: Request fresh appraisal nonce
    const nonceRes = await this.fetch(`${verifierUrl}/v/appraise/nonce`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ devId: this.devId }),
    });

    if (!nonceRes.ok) {
      const err = await nonceRes.json().catch(() => ({}));
      throw new Error(err.reason || err.error || "Appraise nonce request failed");
    }

    const { nonceId, nonce } = await nonceRes.json();

    // L3: Quote over nonce
    const quote = await this.tpm.quote(this.akHandle, nonce);
    const eventLog = typeof this.tpm.readEventLog === "function"
      ? await this.tpm.readEventLog()
      : null;

    // L4–L5: Submit quote and receive AR
    const appraiseRes = await this.fetch(`${verifierUrl}/v/appraise`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        devId: this.devId,
        nonceId,
        quote,
        eventLog,
      }),
    });

    if (!appraiseRes.ok) {
      const err = await appraiseRes.json().catch(() => ({}));
      throw new Error(err.reason || err.error || "Appraisal failed");
    }

    const { ar } = await appraiseRes.json();
    this.latestAr = ar;
    this.lastAttestation = this.clock();
    return ar;
  }

  /**
   * Initiates OIDC authorization transaction via PAR with PKCE and hardware-attested AR.
   *
   * @param {Object} [options]
   * @param {string} [options.acrValues] - Optional requested acr values (e.g. 'mfa')
   * @returns {Promise<{ authorizeUrl: string, authorize_url: string, requestUri: string, state: string }>}
   */
  async startLogin(options = {}) {
    const acrValues = options.acrValues || options.acr_values;

    if (!this.enrolled) {
      throw new Error("Cannot start login: device is not enrolled");
    }

    // 1. Fresh attestation result (AR)
    const ar = await this.attest();

    // 2. PKCE parameters
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto
      .createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");
    const state = crypto.randomBytes(16).toString("base64url");

    const idpIssuer = this.cfg.idpIssuer || "http://localhost:5173";
    const agentUrl = this.cfg.agentUrl || "http://127.0.0.1:7000";
    const redirectUri = `${agentUrl}/callback`;

    // 3. Pushed Authorization Request (PAR)
    const parPayload = {
      client_id: "zta-agent",
      response_type: "code",
      redirect_uri: redirectUri,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      dpop_jkt: this.jkt,
      attestation_result: ar,
      state,
      ...(acrValues ? { acr_values: acrValues } : {}),
    };

    const parRes = await this.fetch(`${idpIssuer}/oauth/par`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(parPayload),
    });

    if (!parRes.ok) {
      const err = await parRes.json().catch(() => ({}));
      throw new Error(err.error_description || err.error || `PAR request failed (${parRes.status})`);
    }

    const { request_uri } = await parRes.json();

    // Store in-memory login transaction
    this.pendingLogin = {
      codeVerifier,
      state,
      requestUri: request_uri,
    };

    const authorizeUrl = `${idpIssuer}/oauth/authorize?client_id=zta-agent&request_uri=${encodeURIComponent(
      request_uri
    )}`;

    return {
      authorizeUrl,
      authorize_url: authorizeUrl,
      requestUri: request_uri,
      state,
    };
  }

  /**
   * Completes authorization transaction: exchanges code for DPoP-bound tokens.
   * Retries on RFC 9449 §8 use_dpop_nonce challenges.
   *
   * @param {string} code - Authorization code
   * @param {string} [state] - State parameter
   * @returns {Promise<Record<string, any>>} Token response payload
   */
  async finishLogin(code, state) {
    if (!code) {
      throw new Error("Missing authorization code in finishLogin");
    }

    if (this.pendingLogin?.state && state && this.pendingLogin.state !== state) {
      throw new Error("State parameter mismatch");
    }

    const codeVerifier = this.pendingLogin?.codeVerifier || "";
    const idpIssuer = this.cfg.idpIssuer || "http://localhost:5173";
    const tokenUrl = `${idpIssuer}/oauth/token`;
    const agentUrl = this.cfg.agentUrl || "http://127.0.0.1:7000";
    const redirectUri = `${agentUrl}/callback`;

    // Ensure K_B public area is resolved
    const kbPub = this.kbPublicArea || this.tpm.keys?.get(this.kbHandle)?.publicArea;
    if (!kbPub) {
      throw new Error("Missing K_B public area for DPoP proof generation");
    }
    const publicJwk = jwkOf(kbPub);

    const sendTokenRequest = async (nonce) => {
      const proof = await signProof({
        signer: (data) => this.tpm.sign(this.kbHandle, data),
        publicJwk,
        htm: "POST",
        htu: tokenUrl,
        nonce: nonce || undefined,
        clock: this.clock,
      });

      return this.fetch(tokenUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          DPoP: proof,
        },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code,
          code_verifier: codeVerifier,
          redirect_uri: redirectUri,
          client_id: "zta-agent",
        }),
      });
    };

    let cachedNonce = this.cachedDpopNonces.get(idpIssuer);
    let res = await sendTokenRequest(cachedNonce);

    if (res.headers.get("DPoP-Nonce")) {
      this.cachedDpopNonces.set(idpIssuer, res.headers.get("DPoP-Nonce"));
    }

    // RFC 9449 §8 Nonce handshake retry
    if (res.status === 400) {
      const errBody = await res.json().catch(() => ({}));
      if (errBody.error === "use_dpop_nonce" || res.headers.get("DPoP-Nonce")) {
        const freshNonce = res.headers.get("DPoP-Nonce") || this.cachedDpopNonces.get(idpIssuer);
        res = await sendTokenRequest(freshNonce);
        if (res.headers.get("DPoP-Nonce")) {
          this.cachedDpopNonces.set(idpIssuer, res.headers.get("DPoP-Nonce"));
        }
      }
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error_description || err.error || `Token exchange failed (${res.status})`);
    }

    const tokens = await res.json();
    this.accessToken = tokens.access_token;
    this.refreshToken = tokens.refresh_token || this.refreshToken;
    this.tokenExpiresAt = this.clock() + (tokens.expires_in || 300) * 1000;

    // Parse AT payload for session info
    try {
      const parts = tokens.access_token.split(".");
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
      this.session = {
        user: payload.sub,
        acr: payload.acr,
        exp: payload.exp,
        role: payload.role,
        dev: payload.dev,
      };
    } catch {}

    this.pendingLogin = null;
    this.startReattestation();
    return tokens;
  }

  /**
   * Refreshes the Access Token using the bound Refresh Token and K_B signature.
   *
   * @returns {Promise<Record<string, any>>}
   */
  async refresh() {
    if (!this.refreshToken) {
      throw new Error("No refresh token available");
    }

    const idpIssuer = this.cfg.idpIssuer || "http://localhost:5173";
    const tokenUrl = `${idpIssuer}/oauth/token`;

    const kbPub = this.kbPublicArea || this.tpm.keys?.get(this.kbHandle)?.publicArea;
    const publicJwk = jwkOf(kbPub);

    const sendRefreshRequest = async (nonce) => {
      const proof = await signProof({
        signer: (data) => this.tpm.sign(this.kbHandle, data),
        publicJwk,
        htm: "POST",
        htu: tokenUrl,
        nonce: nonce || undefined,
        clock: this.clock,
      });

      return this.fetch(tokenUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          DPoP: proof,
        },
        body: JSON.stringify({
          grant_type: "refresh_token",
          refresh_token: this.refreshToken,
        }),
      });
    };

    let cachedNonce = this.cachedDpopNonces.get(idpIssuer);
    let res = await sendRefreshRequest(cachedNonce);

    if (res.headers.get("DPoP-Nonce")) {
      this.cachedDpopNonces.set(idpIssuer, res.headers.get("DPoP-Nonce"));
    }

    if (res.status === 400) {
      const errBody = await res.json().catch(() => ({}));
      if (errBody.error === "use_dpop_nonce" || res.headers.get("DPoP-Nonce")) {
        const freshNonce = res.headers.get("DPoP-Nonce") || this.cachedDpopNonces.get(idpIssuer);
        res = await sendRefreshRequest(freshNonce);
        if (res.headers.get("DPoP-Nonce")) {
          this.cachedDpopNonces.set(idpIssuer, res.headers.get("DPoP-Nonce"));
        }
      }
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error_description || err.error || `Refresh failed (${res.status})`);
    }

    const tokens = await res.json();
    this.accessToken = tokens.access_token;
    if (tokens.refresh_token) {
      this.refreshToken = tokens.refresh_token;
    }
    this.tokenExpiresAt = this.clock() + (tokens.expires_in || 300) * 1000;

    try {
      const parts = tokens.access_token.split(".");
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
      this.session = {
        user: payload.sub,
        acr: payload.acr,
        exp: payload.exp,
        role: payload.role,
        dev: payload.dev,
      };
    } catch {}

    return tokens;
  }

  /**
   * Executes protected resource request via the PEP (:4001).
   * Generates DPoP proof with ath and nonce; retries once on nonce challenge.
   * Auto-refreshes expired access tokens.
   *
   * @param {string} resource - Resource identifier (e.g. 'company.news' or 'company.audit') or path
   * @returns {Promise<Record<string, any>>}
   */
  async request(resource) {
    // 1. Refresh if token is expired
    if (this.tokenExpiresAt && this.clock() >= this.tokenExpiresAt) {
      if (this.refreshToken) {
        await this.refresh();
      }
    }

    if (!this.accessToken) {
      throw new Error("No active access token. Please login first.");
    }

    // 2. Resolve target URI
    const pepBase = this.cfg.pepPublicUrl || "http://localhost:4001";
    let resourcePath;
    const r = Array.isArray(resource) ? resource.join("/") : String(resource || "");
    if (r.startsWith("/")) {
      resourcePath = r;
    } else if (r === "company.audit" || r === "company/audit") {
      resourcePath = "/api/company/audit";
    } else if (r === "company.news" || r === "company/news") {
      resourcePath = "/api/company/news";
    } else {
      resourcePath = `/api/${r.replace(/\./g, "/")}`;
    }

    const targetUrl = `${pepBase}${resourcePath}`;
    const pepOrigin = new URL(pepBase).origin;

    const kbPub = this.kbPublicArea || this.tpm.keys?.get(this.kbHandle)?.publicArea;
    if (!kbPub) {
      throw new Error("Missing K_B key for resource DPoP proof");
    }
    const publicJwk = jwkOf(kbPub);

    const sendRequest = async (nonce) => {
      const proof = await signProof({
        signer: (data) => this.tpm.sign(this.kbHandle, data),
        publicJwk,
        htm: "GET",
        htu: targetUrl,
        nonce: nonce || undefined,
        accessToken: this.accessToken,
        clock: this.clock,
      });

      return this.fetch(targetUrl, {
        method: "GET",
        headers: {
          Authorization: `DPoP ${this.accessToken}`,
          DPoP: proof,
        },
      });
    };

    let cachedNonce = this.cachedDpopNonces.get(pepOrigin);
    let res = await sendRequest(cachedNonce);

    if (res.headers.get("DPoP-Nonce")) {
      this.cachedDpopNonces.set(pepOrigin, res.headers.get("DPoP-Nonce"));
    }

    // Handle PEP nonce challenge
    if (res.status === 401) {
      const authHeader = res.headers.get("WWW-Authenticate") || "";
      const newNonce = res.headers.get("DPoP-Nonce");
      if (authHeader.includes("use_dpop_nonce") || newNonce) {
        res = await sendRequest(newNonce);
        if (res.headers.get("DPoP-Nonce")) {
          this.cachedDpopNonces.set(pepOrigin, res.headers.get("DPoP-Nonce"));
        }
      }
    }

    // 3. Process outcomes
    if (res.status === 401) {
      const authHeader = res.headers.get("WWW-Authenticate") || "";
      const body = await res.json().catch(() => ({}));
      // RFC 9470 Step-Up Authentication challenge
      if (
        authHeader.includes("insufficient_user_authentication") ||
        body.error === "insufficient_user_authentication"
      ) {
        return {
          stepUp: true,
          step_up: true,
          status: 401,
          error: "insufficient_user_authentication",
          acr_values: "mfa",
          ...body,
        };
      }
      return { status: 401, error: body.error || "unauthorized", ...body };
    }

    if (res.ok) {
      const body = await res.json();
      return { status: 200, ...body };
    }

    const errorBody = await res.json().catch(() => ({}));
    return { status: res.status, ...errorBody };
  }

  /**
   * Starts background re-attestation interval (every T_RA).
   */
  startReattestation() {
    this.stopReattestation();
    const intervalMs = (this.cfg.tRA || 300) * 1000;

    this.reattestTimer = setInterval(async () => {
      if (!this.enrolled) return;
      try {
        await this.attest();
      } catch (err) {
        console.error("⚠️ [ZtaClient] Re-attestation cycle failed:", err.message);
      }
    }, intervalMs);

    if (this.reattestTimer.unref) {
      this.reattestTimer.unref();
    }
  }

  /**
   * Stops background re-attestation interval.
   */
  stopReattestation() {
    if (this.reattestTimer) {
      clearInterval(this.reattestTimer);
      this.reattestTimer = null;
    }
  }

  /**
   * Tamper knob for eval and test scenarios.
   * @param {string} [desc]
   */
  async tamper(desc = "agent debug tamper") {
    if (this.tpm && typeof this.tpm.tamper === "function") {
      await this.tpm.tamper(desc);
    }
  }

  /**
   * Clears tokens and session state.
   */
  logout() {
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiresAt = null;
    this.session = null;
    this.pendingLogin = null;
  }
}

export default ZtaClient;
