import express from "express";
import cors from "cors";
import { randomBytes } from "crypto";
import crypto from "crypto";
import fs from "fs";
import { exec } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import * as openid from "openid-client";
import * as jose from 'jose';
import { hsmHmacEK, timingSafeEq } from "./hsm.js";
import { db } from "./firebase.js";
import { hashAnswer } from "./mfa-crypto.js";
import { verifyAnswer } from "./mfa-crypto.js";

const logSection = (title) => {
  console.log("\n" + "═".repeat(60));
  console.log(`🔍 ${title}`);
  console.log("═".repeat(60));
};

// Generate DPoP proof
async function generateDPoPProof(method, url, accessToken = null) {
  if (!app.locals.dpopKeyPair) {
    const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
    app.locals.dpopKeyPair = { publicKey, privateKey };
  }

  const { publicKey, privateKey } = app.locals.dpopKeyPair;
  const jwk = await jose.exportJWK(publicKey);
  
  const payload = {
    htm: method,
    htu: url,
    jti: crypto.randomUUID(),
    iat: Math.floor(Date.now() / 1000),
  };

  if (accessToken) {
    const hash = crypto.createHash('sha256').update(accessToken).digest('base64url');
    payload.ath = hash;
  }

  const dpopProof = await new jose.SignJWT(payload)
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'dpop+jwt',
      jwk: jwk,
    })
    .sign(privateKey);

  return dpopProof;
}


const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.use(express.static(path.join(__dirname, "public")));
app.use(cors());
app.use(express.json());

const debug = (...args) => console.log(new Date().toISOString(), ...args);

app.use((req, res, next) => {
  debug(`${req.method} ${req.url}`);
  next();
});

// Session Configuration
const memoryStore = new session.MemoryStore();

app.use(session({
  name: "zta.sid",
  secret: "zta-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: false,     // localhost only
    path: "/"          // 🔥 REQUIRED
  }
}));

// Initialize OIDC Client
let keycloakConfig;

(async () => {
  try {
    keycloakConfig = {
      issuer: 'http://172.30.32.1:8080/realms/zta-realm',
      authorization_endpoint: 'http://172.30.32.1:8080/realms/zta-realm/protocol/openid-connect/auth',
      token_endpoint: 'http://172.30.32.1:8080/realms/zta-realm/protocol/openid-connect/token',
      userinfo_endpoint: 'http://172.30.32.1:8080/realms/zta-realm/protocol/openid-connect/userinfo',
      end_session_endpoint: 'http://172.30.32.1:8080/realms/zta-realm/protocol/openid-connect/logout',
      jwks_uri: 'http://172.30.32.1:8080/realms/zta-realm/protocol/openid-connect/certs',
    };

    
    console.log('✅ OIDC Client configured with PKCE support (HTTP allowed for local dev)');
  } catch (err) {
    console.error('❌ Failed to initialize OIDC client:', err);
  }
})();

// In-memory TPM device registry
const deviceRegistry = {};

// Helper functions
function isDeviceTrusted(deviceId) {
  const device = deviceRegistry[deviceId];
  return device && device.status === 'trusted';
}

function getDeviceId(req) {
  return req.session.deviceId || 'unknown';
}

function requireTrustedDevice(req, res, next) {
  const deviceId = getDeviceId(req);
  
  if (!isDeviceTrusted(deviceId)) {
    return res.status(403).json({ 
      error: 'Device not registered',
      message: 'Please register your device before logging in',
      deviceId 
    });
  }
  
  next();
}

function requireAuth(req, res, next) {
  if (!req.session.tokenSet) {
    return res.status(401).json({ authenticated: false });
  }
  next();
}

// Error handling middleware
app.use((err, req, res, next) => {
  debug("Error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// Auth check endpoint
app.get('/api/auth/check', (req, res) => {
  const deviceId = getDeviceId(req);
  const device = deviceRegistry[deviceId];
  
  if (req.session.tokenSet && req.session.userInfo) {
    res.json({
      authenticated: true,
      username: req.session.userInfo.preferred_username,
      email: req.session.userInfo.email || '',
      deviceId: deviceId,
      deviceTrusted: device?.status === 'trusted'
    });
  } else {
    res.json({ 
      authenticated: false,
      deviceId: deviceId,
      deviceTrusted: device?.status === 'trusted'
    });
  }
});

// STEP 1: Device Registration Init (Anonymous)
app.get("/api/device/register/init", (req, res) => {
  const nonce = randomBytes(16).toString("base64url");
  const deviceId = req.query.deviceId || crypto.randomUUID();
  
  req.session.registrationNonce = nonce;
  req.session.deviceId = deviceId;
  
  console.log(`📱 Device registration initiated for: ${deviceId}`);
  
  res.json({ 
    nonce, 
    pcrs: [0, 7, 11],
    deviceId 
  });
});

// STEP 2: Device Status Check
app.get('/api/device/status', (req, res) => {
  const deviceId = getDeviceId(req);
  const device = deviceRegistry[deviceId];
  
  if (!device) {
    return res.json({ 
      registered: false,
      canLogin: false,
      message: 'Device not registered',
      deviceId: deviceId
    });
  }
  
  res.json({
    registered: true,
    trusted: device.status === 'trusted',
    canLogin: device.status === 'trusted',
    deviceId: deviceId,
    status: device.status,
    userId: device.user_id
  });
});

// STEP 3: Run TPM Attestation (Anonymous)
app.get("/run-attestation", async (req, res) => {
  try {
    if (!req.session.deviceId) {
      return res.status(400).json({
        error: "Device registration not initialized",
        message: "Call /api/device/register/init first"
      });
    }

    // 🔐 Call Windows TPM Attestation Service
    const WINDOWS_HOST = "172.30.32.1"; // your Windows host IP
    const TPM_SERVICE_URL = `http://${WINDOWS_HOST}:9000/attest`;

    const tpmRes = await fetch(TPM_SERVICE_URL);
    if (!tpmRes.ok) {
      throw new Error("Windows TPM service failed");
    }

    const attestation = await tpmRes.json();

    const evalResult = evaluateAttestation(attestation);
    logSection("TPM ATTESTATION RECEIVED");

    console.log("├─ Manufacturer   :", attestation.manufacturer);
    console.log("├─ Spec Version   :", attestation.spec_version);
    console.log("├─ EK Hash        :", attestation.ek_hash);
    console.log("├─ Timestamp      :", attestation.timestamp);
    console.log("├─ Trust Decision :", evalResult.trusted ? "ACCEPTED ✅" : "REJECTED ❌");

    if (evalResult.reasons?.length) {
      console.log("└─ Reasons:");
      evalResult.reasons.forEach(r => console.log("   •", r));
    }

    const deviceId = req.session.deviceId;

    if (evalResult.trusted && attestation.ek_hash) {
      const ek_hmac = await hsmHmacEK(attestation.ek_hash);

      deviceRegistry[deviceId] = {
        user_id: null,
        ek_hmac,
        ek_hash: attestation.ek_hash,
        status: "trusted",
        registered_at: new Date().toISOString()
      };
    }

    logSection("EK HASH SEALED VIA HSM");

    console.log("├─ EK Hash        :", attestation.ek_hash);
    console.log("├─ HMAC (stored)  :", ek_hmac);
    console.log("└─ Status         : STORED SECURELY");

    return res.json({
      deviceId,
      status: evalResult.trusted ? "trusted" : "untrusted",
      canLogin: evalResult.trusted,
      reasons: evalResult.reasons
    });

  } catch (err) {
    console.error("❌ TPM registration error:", err);
    res.status(500).json({
      error: "TPM registration failed",
      details: err.message
    });
  }
});


// Evaluate TPM attestation
function evaluateAttestation(attestation) {
  const result = { trusted: true, reasons: [] };

  if (!attestation.spec_version?.startsWith("2.0")) {
    result.trusted = false;
    result.reasons.push("Unsupported TPM spec version");
  }

  const trustedVendors = ["AMD", "INTC", "IFX", "STM", "NSM", "HPE"];
  if (!trustedVendors.includes(attestation.manufacturer)) {
    result.trusted = false;
    result.reasons.push(`Unrecognized TPM manufacturer: ${attestation.manufacturer}`);
  }

  if (attestation.ek_cert_b64) {
    try {
      const ekCertBuffer = Buffer.from(attestation.ek_cert_b64, "base64");
      
      if (ekCertBuffer.length < 100) {
        throw new Error(`Certificate too small: ${ekCertBuffer.length} bytes`);
      }

      const base64Der = ekCertBuffer.toString("base64");
      const pemLines = base64Der.match(/.{1,64}/g) || [];
      const pemText = `-----BEGIN CERTIFICATE-----\n${pemLines.join("\n")}\n-----END CERTIFICATE-----`;

      const cert = new crypto.X509Certificate(pemText);

      const extractCN = (x500) => {
        if (!x500 || typeof x500 !== "string") return "Unknown";
        const match = x500.match(/CN=([^,]+)/);
        return match ? match[1].trim() : x500;
      };

      const subjectCN = extractCN(cert.subject);
      const issuerCN = extractCN(cert.issuer);

      result.reasons.push(`EK Cert Subject CN: ${subjectCN}`);
      result.reasons.push(`EK Cert Issuer CN: ${issuerCN}`);
      result.reasons.push(`Valid From: ${cert.validFrom}`);
      result.reasons.push(`Valid To: ${cert.validTo}`);

      const now = new Date();
      const validFrom = new Date(cert.validFrom);
      const validTo = new Date(cert.validTo);

      if (now < validFrom || now > validTo) {
        result.trusted = false;
        result.reasons.push("Certificate is expired or not yet valid");
      }

      result.trusted = true;
    } catch (err) {
      console.error("EK certificate parse error:", err.message);
      
      if (attestation.ek_hash) {
        result.trusted = true;
        result.reasons.push("EK certificate invalid, using EK hash instead");
        result.reasons.push(`EK Hash: ${attestation.ek_hash}`);
      } else {
        result.trusted = false;
        result.reasons.push("Failed to parse EK certificate: " + err.message);
      }
    }
  } else if (attestation.ek_hash) {
    result.trusted = true;
    result.reasons.push(`EK Hash: ${attestation.ek_hash}`);
    result.reasons.push("Trusted via EK hash (no certificate provided)");
  } else {
    result.trusted = false;
    result.reasons.push("Missing EK certificate or hash");
  }

  return result;
}

// STEP 4: Login (ONLY if device is trusted)
app.get('/login', requireTrustedDevice, async (req, res) => {
  if (!keycloakConfig) {
    return res.status(500).send('OIDC client not initialized');
  }

  const deviceId = getDeviceId(req);          // ✅ DEFINE FIRST
  const device = deviceRegistry[deviceId];   // ✅ SAFE
  if (!device || !device.ek_hmac || !device.ek_hash) {
    return res.status(403).send("Device identity incomplete — re-enrollment required");
  }

  logSection("TPM RE-VERIFICATION ON LOGIN");

  console.log("├─ Device ID      :", deviceId);
  console.log("├─ Stored EK Hash :", device.ek_hash);

  const freshHmac = await hsmHmacEK(device.ek_hash);

  console.log("├─ Recomputed HMAC:", freshHmac);
  console.log("├─ Stored HMAC    :", device.ek_hmac);


  if (!timingSafeEq(freshHmac, device.ek_hmac)) {
    console.log("└─ Verification   : MISMATCH ❌");
    console.log("🔒 ACTION         : DEVICE MUST RE-ENROLL");
    device.status = "re_enroll_required";
    return res.status(403).send("Device identity changed — re-enrollment required");
  }

  console.log("└─ Verification   : MATCH ✅");
  console.log("🔐 DEVICE TRUST CONTINUES — LOGIN PERMITTED");

  try {
    const deviceId = getDeviceId(req);
    console.log(`🔐 Login attempt from trusted device: ${deviceId}`);
    
    const code_verifier = openid.randomPKCECodeVerifier();
    const code_challenge = await openid.calculatePKCECodeChallenge(code_verifier);

    req.session.code_verifier = code_verifier;

    console.log('\n🔐 ========== PKCE AUTHENTICATION INITIATED ==========');
    console.log('Device ID:', deviceId);
    console.log('Code Verifier:', code_verifier);
    console.log('Code Challenge:', code_challenge);
    console.log('Code Challenge Method: S256');
    console.log('====================================================\n');

    const params = new URLSearchParams({
      client_id: 'remote-work-app',
      redirect_uri: 'http://localhost:5173/callback',
      response_type: 'code',
      scope: 'openid profile email',
      code_challenge: code_challenge,
      code_challenge_method: 'S256',
    });

    const authorizationUrl = `${keycloakConfig.authorization_endpoint}?${params.toString()}`;
    res.redirect(authorizationUrl);
    //res.redirect("/remote-work.html");
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).send('Login failed: ' + err.message);
  }
});

// STEP 5: Callback - Bind user to device
app.get('/callback', async (req, res) => {
  if (!keycloakConfig) {
    return res.status(500).send('OIDC client not initialized');
  }

  try {
    const code = req.query.code;
    const deviceId = getDeviceId(req);
    
    console.log('\n🔑 ========== OIDC AUTHORIZATION CODE RECEIVED ==========');
    console.log('Device ID:', deviceId);
    console.log('Authorization Code:', code);
    console.log('=======================================================\n');
    console.log('⏳ Exchanging authorization code for tokens with PKCE + DPoP...\n');

// Generate DPoP proof
const dpopProof = await generateDPoPProof('POST', keycloakConfig.token_endpoint);
console.log('🔐 DPoP Proof Generated');



const tokenParams = new URLSearchParams({
  grant_type: 'authorization_code',
  client_id: 'remote-work-app',
  code: code,
  redirect_uri: 'http://localhost:5173/callback',
  code_verifier: req.session.code_verifier,
});

const tokenResponse = await fetch(keycloakConfig.token_endpoint, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
    'DPoP': dpopProof,  // Add DPoP header
  },
  body: tokenParams.toString(),
});

if (!tokenResponse.ok) {
  const errorText = await tokenResponse.text();
  throw new Error(`Token exchange failed: ${errorText}`);
}

const tokens = await tokenResponse.json();
console.log('✅ Token exchange successful with PKCE + DPoP!');
console.log('🔐 Token Type:', tokens.token_type); // Should be "DPoP"
req.session.tokenSet = tokens;
req.session.dpop = dpopProof;


const idTokenParts = tokens.id_token.split('.');
const claims = JSON.parse(Buffer.from(idTokenParts[1], 'base64').toString());
    
    if (deviceRegistry[deviceId]) {
      deviceRegistry[deviceId].user_id = claims.preferred_username;
      deviceRegistry[deviceId].bound_at = new Date().toISOString();
      
      console.log(`✅ User ${claims.preferred_username} bound to device ${deviceId}`);
    }

    console.log('✅ Token exchange successful with PKCE!\n');
    console.log('🔐 ========== USER LOGGED IN ==========');
    console.log('Username:', claims.preferred_username);
    console.log('Device ID:', deviceId);
    console.log('\n📋 OIDC Tokens Received:');
    console.log('─────────────────────────────────────');
    console.log('\n✅ Access Token (JWT):');
    console.log(tokens.access_token);
    console.log('\n✅ ID Token Claims:');
    console.log(JSON.stringify(claims, null, 2));
    console.log('\n📊 Token Info:');
    console.log('  - Token Type:', tokens.token_type || 'Bearer');
    console.log('  - Expires In:', tokens.expires_in || 'N/A', 'seconds');
    console.log('  - PKCE: ✅ Enabled (S256)');
    console.log('======================================\n');

    req.session.tokenSet = tokens;
    req.session.userInfo = claims;
    delete req.session.code_verifier;

    // After successful Keycloak login - update device record
    const userInfo = claims;
    await db.ref(`devices/${deviceId}`).update({
      user_id: userInfo.preferred_username,
      last_seen: new Date().toISOString(),
      last_ip: req.ip,
      last_country: req.headers["x-country"] || "unknown"
    });

    console.log("🔗 Device bound to user:", userInfo.sub);

    // After login success, check MFA enrollment for this device
    const userId = claims.preferred_username;

    // Check if MFA already enrolled
    const snap = await db.ref(`mfa_enrollments/${deviceId}`).once("value");

    if (!snap.exists()) {
      req.session.mfa_enroll_required = true;
      return res.redirect("/mfa-enroll.html");
    }

    res.redirect('/remote-work.html');
  } catch (err) {
    console.error('❌ Token exchange error:', err);
    res.status(500).send('Authentication failed: ' + err.message);
  }
});

// 🔑 Expose session tokens to frontend (post-login only)
app.get("/api/session/tokens", (req, res) => {
  if (!req.session?.tokenSet || !req.session.deviceId) {
    return res.status(401).json({ error: "No active session" });
  }

  res.json({
    access_token: req.session.tokenSet.access_token,
    dpop: req.session.dpop,
    device_id: req.session.deviceId
  });
});


app.post("/mfa/enroll", async (req, res) => {
  const deviceId = req.session.deviceId;
  const userId = req.session.userInfo.preferred_username;

  const { answers } = req.body;

  await db.ref(`mfa_enrollments/${deviceId}`).set({
    user_id: userId,
    questions: {
      q1: {
        question: "What is your favorite color?",
        answer_hash: hashAnswer(answers.q1)
      },
      q2: {
        question: "What city were you born in?",
        answer_hash: hashAnswer(answers.q2)
      }
    },
    enrolled_at: new Date().toISOString()
  });

  delete req.session.mfa_enroll_required;
  res.json({ enrolled: true });
});

app.post("/mfa/verify", async (req, res) => {
  const deviceId = req.session.deviceId;
  const { answers } = req.body;

  const snap = await db.ref(`mfa_enrollments/${deviceId}`).once("value");
  if (!snap.exists()) {
    return res.status(403).json({ error: "MFA not enrolled" });
  }

  const stored = snap.val().questions;

  for (const key in answers) {
    if (!verifyAnswer(answers[key], stored[key].answer_hash)) {
      return res.status(403).json({ error: "MFA failed" });
    }
  }

  // MFA success → short-lived flag
  req.session.mfa_passed = true;
  res.json({ success: true });
});


// Logout
app.get('/logout', (req, res) => {
  const id_token = req.session.tokenSet?.id_token;
  req.session.destroy();
  
  if (id_token && keycloakConfig) {
    const logoutParams = new URLSearchParams({
      id_token_hint: id_token,
      post_logout_redirect_uri: 'http://localhost:5173'
    });
    const logoutUrl = `${keycloakConfig.end_session_endpoint}?${logoutParams.toString()}`;
    res.redirect(logoutUrl);
  } else {
    res.redirect('/');
  }
});

// View devices
app.get("/api/devices", (req, res) => {
  if (Object.keys(deviceRegistry).length === 0) {
    return res.send(`
      <html>
      <head><title>No TPM Devices</title>
      <style>body { font-family: Inter, sans-serif; background:#0f172a; color:#f1f5f9; text-align:center; padding:2rem; } a { color:#06b6d4; text-decoration:none; }</style>
      </head>
      <body>
        <h2>📭 No TPM devices registered yet.</h2>
        <p><a href="/">← Back to home</a></p>
      </body>
      </html>
    `);
  }

  const devicesHTML = Object.entries(deviceRegistry)
    .map(([deviceId, info]) => {
      const { user_id, status, registered_at, ek_hash } = info;
      //const encoded = Buffer.from(JSON.stringify(attestation)).toString("base64");
      return `
      <div style="background:#1e293b;padding:1.5rem;margin:1rem auto;width:650px;border-radius:1rem;box-shadow:0 4px 12px rgba(0,0,0,0.3);">
        <h2 style="color:${status === "trusted" ? "#4ade80" : "#f87171"}">${status === "trusted" ? "✅ TRUSTED" : "❌ UNTRUSTED"} TPM Registration</h2>
        <p><b>Device ID:</b> ${deviceId}</p>
        <p><b>User:</b> ${user_id || 'Not bound yet'}</p>
        <p><b>Status:</b> <span style="color:${status === "trusted" ? "#4ade80" : "#f87171"}">${status}</span></p>
        <p><b>Device Identity:</b> TPM-bound</p>
        <p>
          <b>EK Identity:</b><br/>
          <code style="word-break:break-all; color:#38bdf8;">
            ${ek_hash}
          </code>
        </p>

        <p>
          <b>Verification:</b> EK hash sealed via HSM (HMAC)
        </p>

        <p>
          <b>Trust Model:</b> Hardware-rooted Zero Trust
        </p>

        <p><b>Registered At:</b> ${new Date(created_at).toLocaleString()}</p>
      </div>
      `;
    })
    .join("\n");

  const html = `
  <html>
  <head><title>TPM Device Registry</title>
  <style>
    body { font-family: Inter, sans-serif; background:#0f172a; color:#f1f5f9; text-align:center; padding:2rem; }
    a { color:#06b6d4; text-decoration:none; }
  </style>
  </head>
  <body>
    <h1 style="color:#06b6d4;">🔐 TPM Device Registry</h1>
    ${devicesHTML}
    <p><a href="/">← Back to Home</a></p>
  </body>
  </html>
  `;
  
  res.send(html);
});

// app.get("/api/session/tokens", (req, res) => {
//   if (!req.session.tokenSet || !req.session.dpop) {
//     return res.status(401).json({ error: "Not authenticated" });
//   }

//   res.json({
//     access_token: req.session.tokenSet.access_token,
//     dpop: req.session.dpop
//   });
// });


const server = app.listen(5173, () => {
  console.log("✅ Backend running at http://localhost:5173");
}).on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error("❌ Error: Port 5173 is already in use");
  } else {
    console.error("Server error:", err);
  }
  process.exit(1);
});

process.on("SIGINT", () => {
  server.close();
  console.log("\n✅ Server shut down gracefully");
  process.exit(0);
});