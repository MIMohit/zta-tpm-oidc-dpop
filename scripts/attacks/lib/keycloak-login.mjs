/**
 * @file scripts/attacks/lib/keycloak-login.mjs
 * Browser-equivalent login through the gate with Keycloak as the upstream IdP:
 * gate /oauth/authorize -> Keycloak login form -> POST credentials -> gate callback.
 * Cookies are kept per origin and redirects are followed by hand, as a browser would.
 */

/** Minimal per-origin cookie jar. */
export class CookieJar {
  constructor() {
    this.byOrigin = new Map();
  }

  store(url, res) {
    const origin = new URL(url).origin;
    const jar = this.byOrigin.get(origin) || new Map();
    const setCookies = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
    for (const sc of setCookies) {
      const [pair] = sc.split(";");
      const eq = pair.indexOf("=");
      if (eq > 0) jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
    this.byOrigin.set(origin, jar);
  }

  /** Seeds the jar with a Cookie header value ("a=1; b=2") for url's origin. */
  seed(url, cookieHeader) {
    if (!cookieHeader) return;
    const origin = new URL(url).origin;
    const jar = this.byOrigin.get(origin) || new Map();
    for (const part of cookieHeader.split(";")) {
      const eq = part.indexOf("=");
      if (eq > 0) jar.set(part.slice(0, eq).trim(), part.slice(eq + 1).trim());
    }
    this.byOrigin.set(origin, jar);
  }

  header(url) {
    const jar = this.byOrigin.get(new URL(url).origin);
    return jar ? [...jar].map(([k, v]) => `${k}=${v}`).join("; ") : "";
  }
}

function decodeHtml(s) {
  return s.replace(/&amp;/g, "&").replace(/&#x3d;|&#61;/gi, "=").replace(/&quot;/g, '"');
}

/**
 * Step 1: the gate's /oauth/authorize. On success the gate redirects to Keycloak; on a bad
 * request (e.g. a used request_uri) it answers itself.
 * @param {string} authorizeUrl
 * @param {CookieJar} [jar]
 * @returns {Promise<{ jar: CookieJar, status: number, ok: boolean, kcAuthUrl: string|null, body: string|null }>}
 */
export async function gateAuthorize(authorizeUrl, jar = new CookieJar()) {
  // Send the jar's cookies: a second transaction must run in the existing gate session
  const cookie = jar.header(authorizeUrl);
  const res = await fetch(authorizeUrl, { redirect: "manual", headers: cookie ? { Cookie: cookie } : {} });
  jar.store(authorizeUrl, res);
  const location = res.headers.get("location");
  if (res.status >= 300 && res.status < 400 && location) {
    return { jar, status: res.status, ok: true, kcAuthUrl: new URL(location, authorizeUrl).toString(), body: null };
  }
  return { jar, status: res.status, ok: res.ok, kcAuthUrl: null, body: await res.text().catch(() => "") };
}

/**
 * Step 2: Keycloak's login form, then the gate callback.
 * @param {Object} params
 * @param {string} params.kcAuthUrl - Keycloak authorization URL from gateAuthorize
 * @param {CookieJar} params.jar
 * @param {string} params.username
 * @param {string} params.password
 * @param {Record<string,string>} [params.headers] - extra headers for the gate callback (e.g. X-ZTA-Sim-IP)
 * @returns {Promise<{ status: number, data: Object, gateCookie: string }>}
 */
export async function keycloakCredentials({ kcAuthUrl, jar, username, password, headers = {} }) {
  const pageRes = await fetch(kcAuthUrl, { redirect: "manual", headers: { Cookie: jar.header(kcAuthUrl) } });
  jar.store(kcAuthUrl, pageRes);
  const html = await pageRes.text();
  const action = html.match(/<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"/i)?.[1] || html.match(/<form[^>]*action="([^"]+)"/i)?.[1];
  if (!action) throw new Error(`Keycloak login form not found (${pageRes.status})`);
  const formUrl = new URL(decodeHtml(action), kcAuthUrl).toString();

  const loginRes = await fetch(formUrl, {
    method: "POST",
    redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: jar.header(formUrl) },
    body: new URLSearchParams({ username, password, credentialId: "" }).toString(),
  });
  jar.store(formUrl, loginRes);
  const callbackUrl = loginRes.headers.get("location");
  if (!callbackUrl || loginRes.status < 300 || loginRes.status >= 400) {
    // Keycloak re-renders its form for bad credentials: report it as the gate would
    return { status: 401, data: { error: "invalid_credentials", error_description: "Keycloak rejected the credentials" }, gateCookie: "" };
  }

  const cbHeaders = { Accept: "application/json", ...headers, Cookie: jar.header(callbackUrl) };
  const cbRes = await fetch(callbackUrl, { redirect: "manual", headers: cbHeaders });
  jar.store(callbackUrl, cbRes);
  const text = await cbRes.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { error: "non_json_response", message: text.slice(0, 300) };
  }
  return { status: cbRes.status, data, gateCookie: jar.header(callbackUrl) };
}

/**
 * Logs a user in through the gate in IDP_MODE=keycloak (steps 1 and 2).
 * @returns {Promise<{ jar: CookieJar, gateCookie: string, status: number, data: Object }>}
 */
export async function keycloakBrowserLogin({ authorizeUrl, username, password, simIp, jar = new CookieJar() }) {
  const auth = await gateAuthorize(authorizeUrl, jar);
  if (!auth.kcAuthUrl) {
    throw Object.assign(new Error(`Gate did not redirect to Keycloak (${auth.status}): ${(auth.body || "").slice(0, 200)}`), { status: auth.status });
  }
  const r = await keycloakCredentials({ kcAuthUrl: auth.kcAuthUrl, jar, username, password, headers: simIp ? { "X-ZTA-Sim-IP": simIp } : {} });
  return { jar, ...r };
}
