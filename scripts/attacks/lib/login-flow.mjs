/**
 * @file scripts/attacks/lib/login-flow.mjs
 * The user-login half of the authorisation flow, for attacks that drive it step by step:
 *   const auth = await ctx.authorize(authorizeUrl);              // gate /oauth/authorize
 *   const loginRes = await ctx.primaryLogin({ auth, username, password });
 * With the local IdP the password goes to the gate's /oauth/login. With Keycloak as the main
 * IdP it goes through Keycloak's login form and the gate callback, as a browser would; the
 * gate's local login is disabled in that mode.
 */

import { CookieJar, gateAuthorize, keycloakCredentials } from "./keycloak-login.mjs";

function responseLike(status, data) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(),
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

/**
 * @param {{ idpUrl: string, idpMode?: "local"|"keycloak" }} target
 */
export function loginFlow({ idpUrl, idpMode = "local" }) {
  /**
   * @param {string} authorizeUrl
   * @param {{ cookie?: string }} [opts] - an existing gate session (a second transaction in it)
   * @returns {Promise<{ res: Object, cookie: string, jar?: CookieJar, kcAuthUrl?: string|null }>}
   */
  async function authorize(authorizeUrl, { cookie } = {}) {
    if (idpMode === "keycloak") {
      const jar = new CookieJar();
      jar.seed(authorizeUrl, cookie);
      const a = await gateAuthorize(authorizeUrl, jar);
      let data = null;
      try {
        data = a.body ? JSON.parse(a.body) : { redirect: a.kcAuthUrl };
      } catch {
        data = { error: "non_json_response", message: (a.body || "").slice(0, 300) };
      }
      return { res: responseLike(a.ok ? 200 : a.status, data), cookie: jar.header(authorizeUrl), jar, kcAuthUrl: a.kcAuthUrl };
    }
    const res = await fetch(authorizeUrl, cookie ? { headers: { Cookie: cookie } } : undefined);
    return { res, cookie: (res.headers.get("set-cookie") || "").split(";")[0] || cookie || "" };
  }

  /**
   * @param {{ auth: Awaited<ReturnType<typeof authorize>>, username: string, password: string, headers?: Record<string,string> }} p
   * @returns {Promise<Object>} a fetch Response (local) or a response-like object (Keycloak)
   */
  async function primaryLogin({ auth, username, password, headers = {} }) {
    if (idpMode === "keycloak") {
      if (!auth.kcAuthUrl) return responseLike(400, { error: "invalid_request", error_description: "Authorization did not reach Keycloak" });
      const r = await keycloakCredentials({ kcAuthUrl: auth.kcAuthUrl, jar: auth.jar, username, password, headers });
      auth.cookie = r.gateCookie || auth.cookie;
      return responseLike(r.status, r.data);
    }
    return fetch(`${idpUrl}/oauth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json", ...headers, Cookie: auth.cookie },
      body: JSON.stringify({ username, password }),
    });
  }

  return { authorize, primaryLogin };
}
