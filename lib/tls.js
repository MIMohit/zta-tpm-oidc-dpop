/**
 * @file lib/tls.js
 * TLS for every service endpoint (security requirements S2 and S4). With ZTA_TLS_CERT and
 * ZTA_TLS_KEY set, a service listens with HTTPS (TLS 1.2 minimum, 1.3 preferred, server
 * authentication only); otherwise it listens with plain HTTP, which the production guard in
 * lib/config.js refuses. Clients verify the server against the system trust store plus
 * NODE_EXTRA_CA_CERTS, so no service ever disables certificate verification.
 */

import fs from "node:fs";
import http from "node:http";
import https from "node:https";

/**
 * TLS server options from the environment, or null for plain HTTP.
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {https.ServerOptions | null}
 */
export function tlsServerOptions(env = process.env) {
  const certFile = env.ZTA_TLS_CERT;
  const keyFile = env.ZTA_TLS_KEY;
  if (!certFile && !keyFile) return null;
  if (!certFile || !keyFile) throw new Error("ZTA_TLS_CERT and ZTA_TLS_KEY must be set together");
  return {
    cert: fs.readFileSync(certFile),
    key: fs.readFileSync(keyFile),
    minVersion: "TLSv1.2",
  };
}

/**
 * Starts an Express app on HTTPS when TLS is configured, else on HTTP.
 * @param {import('express').Express} app
 * @param {number|string} port
 * @param {string|undefined} host - undefined listens on all interfaces
 * @param {(url: string) => void} [onListening] - receives the base URL
 * @returns {http.Server | https.Server}
 */
export function listen(app, port, host, onListening) {
  const opts = tlsServerOptions();
  const server = opts ? https.createServer(opts, app) : http.createServer(app);
  const scheme = opts ? "https" : "http";
  server.listen(Number(port), host, () => onListening?.(`${scheme}://${host && host !== "0.0.0.0" ? host : "localhost"}:${port}`));
  return server;
}

export default { tlsServerOptions, listen };
