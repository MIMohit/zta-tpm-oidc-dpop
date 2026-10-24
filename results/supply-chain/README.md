# Supply chain

- `sbom.cdx.json`: CycloneDX 1.5 SBOM of the production dependency tree (`python3 scripts/sbom.py`, from `package-lock.json`).
- `npm-audit-prod.json`: `npm audit --omit=dev`, 2026-10-23.
- `npm-audit-reachability.json`: each advisory mapped to the top-level dependency that pulls it in.

## Findings (2026-10-23)

`npm audit` reports 31 advisories in the production tree. 27 of them come through dependencies that the
evaluated services never load:

- `keycloak-connect`, `axios`, `openid-client`, `uuid`: declared in `package.json`, imported nowhere (the gate
  talks to Keycloak with `jose` in `lib/idp/keycloak-upstream.js`).
- `firebase-admin`: imported lazily by `lib/store.js` only when `STORE=firebase`; every evaluated stack uses the
  file store.

Four come through `express` (`proxy-addr`, `path-to-regexp`, `qs`, `body-parser`). `proxy-addr` matters only
when Express's `trust proxy` setting is enabled; no service enables it, and the client IP used for the risk score is
taken from the TCP socket (`lib/idp/client-ip.js`, `pep.js`). The others are denial-of-service issues in request
parsing, out of scope for the evaluation (threat T5 excludes large-scale DoS) but fixed by updating `express`
within its semver range.

Recommended before release: remove the unused dependencies, make `firebase-admin` an optional dependency, and
run `npm audit fix` for the `express` subtree.
