# Zero Trust with TPM-attested token binding and adaptive MFA

A Zero Trust identity system in which every OpenID Connect / OAuth 2.0 token is bound, with DPoP (RFC 9449),
to a key that the device's **TPM 2.0 generated, certified and attested**, and a session is accepted only if a
fresh attestation result names that same key. An unmodified **Keycloak** authenticates users; a device gate adds
TPM enrolment, boot-state appraisal, pushed authorization requests (RFC 9126), PKCE and risk-adaptive
**WebAuthn step-up**; a **PEP/PDP/PIP** layer checks a TPM-signed proof and the device's current state on every
request. The repository also contains the evaluation: an attack suite of 25 attacks, an ablation switchboard for
28 security mechanisms, benchmarks, a ProVerif model, a fuzzer and the testbed scripts, together with the raw
results.

## Contents

- [Results at a glance](#results-at-a-glance)
- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Testbed](#testbed)
- [Reproducing the evaluation](#reproducing-the-evaluation)
- [The ablation switchboard](#the-ablation-switchboard)
- [Configuration](#configuration)
- [Security notes](#security-notes)
- [Results data](#results-data)

## Results at a glance

| Experiment | Result |
|---|---|
| E1 attack suite, in-process (real `swtpm`, 33 configurations × 25 attacks × 10 repetitions) | 11,550 trials, 0 errors, **0 outcomes differ from the prediction**, 0 attacks succeed under the full design |
| E1 attack suite, live (fresh stack per trial, Keycloak, SoftHSM, TLS 1.3, 3 repetitions) | 3,465 trials, 0 mismatches, 0 attacks succeed; 825/825 (attack, configuration) cells agree with in-process |
| Ablation | 26 of 28 mechanisms individually necessary; M6+M7 and M15+M16 are defence-in-depth pairs |
| Baselines | plain OIDC (B0) admits 19 attacks, software DPoP (B1) 15, attestation without key binding (B2) 6, no per-request state (B3) 1 |
| ProVerif (attacker controls the network **and every device's host**) | 4 properties proved for the full design; each of 8 single-mechanism variants yields an attack trace |
| Real UEFI boots | a PCR0–7 profile admits a device with a replaced kernel; the deployed PCR0–9 profile refuses it |
| Fuzzing (6 parsers × 200,000 inputs) | 29 + 7 false accepts found and fixed; 0 after the fixes |
| Cost (swtpm, TLS, paired design) | login 123.8 ms vs 117.5 ms for plain OIDC; protected request 10.4 ms vs 10.3 ms |
| Cost on an AMD firmware TPM | enrolment 3.2 s (94 % TPM), protected request 177 ms (93 % TPM signature) |
| PEP throughput (4 cores, TLS) | 250 req/s sustained (p50 12.6 ms, p99 38 ms); overloaded at 300 req/s |
| Revocation | effective at the next request: median 18.4 ms, p95 26.9 ms (B3: ~5 min) |
| TLS | +0.6 ms per request, +14 ms per login |
| Adaptive step-up (synthetic, 1,000 users × 37 days × 5 seeds) | 72.8 % of attack logins stepped up, 0.00 % of legitimate logins |

## Architecture

```
 USER DEVICE                      ENTERPRISE ZERO-TRUST PLANE                                  INTERNAL
 ┌───────────────┐  enrol/attest ┌──────────────────────┐   AR, tokens and audit keys  ┌─────┐
 │ TPM 2.0       │◄─────────────►│ Attestation verifier │─────────────────────────────►│ HSM │
 │ EK, AK, K_B   │      (1)      │  :4005  M1–M8, M23   │                              └─────┘
 │ PCRs, log     │               └──────────────────────┘
 ├───────────────┤  PAR(AR, dpop_jkt), login, token (2)                 ┌──────────────┐
 │ Agent+browser │◄──────────────────────────────────►┌────────────────┐│ Keycloak 26  │
 │ (DPoP proofs  │                                    │ IdP gate :5173 ├┤ password,    │
 │  signed by    │                                    │ M9–M14, M22,   ││ OIDC + PKCE  │
 │  K_B in TPM)  │                                    │ M24, M25, M27  │└──────────────┘
 │ WebAuthn      │  request + TPM-signed DPoP proof (3)└────────────────┘
 └───────────────┘──────────────►┌───────────┐  ┌───────────┐  ┌───────────────┐   ┌──────────────┐
                                 │ PEP :4001 │─►│ PDP :4002 │─►│ PIP :4003 +   │   │ Resource     │
                                 │ M15–M19   │  │ M20,M21,  │  │ registry :4004│   │ server :5001 │
                                 └─────┬─────┘  │ M28       │  └───────────────┘   │ (PEP only,   │
                                       └────────┴───────────┴── forward (4) ──────►│  M26)        │
                                                                                   └──────────────┘
```

1. **Enrolment** (Alg. 1): EK certificate chain to a vendor root and inventory check, credential activation
   (AK ↔ EK), a quote over the device's PCR profile under a fresh nonce, `TPM2_Certify` of the binding key `K_B`.
2. **Login** (Alg. 3): PAR carrying the attestation result and `dpop_jkt = Thumb(K_B)`; check **C2**
   `AR.jkt = dpop_jkt`; Keycloak password login; owner/status check; risk score (Alg. 4) → WebAuthn step-up;
   authorization code bound to `jkt`; token endpoint with a TPM-signed DPoP proof; access token with `cnf.jkt`.
3. **Request** (Alg. 5): DPoP scheme, **C3** proof key = `cnf.jkt`, server nonce, replay cache and `iat` window,
   `htm`/`htu`/`ath`; the PDP reads device status, attestation age and risk from the PIP for every request.
4. **Lifecycle**: re-attestation every `T_RA` (300 s); a failed appraisal suspends the device; revocation takes
   effect at the next request; replayed evidence cannot suspend a device.

All services speak TLS 1.3 when started with `ZTA_TLS_CERT`/`ZTA_TLS_KEY`; signing keys live in a PKCS#11 HSM
(SoftHSM in the testbed); the PEP keeps a hash-chained, HSM-signed audit log.

## Repository layout

| Path | Contents |
|---|---|
| `server.js`, `pep.js`, `pdp.js`, `pip.js` | IdP gate, policy enforcement, decision and information points |
| `services/` | attestation verifier, device registry, resource server |
| `lib/verifier/` | enrolment (Alg. 1), appraisal with reference-value profiles (Alg. 2), EK certificates, event-log replay |
| `lib/idp/` | PAR, authorize, Keycloak upstream, device gate, token endpoint, WebAuthn |
| `lib/agent-client.js` | device agent: enrolment, attestation, login, DPoP-signed requests |
| `lib/tpm-real/`, `lib/tpm2/`, `lib/sim-tpm/` | TPM 2.0 backends (kernel resource manager, `swtpm` over TCP, simulator) |
| `lib/ablation.js` | the 28 mechanisms and the baselines; the switchboard |
| `lib/risk.js`, `lib/policy.js` | risk score (Alg. 4) and PDP policy |
| `lib/tls.js`, `lib/hsm.js`, `lib/audit-log.js` | TLS listener, PKCS#11 keys, signed audit log |
| `scripts/attacks/` | the 25 attacks, prediction rules (`lib/expected.mjs`), runners `run.mjs` and `matrix.mjs` |
| `scripts/stack.mjs` | starts a complete live stack (services, SoftHSM token, Keycloak settings, TLS) |
| `bench/` | benchmarks E2–E5, E7, E9 and the adaptive-MFA simulation (E6) |
| `scripts/bench/` | benchmark drivers (`run-all.sh`, `run-rerun.sh`) |
| `scripts/fuzz/` | mutation fuzzer for the six parsers that take attacker-controlled bytes |
| `formal/` | ProVerif model (`zta.pv.in`), variant generator and runner (`run.py`) |
| `testbed/` | KVM fleet with measured boot, `swtpm` CAs, Keycloak, TLS material, reference-value capture |
| `fixtures/` | event logs, reference-value profiles (with checksums and provenance) |
| `tests/` | unit, integration and regression tests (`npm test`) |
| `results/` | raw results of the final runs (see [Results data](#results-data)) |

## Requirements

- Node.js ≥ 20 (evaluated with Node 26)
- `swtpm` and `swtpm_setup` (libtpms) for emulated TPMs; `tpm2-tools` only for capturing fixtures
- Docker, for Keycloak 26.0.7 (`quay.io/keycloak/keycloak:26.0.7`)
- SoftHSM 2 (or another PKCS#11 module) for HSM-held signing keys
- OpenSSL, for the testbed TLS material
- Optional: QEMU/KVM with OVMF for the measured-boot device fleet; a Linux host with a TPM 2.0
  (`/dev/tpmrm0`) for hardware measurements; ProVerif 2.05 and Python 3 for the formal analysis

## Quick start

```sh
npm install
npm test                                   # unit and regression tests (299)

# The attack suite in-process against the full design, with emulated TPMs
node scripts/attacks/run.mjs --attacks all --config full --tpm swtpm

# One attack against one ablation, e.g. A11 with check C2 (M10) switched off
node scripts/attacks/run.mjs --attacks A11 --config -M10 --tpm swtpm
```

## Testbed

```sh
testbed/tls.sh                             # testbed CA + server certificate (testbed/state/tls)
testbed/keycloak.sh start                  # Keycloak on :8080 (HTTP) and :8443 (HTTPS), realm zta-realm

# A live stack with TLS on every service (keep it running; Ctrl-C stops it)
ZTA_TLS=1 NODE_EXTRA_CA_CERTS=$PWD/testbed/state/tls/ca.pem node scripts/stack.mjs up --config full --idp keycloak
```

Every client that talks to a TLS stack, the harness included, must trust the testbed CA through
`NODE_EXTRA_CA_CERTS`; nothing disables certificate verification.

The measured-boot fleet (four Ubuntu VMs with UEFI measured boot and one `swtpm` each: a golden device, a device
with a replaced kernel, a rogue device not in the inventory and a device with a foreign EK certificate) is built
and controlled with `testbed/fleet.sh`; `node scripts/fleet-check.mjs [--profile grub|pcr0-7] [--with-hw]` runs
the full protocol from every device against a live stack. See `testbed/README.md` and `testbed/dev-hw.md` (hardware
TPM).

## Reproducing the evaluation

| Experiment | Command |
|---|---|
| E1 ablation, in-process | `node scripts/attacks/matrix.mjs --tpm swtpm --reps 10 --out results/e1/inproc` |
| E1 ablation, live with TLS | `ZTA_TLS=1 NODE_EXTRA_CA_CERTS=$PWD/testbed/state/tls/ca.pem node scripts/attacks/matrix.mjs --mode live --orchestrate --idp keycloak --tpm swtpm --reps 3 --out results/e1/live` |
| E2–E5, E7, E9 (idle host) | `[ZTA_TLS=1] scripts/bench/run-all.sh results/bench/<run>` |
| Paired E3/E9 and the load knee | `scripts/bench/run-rerun.sh results/bench/<run>` |
| E6 adaptive step-up | `make e6` |
| Fuzzing | `make fuzz` |
| Formal analysis | `make formal` (needs `proverif` on the path or `PROVERIF=…`) |
| Real-boot check (pitfall P-2) | `node scripts/fleet-check.mjs --profile grub` and `--profile pcr0-7` |
| Supply chain | `npm audit --omit=dev`, `python3 scripts/sbom.py` |

Every trial is predicted before it runs (`scripts/attacks/lib/expected.mjs`); each result row records the
prediction, the outcome, where the attack was stopped, the configuration, a hash of the code and the stack
(`tls`, `hsm`, `idp`). A failure to reach a service is recorded as an execution error, never as a rejection.
Timing benchmarks pin services and clients to disjoint cores (`STACK_CPUS`, `CLIENT_CPUS`) and should run on an
otherwise idle host.

## The ablation switchboard

Mechanisms are switched off at service start-up, never at run time:

```sh
ZTA_ABLATE=M10 node server.js              # one mechanism off (check C2)
ZTA_ABLATE=M6,M7 ...                       # several
ZTA_BASELINE=B2 ...                        # a baseline: B0 OIDC+PKCE (Bearer), B1 + software DPoP,
                                           # B2 + attestation not bound to the key, B3 no per-request state,
                                           # B4 static MFA (E6 only)
node scripts/print-ablation.mjs            # the mechanism table
```

Unknown identifiers are refused, every service prints the active configuration, and the production guard refuses
any ablation.

## Configuration

| Variable | Meaning (default) |
|---|---|
| `ZTA_TLS_CERT`, `ZTA_TLS_KEY` | serve HTTPS with this certificate (unset: HTTP, refused in production) |
| `IDP_ISSUER`, `VERIFIER_URL`, `PIP_URL`, `PDP_URL`, `PEP_PUBLIC_URL`, `RESOURCE_URL` | service URLs |
| `IDP_MODE`, `KEYCLOAK_ISSUER`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET` | `keycloak` for the upstream IdP (`testbed/keycloak.sh env`) |
| `ZTA_TAU_AR`, `ZTA_T_AT`, `ZTA_T_RA`, `ZTA_T_NONCE`, `ZTA_W_JTI`, `ZTA_SKEW`, `ZTA_T_SU` | protocol times (120, 300, 300, 60, 120, 30, 300 s) |
| `ZTA_THETA_LOGIN`, `ZTA_THETA_DENY` | login step-up and deny thresholds (0.5, 0.85) |
| `EK_ROOTS_DIR`, `EK_INTERMEDIATES_DIR` | trusted TPM vendor roots and intermediates |
| `VERIFIER_RV_PROFILES` | reference-value profiles, `name=path,…` (PCR set declared per profile) |
| `ZTA_PKCS11_LIB`, `SOFTHSM2_CONF` | PKCS#11 module for the signing keys |
| `ZTA_ENV=production` | enables the production guard (see below) |
| `ZTA_SIM_IP_HEADER` | evaluation only: trust `X-ZTA-Sim-IP` as the client location (refused in production) |

## Security notes

- With `ZTA_ENV=production` the services refuse to start with a plain-HTTP listener or a non-`https` service URL,
  a simulated client-IP header, trust-on-first-use of boot digests, ignored EK-certificate expiry, debug
  endpoints, a non-TPM device backend, development secrets or any ablation.
- The testbed runs Keycloak in development mode and uses a local CA; neither is a production configuration.
- Out of scope: denial of service, physical extraction of TPM keys (e.g. fault injection on firmware TPMs),
  compromise after a measured boot that leaves measured components unchanged.
- `results/supply-chain/README.md` records the dependency audit: most advisories come from dependencies the
  services do not load.

## Results data

| Path | Contents |
|---|---|
| `results/e1-final/20261024-final/inproc-swtpm/` | E1 in-process: `attacks.jsonl` (one row per trial), matrices, manifests |
| `results/e1-final/20261024-final/live-tls/` | E1 live with TLS: `attacks.jsonl`, `attacks-merged.jsonl` (four trials whose stack failed to start replaced by a re-run, see `MERGE.md`) |
| `results/e1-final/20261023-1623/bench/` | E2–E5, E7, E9 without TLS |
| `results/e1-final/20261023-1623/bench-tls/` | the same with TLS 1.3; `paired/` E3/E9 with the paired design; `e4-knee/` intermediate load rates |
| `results/e6-risk/` | adaptive step-up simulation, five seeds |
| `results/fuzz/` | fuzzing before and after the fixes |
| `results/fleet-check/` | real-boot runs under the PCR0–9 and PCR0–7 profiles |
| `results/supply-chain/` | `npm audit`, reachability analysis, CycloneDX SBOM |
| `formal/results/` | generated ProVerif models and outputs per variant |

Each benchmark directory contains `env-start.json`/`env-end.json` with the host environment; each E1 run contains
manifests with the code hash and configuration.
