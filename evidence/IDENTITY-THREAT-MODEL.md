# WP-G2-I01 identity threat model

- **Checkpoint:** 2026-07-19
- **Scope:** provider-neutral OIDC Authorization Code + PKCE login and opaque browser sessions (`packages/auth-web`)
- **Human gate:** `identity-threat-model-review` — **pending owner disposition**
- **Authorities:** `docs/specifications/IDENTITY-AUTHORIZATION.md`, `contracts/openapi/auth.v1.yaml`, `contracts/schemas/browser-session.v1.schema.json`, ADR-0002 section 2

This document supports the human gate; it does not accept it. Acceptance is the
repository owner's explicit disposition, recorded separately, and is not a WCAG,
penetration-test or production certification.

## Assets

- The `(issuer, subject)` identity and its opaque `usr_*` / `ten_*` mapping.
- The application session cookie value and its keyed digest.
- The CSRF synchronizer secret and its digest.
- The OIDC transaction state, nonce and PKCE verifier.
- Provider ID tokens in transit (never at rest).

## Trust boundaries

1. Browser ↔ BFF: only opaque `__Host-` cookies cross; no token, digest or
   provider claim is exposed to the browser.
2. BFF ↔ OIDC issuer: confidential client, exact HTTPS issuer allowlist,
   Authorization Code + PKCE `S256`.
3. BFF ↔ authorization issuer (`crates/authz-biscuit`): out of scope here; a
   browser never receives a Biscuit and this package issues none.
4. BFF ↔ durable storage (`WP-G2-D01`): modelled as ports; the in-memory
   implementation is qualification-only.

## Threats, mitigations and evidence

| STRIDE          | Threat                                                           | Mitigation                                                                                                          | Evidence                                                             |
| --------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Spoofing        | Forged/unsigned ID token (`alg=none`, HMAC public-key confusion) | Closed `RS256`/`ES256` allowlist; algorithm checked before any verify; asymmetric keys only                         | `src/oidc/jws.test.ts`                                               |
| Spoofing        | Issuer/audience substitution                                     | Exact issuer and audience equality after signature                                                                  | `src/oidc/jws.test.ts`                                               |
| Tampering       | Modified payload with valid-shape signature                      | Signature bound to `header.payload`; tamper fails verify                                                            | `src/oidc/jws.test.ts`                                               |
| Repudiation     | Replayed authorization code or nonce                             | One-use PKCE-bound code; nonce bound to the one-use transaction; cross-transaction replay refused                   | `src/oidc/jws.test.ts`, `src/oidc/transaction.test.ts`               |
| Info disclosure | Provider tokens/secrets in logs or storage                       | Digests-only record; captured-console inspection over a full cycle and a refusal                                    | `src/observability/redaction.test.ts`, `src/session/session.test.ts` |
| Info disclosure | User/tenant existence leak in refusals                           | Single stable refusal codes; generic 401; identical shapes                                                          | `src/http/handlers.test.ts`                                          |
| Elevation       | Session fixation across authentication                           | Fresh cookie and CSRF secret on session creation; rotation retires the old cookie                                   | `src/session/session.test.ts`                                        |
| Elevation       | Cross-tenant identity confusion                                  | `(issuer, subject)` digest mapped server-side to opaque facts; unmapped subject fails closed                        | `src/oidc/transaction.test.ts`                                       |
| DoS/abuse       | Stale or long-lived transaction                                  | 10-minute one-use transaction; expiry enforced under injected clock                                                 | `src/oidc/transaction.test.ts`                                       |
| Redirect abuse  | Open redirect via `returnPath`                                   | Anti-open-redirect pattern (absolute local path, no scheme/authority, no `//`) enforced at the handler and the flow | `src/http/handlers.test.ts`                                          |

## Residual risks (for the reviewer)

- The durable membership source and its revision authority are ports; the
  cross-tenant guarantee is only as strong as the `WP-G2-D01` implementation
  and its RLS defence-in-depth.
- Absolute-expiry and idle-timeout correctness relies on a trusted server
  clock; production must use a monotonic source and reject rollback.
- Session storage is in-memory here, so refusal-evidence retention and
  cross-instance revocation are proven only against the port contract.

## Open question for the gate

`auth.session_revision_mismatch` (HTTP 412) extends the locked refusal table
for the logout precondition. It must be ratified with the `auth.v1` owner, or
the DELETE precondition remapped onto an existing code, before this gate is
accepted.
