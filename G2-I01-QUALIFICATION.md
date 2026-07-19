# WP-G2-I01 — OIDC and opaque browser session qualification

- **Checkpoint:** 2026-07-19
- **Status:** implementation complete; both human gates pending
- **Runtime:** Bun `>=1.4.0`; qualification evidence uses exact bootstrap Bun `1.4.0-canary.1+57f349f63`
- **Production status:** blocked
- **Human gates:** `identity-threat-model-review`, `browser-session-security-review` — **not accepted**

## Acceptance map

| Locked acceptance                                                                            | Evidence                                                                                                                                                                                                                                                                                                                                        |
| -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| State, nonce, PKCE, issuer, audience, expiry and replay negative vectors fail closed         | `src/oidc/jws.test.ts` (alg=none, HMAC public-key confusion, EdDSA/ES384/RS512, unknown/missing kid, tampered payload, issuer/audience/nonce substitution, expired/future token, malformed JWS) and `src/oidc/transaction.test.ts` (one-use transaction, state divergence, stale transaction, cross-transaction nonce replay, unmapped subject) |
| Cookie attributes, CSRF, rotation, idle/absolute expiry and logout pass real-browser tests   | `e2e/auth.e2e.ts` on Chromium, Firefox and WebKit: full PKCE login, Secure/HttpOnly/SameSite=Strict opaque cookie invisible to `document.cookie`, synchronizer-token logout, idle and absolute expiry under server time travel; unit rotation and CSRF coverage in `src/session/session.test.ts` and `src/csrf/csrf.test.ts`                    |
| Provider tokens, cookie values and CSRF secrets are absent from logs and storage projections | `src/observability/redaction.test.ts` (captured-console inspection of a full login/logout cycle and a refusal) and the digests-only session record asserted in `src/session/session.test.ts`                                                                                                                                                    |

## Delivered boundary

- `@libre-ai/auth-web`: the four browser endpoints of `contracts/openapi/auth.v1.yaml`
  (`POST /v1/auth/login`, `GET /v1/auth/callback`, `GET /v1/auth/session`,
  `DELETE /v1/auth/session`), provider-neutral OIDC Authorization Code + PKCE
  (`S256`), a closed `RS256`/`ES256` ID-token verification boundary, opaque
  keyed-digest sessions, a CSRF synchronizer with Origin/Fetch-Metadata
  defence, and an in-process deterministic development issuer.
- Storage is a port with a deterministic in-memory implementation; the
  membership source and durable adapters are ports whose real
  implementations belong to `WP-G2-D01`.

## Contract conformity

- Every persisted session record validates against
  `browser-session.v1.schema.json` through the canonical registry before it
  is stored; identity facts that violate the shape fail closed.
- `GET /v1/auth/session` returns exactly the six contract fields
  (`userId`, `tenantId`, `roles`, `idleExpiresAt`, `absoluteExpiresAt`,
  `revision`) — no digest, secret or membership internal.
- Refusals use the `problem-details.v1` envelope and reveal the stable code
  only; a strict registry assertion validates the emitted problem.

## Cookie and CSRF protocol

- `__Host-libre_ai_oidc`: Secure, HttpOnly, SameSite=Lax, Path=/, 10-minute
  one-use transaction cookie; only its keyed digest is stored.
- `__Host-libre_ai_session`: Secure, HttpOnly, SameSite=Strict, Path=/, no
  Domain, ≥256-bit opaque value; only its HMAC-SHA-256 keyed digest is stored.
- Idle timeout 30 minutes (sliding), absolute lifetime 12 hours (fixed);
  authentication and CSRF refresh rotate the relevant secret.
- Cookie-authenticated mutations require exact allowed Origin, same-origin
  Fetch Metadata where present, a synchronizer `X-CSRF-Token`, a well-formed
  `Idempotency-Key` and an `If-Match` revision precondition.

## Refusal codes owned by this package

`auth.oidc_state_invalid`, `auth.oidc_claim_invalid`, `auth.session_missing`,
`auth.session_expired`, `auth.session_revoked`, `auth.csrf_invalid`. The
Biscuit codes (`auth.biscuit_invalid`, `auth.biscuit_revoked`,
`auth.operation_denied`) and the shared `auth.key_unavailable` belong to the
authorization issuer (`crates/authz-biscuit`). `auth.tenant_mismatch` is
reserved for the authorizer boundary consuming these facts.

A `412` precondition uses the candidate code `auth.session_revision_mismatch`,
recorded here for the `browser-session-security-review` gate: it extends the
locked refusal table and must be ratified with the contract owner before the
gate is accepted.

## Verification record

```text
bun run check:bun:runtime                     PASS — Bun 1.4.0
bun test packages/auth-web                     PASS — 66 tests, 6 files
bun run --cwd packages/auth-web e2e            PASS — 9/9 across Chromium, Firefox, WebKit
bun run lint                                   PASS
bun run typecheck                              PASS
```

The complete root Bun gate (`bun run check`) and REUSE lint pass on the tree
that carries this package. No external dependency was added: cryptography
uses the Bun WebCrypto API only, and `@playwright/test` joins through the
existing testing catalog.

## Deferred and blocked

- The `/v1/internal/*` Biscuit issuance, attenuation, revocation, key and
  rotation surface of `auth.v1` is not implemented here; it belongs to the
  authorization issuer and its later integration. A browser never receives a
  Biscuit.
- Durable PostgreSQL/Redis session storage, the real membership source and
  the operational retention job belong to `WP-G2-D01`; this package delivers
  the ports and an in-memory implementation only.
- Sovereign production-provider selection, secret storage and Clever
  infrastructure remain `G4`.
- The Bun production gate, `g2-foundation-acceptance` and all Clever Cloud
  actions remain blocked. Neither human gate is accepted; no production,
  user-data or release authority is granted.
