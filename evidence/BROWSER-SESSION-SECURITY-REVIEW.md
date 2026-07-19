# WP-G2-I01 browser session security review

- **Checkpoint:** 2026-07-19
- **Scope:** opaque browser session lifecycle, cookies, CSRF and logout (`packages/auth-web`)
- **Human gate:** `browser-session-security-review` — **pending owner disposition**
- **Authorities:** `docs/specifications/IDENTITY-AUTHORIZATION.md`, `contracts/openapi/auth.v1.yaml`, `contracts/schemas/browser-session.v1.schema.json`

This document supports the human gate; it does not accept it. Acceptance is the
repository owner's explicit disposition, recorded separately, and grants no
production, user-data or release authority.

## Cookie posture

| Property           | Transaction cookie     | Session cookie                 | Evidence                                                   |
| ------------------ | ---------------------- | ------------------------------ | ---------------------------------------------------------- |
| Name               | `__Host-libre_ai_oidc` | `__Host-libre_ai_session`      | `src/http/handlers.test.ts`                                |
| Secure / HttpOnly  | yes / yes              | yes / yes                      | `src/http/handlers.test.ts`, `e2e/auth.e2e.ts`             |
| SameSite           | Lax                    | Strict                         | `src/http/handlers.test.ts`, `e2e/auth.e2e.ts`             |
| Path / Domain      | `/` / none             | `/` / none                     | `src/http/handlers.test.ts`                                |
| Lifetime           | 10 min, one use        | idle 30 min, absolute 12 h     | `src/http/handlers.test.ts`, `src/session/session.test.ts` |
| Stored form        | keyed digest only      | HMAC-SHA-256 keyed digest only | `src/session/session.test.ts`                              |
| Browser visibility | —                      | invisible to `document.cookie` | `e2e/auth.e2e.ts`                                          |

## Session state machine

- `active → revoked | expired`, no reactivation; revoked and expired records
  refuse immediately and stay addressable until expiry + 24 hours for
  refusal/replay evidence, then prune.
- Idle expiry slides on activity **without** bumping the optimistic revision,
  so a client `If-Match` precondition never goes stale by construction;
  absolute expiry is fixed and refuses even under continuous activity.
- Evidence: `src/session/session.test.ts`, `e2e/auth.e2e.ts`.

## CSRF and logout

- Cookie-authenticated mutations require: exact allowed `Origin`, same-origin
  `Sec-Fetch-Site` where present, a synchronizer `X-CSRF-Token` compared in
  constant time against the stored digest, a well-formed `Idempotency-Key`,
  and an `If-Match` revision precondition.
- Ordering on `DELETE /v1/auth/session`: resolve session → header format (400)
  → CSRF/Origin defence (403) → revision precondition (412) → revoke the
  server record → clear the cookie (204). Revocation precedes cookie clearing.
- Evidence: `src/csrf/csrf.test.ts`, `src/http/handlers.test.ts`,
  `e2e/auth.e2e.ts`.

## Secret handling

- No raw cookie, CSRF secret, PKCE verifier, authorization code or provider
  token is stored or logged; a captured-console cycle and a refusal assert
  absence. The stored record carries digests only.
- Evidence: `src/observability/redaction.test.ts`, `src/session/session.test.ts`.

## Findings for the reviewer

1. **Refusal-code addition (must ratify).** The logout revision precondition
   emits `auth.session_revision_mismatch` (412), which is not in the locked
   refusal table. Either ratify the addition with the `auth.v1` owner or remap
   the precondition onto an existing code before accepting this gate.
2. **In-memory storage (scope note).** Cross-instance revocation immediacy and
   the 24-hour retention purge are proven against the port contract only; the
   durable guarantee lands with `WP-G2-D01`.
3. **Clock trust (residual).** Idle/absolute enforcement trusts the server
   clock; production must use a monotonic source and reject rollback.

## Verification

`bun test packages/auth-web` → 66 tests, 6 files, all pass.
`bun run --cwd packages/auth-web e2e` → 9/9 across Chromium, Firefox, WebKit.
`bun run lint`, `bun run typecheck`, root `bun run check` and REUSE lint pass.
