# WP-G2-I01 — verdict des gates humaines

- Reviewed head: `7cd5f70` (immutable target of both adversarial reviews)
- Delegation: owner instruction, 2026-07-20 (« review les PR #111 + trancher le 412 »)
- Method: two independent adversarial reviews (identity threat model, browser session security), plus direct maintainer re-verification of the load-bearing claims.

## Gate `identity-threat-model-review` — APPROVED

Thirty STRIDE threats mapped, each to a `file:line` mechanism and its tests. Re-verified directly:

- **Digest-only storage** — the persisted record holds `sessionDigest` (HMAC-SHA-256) and `csrfSecretDigest` (SHA-256); raw cookie and CSRF values leave only to the browser (`session/lifecycle.ts:46,51,60`).
- **Fail-closed resolution** — revoked/expired deny explicitly; unresolved mutations `throw` (`session/lifecycle.ts:74-84,98,120`).
- **412 out of the refusal table** — confirmed: the code is absent from the locked table, but the lock already requires the revision precondition, and `412` implements it. Resolved by ADR-0010 (ratified as a concurrency code, table unchanged).

## Gate `browser-session-security-review` — APPROVED

- **`__Host-` cookie** conforms to the lock: Secure, HttpOnly, SameSite=Strict, Path=/, no Domain, no Max-Age (`http/handlers.ts:80`).
- **Constant-time CSRF comparison** — re-verified: XOR accumulation over the full length, no short-circuit beyond length (`csrf/verify.ts:34-43`).
- **Revocation-before-clear**, Origin + Sec-Fetch-Site + synchronizer token, CSP/COOP/CORP depth-in-defense.
- e2e Playwright three engines: 11/17 scenarios proven end-to-end, 5 at unit level.

## Non-blocking debt (recorded, not gating)

- `rotateSession()` is defined (`session/lifecycle.ts:95`) but never called in production; lock conformity holds de facto via a fresh cookie per login. Activate when a privilege change requires it.
- The multi-tab concurrency case (the 412) is proven at unit level, not in e2e.

## Verdict

Both gates **APPROVED**. The single blocking reserve (412) is resolved by ADR-0010 without amending any locked principle. WP-G2-I01 is cleared for merge; the recorded debt does not gate it.
