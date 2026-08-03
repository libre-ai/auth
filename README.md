# `@libre-ai/auth-web`

Provider-neutral OIDC Authorization Code + PKCE (`S256`) boundary and opaque browser
sessions for `WP-G2-I01`, under `contracts/openapi/auth.v1.yaml`,
`contracts/schemas/browser-session.v1.schema.json` and
`docs/specifications/IDENTITY-AUTHORIZATION.md`.

The package implements the four browser endpoints (`login`, `callback`, `session`
read, logout), keyed-digest opaque sessions (`__Host-` cookies, CSRF synchronizer,
fixation rotation, idle/absolute expiry), a closed `RS256`/`ES256` ID-token
verification boundary and an in-process deterministic development issuer.

Storage is a port with a deterministic in-memory implementation; durable adapters
belong to `WP-G2-D01`. The `/v1/internal/*` Biscuit surface of `auth.v1` belongs to
the authorization issuer (`crates/authz-biscuit`) and its later integration package.
A browser never receives a Biscuit; this package never stores provider tokens, raw
cookie values or CSRF secrets — digests only.

## Quickstart

```sh
bun add @libre-ai/auth-web
```

```ts
import {
  AuthHttpBoundary,
  InMemorySessionStore,
  OidcLoginFlow,
  SessionService,
} from "@libre-ai/auth-web";

// Compose the OIDC login flow and the session service (backed by a SessionStore
// — the in-memory store below is deterministic for tests, the durable adapter is
// the WP-G2-D01 data platform), then wire the HTTP boundary:
const boundary = new AuthHttpBoundary({
  allowedOrigin: "https://app.example.fr",
  flow, // OidcLoginFlow
  sessions, // SessionService over new InMemorySessionStore()
});
// Route the four browser endpoints behind Bun.serve:
//   boundary.handleLogin / handleCallback / handleGetSession / handleDeleteSession
// The exact request/response contracts are contracts/openapi/auth.v1.yaml.
```

## Storage port

Storage is a port: the in-memory store is deterministic for tests; the durable
adapter is the WP-G2-D01 tenant-isolated data platform. See
`contracts/openapi/auth.v1.yaml` for the wire contract and
`docs/specifications/IDENTITY-AUTHORIZATION.md` for the locked identity model.

The port has **two** write primitives, and the difference between them is the
whole point.

```ts
// 1. Compare-and-swap, not an upsert.
save(record: BrowserSessionRecord, expectedRevision: number | null): Promise<SessionSaveOutcome>;
// SessionSaveOutcome = "stored" | "revision_conflict"

// 2. Terminal, monotone, unconditional.
revoke(id: string, revocation: { revocationReason: string; revokedAt: string }):
  Promise<SessionRevokeOutcome>;
// SessionRevokeOutcome = "revoked" | "already_revoked" | "absent"
```

`expectedRevision` is the revision the caller read: `null` requires the record
to be absent (creation), a number requires the stored record to still sit at
exactly that revision. An adapter **must** evaluate the precondition and apply
the write as a single atomic operation on the durable side, and return
`"revision_conflict"` without writing when it does not hold.

```sql
-- expectedRevision = n
UPDATE browser_sessions SET … , revision = $2
 WHERE id = $1 AND revision = $3;             -- $3 = expectedRevision

-- expectedRevision = null: an ABSENCE requirement. Not `WHERE revision IS
-- NULL` — there is no row, so no predicate over its columns can ever match
-- and such an adapter creates nothing at all.
INSERT INTO browser_sessions (…) VALUES (…) ON CONFLICT (id) DO NOTHING;
-- 0 rows affected → "revision_conflict"
```

This is load-bearing for revocation, not an optimisation. Resolving a session
slides the idle window, so **every authenticated request is a writer**: an
adapter that reads and then writes unconditionally lets an ordinary in-flight
request overwrite a logout decided a few milliseconds earlier, and the session
keeps authenticating after the client was told it was closed.

`revoke()` carries no revision precondition, deliberately. A revocation is
monotone and terminal — no concurrent writer can make it wrong — and it is the
one write whose refusal is a user who **cannot log out** while other requests
keep touching the session. The adapter guards only the terminal state and
**bumps the revision itself**; that bump is what makes every compare-and-swap
issued before it conflict instead of writing the pre-revocation state back.

```sql
UPDATE browser_sessions
   SET status = 'revoked', revoked_at = $2, revocation_reason = $3,
       revision = revision + 1
 WHERE id = $1 AND status <> 'revoked';
-- 1 row → "revoked"; 0 rows → "already_revoked" (or "absent")
```

**Adapter break, 0.1.0 → 0.2.0.** An out-of-tree store written for 0.1.0 must
be updated. Note that the two changes fail differently: a `save()` that ignores
the new second argument still type-checks (TypeScript accepts a function of
fewer parameters) and silently loses revocations, whereas the missing `revoke()`
is a compile error. Do not paper over the second by delegating `revoke()` to a
read-then-`save()` — that reintroduces the lost update this port exists to
prevent.

`removeByIds()` is the only mutator with no precondition at all, and needs
none: `pruneExpired()` calls it on records already at least 24 hours past the
expiry of a terminal or long-dead session. It is a deletion, not a state
transition, so it can neither resurrect a session nor erase a decision.
Adapters must not widen it into a general delete used by any other path.

## Publication status

**Publish-ready** (`publishConfig.access=public`): the npm `@libre-ai` scope is
reserved (owner, 2026-07-22) and the `private` guard is lifted; publication is
the owner-run `Release satellites` workflow (LEXICON §7.4 — the release itself
stays an owner-gated external action; see
`docs/transformation/WAVE1-PUBLICATION-RUNBOOK.md`). **Bun-first package:** it
ships TypeScript source (no dist build) — consumers need a TS-aware toolchain
(bun natively; vite/esbuild-based bundlers otherwise).

**License — EUPL-1.2 (reciprocal).** Unlike the Apache-2.0 satellites, this
package is copyleft (ADR-0004: the EUPL protects first-party network runtimes).
Distributing a derivative work to third parties — including operating a modified
version as a network service for them (the EUPL treats that communication as
distribution) — obliges you to release the source under the EUPL-1.2. A
compatible copyleft licence (art. 5's listed set: GPL/AGPL/MPL…) is only an
option when the derivative combines this code with a work already under that
licence. Purely internal use imposes no such obligation. The bundled `LICENSE`
governs.

## État du projet

<!-- libre-ai:project-status:begin -->
<!-- Section générée depuis project.v1.yaml — ne pas éditer à la main. -->

- Situation actuelle : Née verte en γ 3.4 ; son pattern peerDependencies pour briques internes est devenu la convention de flotte.
- Maturité : usable
- Exposition : spec-published
- Confiance : medium
- Preuves vérifiées le : 2026-07-30
- Avancement : 50 % du périmètre actuellement déclaré

<!-- libre-ai:project-status:end -->

La fiche [`project.v1.yaml`](./project.v1.yaml) est l'autorité de l'état du projet ; cette section en est générée et le gate de flotte échoue si elles divergent.
