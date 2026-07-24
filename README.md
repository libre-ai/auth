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

Storage is a port: the in-memory store is deterministic for tests; the durable
adapter is the WP-G2-D01 tenant-isolated data platform. See
`contracts/openapi/auth.v1.yaml` for the wire contract and
`docs/specifications/IDENTITY-AUTHORIZATION.md` for the locked identity model.

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
