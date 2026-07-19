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
