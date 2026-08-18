# auth Canonical Agent Rules

## Authority

Web authentication brick of the Libre AI constellation, couche 4: opaque
HttpOnly sessions, CSRF protection, Biscuit token integration. Descends from
the hub dismantling (ADR-0020) via `git filter-repo`; the hub remains the
clonable archive.
Doctrine lives upstream: https://raw.githubusercontent.com/libre-ai/governance/main/docs/README.md

## Boundaries

- Session security is owned here; `sdk-ts` (contract types) and
  `web-platform` (application substrate) are peers, sha-pinned by
  consumers, never vendored into this repository.
- Product code and specifications for consuming applications live in their
  own repositories. Fleet doctrine and quality gates live upstream in
  `libre-ai/governance`.

## Quality gates

Run `bun run check` before pushing (Bun floor, secret scan, personal-data
scan, lint, typecheck, tests); never hide a red test.

## Agents

- Read actual state before editing.
- Stage files before running tree-walking gates (`git ls-files`-based
  scanners do not see untracked files).
- Security > quality > performance > completeness.
