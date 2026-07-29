# auth Canonical Agent Rules

Web authentication brick of the Libre AI constellation (couche 4). Born from the hub dismantling (ADR-0020): history carried by git
filter-repo; the hub remains the clonable archive. Internal dependencies
are sha-pinned GitHub git-deps (a dependency evolution is a pin bump).
The governance gate template is consumed as pinned reusable workflows and
a pinned tooling git-dep — never duplicated.

Run `bun run check` before pushing; never hide a red test. Stage files
before tree-walking gates. Security > quality > performance > completeness.
