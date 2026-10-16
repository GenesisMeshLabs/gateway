## What changed

<!-- What does this pull request change, and why? Link the issue or plan. -->

## How it was tested

<!-- Commands you ran and their results. -->

- [ ] `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings` and `cargo test --locked --all-targets` pass
- [ ] Every `node tools/test_ui_*.mjs` passes (console changes)
- [ ] `python tests/reference/build_service_catalog.py --core ../genesismesh --check` passes (catalog changes)

**Bug fix:** the test that fails without this change is ___
<!-- Name the test, and say how you checked that it fails on the parent commit. A fix that cannot be tested needs the Maintainer's label `no-test-needed` and the reason here. -->

## Changelog

- [ ] A changelog fragment, not `CHANGELOG.md`. This repository has no `changelog.d/` yet: write the release note here, under the next version.
- [ ] No user-visible change

## Breaking change

- [ ] No breaking change
- [ ] Breaking or behaviour change: the release note has an `### Upgrading` entry saying what operators must do

## Flagged paths

These need the Maintainer's merge. Tick each one this pull request touches:

- [ ] Public contract (gateway routes, `ui/openapi.json`, the authority catalog `ui/services.json`, error codes, configuration variables)
- [ ] Vectors (`tests/reference/`, `tests/vectors.json`)
- [ ] Durable state schema and migrations (`src/gateway/durable.rs`)
- [ ] Signing, verification, authentication or key handling (`src/canonical.rs`, `src/crypto.rs`, `src/trust.rs`, `src/admin_auth.rs`, `src/gateway/security.rs`, `src/gateway/oidc.rs`, `ui/signing.js`)
- [ ] CI workflows (`.github/`)
- [ ] `SECURITY.md`

- [ ] No secrets, tokens or private key files committed
