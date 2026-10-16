# Contributing to the Genesis Mesh gateway

## Where things are

[docs/architecture.md](docs/architecture.md) has the module map, the layers
and the dependency rule (`tests/architecture.rs` enforces it), the request
pipeline, and where each common change goes, with the test that fails when a
step is missed. In short: `src/` outside `gateway/` is the trust library,
which never uses `gateway`; `src/gateway/` is the HTTP service; `ui/` is the
console, whose `ui/services.json` and the service paths of `ui/openapi.json`
are generated from the core.

## Checks

Run before every pull request (CI runs the same on Linux and Windows):

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --doc
node --test tools/test_ui_*.mjs
# Catalog changes, with the core checked out next to this repository:
python tests/reference/build_service_catalog.py --core ../genesismesh --check
```

The Redis quota test is ignored without Redis; CI runs it against a Redis
service. CI also builds the image and runs it against the Network Authority
image; those jobs fail rather than skip when a piece is missing.

## Pull requests

- Conventional titles: `fix:`, `feat:`, `docs:`, `ci:`, `chore:`, `test:`.
- A bug fix carries the test that fails without it. The "Regression test"
  check fails a `fix:` pull request that changes source without changing a
  test, unless the Maintainer labels it `no-test-needed`.
- A change that needs a core change uses a branch of the same name in both
  repositories; CI checks against the core branch of that name, or core
  `main`. The core merges first.
- The gateway has no changelog yet: put the release note, with an
  `### Upgrading` entry for any behaviour change, in the pull request.
- Operation IDs are the gateway's public URLs. The "Operation IDs" check
  fails when a pull request removes an operation released in the latest tag,
  or changes its method, group, operator tier or parameters so that an old
  request fails. Such a change needs the Maintainer's `breaking` label and an
  `### Upgrading` entry in the pull request description.
- CI measures line coverage (`cargo llvm-cov`) and fails below the floor in
  `.github/workflows/ci.yml`. Raise the floor when coverage rises; never
  lower it to make a pull request pass.
- Contracts, vectors, the durable state schema, signing and authentication
  code and `.github/` are flagged paths: the Maintainer merges those.
