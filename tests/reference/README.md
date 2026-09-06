# Reference compatibility fixtures

These Python scripts are developer-only checks against the Python protocol
reference. They are not used by the gateway, operator CLI or packaging.

From the gateway repository, with reference dependencies installed:

```text
python tests/reference/gen_vectors.py
python tests/reference/build_service_catalog.py
```

Review all generated changes. Catalog generation must never silently expand the
deployed allowlist. The Rust interoperability tests consume committed vectors and
run without Python. `tools/test_ui_signing.mjs` compares browser signing with
Python canonical JSON as a separate CI check.
