#!/usr/bin/env bash
# Quality gate: a fix that changes source must change a test.
# Inputs (environment): TITLE and LABELS (comma-separated) of the pull
# request, BASE_SHA and HEAD_SHA of its range. Untrusted values arrive only
# through the environment and are never evaluated.
set -euo pipefail

fix='^fix(\([^)]*\))?!?:'
if ! [[ $TITLE =~ $fix ]]; then
  echo "Not a fix (the title does not start with fix: or fix(...):); nothing to check."
  exit 0
fi
if [[ ",$LABELS," == *",no-test-needed,"* ]]; then
  echo "Labelled no-test-needed by the Maintainer; passing."
  exit 0
fi

changed="$(git diff --name-only "$BASE_SHA...$HEAD_SHA")"
# Source: the service, the console, the catalog generator, packaging and
# tooling. Docs, CI, vectors and the lock file are not.
source_files="$(grep -E '^(src/|ui/|deploy/|tools/|tests/reference/[^/]+\.py$|Dockerfile$|Cargo\.toml$)' <<<"$changed" | grep -Ev '^tools/test_' || true)"
if [ -z "$source_files" ]; then
  echo "No source file changed; passing."
  exit 0
fi
# Tests: integration tests, console tests, or a new unit test in src/.
test_files="$(grep -E '^(tests/.+\.rs|tools/test_[^/]+\.mjs)$' <<<"$changed" || true)"
unit_tests="$(git diff "$BASE_SHA...$HEAD_SHA" -- src | grep -E '^\+[[:space:]]*#\[(tokio::)?test' || true)"
if [ -n "$test_files$unit_tests" ]; then
  echo "Source changed and tests changed:"
  printf '%s\n' "$test_files" | sed '/^$/d; s/^/  /'
  [ -z "$unit_tests" ] || echo "  (and new unit tests in src/)"
  exit 0
fi
echo "Source files changed without a test:"
printf '%s\n' "$source_files" | sed 's/^/  /'
echo "::error::A fix needs the test that fails without it (tests/*.rs, tools/test_*.mjs or a #[test] in src/), or the Maintainer's label no-test-needed."
exit 1
