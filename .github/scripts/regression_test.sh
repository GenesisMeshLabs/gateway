#!/usr/bin/env bash
# Quality gate: a fix that changes source must add or modify a test.
# Inputs (environment): TITLE and LABELS (comma-separated) of the pull
# request, BASE_SHA and HEAD_SHA of its range. Untrusted values arrive only
# through the environment and are never evaluated.
# Cases: .github/scripts/test_regression_test.sh.
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

range="$BASE_SHA...$HEAD_SHA"
# Every changed path, deletions included: deleting source is a source change.
changed="$(git diff --name-only --no-renames "$range")"
# Source: the service, the console, the catalog generator, packaging and
# tooling. Docs, CI, vectors, fixtures and the lock file are not.
source_files="$(grep -E '^(src/|ui/|deploy/|tools/|tests/reference/[^/]+\.py$|Dockerfile$|Cargo\.toml$)' <<<"$changed" | grep -Ev '^tools/test_' || true)"
if [ -z "$source_files" ]; then
  echo "No source file changed; passing."
  exit 0
fi

# Tests count only when added or modified, never deleted: integration tests
# (tests/**/*.rs, not vectors or fixtures) and console tests.
kept="$(git diff --name-only --no-renames --diff-filter=AM "$range")"
test_files="$(grep -E '^(tests/.+\.rs|tools/test_[^/]+\.mjs)$' <<<"$kept" || true)"
# Inline Rust tests: an added or changed line at or after the first
# #[cfg(test)] of a src/ file (the test module closes the file by convention).
inline_tests=""
while IFS= read -r file; do
  [ -n "$file" ] || continue
  start="$(git show "$HEAD_SHA:$file" | grep -n -m1 -E '^[[:space:]]*#\[cfg\(test\)\]' | cut -d: -f1 || true)"
  [ -n "$start" ] || continue
  if git diff -U0 "$range" -- "$file" | awk -v start="$start" '
      /^@@/ {
        split($3, new, ",")
        first = substr(new[1], 2) + 0
        count = (new[2] == "") ? 1 : new[2] + 0
        if (count > 0 && first + count - 1 >= start) found = 1
      }
      END { exit !found }'; then
    inline_tests+="$file"$'\n'
  fi
done < <(grep -E '^src/.+\.rs$' <<<"$kept" || true)

if [ -n "$test_files$inline_tests" ]; then
  echo "Source changed and tests were added or modified:"
  printf '%s\n' "$test_files" | sed '/^$/d; s/^/  /'
  printf '%s\n' "$inline_tests" | sed '/^$/d; s/^/  /; s/$/ (inline tests)/'
  exit 0
fi
echo "Source files changed without an added or modified test:"
printf '%s\n' "$source_files" | sed 's/^/  /'
echo "::error::A fix needs the test that fails without it (tests/*.rs, tools/test_*.mjs or a #[cfg(test)] module in src/), or the Maintainer's label no-test-needed."
exit 1
