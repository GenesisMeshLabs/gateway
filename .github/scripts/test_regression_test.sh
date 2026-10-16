#!/usr/bin/env bash
# Cases for regression_test.sh, each in a throwaway repository.
set -euo pipefail
check="$(cd "$(dirname "$0")" && pwd)/regression_test.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

# A base commit with a source file that ends in an inline test module, an
# integration test, a console test and a vector.
base() {
  rm -rf "$work/repo" && mkdir -p "$work/repo" && cd "$work/repo"
  git init -q && git config user.email t@example.org && git config user.name t && git config core.autocrlf false
  mkdir -p src tests/reference tools docs
  printf 'pub fn f() -> u8 {\n    1\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn f_is_one() {\n        assert_eq!(super::f(), 1);\n    }\n}\n' > src/lib.rs
  printf 'pub fn g() {}\n' > src/other.rs
  printf '#[test]\nfn t() {}\n' > tests/api.rs
  printf 'assert(true);\n' > tools/test_ui_a.mjs
  printf '{"v":1}\n' > tests/reference/vectors.json
  printf 'docs\n' > docs/a.md
  git add -A && git commit -qm base
  BASE=$(git rev-parse HEAD)
}

# expect <0|1> <description> [title]: commit the working tree, run the check.
expect() {
  git add -A && git commit -qm change
  local status=0
  TITLE="${3:-fix: something}" LABELS="" BASE_SHA="$BASE" HEAD_SHA="$(git rev-parse HEAD)" \
    bash "$check" > "$work/out" 2>&1 || status=$?
  if [ "$status" != "$1" ]; then
    echo "FAIL: $2 (exit $status, expected $1)"; sed 's/^/    /' "$work/out"; failures=$((failures + 1))
  else
    echo "ok:   $2"
  fi
}

base; sed -i 's/1$/2/' src/other.rs; echo '// x' >> src/other.rs; printf '#[test]\nfn u() {}\n' > tests/new.rs
expect 0 "source change with an added integration test"
base; echo '// x' >> src/other.rs; echo '#[test] fn v() {}' >> tests/api.rs
expect 0 "source change with a modified integration test"
base; echo '// x' >> src/other.rs; echo 'assert(1);' >> tools/test_ui_a.mjs
expect 0 "source change with a modified console test"
base; echo '// x' >> src/other.rs; git rm -q tests/api.rs
expect 1 "source change with only a deleted test"
base; git rm -q src/other.rs
expect 1 "a deleted source file is a source change"
base; git rm -q src/other.rs; git rm -q tests/api.rs
expect 1 "a deleted source file and a deleted test"
base; echo '// x' >> src/other.rs; printf '{"v":2}\n' > tests/reference/vectors.json
expect 1 "source change with only a vector or fixture change"
base; sed -i 's/^    1$/    2/' src/lib.rs; sed -i 's/assert_eq!(super::f(), 1)/assert_eq!(super::f(), 2)/' src/lib.rs
expect 0 "source change extending an existing inline test module"
base; echo '// x' >> src/other.rs; sed -i 's/^    1$/    2/' src/lib.rs
expect 1 "source change above the inline test module only"
base; echo '// x' >> src/other.rs; sed -i '/fn f_is_one/,/^    }/d' src/lib.rs
expect 1 "source change that only deletes inline test lines"
base; echo '// x' >> src/other.rs; echo 'more' >> docs/a.md
expect 1 "source change with only docs"
base; echo 'more' >> docs/a.md
expect 0 "docs only"
base; echo '// x' >> src/other.rs
expect 0 "not a fix" "feat: something"
base; echo '// x' >> src/other.rs
TITLE='fix: x' LABELS="bug,no-test-needed" BASE_SHA="$BASE" HEAD_SHA="$BASE" bash "$check" > /dev/null && echo "ok:   the no-test-needed label" || { echo "FAIL: the no-test-needed label"; failures=$((failures + 1)); }

[ "$failures" -eq 0 ] || { echo "$failures case(s) failed"; exit 1; }
echo "All cases passed."
