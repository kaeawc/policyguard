#!/usr/bin/env bash
# Runs the built policyguard binary against every example policy's
# compliant + violating fixture (across all supported languages) and
# asserts that the exit code matches the expected outcome (0 for
# compliant, 1 for violating).
#
# Used both locally (`make check-fixtures`) and in CI (commit.yml).
set -euo pipefail

BIN="${BIN:-./policyguard}"
POLICIES="examples/policies"
FIXTURES_ROOT="tests/fixtures"

if [[ ! -x "$BIN" ]]; then
  echo "policyguard binary not found at $BIN — run 'make build' first" >&2
  exit 2
fi

pass=0
fail=0

run_case() {
  local label="$1" expected_code="$2" lang="$3" dir="$4"
  set +e
  "$BIN" check --policies "$POLICIES" --lang "$lang" "$dir" >/tmp/policyguard-out 2>&1
  local got=$?
  set -e
  if [[ "$got" -eq "$expected_code" ]]; then
    echo "ok   $label (exit $got)"
    pass=$((pass + 1))
  else
    echo "FAIL $label expected exit $expected_code, got $got"
    cat /tmp/policyguard-out
    fail=$((fail + 1))
  fi
}

for lang_dir in "$FIXTURES_ROOT"/*/; do
  lang="$(basename "$lang_dir")"
  policies_root="${lang_dir}policies"
  [[ -d "$policies_root" ]] || continue
  for policy_dir in "$policies_root"/*/; do
    name="$(basename "$policy_dir")"
    for sub in "$policy_dir"*/; do
      sub_name="$(basename "$sub")"
      case "$sub_name" in
        compliant*) run_case "$lang/$name $sub_name" 0 "$lang" "$sub" ;;
        violating*) run_case "$lang/$name $sub_name" 1 "$lang" "$sub" ;;
      esac
    done
  done
done

echo
echo "$pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
