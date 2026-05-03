#!/usr/bin/env bash
# Runs the built policyguard binary against every example policy's
# compliant + violating fixture and asserts that the exit code matches
# the expected outcome (0 for compliant, 1 for violating).
#
# Used both locally (`make check-fixtures`) and in CI (commit.yml).
set -euo pipefail

BIN="${BIN:-./policyguard}"
POLICIES="examples/policies"
FIXTURES_ROOT="tests/fixtures/python/policies"

if [[ ! -x "$BIN" ]]; then
  echo "policyguard binary not found at $BIN — run 'make build' first" >&2
  exit 2
fi

pass=0
fail=0

run_case() {
  local label="$1" expected_code="$2" dir="$3"
  set +e
  "$BIN" check --policies "$POLICIES" "$dir" >/tmp/policyguard-out 2>&1
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

for policy_dir in "$FIXTURES_ROOT"/*/; do
  name="$(basename "$policy_dir")"
  if [[ -d "$policy_dir/compliant" ]]; then
    run_case "$name compliant" 0 "$policy_dir/compliant"
  fi
  if [[ -d "$policy_dir/violating" ]]; then
    run_case "$name violating" 1 "$policy_dir/violating"
  fi
done

echo
echo "$pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
