#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'Usage: kong_conformance_harness_t.sh <harness> <mock-command>' >&2
  exit 2
fi

soundcheck_harness_source="$1"
soundcheck_fixture_source="$2"
soundcheck_source_dir="$(cd "$(dirname "$soundcheck_harness_source")" && pwd)"
soundcheck_test_dir="$(mktemp -d "${TMPDIR:-/tmp}/soundcheck-conformance-test.XXXXXX")"
readonly soundcheck_test_dir

cleanup() {
  local status=$?
  trap - EXIT
  if [[ "$status" -ne 0 ]]; then
    printf 'Harness test failed; diagnostics retained at %s\n' "$soundcheck_test_dir" >&2
    exit "$status"
  fi
  # This immutable path is the fresh mktemp directory created above, never a
  # repository path or a location supplied by the caller.
  rm -rf -- "$soundcheck_test_dir"
}
trap cleanup EXIT

soundcheck_test_repo="$soundcheck_test_dir/repo"
soundcheck_test_bin="$soundcheck_test_dir/bin"
mkdir -p "$soundcheck_test_repo/bench/kong/conformance" \
  "$soundcheck_test_repo/_build/default/bench" "$soundcheck_test_bin"
cp "$soundcheck_harness_source" "$soundcheck_test_repo/bench/kong/conformance/run.sh"
cp "$soundcheck_source_dir/kong.yaml" "$soundcheck_source_dir/probes.tsv" \
  "$soundcheck_test_repo/bench/kong/conformance/"
cp "$soundcheck_fixture_source" "$soundcheck_test_bin/mock-command"
chmod +x "$soundcheck_test_bin/mock-command"
for soundcheck_command in opam dune docker curl; do
  ln -s mock-command "$soundcheck_test_bin/$soundcheck_command"
done
ln -s "$soundcheck_test_bin/mock-command" \
  "$soundcheck_test_repo/_build/default/bench/kong_model_oracle.exe"

fail() {
  printf 'Harness case %s: %s\n' "$soundcheck_case" "$1" >&2
  exit 1
}

expect_contains() {
  if ! grep -Fq -- "$2" "$1"; then
    fail "missing expected text: $2"
  fi
}

expect_absent() {
  if grep -Fq -- "$2" "$1"; then
    fail "unexpected text: $2"
  fi
}

expect_line() {
  if ! grep -Fxq -- "$2" "$1"; then
    fail "missing exact command: $2"
  fi
}

soundcheck_first_id="$(printf '%064d' 1)"
soundcheck_second_id="$(printf '%064d' 2)"
for soundcheck_case in collision startup readiness timeout mismatch success; do
  soundcheck_log="$soundcheck_test_dir/$soundcheck_case.commands"
  soundcheck_stdout="$soundcheck_test_dir/$soundcheck_case.stdout"
  soundcheck_stderr="$soundcheck_test_dir/$soundcheck_case.stderr"
  soundcheck_status=0
  PATH="$soundcheck_test_bin:$PATH" \
    SOUNDCHECK_HARNESS_TEST_CASE="$soundcheck_case" \
    SOUNDCHECK_HARNESS_TEST_LOG="$soundcheck_log" \
    bash "$soundcheck_test_repo/bench/kong/conformance/run.sh" \
    >"$soundcheck_stdout" 2>"$soundcheck_stderr" || soundcheck_status=$?

  case "$soundcheck_case" in
    collision|startup) soundcheck_expected_status=125 ;;
    success) soundcheck_expected_status=0 ;;
    *) soundcheck_expected_status=1 ;;
  esac
  [[ "$soundcheck_status" -eq "$soundcheck_expected_status" ]] || \
    fail "expected exit $soundcheck_expected_status, got $soundcheck_status"

  if [[ "$soundcheck_case" == collision ]]; then
    expect_absent "$soundcheck_log" 'docker rm '
    expect_absent "$soundcheck_log" 'docker start '
  else
    expect_line "$soundcheck_log" "docker rm --force $soundcheck_first_id"
    expect_absent "$soundcheck_log" 'docker rm --force soundcheck-kong-conformance-'
    if [[ "$soundcheck_case" == success ]]; then
      expect_line "$soundcheck_log" "docker rm --force $soundcheck_second_id"
      [[ "$(grep -c '^docker rm ' "$soundcheck_log")" -eq 2 ]] || \
        fail 'success did not clean up exactly two owned containers'
      expect_absent "$soundcheck_stderr" 'Kong container diagnostics'
    else
      [[ "$(grep -c '^docker rm ' "$soundcheck_log")" -eq 1 ]] || \
        fail 'failure did not clean up exactly one owned container'
      expect_contains "$soundcheck_stderr" 'fixture container logs'
      expect_contains "$soundcheck_stderr" 'fixture-state'
    fi
  fi

  case "$soundcheck_case" in
    readiness)
      expect_contains "$soundcheck_stderr" 'Kong failed to become ready'
      ;;
    timeout)
      expect_contains "$soundcheck_stderr" 'Request failed [traditional/literal-long]'
      ;;
    mismatch)
      expect_contains "$soundcheck_stderr" 'MISMATCH [traditional/literal-long]'
      ;;
    success)
      [[ "$(grep -c '^ok \[traditional\] ' "$soundcheck_stdout")" -eq 18 ]] || \
        fail 'traditional flavor did not complete all 18 probes'
      [[ "$(grep -c '^ok \[traditional_compatible\] ' "$soundcheck_stdout")" -eq 18 ]] || \
        fail 'traditional_compatible flavor did not complete all 18 probes'
      expect_contains "$soundcheck_stdout" 'Kong differential conformance passed'
      ;;
  esac
  if [[ "$soundcheck_case" != success ]]; then
    expect_absent "$soundcheck_stdout" 'Kong differential conformance passed'
  fi
  printf '[ok] harness lifecycle: %s\n' "$soundcheck_case"
done
echo 'All harness lifecycle checks passed (mock commands; no Docker required).'
