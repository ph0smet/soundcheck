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
# Dune copies dependencies read-only. Copy each private mock config only once;
# overwriting a previous copy is both unnecessary and fails in its sandbox.
cp "$soundcheck_source_dir/kong.yaml" "$soundcheck_test_repo/bench/kong/conformance/"
# Keep lifecycle expectations independent of the real semantic matrix. These
# tiny fixture requests test metadata, all three classes, and comparison only.
printf '%s\n' \
  'fixture-routing|http|GET|/fixture-routing|-|-|anonymous|-|allow|fixture-route|fixture-service|200|exact|both' \
  'fixture-authenticated|http|GET|/fixture-authenticated|-|-|authenticated|fixture-key:valid;x-region:us|allow|fixture-route|fixture-service|200|exact|both' \
  'fixture-anonymous|http|GET|/fixture-anonymous|-|-|anonymous|-|deny|fixture-route|fixture-service|401|exact|both' \
  'fixture-conservative|http|GET|/fixture-conservative|-|-|anonymous|-|allow|fixture-route|fixture-service|200|conservative|both' \
  'fixture-conservative-deny|http|GET|/fixture-conservative-deny|-|-|anonymous|-|deny|fixture-route|fixture-service|401|conservative|both' \
  'fixture-unsupported|http|GET|/fixture-unsupported|-|-|anonymous|-|allow|fixture-route|fixture-service|200|unsupported|both' \
  > "$soundcheck_test_repo/bench/kong/conformance/probes.tsv"
for soundcheck_matrix in auth paths mixed reducer category hosts boundaries; do
  cp "$soundcheck_source_dir/kong.yaml" "$soundcheck_test_repo/bench/kong/conformance/$soundcheck_matrix.yaml"
  cp "$soundcheck_test_repo/bench/kong/conformance/probes.tsv" \
    "$soundcheck_test_repo/bench/kong/conformance/$soundcheck_matrix-probes.tsv"
done
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
for soundcheck_case in collision startup readiness timeout malformed-response malformed-model \
    mismatch model-mismatch matching-wrong status-mismatch oracle-failure silent-downgrade \
    unexpected-unknown unsupported-accepted wrong-unknown conservative-dropped \
    conservative-may-escape conservative-must-escape duplicate-candidate empty-matrix success; do
  soundcheck_log="$soundcheck_test_dir/$soundcheck_case.commands"
  soundcheck_stdout="$soundcheck_test_dir/$soundcheck_case.stdout"
  soundcheck_stderr="$soundcheck_test_dir/$soundcheck_case.stderr"
  soundcheck_status=0
  if [[ "$soundcheck_case" == empty-matrix ]]; then
    mv "$soundcheck_test_repo/bench/kong/conformance/probes.tsv" "$soundcheck_test_dir/probes.saved"
    printf '' > "$soundcheck_test_repo/bench/kong/conformance/probes.tsv"
  fi
  PATH="$soundcheck_test_bin:$PATH" \
    SOUNDCHECK_HARNESS_TEST_CASE="$soundcheck_case" \
    SOUNDCHECK_HARNESS_TEST_LOG="$soundcheck_log" \
    bash "$soundcheck_test_repo/bench/kong/conformance/run.sh" \
    >"$soundcheck_stdout" 2>"$soundcheck_stderr" || soundcheck_status=$?
  if [[ "$soundcheck_case" == empty-matrix ]]; then
    mv "$soundcheck_test_dir/probes.saved" "$soundcheck_test_repo/bench/kong/conformance/probes.tsv"
  fi

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
      for soundcheck_id in {2..16}; do
        expect_line "$soundcheck_log" "docker rm --force $(printf '%064d' "$soundcheck_id")"
      done
      [[ "$(grep -c '^docker rm ' "$soundcheck_log")" -eq 16 ]] || \
        fail 'success did not clean up exactly sixteen owned containers'
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
      expect_contains "$soundcheck_stderr" 'Request failed [traditional/routing/fixture-routing]'
      ;;
    malformed-response)
      expect_contains "$soundcheck_stderr" 'Invalid HTTP response [traditional/routing/fixture-routing]'
      ;;
    malformed-model|wrong-unknown)
      expect_contains "$soundcheck_stderr" 'Invalid model response [traditional/routing/'
      ;;
    duplicate-candidate)
      expect_contains "$soundcheck_stderr" 'Duplicate model candidate [traditional/routing/'
      ;;
    empty-matrix)
      expect_contains "$soundcheck_stderr" 'No probes executed [traditional/routing]'
      ;;
    mismatch|model-mismatch|matching-wrong|status-mismatch|silent-downgrade|unexpected-unknown)
      expect_contains "$soundcheck_stderr" 'MISMATCH [traditional/routing/fixture-routing]'
      expect_contains "$soundcheck_stderr" 'expected:'
      ;;
    unsupported-accepted|conservative-dropped|conservative-may-escape|conservative-must-escape)
      expect_contains "$soundcheck_stderr" 'MISMATCH [traditional/routing/fixture-'
      expect_contains "$soundcheck_stderr" 'expected:'
      ;;
    oracle-failure)
      expect_contains "$soundcheck_stderr" 'Model oracle failed [traditional/routing/fixture-routing]'
      ;;
    success)
      [[ "$(grep -c '^ok \[traditional/' "$soundcheck_stdout")" -eq 48 ]] || \
        fail 'traditional flavor did not complete all 48 fixture probes'
      [[ "$(grep -c '^ok \[traditional_compatible/' "$soundcheck_stdout")" -eq 48 ]] || \
        fail 'traditional_compatible flavor did not complete all 48 fixture probes'
      expect_contains "$soundcheck_log" 'authenticated http GET /fixture-authenticated 127.0.0.1  fixture-key:valid x-region:us'
      expect_contains "$soundcheck_log" 'anonymous http GET /fixture-anonymous 127.0.0.1 '
      expect_contains "$soundcheck_stdout" 'Kong conformance checks passed (matrix: all; exact=48 conservative=32 unsupported-boundary=16)'
      ;;
  esac
  if [[ "$soundcheck_case" != success ]]; then
    expect_absent "$soundcheck_stdout" 'Kong conformance checks passed'
  fi
  printf '[ok] harness lifecycle: %s\n' "$soundcheck_case"
done
echo 'All harness lifecycle checks passed (mock commands; no Docker required).'
