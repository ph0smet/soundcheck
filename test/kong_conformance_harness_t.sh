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
# Later negative controls mutate this owned copy, never the read-only input.
chmod u+w "$soundcheck_test_repo/bench/kong/conformance/run.sh"
# Dune copies dependencies read-only. Copy each private mock config only once;
# overwriting a previous copy is both unnecessary and fails in its sandbox.
cp "$soundcheck_source_dir/kong.yaml" "$soundcheck_test_repo/bench/kong/conformance/"
# Keep lifecycle expectations independent of the real semantic matrix. These
# tiny fixture requests test metadata, all three classes, and comparison only.
printf '%s\n' \
  'fixture-routing|http|GET|/fixture-routing|-|-|anonymous|-|allow|fixture-route|fixture-service|200|exact|both|-' \
  'fixture-authenticated|http|GET|/fixture-authenticated|-|-|authenticated|fixture-key:valid;x-region:us|allow|fixture-route|fixture-service|200|exact|both|-' \
  'fixture-anonymous|http|GET|/fixture-anonymous|-|-|anonymous|-|deny|fixture-route|fixture-service|401|exact|both|-' \
  'fixture-conservative|http|GET|/fixture-conservative|-|-|anonymous|-|allow|fixture-route|fixture-service|200|conservative|both|-' \
  'fixture-conservative-deny|http|GET|/fixture-conservative-deny|-|-|anonymous|-|deny|fixture-route|fixture-service|401|conservative|both|-' \
  'fixture-unsupported|http|GET|/fixture-unsupported|-|-|anonymous|-|allow|fixture-route|fixture-service|200|unsupported|both|-' \
  > "$soundcheck_test_repo/bench/kong/conformance/probes.tsv"
for soundcheck_matrix in auth paths mixed reducer category hosts boundaries ip termination oss-auth; do
  cp "$soundcheck_source_dir/kong.yaml" "$soundcheck_test_repo/bench/kong/conformance/$soundcheck_matrix.yaml"
  if [[ "$soundcheck_matrix" == ip || "$soundcheck_matrix" == termination ]]; then
    sed 's/|-$/|10.1.2.3/' "$soundcheck_test_repo/bench/kong/conformance/probes.tsv" \
      > "$soundcheck_test_repo/bench/kong/conformance/$soundcheck_matrix-probes.tsv"
  else
    cp "$soundcheck_test_repo/bench/kong/conformance/probes.tsv" \
      "$soundcheck_test_repo/bench/kong/conformance/$soundcheck_matrix-probes.tsv"
  fi
done
printf '%s\n' 'fixture-source|http|GET|/fixture-source|-|-|anonymous|-|allow|fixture-route|fixture-service|200|exact|both|10.1.2.3' \
  >> "$soundcheck_test_repo/bench/kong/conformance/ip-probes.tsv"
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
      for soundcheck_id in {2..22}; do
        expect_line "$soundcheck_log" "docker rm --force $(printf '%064d' "$soundcheck_id")"
      done
      [[ "$(grep -c '^docker rm ' "$soundcheck_log")" -eq 22 ]] || \
        fail 'success did not clean up exactly twenty-two owned containers'
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
      [[ "$(grep -c '^ok \[traditional/' "$soundcheck_stdout")" -eq 67 ]] || \
        fail 'traditional flavor did not complete all 67 fixture probes'
      [[ "$(grep -c '^ok \[traditional_compatible/' "$soundcheck_stdout")" -eq 67 ]] || \
        fail 'traditional_compatible flavor did not complete all 67 fixture probes'
      expect_contains "$soundcheck_log" 'authenticated http GET /fixture-authenticated 127.0.0.1  0.0.0.0 fixture-key:valid x-region:us'
      expect_contains "$soundcheck_log" 'anonymous http GET /fixture-anonymous 127.0.0.1 '
      expect_contains "$soundcheck_log" 'anonymous http GET /fixture-source 127.0.0.1  10.1.2.3'
      expect_contains "$soundcheck_stdout" 'Kong conformance checks passed (matrix: all; exact=68 conservative=44 unsupported-boundary=22)'
      ;;
  esac
  if [[ "$soundcheck_case" != success ]]; then
    expect_absent "$soundcheck_stdout" 'Kong conformance checks passed'
  fi
  printf '[ok] harness lifecycle: %s\n' "$soundcheck_case"
done

# Protocol and negative mutation controls: independently check that authored
# source addresses reach both target transport and model without substitution.
for soundcheck_case in focused-ip invalid-source source-cidr source-leading-zero missing-source missing-source-placeholder \
    reserved-source-header malformed-source-header source-in-wrong-matrix query-path unknown-matrix \
    omitted-source-injection changed-oracle-source omitted-trust-setup; do
  soundcheck_log="$soundcheck_test_dir/$soundcheck_case.commands"
  soundcheck_stdout="$soundcheck_test_dir/$soundcheck_case.stdout"
  soundcheck_stderr="$soundcheck_test_dir/$soundcheck_case.stderr"
  soundcheck_status=0
  soundcheck_selection=ip
  soundcheck_expected_status=1
  soundcheck_row='fixture-source|http|GET|/fixture-source|-|-|anonymous|-|allow|fixture-route|fixture-service|200|exact|both|10.1.2.3'
  cp "$soundcheck_harness_source" "$soundcheck_test_repo/bench/kong/conformance/run.sh"
  case "$soundcheck_case" in
    focused-ip) soundcheck_expected_status=0 ;;
    invalid-source) soundcheck_row="${soundcheck_row%|*}|10.1.2.256" ;;
    source-cidr) soundcheck_row="${soundcheck_row%|*}|10.1.2.3/32" ;;
    source-leading-zero) soundcheck_row="${soundcheck_row%|*}|010.1.2.3" ;;
    missing-source) soundcheck_row="${soundcheck_row%|*}" ;;
    missing-source-placeholder) soundcheck_row="${soundcheck_row%|*}|-" ;;
    reserved-source-header)
      soundcheck_row='fixture-source|http|GET|/fixture-source|-|-|anonymous|x-Soundcheck-Client-IP:192.0.2.1|allow|fixture-route|fixture-service|200|exact|both|10.1.2.3' ;;
    malformed-source-header)
      soundcheck_row='fixture-source|http|GET|/fixture-source|-|-|anonymous|X-Soundcheck-Client-IP :192.0.2.1|allow|fixture-route|fixture-service|200|exact|both|10.1.2.3' ;;
    source-in-wrong-matrix) soundcheck_selection=auth ;;
    query-path)
      soundcheck_row='fixture-source|http|GET|/fixture-source?stop=yes|-|-|anonymous|-|allow|fixture-route|fixture-service|200|exact|both|10.1.2.3' ;;
    unknown-matrix) soundcheck_selection=does-not-exist; soundcheck_expected_status=2 ;;
    omitted-source-injection)
      sed '/curl_args+=(--header "X-Soundcheck-Client-IP: \$source_ip")/d' "$soundcheck_harness_source" \
        > "$soundcheck_test_repo/bench/kong/conformance/run.sh" ;;
    changed-oracle-source)
      sed 's/oracle_source_ip="\$source_ip"/oracle_source_ip="192.0.2.1"/' "$soundcheck_harness_source" \
        > "$soundcheck_test_repo/bench/kong/conformance/run.sh" ;;
    omitted-trust-setup)
      soundcheck_expected_status=99
      sed 's/KONG_REAL_IP_HEADER=X-Soundcheck-Client-IP/KONG_REAL_IP_HEADER=X-Wrong-Header/' "$soundcheck_harness_source" \
        > "$soundcheck_test_repo/bench/kong/conformance/run.sh" ;;
  esac
  printf '%s\n' "$soundcheck_row" > "$soundcheck_test_repo/bench/kong/conformance/ip-probes.tsv"
  if [[ "$soundcheck_selection" == auth ]]; then
    printf '%s\n' "$soundcheck_row" > "$soundcheck_test_repo/bench/kong/conformance/auth-probes.tsv"
  fi
  PATH="$soundcheck_test_bin:$PATH" \
    SOUNDCHECK_HARNESS_TEST_CASE="$soundcheck_case" \
    SOUNDCHECK_HARNESS_TEST_LOG="$soundcheck_log" \
    bash "$soundcheck_test_repo/bench/kong/conformance/run.sh" "$soundcheck_selection" \
    >"$soundcheck_stdout" 2>"$soundcheck_stderr" || soundcheck_status=$?
  [[ "$soundcheck_status" -eq "$soundcheck_expected_status" ]] || \
    fail "expected exit $soundcheck_expected_status, got $soundcheck_status"
  case "$soundcheck_case" in
    focused-ip)
      [[ "$(grep -c '^docker create ' "$soundcheck_log")" -eq 2 ]] || fail 'focused selection did not run exactly two containers'
      expect_contains "$soundcheck_stdout" 'Kong conformance checks passed (matrix: ip; exact=2 conservative=0 unsupported-boundary=0)' ;;
    invalid-source|source-cidr|source-leading-zero|source-in-wrong-matrix)
      expect_contains "$soundcheck_stderr" 'Invalid probe source IP' ;;
    missing-source|query-path) expect_contains "$soundcheck_stderr" 'Invalid probe metadata' ;;
    missing-source-placeholder) expect_contains "$soundcheck_stderr" 'Missing probe source IP' ;;
    reserved-source-header) expect_contains "$soundcheck_stderr" 'Reserved source-IP header' ;;
    malformed-source-header) expect_contains "$soundcheck_stderr" 'Invalid probe header name' ;;
    unknown-matrix)
      expect_contains "$soundcheck_stderr" 'Usage: run.sh'
      [[ ! -e "$soundcheck_log" ]] || fail 'unknown matrix ran external commands' ;;
    omitted-source-injection) expect_contains "$soundcheck_stderr" 'Request failed [traditional/ip/fixture-source]' ;;
    changed-oracle-source) expect_contains "$soundcheck_stderr" 'Model oracle failed [traditional/ip/fixture-source]' ;;
    omitted-trust-setup) expect_absent "$soundcheck_log" 'docker start ' ;;
  esac
  if [[ "$soundcheck_case" != focused-ip ]]; then
    expect_absent "$soundcheck_stdout" 'Kong conformance checks passed'
  fi
  printf '[ok] harness source/selection: %s\n' "$soundcheck_case"
done
# Transport query controls keep the normalized model path separate. Positive
# cases require the exact query at curl; mutants test omission and model leakage.
for soundcheck_case in query-present query-empty-value query-unrelated query-multiple \
    query-fragment query-escaped query-whitespace query-glob query-missing-equals \
    query-trailing-separator query-extra-column query-wrong-matrix \
    query-not-appended query-in-model; do
  soundcheck_log="$soundcheck_test_dir/$soundcheck_case.commands"
  soundcheck_stdout="$soundcheck_test_dir/$soundcheck_case.stdout"
  soundcheck_stderr="$soundcheck_test_dir/$soundcheck_case.stderr"
  soundcheck_status=0
  soundcheck_selection=termination
  soundcheck_expected_status=1
  soundcheck_query='x-stop=yes'
  soundcheck_decision=deny
  soundcheck_http=418
  cp "$soundcheck_harness_source" "$soundcheck_test_repo/bench/kong/conformance/run.sh"
  case "$soundcheck_case" in
    query-present) soundcheck_expected_status=0 ;;
    query-empty-value) soundcheck_query='x-stop='; soundcheck_expected_status=0 ;;
    query-unrelated)
      soundcheck_query='unrelated=yes'; soundcheck_expected_status=0
      soundcheck_decision=allow; soundcheck_http=200 ;;
    query-multiple) soundcheck_query='unrelated=yes&x-stop=yes'; soundcheck_expected_status=0 ;;
    query-fragment) soundcheck_query='x-stop=yes#fragment' ;;
    query-escaped) soundcheck_query='x-stop=%79es' ;;
    query-whitespace) soundcheck_query='x-stop=yes extra' ;;
    query-glob) soundcheck_query='x-stop=[ab]' ;;
    query-missing-equals) soundcheck_query='x-stop' ;;
    query-trailing-separator) soundcheck_query='x-stop=yes&' ;;
    query-extra-column) soundcheck_query='x-stop=yes|extra' ;;
    query-wrong-matrix) soundcheck_selection=ip ;;
    query-not-appended)
      sed 's/request_url+="?$query"/: # intentionally omit query/' "$soundcheck_harness_source" \
        > "$soundcheck_test_repo/bench/kong/conformance/run.sh" ;;
    query-in-model)
      sed 's/"$method" "$path" "$host_value"/"$method" "$path?$query" "$host_value"/' "$soundcheck_harness_source" \
        > "$soundcheck_test_repo/bench/kong/conformance/run.sh" ;;
  esac
  printf '%s\n' \
    "fixture-query|http|GET|/fixture-query|-|-|anonymous|-|$soundcheck_decision|fixture-route|fixture-service|$soundcheck_http|conservative|both|10.1.2.3|$soundcheck_query" \
    > "$soundcheck_test_repo/bench/kong/conformance/$soundcheck_selection-probes.tsv"
  PATH="$soundcheck_test_bin:$PATH" \
    SOUNDCHECK_HARNESS_TEST_CASE="$soundcheck_case" \
    SOUNDCHECK_HARNESS_TEST_LOG="$soundcheck_log" \
    bash "$soundcheck_test_repo/bench/kong/conformance/run.sh" "$soundcheck_selection" \
    >"$soundcheck_stdout" 2>"$soundcheck_stderr" || soundcheck_status=$?
  [[ "$soundcheck_status" -eq "$soundcheck_expected_status" ]] || \
    fail "expected exit $soundcheck_expected_status, got $soundcheck_status"
  case "$soundcheck_case" in
    query-present|query-empty-value|query-unrelated|query-multiple)
      expect_contains "$soundcheck_stdout" 'Kong conformance checks passed (matrix: termination; exact=0 conservative=2 unsupported-boundary=0)'
      expect_contains "$soundcheck_log" 'anonymous http GET /fixture-query 127.0.0.1  10.1.2.3' ;;
    query-extra-column) expect_contains "$soundcheck_stderr" 'Invalid probe metadata' ;;
    query-not-appended) expect_contains "$soundcheck_stderr" 'Request failed [traditional/termination/fixture-query]' ;;
    query-in-model) expect_contains "$soundcheck_stderr" 'Model oracle failed [traditional/termination/fixture-query]' ;;
    *) expect_contains "$soundcheck_stderr" 'Invalid probe query' ;;
  esac
  if [[ "$soundcheck_expected_status" -ne 0 ]]; then
    expect_absent "$soundcheck_stdout" 'Kong conformance checks passed'
  fi
  printf '[ok] harness query: %s\n' "$soundcheck_case"
done
echo 'All harness lifecycle checks passed (mock commands; no Docker required).'
