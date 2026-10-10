#!/usr/bin/env bash
set -euo pipefail

# The same file is copied into a synthetic trusted Action as a mock verifier.
# Real-verifier cases at the end replace that copy with the actual CLI.
if [[ "${1:-}" == verify ]]; then
  [[ $# -eq 6 && "$3" == --contract && "$5" == --format && "$6" == github ]] || exit 91
  [[ "$2" == "$GITHUB_WORKSPACE/config.yaml" ]] || exit 92
  [[ "$4" == "$RUNNER_TEMP/"*/contract.yaml && "$4" != "$GITHUB_WORKSPACE/"* ]] || exit 93
  cmp -s "$4" "$SOUNDCHECK_EXPECTED_CONTRACT" || exit 94
  [[ "$(LC_ALL=C ls -ld "$4")" == '-r--------'* ]] || exit 95
  [[ "$(LC_ALL=C ls -ld "$(dirname "$4")")" == 'drwx------'* ]] || exit 96
  printf '%s\n' "$4" > "$SOUNDCHECK_GATE_TEST_LOG"
  exit "${SOUNDCHECK_MOCK_STATUS:-0}"
fi

if [[ $# -ne 2 ]]; then
  echo 'Usage: approved_contract_gate_t.sh <helper> <soundcheck-executable>' >&2
  exit 2
fi
soundcheck_helper_source="$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
soundcheck_cli_source="$(cd "$(dirname "$2")" && pwd -P)/$(basename "$2")"
soundcheck_test_source="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/$(basename "${BASH_SOURCE[0]}")"
soundcheck_test_dir="$(mktemp -d "${TMPDIR:-/tmp}/soundcheck-gate-test.XXXXXX")"
soundcheck_test_dir="$(cd "$soundcheck_test_dir" && pwd -P)"
readonly soundcheck_test_dir

cleanup() {
  local status=$?
  trap - EXIT
  if [[ "$status" -ne 0 ]]; then
    printf 'Gate test failed; diagnostics retained at %s\n' "$soundcheck_test_dir" >&2
    exit "$status"
  fi
  # The immutable directory is created by mktemp above, never caller-supplied.
  rm -rf -- "$soundcheck_test_dir"
}
trap cleanup EXIT

soundcheck_workspace="$soundcheck_test_dir/workspace"
soundcheck_action="$soundcheck_test_dir/trusted-action"
soundcheck_runner_temp="$soundcheck_test_dir/runner-temp"
soundcheck_event="$soundcheck_test_dir/event.json"
soundcheck_case=setup
soundcheck_count=0
mkdir -p "$soundcheck_workspace/contracts" "$soundcheck_action/scripts" \
  "$soundcheck_action/_build/default/cli" "$soundcheck_runner_temp"
cp "$soundcheck_helper_source" "$soundcheck_action/scripts/verify-approved-contract.sh"
cp "$soundcheck_test_source" "$soundcheck_action/_build/default/cli/main.exe"
chmod +x "$soundcheck_action/_build/default/cli/main.exe"

fail() {
  printf 'Gate case %s: %s\n' "$soundcheck_case" "$1" >&2
  exit 1
}

expect_contains() {
  if ! grep -Fq -- "$2" "$1"; then
    fail "missing expected text: $2"
  fi
}

git_fixture() {
  git -c core.hooksPath=/dev/null -c commit.gpgsign=false \
    -c user.name='Soundcheck local test' -c user.email='test@example.invalid' \
    -C "$soundcheck_workspace" "$@"
}

# No network or hosted repository is involved. Even the commit identity is
# synthetic and local to each invocation of this regression test.
git_fixture init --quiet
git_fixture checkout --quiet -b main
git_fixture commit --quiet --allow-empty -m 'Local seed'
soundcheck_seed="$(git_fixture rev-parse HEAD)"

cat > "$soundcheck_test_dir/approved.yaml" <<'YAML'
schema_version: 1
kind: authenticated-access
scope:
  path_prefix: /admin
  method: GET
YAML
cat > "$soundcheck_test_dir/candidate.yaml" <<'YAML'
schema_version: 1
kind: authenticated-access
scope:
  path_prefix: /public
  method: GET
YAML
cat > "$soundcheck_workspace/config.yaml" <<'YAML'
services:
  - name: app
    routes:
      - name: admin
        paths: [/admin]
        methods: [GET]
      - name: public
        paths: [/public]
        methods: [GET]
        plugins:
          - name: key-auth
YAML
cp "$soundcheck_test_dir/approved.yaml" "$soundcheck_workspace/contracts/security.yaml"
cp "$soundcheck_test_dir/approved.yaml" "$soundcheck_workspace/contracts/contract with space.yaml"
cp "$soundcheck_test_dir/approved.yaml" "$soundcheck_workspace/contracts/literal[1].yaml"
cp "$soundcheck_test_dir/candidate.yaml" "$soundcheck_workspace/contracts/literal1.yaml"
ln -s security.yaml "$soundcheck_workspace/contracts/base-link.yaml"
git_fixture add .
git_fixture update-index --add --cacheinfo "160000,$soundcheck_seed,contracts/module"
git_fixture commit --quiet -m 'Local approved base'
soundcheck_base="$(git_fixture rev-parse HEAD)"
soundcheck_blob="$(git_fixture rev-parse "$soundcheck_base:contracts/security.yaml")"
soundcheck_tree="$(git_fixture rev-parse "$soundcheck_base^{tree}")"
git_fixture tag --annotate approved-tag --message 'Local tag' "$soundcheck_base"
soundcheck_tag="$(git_fixture rev-parse approved-tag)"

# Candidate content and a moving branch ref must not replace the event SHA.
cp "$soundcheck_test_dir/candidate.yaml" "$soundcheck_workspace/contracts/security.yaml"
mkdir -p "$soundcheck_workspace/scripts" "$soundcheck_workspace/_build/default/cli"
printf '#!/usr/bin/env bash\nexit 90\n' > "$soundcheck_workspace/scripts/verify-approved-contract.sh"
cp "$soundcheck_workspace/scripts/verify-approved-contract.sh" \
  "$soundcheck_workspace/_build/default/cli/main.exe"
chmod +x "$soundcheck_workspace/_build/default/cli/main.exe"
git_fixture add .
git_fixture commit --quiet -m 'Local candidate weakens contract'
soundcheck_candidate="$(git_fixture rev-parse HEAD)"

write_pr_event() {
  jq -n --arg sha "${1:-$soundcheck_base}" --arg ref "${2:-main}" \
    --arg base_repo "${3:-local/soundcheck}" \
    '{repository: {full_name: "local/soundcheck", default_branch: "main"},
      pull_request: {base: {sha: $sha, ref: $ref, repo: {full_name: $base_repo}}}}' \
    > "$soundcheck_event"
}

write_push_event() {
  jq -n --arg sha "$soundcheck_candidate" \
    '{repository: {full_name: "local/soundcheck", default_branch: "main"},
      after: $sha, ref: "refs/heads/main", deleted: false, forced: false}' \
    > "$soundcheck_event"
}

run_gate() {
  soundcheck_case="$1"
  local expected_status="$2" expected_text="$3" actual_status=0
  shift 3
  local output="$soundcheck_test_dir/$soundcheck_case.output"
  local invocation="$soundcheck_test_dir/$soundcheck_case.invocation"
  SOUNDCHECK_CONFIG_INPUT=config.yaml \
    SOUNDCHECK_CONTRACT_INPUT=contracts/security.yaml \
    SOUNDCHECK_EXPECTED_CONTRACT="$soundcheck_test_dir/approved.yaml" \
    SOUNDCHECK_GATE_TEST_LOG="$invocation" \
    GITHUB_WORKSPACE="$soundcheck_workspace" \
    GITHUB_EVENT_PATH="$soundcheck_event" \
    GITHUB_EVENT_NAME=pull_request \
    GITHUB_REPOSITORY=local/soundcheck \
    GITHUB_BASE_REF=main \
    GITHUB_SHA="$soundcheck_candidate" \
    GITHUB_SERVER_URL=https://github.example.invalid \
    GITHUB_REF=refs/pull/1/merge \
    GITHUB_REF_TYPE=branch \
    GITHUB_REF_PROTECTED=false \
    RUNNER_TEMP="$soundcheck_runner_temp" \
    env "$@" bash "$soundcheck_action/scripts/verify-approved-contract.sh" \
    > "$output" 2>&1 || actual_status=$?
  [[ "$actual_status" -eq "$expected_status" ]] || \
    fail "expected exit $expected_status, got $actual_status (see $output)"
  [[ -z "$expected_text" ]] || expect_contains "$output" "$expected_text"
  [[ -z "$(find "$soundcheck_runner_temp" -mindepth 1 -print -quit)" ]] || \
    fail 'approved contract temporary file was not cleaned'
  if [[ -f "$invocation" ]]; then
    [[ ! -e "$(< "$invocation")" ]] || fail 'verifier contract file survived cleanup'
  fi
  soundcheck_count=$((soundcheck_count + 1))
  printf '[ok] approved contract gate: %s\n' "$soundcheck_case"
}

write_pr_event
run_gate pr-base-not-candidate 0 "$soundcheck_base:contracts/security.yaml"
for soundcheck_verifier_status in 1 2 3 4 5 6; do
  run_gate "verifier-exit-$soundcheck_verifier_status" "$soundcheck_verifier_status" '' \
    "SOUNDCHECK_MOCK_STATUS=$soundcheck_verifier_status"
done
run_gate literal-space-path 0 '' 'SOUNDCHECK_CONTRACT_INPUT=contracts/contract with space.yaml'
run_gate literal-glob-path 0 '' 'SOUNDCHECK_CONTRACT_INPUT=contracts/literal[1].yaml'

git_fixture replace "$soundcheck_base" "$soundcheck_candidate"
run_gate replacement-objects-ignored 0 "$soundcheck_base:contracts/security.yaml"
git_fixture replace --delete "$soundcheck_base" >/dev/null

mv "$soundcheck_workspace/contracts/security.yaml" "$soundcheck_test_dir/saved-candidate.yaml"
run_gate candidate-contract-deleted 0 ''
ln -s "$soundcheck_test_dir/candidate.yaml" "$soundcheck_workspace/contracts/security.yaml"
run_gate candidate-contract-symlink-ignored 0 ''
rm "$soundcheck_workspace/contracts/security.yaml"
mv "$soundcheck_test_dir/saved-candidate.yaml" "$soundcheck_workspace/contracts/security.yaml"

run_gate base-symlink-rejected 1 'regular Git blob' SOUNDCHECK_CONTRACT_INPUT=contracts/base-link.yaml
run_gate base-directory-rejected 1 'regular Git blob' SOUNDCHECK_CONTRACT_INPUT=contracts
run_gate base-submodule-rejected 1 'regular Git blob' SOUNDCHECK_CONTRACT_INPUT=contracts/module
run_gate base-path-missing 1 'exactly one tree entry' SOUNDCHECK_CONTRACT_INPUT=contracts/missing.yaml
soundcheck_path_case=0
for soundcheck_bad_path in /contracts/security.yaml ../contracts/security.yaml \
  ./contracts/security.yaml contracts/../security.yaml contracts//security.yaml \
  contracts/security.yaml/ 'contracts\security.yaml' $'contracts/security.yaml\n'; do
  soundcheck_path_case=$((soundcheck_path_case + 1))
  run_gate "contract-path-$soundcheck_path_case" 1 'normalized repository-relative' \
    "SOUNDCHECK_CONTRACT_INPUT=$soundcheck_bad_path"
done

soundcheck_sha_case=0
for soundcheck_bad_sha in HEAD "${soundcheck_base:0:12}" --help \
  0000000000000000000000000000000000000000; do
  soundcheck_sha_case=$((soundcheck_sha_case + 1))
  write_pr_event "$soundcheck_bad_sha"
  run_gate "invalid-sha-$soundcheck_sha_case" 1 'full nonzero commit SHA'
done
for soundcheck_object in "$soundcheck_blob" "$soundcheck_tree" "$soundcheck_tag"; do
  write_pr_event "$soundcheck_object"
  run_gate "noncommit-${soundcheck_object:0:8}" 1 'not a commit object'
done
write_pr_event "$soundcheck_base" 'main..invalid'
run_gate invalid-base-ref 1 'Invalid pull request base branch' GITHUB_BASE_REF=main..invalid
write_pr_event "$soundcheck_base" other
run_gate base-ref-mismatch 1 'base does not match'
write_pr_event "$soundcheck_base" main other/repository
run_gate base-repo-mismatch 1 'base does not match'
write_pr_event
run_gate workflow-repo-mismatch 1 'Event repository does not match' GITHUB_REPOSITORY=other/repository
run_gate missing-base-context 1 'base does not match' GITHUB_BASE_REF=
run_gate unsupported-target-event 1 'Supported events are' GITHUB_EVENT_NAME=pull_request_target
run_gate unsupported-manual-event 1 'Supported events are' GITHUB_EVENT_NAME=workflow_dispatch
run_gate unsupported-merge-queue-event 1 'Supported events are' GITHUB_EVENT_NAME=merge_group
run_gate absent-event 1 'regular GitHub event payload' GITHUB_EVENT_PATH="$soundcheck_test_dir/missing.json"
ln -s "$soundcheck_event" "$soundcheck_test_dir/event-link.json"
run_gate event-symlink 1 'regular GitHub event payload' GITHUB_EVENT_PATH="$soundcheck_test_dir/event-link.json"
printf '{invalid json\n' > "$soundcheck_event"
run_gate malformed-event 1 'Event payload has no repository identity'
jq -n '{repository:{full_name:"local/soundcheck"},pull_request:{base:{ref:"main",repo:{full_name:"local/soundcheck"}}}}' \
  > "$soundcheck_event"
run_gate missing-base-sha 1 'no immutable base SHA'
write_pr_event

run_gate config-traversal 1 'normalized workspace-relative' SOUNDCHECK_CONFIG_INPUT=../config.yaml
ln -s config.yaml "$soundcheck_workspace/config-link.yaml"
run_gate config-symlink 1 'must not traverse symlinks' SOUNDCHECK_CONFIG_INPUT=config-link.yaml
ln -s "$soundcheck_workspace" "$soundcheck_workspace/linked-directory"
run_gate config-ancestor-symlink 1 'must not traverse symlinks' SOUNDCHECK_CONFIG_INPUT=linked-directory/config.yaml
run_gate config-missing 1 'regular workspace file' SOUNDCHECK_CONFIG_INPUT=missing.yaml
run_gate temp-directory-missing 1 'RUNNER_TEMP' RUNNER_TEMP="$soundcheck_test_dir/missing-temp"

# A missing base never falls back to the branch or candidate contract. The mock
# records fetch args, then fails or fetches solely from our synthetic local repo.
mkdir "$soundcheck_test_dir/mock-bin"
cat > "$soundcheck_test_dir/mock-bin/git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
  if [[ "$arg" == fetch ]]; then
    printf '%s\n' "$@" > "$SOUNDCHECK_FETCH_LOG"
    case "${SOUNDCHECK_FETCH_MODE:-fail}" in
      fail) exit 42 ;;
      empty) exit 0 ;;
      local)
        args=("$@")
        args[$(($# - 2))]="$SOUNDCHECK_FETCH_SOURCE"
        exec "$SOUNDCHECK_REAL_GIT" -c protocol.file.allow=always "${args[@]}"
        ;;
      *) exit 43 ;;
    esac
  fi
done
exec "$SOUNDCHECK_REAL_GIT" "$@"
SH
chmod +x "$soundcheck_test_dir/mock-bin/git"
soundcheck_missing_sha=1111111111111111111111111111111111111111
write_pr_event "$soundcheck_missing_sha"
run_gate missing-object-exact-fetch 1 'Could not fetch the exact approved contract revision' \
  "PATH=$soundcheck_test_dir/mock-bin:$PATH" "SOUNDCHECK_REAL_GIT=$(command -v git)" \
  "SOUNDCHECK_FETCH_LOG=$soundcheck_test_dir/fetch.args"
expect_contains "$soundcheck_test_dir/fetch.args" 'https://github.example.invalid/local/soundcheck.git'
expect_contains "$soundcheck_test_dir/fetch.args" "$soundcheck_missing_sha"
expect_contains "$soundcheck_test_dir/fetch.args" '--no-write-fetch-head'
if grep -Fxq origin "$soundcheck_test_dir/fetch.args" || grep -Fxq main "$soundcheck_test_dir/fetch.args"; then
  fail 'fetch used a mutable branch or candidate origin'
fi
run_gate missing-object-unsafe-server 1 'HTTPS GitHub server URL' GITHUB_SERVER_URL=file:///tmp
run_gate missing-object-after-fetch 1 'still unavailable after fetch' \
  "PATH=$soundcheck_test_dir/mock-bin:$PATH" "SOUNDCHECK_REAL_GIT=$(command -v git)" \
  SOUNDCHECK_FETCH_MODE=empty "SOUNDCHECK_FETCH_LOG=$soundcheck_test_dir/empty-fetch.args"

soundcheck_shallow_workspace="$soundcheck_test_dir/shallow-workspace"
git -c protocol.file.allow=always clone --quiet --depth=1 \
  "file://$soundcheck_workspace" "$soundcheck_shallow_workspace"
if git -C "$soundcheck_shallow_workspace" cat-file -e "$soundcheck_base" 2>/dev/null; then
  fail 'shallow fixture unexpectedly already contains the base commit'
fi
write_pr_event
run_gate shallow-base-exact-fetch 0 "$soundcheck_base:contracts/security.yaml" \
  "GITHUB_WORKSPACE=$soundcheck_shallow_workspace" \
  "PATH=$soundcheck_test_dir/mock-bin:$PATH" "SOUNDCHECK_REAL_GIT=$(command -v git)" \
  SOUNDCHECK_FETCH_MODE=local "SOUNDCHECK_FETCH_SOURCE=file://$soundcheck_workspace" \
  "SOUNDCHECK_FETCH_LOG=$soundcheck_test_dir/shallow-fetch.args"
[[ "$(git -C "$soundcheck_shallow_workspace" rev-parse HEAD)" == "$soundcheck_candidate" ]] || \
  fail 'fetch changed the candidate checkout revision'
expect_contains "$soundcheck_test_dir/shallow-fetch.args" 'https://github.example.invalid/local/soundcheck.git'
expect_contains "$soundcheck_test_dir/shallow-fetch.args" "$soundcheck_base"

write_push_event
soundcheck_push_env=(GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/main \
  GITHUB_REF_PROTECTED=true "SOUNDCHECK_EXPECTED_CONTRACT=$soundcheck_test_dir/candidate.yaml")
run_gate protected-default-push 0 "$soundcheck_candidate:contracts/security.yaml" "${soundcheck_push_env[@]}"
run_gate unprotected-push 1 'protected repository default branch' "${soundcheck_push_env[@]}" GITHUB_REF_PROTECTED=false
run_gate feature-push 1 'protected repository default branch' "${soundcheck_push_env[@]}" GITHUB_REF=refs/heads/feature
run_gate tag-push 1 'protected repository default branch' "${soundcheck_push_env[@]}" GITHUB_REF_TYPE=tag
run_gate push-sha-mismatch 1 'does not match the workflow SHA' "${soundcheck_push_env[@]}" "GITHUB_SHA=$soundcheck_base"
for soundcheck_push_flag in deleted forced; do
  jq --arg flag "$soundcheck_push_flag" '.[$flag] = true' "$soundcheck_event" > "$soundcheck_test_dir/event-mutated.json"
  run_gate "$soundcheck_push_flag-push" 1 'Deleted, forced, or mismatched' \
    "${soundcheck_push_env[@]}" "GITHUB_EVENT_PATH=$soundcheck_test_dir/event-mutated.json"
done

# End-to-end negative control: candidate-selected scope would pass, but the
# authoritative base scope still rejects this exact same unsafe configuration.
chmod u+w "$soundcheck_action/_build/default/cli/main.exe"
cp "$soundcheck_cli_source" "$soundcheck_action/_build/default/cli/main.exe"
chmod +x "$soundcheck_action/_build/default/cli/main.exe"
"$soundcheck_action/_build/default/cli/main.exe" verify "$soundcheck_workspace/config.yaml" \
  --contract "$soundcheck_workspace/contracts/security.yaml" --format json \
  > "$soundcheck_test_dir/candidate-contract-direct.json"
expect_contains "$soundcheck_test_dir/candidate-contract-direct.json" '"result":"proved"'
write_pr_event
run_gate real-cli-rejects-contract-weakening 3 'violated'
cat > "$soundcheck_workspace/config.yaml" <<'YAML'
services:
  - name: app
    routes:
      - name: admin
        paths: [/admin]
        methods: [GET]
        plugins:
          - name: key-auth
      - name: public
        paths: [/public]
        methods: [GET]
        plugins:
          - name: key-auth
YAML
run_gate real-cli-accepts-config-repair 0 'proved'
printf 'All %s approved-contract gate checks passed (local Git, no network).\n' "$soundcheck_count"
