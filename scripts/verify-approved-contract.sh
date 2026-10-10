#!/usr/bin/env bash
set -euo pipefail

# Run only from a trusted, commit-pinned Action. The candidate repository owns
# the config bytes, never this helper, verifier, event metadata, or contract
# selection policy. Repository protection and separate contract approval are
# deployment prerequisites; extracting a base blob does not establish them.
fail() {
  printf '::error title=Soundcheck contract source::%s\n' "$1" >&2
  exit 1
}

[[ $# -eq 0 ]] || fail 'This helper accepts inputs through the Action environment only.'
for soundcheck_command in git jq mktemp; do
  command -v "$soundcheck_command" >/dev/null || fail "Missing required command: $soundcheck_command"
done

valid_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ && "$1" != 0000000000000000000000000000000000000000 ]]
}

valid_relative_path() {
  local value="$1" component
  local components=()
  [[ -n "$value" && "$value" != /* && "$value" != */ &&
     "$value" != *//* && "$value" != *\\* && ! "$value" =~ [[:cntrl:]] ]] || return 1
  IFS='/' read -r -a components <<< "$value"
  for component in "${components[@]}"; do
    [[ "$component" != . && "$component" != .. && -n "$component" ]] || return 1
  done
}

soundcheck_config_input="${SOUNDCHECK_CONFIG_INPUT:-}"
soundcheck_contract_input="${SOUNDCHECK_CONTRACT_INPUT:-}"
valid_relative_path "$soundcheck_config_input" || fail 'config must be a normalized workspace-relative file path.'
valid_relative_path "$soundcheck_contract_input" || fail 'contract must be a normalized repository-relative file path.'

[[ "${GITHUB_WORKSPACE:-}" == /* && -d "$GITHUB_WORKSPACE" ]] || fail 'GITHUB_WORKSPACE must identify the checked-out repository.'
soundcheck_workspace="$(cd "$GITHUB_WORKSPACE" && pwd -P)"
soundcheck_action_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
soundcheck_verifier="$soundcheck_action_root/_build/default/cli/main.exe"
[[ -f "$soundcheck_verifier" && -x "$soundcheck_verifier" ]] || fail 'The trusted Action verifier has not been built.'

# Do not inherit repository selection, replacement objects, or pathspec modes
# from another step. The full event SHA and literal path are the only selectors.
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_NAMESPACE GIT_REPLACE_REF_BASE \
  GIT_GLOB_PATHSPECS GIT_NOGLOB_PATHSPECS GIT_ICASE_PATHSPECS
export GIT_NO_REPLACE_OBJECTS=1 GIT_LITERAL_PATHSPECS=1 GIT_TERMINAL_PROMPT=0
git_repo() {
  git --no-replace-objects -c core.hooksPath=/dev/null -C "$soundcheck_workspace" "$@"
}
[[ "$(git_repo rev-parse --show-toplevel)" == "$soundcheck_workspace" ]] || fail 'Checkout must be at the workspace repository root.'

[[ "${GITHUB_EVENT_PATH:-}" == /* && -f "$GITHUB_EVENT_PATH" && ! -L "$GITHUB_EVENT_PATH" ]] || fail 'A regular GitHub event payload is required.'
[[ "${GITHUB_REPOSITORY:-}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail 'Invalid GitHub repository identity.'
valid_relative_path "$GITHUB_REPOSITORY" || fail 'Invalid GitHub repository identity.'
soundcheck_event_repo="$(jq -er '.repository.full_name | strings' "$GITHUB_EVENT_PATH")" || fail 'Event payload has no repository identity.'
[[ "$soundcheck_event_repo" == "$GITHUB_REPOSITORY" ]] || fail 'Event repository does not match the running workflow.'

case "${GITHUB_EVENT_NAME:-}" in
  pull_request)
    # REF_PROTECTED describes the PR merge ref here, not the base branch.
    # Protection of the actual base and its contract review policy are external.
    soundcheck_source_sha="$(jq -er '.pull_request.base.sha | strings' "$GITHUB_EVENT_PATH")" || fail 'Pull request payload has no immutable base SHA.'
    soundcheck_base_ref="$(jq -er '.pull_request.base.ref | strings' "$GITHUB_EVENT_PATH")" || fail 'Pull request payload has no base branch.'
    soundcheck_base_repo="$(jq -er '.pull_request.base.repo.full_name | strings' "$GITHUB_EVENT_PATH")" || fail 'Pull request payload has no base repository.'
    [[ "$soundcheck_base_repo" == "$GITHUB_REPOSITORY" &&
       -n "${GITHUB_BASE_REF:-}" && "$soundcheck_base_ref" == "$GITHUB_BASE_REF" ]] || fail 'Pull request base does not match the workflow repository and base branch.'
    git check-ref-format "refs/heads/$soundcheck_base_ref" >/dev/null || fail 'Invalid pull request base branch.'
    ;;
  push)
    # This bit only says protections/rulesets exist. It cannot establish that
    # the required review and separate contract approval actually took place.
    soundcheck_default_branch="$(jq -er '.repository.default_branch | strings' "$GITHUB_EVENT_PATH")" || fail 'Push payload has no default branch.'
    git check-ref-format "refs/heads/$soundcheck_default_branch" >/dev/null || fail 'Invalid default branch.'
    [[ "${GITHUB_REF_TYPE:-}" == branch && "${GITHUB_REF_PROTECTED:-}" == true &&
       "${GITHUB_REF:-}" == "refs/heads/$soundcheck_default_branch" ]] || fail 'Push verification requires the protected repository default branch.'
    jq -e --arg ref "$GITHUB_REF" '.ref == $ref and .deleted == false and .forced == false' \
      "$GITHUB_EVENT_PATH" >/dev/null || fail 'Deleted, forced, or mismatched push events are not supported.'
    soundcheck_source_sha="$(jq -er '.after | strings' "$GITHUB_EVENT_PATH")" || fail 'Push payload has no immutable after SHA.'
    [[ "$soundcheck_source_sha" == "${GITHUB_SHA:-}" ]] || fail 'Push after SHA does not match the workflow SHA.'
    ;;
  *) fail 'Supported events are pull_request and protected-default-branch push only.' ;;
esac
valid_sha "$soundcheck_source_sha" || fail 'Approved contract revision must be a full nonzero commit SHA.'

if ! soundcheck_object_type="$(git_repo cat-file -t "$soundcheck_source_sha" 2>/dev/null)"; then
  # Default shallow checkout may lack the base commit. Fetch that exact object
  # from the event repository, never a mutable branch or candidate-controlled
  # origin URL. Existing checkout credentials can authorize a private repo.
  [[ "${GITHUB_SERVER_URL:-}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || fail 'An HTTPS GitHub server URL is required to fetch the approved revision.'
  soundcheck_source_url="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY.git"
  git_repo -c protocol.allow=never -c protocol.https.allow=always \
    -c http.lowSpeedLimit=1024 -c http.lowSpeedTime=30 \
    fetch --quiet --no-tags --depth=1 --no-write-fetch-head -- \
    "$soundcheck_source_url" "$soundcheck_source_sha" || fail 'Could not fetch the exact approved contract revision.'
  soundcheck_object_type="$(git_repo cat-file -t "$soundcheck_source_sha" 2>/dev/null)" || fail 'Approved revision is still unavailable after fetch.'
fi
[[ "$soundcheck_object_type" == commit ]] || fail 'Approved revision is not a commit object.'

soundcheck_entry="$(git_repo ls-tree --full-tree --format='%(objectmode) %(objecttype) %(objectname)' \
  "$soundcheck_source_sha" -- "$soundcheck_contract_input")" || fail 'Cannot resolve the approved contract path.'
[[ -n "$soundcheck_entry" && "$soundcheck_entry" != *$'\n'* ]] || fail 'Approved contract path must select exactly one tree entry.'
IFS=' ' read -r soundcheck_mode soundcheck_type soundcheck_blob soundcheck_extra <<< "$soundcheck_entry"
[[ ( "$soundcheck_mode" == 100644 || "$soundcheck_mode" == 100755 ) &&
   "$soundcheck_type" == blob && -z "$soundcheck_extra" ]] || fail 'Approved contract must be a regular Git blob, not a symlink, directory, or submodule.'
valid_sha "$soundcheck_blob" || fail 'Approved contract has an invalid blob identity.'

# Reject config symlinks, including ancestor directories. The config belongs to
# the candidate workspace, but must not redirect verification outside it.
soundcheck_config_path="$soundcheck_workspace"
IFS='/' read -r -a soundcheck_components <<< "$soundcheck_config_input"
for soundcheck_component in "${soundcheck_components[@]}"; do
  soundcheck_config_path="$soundcheck_config_path/$soundcheck_component"
  [[ ! -L "$soundcheck_config_path" ]] || fail 'Candidate config path must not traverse symlinks.'
done
[[ -f "$soundcheck_config_path" ]] || fail 'Candidate config must be a regular workspace file.'

[[ "${RUNNER_TEMP:-}" == /* && -d "$RUNNER_TEMP" ]] || fail 'RUNNER_TEMP must identify an existing absolute temporary directory.'
umask 077
soundcheck_temp_dir="$(mktemp -d "$RUNNER_TEMP/soundcheck-approved-contract.XXXXXX")"
readonly soundcheck_temp_dir
soundcheck_contract_file="$soundcheck_temp_dir/contract.yaml"
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  # Only the immutable mktemp path and the one file this invocation creates.
  if ! rm -f -- "$soundcheck_contract_file" || ! rmdir -- "$soundcheck_temp_dir"; then
    printf 'Soundcheck: could not fully clean the approved-contract temporary directory.\n' >&2
    [[ "$status" -ne 0 ]] || status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

git_repo cat-file blob "$soundcheck_blob" > "$soundcheck_contract_file" || fail 'Cannot extract the approved contract blob.'
chmod 400 "$soundcheck_contract_file"
printf 'Approved contract: %s:%s (blob %s)\n' \
  "$soundcheck_source_sha" "$soundcheck_contract_input" "$soundcheck_blob"
"$soundcheck_verifier" verify "$soundcheck_config_path" \
  --contract "$soundcheck_contract_file" --format github
