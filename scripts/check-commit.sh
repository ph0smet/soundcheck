#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'Usage: bash scripts/check-commit.sh [revision]' \
    'Build and force regression tests in a clean worktree of a commit (default: HEAD).' \
    'Uncommitted edits are excluded. Does not commit, push, or run Docker.' \
    'Uses the existing opam environment. Retains the worktree on failure.'
}

if [[ $# -gt 1 ]]; then
  usage >&2
  exit 2
fi
case "${1:-HEAD}" in
  -h|--help) usage; exit 0 ;;
esac

soundcheck_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
soundcheck_repo_root="$(cd "$soundcheck_script_dir/.." && pwd)"
cd "$soundcheck_repo_root"
soundcheck_commit="$(git rev-parse --verify --end-of-options "${1:-HEAD}^{commit}")"

# Resolve the switch before moving to the throwaway checkout, so a local switch
# in the original checkout remains available to this run.
soundcheck_opam_env="$(opam env)"
eval "$soundcheck_opam_env"
for soundcheck_command in dune z3; do
  if ! command -v "$soundcheck_command" >/dev/null 2>&1; then
    printf 'Required command is missing: %s\n' "$soundcheck_command" >&2
    exit 1
  fi
done

soundcheck_temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/soundcheck-check.XXXXXX")"
soundcheck_worktree="$soundcheck_temp_dir/worktree"

cleanup() {
  local soundcheck_status=$?
  trap - EXIT
  cd "$soundcheck_repo_root"
  if [[ "$soundcheck_status" -ne 0 ]]; then
    printf 'Validation failed; temporary files retained at %s\n' "$soundcheck_temp_dir" >&2
    exit "$soundcheck_status"
  fi
  # Never force removal: preserve unexpected changes for inspection.
  if ! git worktree remove "$soundcheck_worktree"; then
    printf 'Could not clean up worktree; retained at %s\n' "$soundcheck_worktree" >&2
    exit 1
  fi
  rmdir "$soundcheck_temp_dir"
}
trap cleanup EXIT

printf 'Checking commit %s; uncommitted edits are excluded.\n' "$soundcheck_commit"
git worktree add --detach "$soundcheck_worktree" "$soundcheck_commit"
cd "$soundcheck_worktree"
dune build @all
dune test --force
printf 'Clean-worktree regression checks passed for %s.\n' "$soundcheck_commit"
