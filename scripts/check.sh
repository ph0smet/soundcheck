#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'Usage: bash scripts/check.sh [fast|full|conformance]' \
    '  fast         Incremental build and regression tests (default).' \
    '  full         Build, force regression tests, then real-Kong conformance.' \
    '  conformance  Pinned real-Kong checks only; serialize runs on this host.' \
    'Uses the existing opam environment; does not install dependencies.' \
    'Full and conformance require Docker, a running daemon, and curl.'
}

if [[ $# -gt 1 ]]; then
  usage >&2
  exit 2
fi

soundcheck_mode="${1:-fast}"
case "$soundcheck_mode" in
  fast|full|conformance) ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

soundcheck_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
soundcheck_repo_root="$(cd "$soundcheck_script_dir/.." && pwd)"
cd "$soundcheck_repo_root"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'Required command is missing: %s\n' "$1" >&2
    exit 1
  fi
}

require_command opam
soundcheck_opam_env="$(opam env)"
eval "$soundcheck_opam_env"
require_command dune
require_command z3

if [[ "$soundcheck_mode" != fast ]]; then
  require_command docker
  require_command curl
  if ! docker info >/dev/null; then
    printf '%s\n' 'Docker is unavailable; conformance was not run.' >&2
    exit 1
  fi
fi

case "$soundcheck_mode" in
  fast)
    dune build @all
    dune test
    ;;
  full)
    dune build @all
    dune test --force
    bash bench/kong/conformance/run.sh
    ;;
  conformance)
    bash bench/kong/conformance/run.sh
    ;;
esac

printf 'Soundcheck %s checks passed.\n' "$soundcheck_mode"
