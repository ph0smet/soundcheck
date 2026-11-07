#!/usr/bin/env bash
set -euo pipefail

soundcheck_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
soundcheck_repo_root="$(cd "$soundcheck_script_dir/../../.." && pwd)"
soundcheck_go="${GO:-go}"
soundcheck_z3="${Z3:-z3}"
soundcheck_python="${PYTHON:-python3}"

if [[ $# -ne 0 ]]; then
  printf '%s\n' 'Usage: bash bench/kubernetes-rbac/conformance/run.sh' \
    'Optional executable overrides: GO, Z3, PYTHON.' \
    'Runs the pinned upstream comparison; missing tools fail, never skip.' >&2
  exit 2
fi

cd "$soundcheck_repo_root"
for soundcheck_command in "$soundcheck_go" "$soundcheck_z3" "$soundcheck_python" opam; do
  if ! command -v "$soundcheck_command" >/dev/null 2>&1; then
    printf 'Required conformance command is missing: %s\n' "$soundcheck_command" >&2
    exit 1
  fi
done
eval "$(opam env)"
if ! command -v dune >/dev/null 2>&1; then
  printf '%s\n' 'Required conformance command is missing: dune' >&2
  exit 1
fi
soundcheck_build_dir="$soundcheck_repo_root/_build/rbac-conformance"
mkdir -p "$soundcheck_build_dir"

# Use only the caller's Go toolchain. Module downloads are explicit work of this
# conformance command, never part of dune test or the shipped verifier runtime.
export GOTOOLCHAIN=local
export GOWORK=off
export CGO_ENABLED=0
"$soundcheck_go" version
"$soundcheck_z3" -version
"$soundcheck_go" -C "$soundcheck_script_dir/oracle" mod download
"$soundcheck_go" -C "$soundcheck_script_dir/oracle" mod verify
"$soundcheck_go" -C "$soundcheck_script_dir/oracle" test -mod=readonly -count=1 ./...
"$soundcheck_go" -C "$soundcheck_script_dir/oracle" build -mod=readonly -trimpath \
  -o "$soundcheck_build_dir/reference-oracle" .
"$soundcheck_go" -C "$soundcheck_script_dir/oracle" list -mod=readonly -m -json all \
  > "$soundcheck_build_dir/modules.jsonl"
"$soundcheck_go" -C "$soundcheck_script_dir/oracle" mod download -json k8s.io/kubernetes@v1.34.0 \
  > "$soundcheck_build_dir/kubernetes-module.json"
"$soundcheck_go" version -m "$soundcheck_build_dir/reference-oracle" \
  > "$soundcheck_build_dir/reference-build.txt"

"$soundcheck_python" "$soundcheck_script_dir/test_runner.py"
dune build bench/kubernetes-rbac/model_oracle.exe cli/main.exe
"$soundcheck_python" "$soundcheck_script_dir/run.py" \
  --reference "$soundcheck_build_dir/reference-oracle" \
  --model "$soundcheck_repo_root/_build/default/bench/kubernetes-rbac/model_oracle.exe" \
  --soundcheck "$soundcheck_repo_root/_build/default/cli/main.exe" \
  --z3 "$soundcheck_z3" \
  --output "$soundcheck_build_dir/results.json"
