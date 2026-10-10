#!/usr/bin/env bash
# Run the Soundcheck CLI from the Docker image, with no local OCaml or Z3 install.
# The current directory is mounted at /work, so paths must be inside it.
#
#   ./soundcheck.sh verify kong.yaml --format json
#   ./soundcheck.sh compare before.yaml after.yaml --mode route-service
#   ./soundcheck.sh mcp --contract contract.yaml      # MCP over stdio
#
# Exit codes are the engine's own (0 proved, 3 violated, ...); 125 means the
# image is missing or Docker could not start the container.

set -euo pipefail

IMAGE="${SOUNDCHECK_IMAGE:-soundcheck:local}"
USER_ARGS=()

case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*)
    HOST_DIR="$(pwd -W)"
    export MSYS_NO_PATHCONV=1
    ;;
  Linux)
    HOST_DIR="$PWD"
    # Files the engine writes (e.g. --emit-smt) should belong to the caller.
    USER_ARGS=(--user "$(id -u):$(id -g)")
    ;;
  *)
    HOST_DIR="$PWD"
    ;;
esac

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "soundcheck: image $IMAGE not found. Build it with ./start.sh --docker or: docker build -t $IMAGE ." >&2
  exit 125
fi

# The ${a[@]+...} form keeps macOS bash 3.2 happy with an empty array under set -u.
exec docker run --rm -i ${USER_ARGS[@]+"${USER_ARGS[@]}"} -v "$HOST_DIR:/work" -w /work "$IMAGE" soundcheck "$@"
