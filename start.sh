#!/usr/bin/env bash
# Start Soundcheck and wait until the web UI responds. Stop with ./stop.sh.
#
#   ./start.sh [--port N] [--skip-tests]               Docker, production image (default)
#   ./start.sh --dev [--port N] [--skip-tests]         live dev: hot reload + engine in Docker
#   ./start.sh --native [--prod] [--port N] [--skip-engine]   local OCaml toolchain
#
#   (default)      build and run the all-in-one image (engine + z3 + UI); needs
#                  only Docker. The CLI then works via ./soundcheck.sh.
#   --dev          run the Next.js dev server natively with hot reload, and the
#                  engine + z3 in a long-lived container. Edits to frontend/ show
#                  up instantly. After changing engine code, rerun ./start.sh --dev:
#                  it rebuilds and swaps only the engine container.
#   --native       run the UI with Node and the engine from a local dune build
#   --prod         native: production build + `next start` (default: dev server)
#   --skip-engine  native: do not run `dune build`
#   --skip-tests   Docker/dev: skip the `dune test` gate during the image build
#   --port N       web port (default: 3000, or $PORT)
#
# The engine is a CLI invoked per request. The MCP server (`soundcheck mcp`) is
# started on demand by the agent that uses it over stdio.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND="$ROOT/frontend"
RUN_DIR="$ROOT/.run"
PID_FILE="$RUN_DIR/frontend.pid"
LOG_FILE="$RUN_DIR/frontend.log"
IMAGE="${SOUNDCHECK_IMAGE:-soundcheck:local}"
ENGINE_IMAGE="soundcheck-engine:local"
CONTAINER="soundcheck-web"
ENGINE_CONTAINER="soundcheck-engine"

RUN_MODE="docker"
NEXT_MODE="dev"
PORT="${PORT:-3000}"
BUILD_ENGINE=1
RUN_TESTS=1

while [ $# -gt 0 ]; do
  case "$1" in
    --dev) RUN_MODE="dev" ;;
    --native) RUN_MODE="native" ;;
    --prod) NEXT_MODE="prod" ;;
    --port) PORT="${2:?--port requires a value}"; shift ;;
    --skip-engine) BUILD_ENGINE=0 ;;
    --skip-tests) RUN_TESTS=0 ;;
    -h|--help) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

if [ "$RUN_MODE" != native ] && { [ "$NEXT_MODE" = prod ] || [ "$BUILD_ENGINE" = 0 ]; }; then
  echo "--prod and --skip-engine apply to --native only" >&2
  exit 2
fi

case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) WINDOWS=1 ;; *) WINDOWS=0 ;; esac

info() { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Paths handed to Windows-native programs (node, docker) must be Windows paths.
native_path() {
  if [ "$WINDOWS" = 1 ]; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

pid_alive() {
  local pid="$1"
  if [ "$WINDOWS" = 1 ]; then
    tasklist //FI "PID eq $pid" 2>/dev/null | grep -q " $pid "
  else
    kill -0 "$pid" 2>/dev/null
  fi
}

port_busy() {
  if [ "$WINDOWS" = 1 ]; then
    netstat -ano 2>/dev/null | grep -E "[:.]$PORT[[:space:]].*LISTENING" >/dev/null
  elif command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1
  else
    (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null
  fi
}

running() {
  command -v docker >/dev/null 2>&1 &&
    [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = "true" ]
}

require_docker() {
  command -v docker >/dev/null 2>&1 || fail "Docker is not installed. Install it, or use --native with a local toolchain."
  docker info >/dev/null 2>&1 || fail "the Docker daemon is not running. Start Docker Desktop (or dockerd), or use --native."
}

# Polls the UI until it answers; $1 is a command that fails once the server died.
wait_until_ready() {
  local alive_check="$1" url="http://localhost:$PORT" status
  for _ in $(seq 1 90); do
    if ! $alive_check; then
      return 1
    fi
    if status="$(curl -fsS "$url/api/engine" 2>/dev/null)"; then
      info "Soundcheck is running at $url"
      case "$status" in
        *'"available":true'*'"solver":{"available":true'*) info "Engine ready ($(printf '%s' "$status" | sed -n 's/.*"profile":"\([^"]*\)".*/\1/p'))" ;;
        *) warn "engine not ready: $(printf '%s' "$status" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p')" ;;
      esac
      return 0
    fi
    sleep 1
  done
  return 2
}

mkdir -p "$RUN_DIR"

if running "$CONTAINER"; then
  info "Soundcheck is already running in Docker (container $CONTAINER). Use ./stop.sh first."
  exit 0
fi
# Rerunning --dev during a dev session only refreshes the engine container, so
# engine changes land without restarting the hot-reloading web server.
REFRESH_ENGINE_ONLY=0
if [ -f "$PID_FILE" ] && pid_alive "$(cat "$PID_FILE")"; then
  if [ "$RUN_MODE" = dev ] && [ "$(cat "$RUN_DIR/mode" 2>/dev/null)" = dev ]; then
    REFRESH_ENGINE_ONLY=1
  else
    info "Soundcheck is already running (pid $(cat "$PID_FILE")). Use ./stop.sh first."
    exit 0
  fi
else
  rm -f "$PID_FILE"
  port_busy && fail "port $PORT is already in use. Pick another with --port N."
fi

# --- docker mode: production image -------------------------------------------

if [ "$RUN_MODE" = docker ]; then
  require_docker
  info "Building image $IMAGE (cached layers make rebuilds fast)"
  docker build --build-arg RUN_TESTS="$RUN_TESTS" -t "$IMAGE" "$ROOT"

  # A stopped container with our name is a leftover from a previous run.
  docker rm "$CONTAINER" >/dev/null 2>&1 || true

  info "Starting container $CONTAINER on port $PORT"
  docker run -d --rm --name "$CONTAINER" -p "$PORT:3000" "$IMAGE" web >/dev/null
  echo docker >"$RUN_DIR/mode"
  echo "$PORT" >"$RUN_DIR/frontend.port"

  web_alive() { running "$CONTAINER"; }
  if wait_until_ready web_alive; then
    echo "    logs: docker logs -f $CONTAINER"
    echo "    cli:  ./soundcheck.sh verify <config.yaml> [...]"
    echo "    stop: ./stop.sh"
    exit 0
  fi
  docker logs --tail 30 "$CONTAINER" >&2 2>&1 || true
  fail "the container did not become ready"
fi

# --- dev mode: engine container ----------------------------------------------

if [ "$RUN_MODE" = dev ]; then
  require_docker
  info "Building the engine image $ENGINE_IMAGE (skips the web build)"
  docker build --target engine-runtime --build-arg RUN_TESTS="$RUN_TESTS" -t "$ENGINE_IMAGE" "$ROOT"

  WORKDIR="$RUN_DIR/engine-work"
  mkdir -p "$WORKDIR"

  wanted="$(docker image inspect -f '{{.Id}}' "$ENGINE_IMAGE")"
  if running "$ENGINE_CONTAINER" && [ "$(docker inspect -f '{{.Image}}' "$ENGINE_CONTAINER")" = "$wanted" ]; then
    info "Reusing engine container $ENGINE_CONTAINER"
  else
    docker rm -f "$ENGINE_CONTAINER" >/dev/null 2>&1 || true
    USER_ARGS=()
    [ "$(uname -s)" = Linux ] && USER_ARGS=(--user "$(id -u):$(id -g)")
    info "Starting engine container $ENGINE_CONTAINER"
    MSYS_NO_PATHCONV=1 docker run -d --rm --name "$ENGINE_CONTAINER" \
      ${USER_ARGS[@]+"${USER_ARGS[@]}"} \
      -v "$(native_path "$WORKDIR"):/work/jobs" "$ENGINE_IMAGE" >/dev/null
  fi

  if [ "$REFRESH_ENGINE_ONLY" = 1 ]; then
    info "Engine refreshed. The dev server on port $(cat "$RUN_DIR/frontend.port") picks it up on the next request."
    exit 0
  fi

  export SOUNDCHECK_BIN="$(native_path "$ROOT/docker/engine-bridge.mjs")"
  export SOUNDCHECK_WORKDIR="$(native_path "$WORKDIR")"
  export SOUNDCHECK_ENGINE_CONTAINER="$ENGINE_CONTAINER"
fi

# --- native mode: engine -----------------------------------------------------

if [ "$RUN_MODE" = native ]; then
  if [ -n "${SOUNDCHECK_BIN:-}" ]; then
    info "Using engine from SOUNDCHECK_BIN=$SOUNDCHECK_BIN"
  elif [ "$BUILD_ENGINE" = 1 ]; then
    if command -v opam >/dev/null 2>&1; then
      eval "$(opam env 2>/dev/null)" || true
    fi
    if command -v dune >/dev/null 2>&1; then
      info "Building the engine (dune build)"
      if ! (cd "$ROOT" && dune build 2>&1); then
        warn "dune build failed. The web app will start, but live verification is unavailable."
      fi
    else
      warn "dune not found. The web app will start read-only. Use --dev to run the engine in Docker."
    fi
  fi
  command -v z3 >/dev/null 2>&1 || warn "z3 not found on PATH. Verification and comparison need it (or use --dev)."
fi

# --- web app (dev and native) ------------------------------------------------

command -v node >/dev/null 2>&1 || fail "Node.js is required (v20 or newer)."
command -v npm >/dev/null 2>&1 || fail "npm is required."

cd "$FRONTEND"
STAMP="node_modules/.soundcheck-installed"
if [ ! -f "$STAMP" ] || [ package.json -nt "$STAMP" ] || [ package-lock.json -nt "$STAMP" ]; then
  info "Installing frontend dependencies"
  npm install --no-audit --no-fund
  touch "$STAMP"
fi

NEXT="node_modules/next/dist/bin/next"
if [ "$NEXT_MODE" = "prod" ]; then
  info "Building the web app for production"
  node "$NEXT" build
  ARGS=(start -p "$PORT")
else
  ARGS=(dev -p "$PORT")
fi

info "Starting the web app (next $([ "$NEXT_MODE" = prod ] && echo start || echo dev)) on port $PORT"
export SOUNDCHECK_REPO="$(native_path "$ROOT")"
nohup node "$NEXT" "${ARGS[@]}" >"$LOG_FILE" 2>&1 &
PID=$!
if [ "$WINDOWS" = 1 ] && [ -r "/proc/$PID/winpid" ]; then
  PID="$(cat "/proc/$PID/winpid")"
fi
echo "$PID" >"$PID_FILE"
echo "$RUN_MODE" >"$RUN_DIR/mode"
echo "$PORT" >"$RUN_DIR/frontend.port"

native_alive() { pid_alive "$PID"; }

if wait_until_ready native_alive; then
  [ "$RUN_MODE" = dev ] && echo "    live: edits under frontend/ reload instantly; rerun ./start.sh --dev to refresh the engine"
  echo "    pid:  $PID"
  echo "    logs: $LOG_FILE"
  echo "    stop: ./stop.sh"
  exit 0
fi
tail -n 30 "$LOG_FILE" >&2 || true
rm -f "$PID_FILE"
fail "the web app did not become ready (log: $LOG_FILE)"
