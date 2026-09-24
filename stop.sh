#!/usr/bin/env bash
# Stop the services started by ./start.sh (native or --docker).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="$ROOT/.run"
PID_FILE="$RUN_DIR/frontend.pid"
PORT_FILE="$RUN_DIR/frontend.port"

case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) WINDOWS=1 ;; *) WINDOWS=0 ;; esac

info() { printf '\033[1m==>\033[0m %s\n' "$*"; }

pid_alive() {
  if [ "$WINDOWS" = 1 ]; then
    tasklist //FI "PID eq $1" 2>/dev/null | grep -q " $1 "
  else
    kill -0 "$1" 2>/dev/null
  fi
}

kill_tree() {
  local pid="$1"
  if [ "$WINDOWS" = 1 ]; then
    taskkill //PID "$pid" //T //F >/dev/null 2>&1 || true
  else
    local child
    for child in $(pgrep -P "$pid" 2>/dev/null || true); do kill_tree "$child"; done
    kill "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5; do pid_alive "$pid" || return 0; sleep 1; done
    kill -9 "$pid" 2>/dev/null || true
  fi
}

# Next.js can leave a worker bound to the port after its parent exits, so also
# stop whatever *node* process still listens on the recorded port.
port_node_pids() {
  local port="$1"
  if [ "$WINDOWS" = 1 ]; then
    netstat -ano 2>/dev/null | grep -E "[:.]$port[[:space:]].*LISTENING" | awk '{print $NF}' | sort -u |
      while read -r pid; do
        tasklist //FI "PID eq $pid" //FO CSV //NH 2>/dev/null | grep -qi '^"node' && echo "$pid"
      done
  elif command -v lsof >/dev/null 2>&1; then
    lsof -a -t -iTCP:"$port" -sTCP:LISTEN -c node 2>/dev/null || true
  fi
}

stopped=0

# Only the containers start.sh names; images and volumes are untouched.
for CONTAINER in soundcheck-web soundcheck-engine; do
  if command -v docker >/dev/null 2>&1 &&
    [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = "true" ]; then
    info "Stopping container $CONTAINER"
    docker stop "$CONTAINER" >/dev/null
    stopped=1
  fi
done
rm -f "$RUN_DIR/mode"
# Scratch inputs the dev-mode engine read through its bind mount.
rm -rf "$RUN_DIR/engine-work"

if [ -f "$PID_FILE" ]; then
  PID="$(cat "$PID_FILE")"
  if pid_alive "$PID"; then
    info "Stopping the web app (pid $PID)"
    kill_tree "$PID"
    stopped=1
  fi
  rm -f "$PID_FILE"
fi

if [ -f "$PORT_FILE" ]; then
  PORT="$(cat "$PORT_FILE")"
  for pid in $(port_node_pids "$PORT"); do
    info "Stopping leftover node process $pid on port $PORT"
    kill_tree "$pid"
    stopped=1
  done
  rm -f "$PORT_FILE"
fi

if [ "$stopped" = 1 ]; then
  info "Soundcheck stopped"
else
  info "Soundcheck is not running"
fi
