#!/usr/bin/env bash
# Stop the services started by ./start.sh (native or --docker).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="${SOUNDCHECK_RUN_DIR:-$ROOT/.run}"
PID_FILE="$RUN_DIR/frontend.pid"
PORT_FILE="$RUN_DIR/frontend.port"

case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) WINDOWS=1 ;; *) WINDOWS=0 ;; esac

info() { printf '\033[1m==>\033[0m %s\n' "$*"; }

# pid_alive, owned and kill_tree: process ownership shared with start.sh.
# shellcheck source=scripts/launcher-common.sh
. "$ROOT/scripts/launcher-common.sh"

# Next.js can leave a worker bound to the port after its parent exits, so also
# look at the processes listening on the recorded port. Only those that run this
# checkout's Next.js (see owned) are stopped; another app that took the port is
# not. On Linux and macOS no process-name filter is applied: Next.js renames its
# server process, so it is no longer called "node" there.
port_pids() {
  local port="$1"
  if [ "$WINDOWS" = 1 ]; then
    netstat -ano 2>/dev/null | grep -E "[:.]$port[[:space:]].*LISTENING" | awk '{print $NF}' | sort -u |
      while read -r pid; do
        tasklist //FI "PID eq $pid" //FO CSV //NH 2>/dev/null | grep -qi '^"node' && echo "$pid"
      done
  elif [ -r /proc/net/tcp ]; then
    # Linux: read the kernel's table directly. lsof is not used here: it skips
    # processes whose renamed title ("next-server (v...") breaks its parsing of
    # /proc/PID/stat, and it is often not installed.
    proc_port_pids "$port"
  elif command -v lsof >/dev/null 2>&1; then
    lsof -t -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | sort -u || true
  fi
}

# Linux: find the listening socket's inode in the kernel's table, then the
# process holding that socket.
proc_port_pids() {
  local hex inodes pid fd target
  hex="$(printf '%04X' "$1")"
  # Columns: local_address (ip:PORT in hex), state (0A = LISTEN), inode (10th).
  inodes="$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null |
    awk -v port=":$hex" '$4 == "0A" && substr($2, length($2) - 4) == port { print $10 }' | sort -u)"
  [ -n "$inodes" ] || return 0
  for pid in /proc/[0-9]*; do
    pid="${pid#/proc/}"
    for fd in /proc/"$pid"/fd/*; do
      target="$(readlink "$fd" 2>/dev/null)" || continue
      case "$target" in "socket:["*"]")
        target="${target#socket:[}"; target="${target%]}"
        if printf '%s\n' "$inodes" | grep -qx "$target"; then echo "$pid"; break; fi ;;
      esac
    done
  done
}

stopped=0

# Only the containers start.sh names; images and volumes are untouched.
for CONTAINER in soundcheck-web soundcheck-engine; do
  command -v docker >/dev/null 2>&1 || break
  state="$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)"
  if [ "$state" = "true" ]; then
    info "Stopping container $CONTAINER"
    docker stop "$CONTAINER" >/dev/null
    stopped=1
  fi
  # The web container is started without --rm (so crash logs survive); remove it,
  # running or crashed. It holds no volumes; images are left alone.
  if [ -n "$state" ] && [ "$CONTAINER" = soundcheck-web ]; then
    docker rm "$CONTAINER" >/dev/null 2>&1 || true
  fi
done
rm -f "$RUN_DIR/mode"
# Scratch inputs the dev-mode engine read through its bind mount.
rm -rf "$RUN_DIR/engine-work"

if [ -f "$PID_FILE" ]; then
  PID="$(cat "$PID_FILE")"
  if owned "$PID"; then
    info "Stopping the web app (pid $PID)"
    kill_tree "$PID"
    stopped=1
  elif pid_alive "$PID"; then
    info "pid $PID is no longer the Soundcheck web app (the number was reused); leaving it alone"
  fi
  rm -f "$PID_FILE"
fi

if [ -f "$PORT_FILE" ]; then
  PORT="$(cat "$PORT_FILE")"
  for pid in $(port_pids "$PORT"); do
    if owned "$pid"; then
      info "Stopping leftover Soundcheck process $pid on port $PORT"
      kill_tree "$pid"
      stopped=1
    else
      info "Port $PORT is used by another application (pid $pid); leaving it alone"
    fi
  done
  rm -f "$PORT_FILE"
fi

if [ "$stopped" = 1 ]; then
  info "Soundcheck stopped"
else
  info "Soundcheck is not running"
fi
