#!/usr/bin/env bash
# Shared by start.sh and stop.sh: identifies the processes this checkout's
# launcher started, so neither script ever stops someone else's process.
# Sourced, not run. Expects ROOT (the repository root) and WINDOWS (0 or 1).
#
# Ownership: start.sh launches Next.js from this checkout's frontend directory,
# by the absolute path of its node_modules/next. A process is ours when either
#   - its command line carries that path (Windows, where it never changes), or
#   - it is a Node executable whose working directory is this checkout's
#     frontend (Linux and macOS). Next.js renames its server process
#     (process.title = "next-server (vX)"), which rewrites the command line
#     there, but cannot change the executable or the working directory.
# A PID that was reused, or a different application that later took the port,
# matches neither, so it is left alone.

pid_alive() {
  if [ "$WINDOWS" = 1 ]; then
    tasklist //FI "PID eq $1" 2>/dev/null | grep -q " $1 "
  else
    kill -0 "$1" 2>/dev/null
  fi
}

# Lower-cased with forward slashes on Windows, where paths are case-insensitive.
normalize_path() {
  if [ "$WINDOWS" = 1 ]; then tr 'A-Z\\' 'a-z/'; else cat; fi
}

owner_mark() {
  local frontend="$ROOT/frontend"
  if [ "$WINDOWS" = 1 ]; then frontend="$(cygpath -w "$frontend")"; fi
  printf '%s/node_modules/next/' "$frontend" | normalize_path
}

process_cmdline() {
  local pid="$1"
  if [ "$WINDOWS" = 1 ]; then
    powershell.exe -NoProfile -NonInteractive -Command \
      "(Get-CimInstance Win32_Process -Filter 'ProcessId=$pid').CommandLine" 2>/dev/null | tr -d '\r'
  elif [ -r "/proc/$pid/cmdline" ]; then
    tr '\0' ' ' <"/proc/$pid/cmdline"
  else
    ps -ww -o command= -p "$pid" 2>/dev/null || true
  fi
}

# One open file of PID by lsof descriptor name (cwd, txt), for macOS and BSDs.
lsof_path() {
  command -v lsof >/dev/null 2>&1 || return 0
  lsof -a -p "$1" -d "$2" -Fn 2>/dev/null | sed -n 's/^n//p' | head -n 1
}

process_cwd() {
  if [ -e "/proc/$1/cwd" ]; then readlink "/proc/$1/cwd" 2>/dev/null || true; else lsof_path "$1" cwd; fi
}

process_exe() {
  if [ -e "/proc/$1/exe" ]; then readlink "/proc/$1/exe" 2>/dev/null || true; else lsof_path "$1" txt; fi
}

# True when PID is alive and runs this checkout's Next.js.
owned() {
  local pid="$1" cmdline mark frontend
  case "$pid" in '' | *[!0-9]*) return 1 ;; esac
  pid_alive "$pid" || return 1
  cmdline="$(process_cmdline "$pid" | normalize_path)"
  mark="$(owner_mark)"
  case "$cmdline" in *"$mark"*) return 0 ;; esac
  [ "$WINDOWS" = 1 ] && return 1
  frontend="$(cd "$ROOT/frontend" 2>/dev/null && pwd -P)" || return 1
  [ "$(process_cwd "$pid")" = "$frontend" ] || return 1
  case "$(basename "$(process_exe "$pid")" 2>/dev/null)" in node | nodejs | node[0-9]*) return 0 ;; esac
  return 1
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
