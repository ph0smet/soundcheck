#!/usr/bin/env bash
# Regression tests for start.sh/stop.sh process ownership. Runs on Linux, macOS
# and Windows (Git Bash). It never touches a real session: it uses its own run
# directory, and `docker` is replaced by a logging stub for the whole run, so the
# globally named soundcheck-* containers are never inspected, stopped or removed.
#
#   bash scripts/launcher-test.sh
#   SOUNDCHECK_TEST_REAL_NEXT=1 bash scripts/launcher-test.sh   # also builds and
#     starts the real Next.js production server, then stops it with stop.sh
#     (needs frontend dependencies installed; takes a minute or two)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) WINDOWS=1 ;; *) WINDOWS=0 ;; esac
# shellcheck source=scripts/launcher-common.sh
. "$ROOT/scripts/launcher-common.sh"

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/soundcheck-launcher-test.XXXXXX")"
export SOUNDCHECK_RUN_DIR="$SCRATCH/run" SOUNDCHECK_NO_PAUSE=1 NO_COLOR=1
mkdir -p "$SOUNDCHECK_RUN_DIR" "$SCRATCH/bin"
PORT="${SOUNDCHECK_TEST_PORT:-4109}"
failures=0
started=()

# Docker stub: logs every call and reports every container as not running.
{
  echo '#!/usr/bin/env bash'
  printf 'printf "%%s\\n" "$*" >>%q\n' "$SCRATCH/docker.log"
  echo 'case "$1" in inspect) echo false ;; esac'
  echo 'exit 0'
} >"$SCRATCH/bin/docker"
chmod +x "$SCRATCH/bin/docker"
export PATH="$SCRATCH/bin:$PATH"

cleanup() {
  local pid
  for pid in ${started[@]+"${started[@]}"}; do kill_tree "$pid"; done
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

check() {
  if eval "$2"; then printf 'ok    %s\n' "$1"; else printf 'FAIL  %s\n' "$1"; failures=$((failures + 1)); fi
}

# The PID other tools see: the Windows PID under Git Bash.
os_pid() {
  if [ "$WINDOWS" = 1 ] && [ -r "/proc/$1/winpid" ]; then cat "/proc/$1/winpid"; else printf '%s' "$1"; fi
}

native_path() { if [ "$WINDOWS" = 1 ]; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

wait_for_port() {
  for _ in $(seq 1 20); do curl -sf -o /dev/null "http://127.0.0.1:$1/" && return 0; sleep 0.5; done
}

check "docker resolves to the stub" '[ "$(command -v docker)" = "$SCRATCH/bin/docker" ]'

# An unrelated Node application listening on $PORT, as another project would.
cat >"$SCRATCH/other-app.js" <<'EOF'
require("http").createServer((_, res) => res.end("someone else's app")).listen(Number(process.argv[2]), "127.0.0.1");
EOF
node "$SCRATCH/other-app.js" "$PORT" >/dev/null 2>&1 &
OTHER="$(os_pid $!)"
started+=("$OTHER")
wait_for_port "$PORT"

check "the unrelated app is running" "pid_alive $OTHER"
check "the unrelated app is not recognised as Soundcheck" "! owned $OTHER"

# 1. stop.sh must not stop another app that took the recorded port.
echo "$PORT" >"$SOUNDCHECK_RUN_DIR/frontend.port"
bash "$ROOT/stop.sh" >"$SCRATCH/stop1.log" 2>&1
check "stop.sh leaves an unrelated app on the recorded port alone" "pid_alive $OTHER"
check "stop.sh says why it left it alone" "grep -q 'another application' '$SCRATCH/stop1.log'"

# 2. stop.sh must not stop a process that reused the recorded PID.
echo "$OTHER" >"$SOUNDCHECK_RUN_DIR/frontend.pid"
bash "$ROOT/stop.sh" >"$SCRATCH/stop2.log" 2>&1
check "stop.sh leaves a process that reused the recorded PID alone" "pid_alive $OTHER"
check "stop.sh forgets the stale PID" "[ ! -f '$SOUNDCHECK_RUN_DIR/frontend.pid' ]"

# 3. A start that never becomes ready must stop what it launched before
#    forgetting it. The mock "node" stays alive but never serves anything.
cat >"$SCRATCH/fake-node" <<'EOF'
#!/usr/bin/env bash
sleep 300 &
wait
EOF
chmod +x "$SCRATCH/fake-node"
mkdir -p "$ROOT/frontend/node_modules"
[ -f "$ROOT/frontend/node_modules/.soundcheck-installed" ] || touch "$ROOT/frontend/node_modules/.soundcheck-installed"
SOUNDCHECK_NODE="$SCRATCH/fake-node" SOUNDCHECK_READY_TIMEOUT=3 \
  bash "$ROOT/start.sh" --native --skip-engine --port "$((PORT + 1))" >"$SCRATCH/start.log" 2>&1
status=$?
check "start.sh fails when the web app never becomes ready" "[ $status -ne 0 ]"
check "start.sh reports the failure" "grep -q 'did not become ready' '$SCRATCH/start.log'"
check "start.sh stopped the web app it launched" "grep -q 'Stopping the web app that failed to start' '$SCRATCH/start.log'"
launched="$(sed -n 's/.*Stopping the web app that failed to start (pid \([0-9]*\)).*/\1/p' "$SCRATCH/start.log")"
check "the launched process is gone" "[ -n '$launched' ] && ! pid_alive '$launched'"
check "start.sh removed its PID file" "[ ! -f '$SOUNDCHECK_RUN_DIR/frontend.pid' ]"

# 4. And stop.sh does stop a web app this checkout launched: ownership must not
#    simply always say no. The mock carries the absolute Next.js path, as start.sh passes it.
next_path="$(native_path "$ROOT/frontend/node_modules/next/dist/bin/next")"
"$SCRATCH/fake-node" "$next_path" dev -H 127.0.0.1 -p "$((PORT + 2))" >/dev/null 2>&1 &
OURS="$(os_pid $!)"
started+=("$OURS")
sleep 1
check "a launcher-started web app is recognised as Soundcheck" "owned $OURS"
echo "$OURS" >"$SOUNDCHECK_RUN_DIR/frontend.pid"
bash "$ROOT/stop.sh" >"$SCRATCH/stop3.log" 2>&1
check "stop.sh stops the web app this checkout launched" "! pid_alive $OURS"

# 5. Next.js renames its server process (process.title = "next-server (vX)"),
#    which rewrites the command line on Linux and macOS. A real Node process that
#    does the same, started the way start.sh starts Next (from the frontend
#    directory, with the Next.js path), must still be recognised and stopped,
#    both by its recorded PID and by the recorded port alone.
cat >"$SCRATCH/renamed-next.js" <<'EOF'
process.title = "next-server (v16.3.6)";
require("fs").writeFileSync(process.argv[4], String(process.pid));
require("http").createServer((_, res) => res.end("renamed")).listen(Number(process.argv[2]), "127.0.0.1");
EOF
renamed_start() {
  # Node reports its own PID: under Git Bash, $! can name a wrapper process.
  rm -f "$SCRATCH/renamed.pid"
  (cd "$ROOT/frontend" && exec node "$(native_path "$SCRATCH/renamed-next.js")" "$1" "$next_path"     "$(native_path "$SCRATCH/renamed.pid")") >/dev/null 2>&1 &
  started+=("$(os_pid $!)")
  wait_for_port "$1"
  RENAMED="$(cat "$SCRATCH/renamed.pid" 2>/dev/null || true)"
  started+=("$RENAMED")
}

renamed_start "$((PORT + 3))"
if [ "$WINDOWS" = 0 ] && [ -r "/proc/$RENAMED/cmdline" ]; then
  check "the rename hid the Next.js path from the command line, as in Next 16" \
    "! tr '\\0' ' ' <'/proc/$RENAMED/cmdline' | grep -q node_modules/next"
fi
check "a renamed web app is recognised as Soundcheck" "owned $RENAMED"
echo "$RENAMED" >"$SOUNDCHECK_RUN_DIR/frontend.pid"
echo "$((PORT + 3))" >"$SOUNDCHECK_RUN_DIR/frontend.port"
bash "$ROOT/stop.sh" >"$SCRATCH/stop4.log" 2>&1
check "stop.sh stops a renamed web app by its PID" "! pid_alive $RENAMED"
check "stop.sh reports that it stopped it" "grep -q 'Soundcheck stopped' '$SCRATCH/stop4.log'"

renamed_start "$((PORT + 4))"
echo "$((PORT + 4))" >"$SOUNDCHECK_RUN_DIR/frontend.port"
bash "$ROOT/stop.sh" >"$SCRATCH/stop5.log" 2>&1
check "stop.sh stops a renamed web app found only on the recorded port" "! pid_alive $RENAMED"

# 6. Optional: the real thing. Build and start the production server with
#    start.sh, then stop it with stop.sh.
if [ "${SOUNDCHECK_TEST_REAL_NEXT:-0}" = 1 ]; then
  REAL_PORT="$((PORT + 5))"
  SOUNDCHECK_READY_TIMEOUT=120 bash "$ROOT/start.sh" --native --prod --skip-engine --port "$REAL_PORT" \
    >"$SCRATCH/start-real.log" 2>&1
  status=$?
  check "start.sh starts the real production server" "[ $status -eq 0 ]"
  REAL="$(cat "$SOUNDCHECK_RUN_DIR/frontend.pid" 2>/dev/null || true)"
  [ -n "$REAL" ] && started+=("$REAL")
  check "the real server answers" "curl -sf -o /dev/null 'http://127.0.0.1:$REAL_PORT/api/engine'"
  check "the real server is recognised as Soundcheck" "owned '$REAL'"
  bash "$ROOT/stop.sh" >"$SCRATCH/stop-real.log" 2>&1
  check "stop.sh reports that it stopped the real server" "grep -q 'Soundcheck stopped' '$SCRATCH/stop-real.log'"
  check "the real server process is gone" "[ -n '$REAL' ] && ! pid_alive '$REAL'"
  answered=1
  for _ in $(seq 1 10); do
    curl -sf -o /dev/null "http://127.0.0.1:$REAL_PORT/" || { answered=0; break; }
    sleep 1
  done
  check "nothing answers on the real server's port" "[ $answered -eq 0 ]"
  if [ "$failures" -ne 0 ]; then
    printf '\n--- start.sh (real) ---\n'; cat "$SCRATCH/start-real.log"
    printf '\n--- stop.sh (real) ---\n'; cat "$SCRATCH/stop-real.log"
  fi
fi

check "stop.sh went through the docker stub" "grep -q '^inspect .*soundcheck-web' '$SCRATCH/docker.log'"

if [ "$failures" -ne 0 ]; then
  printf '\n%d check(s) failed. start.sh output:\n' "$failures"
  cat "$SCRATCH/start.log"
  exit 1
fi
printf '\nAll launcher checks passed.\n'
