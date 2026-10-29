#!/usr/bin/env bash
# Regression test for dev-mode engine capacity (docker/engine-slot.sh): however
# often requests are cancelled, no more than SLOTS jobs run in the container.
# Needs Docker. Uses a plain Debian container and `sleep` in place of the engine.
#
#   bash scripts/engine-slot-test.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f"
CONTAINER="soundcheck-slot-test-$$"
SLOTS=4
failures=0

case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) WINDOWS=1; export MSYS_NO_PATHCONV=1 ;; *) WINDOWS=0 ;; esac
host_path() { if [ "$WINDOWS" = 1 ]; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

check() {
  if eval "$2"; then printf 'ok    %s\n' "$1"; else printf 'FAIL  %s\n' "$1"; failures=$((failures + 1)); fi
}

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$CONTAINER" \
  -v "$(host_path "$ROOT/docker/engine-slot.sh"):/usr/local/bin/soundcheck-slot:ro" \
  "$IMAGE" sleep infinity >/dev/null || { echo "could not start the test container"; exit 1; }

# A cancelled request: start a job, then kill only the local docker client, as a
# forced kill of the bridge would. The container-side job is not signalled.
cancelled_job() {
  docker exec "$CONTAINER" sh /usr/local/bin/soundcheck-slot "$SLOTS" "job-$1" 40s -- sleep 30 >/dev/null 2>&1 &
  local client=$!
  sleep 1
  kill "$client" 2>/dev/null || true
  wait "$client" 2>/dev/null || true
}

# ps is not in debian-slim; count from /proc instead.
running_jobs() {
  docker exec "$CONTAINER" sh -c 'for f in /proc/[0-9]*/cmdline; do tr "\0" " " <"$f" 2>/dev/null; echo; done' |
    grep -c '^sleep 30 $' || true
}

for n in 1 2 3 4 5 6; do cancelled_job "$n"; done
sleep 1
check "six cancelled requests leave at most $SLOTS jobs running" "[ \"\$(running_jobs)\" -le $SLOTS ]"
check "the slots are actually used ($SLOTS jobs running)" "[ \"\$(running_jobs)\" -eq $SLOTS ]"

# Cancelling where the job runs (what the bridge does when it can) frees a slot,
# and a waiting job takes it, so the count stays at the limit.
docker exec "$CONTAINER" sh -c 'kill -TERM "$(cat /tmp/soundcheck-slots/job-job-1.pid)"'
sleep 2
check "a cancelled container-side job stops" "! docker exec '$CONTAINER' sh -c 'kill -0 \"\$(cat /tmp/soundcheck-slots/job-job-1.pid)\"' 2>/dev/null"
check "a waiting job takes the freed slot, still within the limit" "[ \"\$(running_jobs)\" -eq $SLOTS ]"

# Waiting is bounded: with every slot busy, a new job gives up at its limit
# instead of starting work later for a request nobody is waiting on.
started=$(date +%s)
docker exec "$CONTAINER" sh /usr/local/bin/soundcheck-slot "$SLOTS" job-late 3s -- sleep 30 >/dev/null 2>&1
status=$?
elapsed=$(( $(date +%s) - started ))
check "a job that cannot get a slot exits 124" "[ $status -eq 124 ]"
check "it gives up within its limit (took ${elapsed}s)" "[ $elapsed -le 8 ]"

# The job's own exit code passes through.
docker exec "$CONTAINER" sh /usr/local/bin/soundcheck-slot 99 job-exit 5s -- sh -c 'exit 3' >/dev/null 2>&1
status=$?
check "the job's exit code passes through (3)" "[ $status -eq 3 ]"

if [ "$failures" -ne 0 ]; then
  printf '\n%d check(s) failed.\n' "$failures"
  exit 1
fi
printf '\nAll engine slot checks passed.\n'
