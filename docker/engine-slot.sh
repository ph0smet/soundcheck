#!/bin/sh
# Runs one engine job inside the dev-mode engine container, holding one of SLOTS
# concurrency slots for the job's whole life.
#
#   soundcheck-slot SLOTS JOB_ID LIMIT -- command [args...]
#
# Capacity is governed here, where the work runs, not by the web server: when a
# request is cancelled the web server only loses its `docker exec` client, but
# the job in this container keeps running until it ends or reaches LIMIT. Each
# slot is an flock held on an inherited file descriptor, so the kernel releases
# it exactly when the job's processes exit, for whatever reason. Waiting for a
# slot is bounded by LIMIT too, so an abandoned request cannot start work later.
#
# Exit codes are the command's own; 124 means LIMIT expired (waiting or running).
set -eu

slots="$1" job="$2" limit="$3"
shift 3
[ "${1:-}" = "--" ] && shift

dir=/tmp/soundcheck-slots
mkdir -p "$dir"
# The PID stays valid after the exec below, so the bridge can signal this job
# while it waits or runs. timeout forwards SIGTERM to the command.
echo "$$" >"$dir/job-$job.pid"

seconds="${limit%s}"
deadline=$(( $(date +%s) + seconds ))
while :; do
  i=0
  while [ "$i" -lt "$slots" ]; do
    exec 9>"$dir/slot-$i.lock"
    if flock -n 9; then
      # fd 9 (and so the slot) is inherited by timeout and the engine.
      exec timeout --kill-after=2s "$limit" "$@"
    fi
    exec 9>&-
    i=$((i + 1))
  done
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "soundcheck-slot: no engine slot became free within $limit" >&2
    exit 124
  fi
  sleep 0.1
done
