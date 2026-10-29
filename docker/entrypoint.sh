#!/bin/sh
# `web` (default) serves the UI; engine commands run the CLI directly so exit
# codes and stdio (for `mcp`) pass straight through.
set -e

case "${1:-web}" in
  web)
    exec node /app/server.js
    ;;
  soundcheck)
    shift
    exec soundcheck "$@"
    ;;
  verify | compare | profile | mcp)
    exec soundcheck "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
