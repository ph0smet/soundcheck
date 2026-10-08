#!/usr/bin/env bash
set -euo pipefail

# These mocks exercise harness control flow, not Kong or Soundcheck semantics.
# Every external runtime command is intercepted in an isolated temporary tree.
case "${0##*/}" in
  opam)
    [[ "$*" == env ]]
    ;;
  dune)
    [[ "$*" == 'build bench/kong_model_oracle.exe' ]]
    ;;
  kong_model_oracle.exe)
    printf 'allow\tfixture-route\tfixture-service\n'
    ;;
  docker)
    printf 'docker %s\n' "$*" >> "$SOUNDCHECK_HARNESS_TEST_LOG"
    case "$1" in
      create)
        if [[ "$SOUNDCHECK_HARNESS_TEST_CASE" == collision ]]; then
          echo 'fixture: existing container name conflict' >&2
          exit 125
        fi
        if [[ "$*" == *soundcheck-kong-conformance-traditional_compatible* ]]; then
          printf '%064d\n' 2
        else
          printf '%064d\n' 1
        fi
        ;;
      start)
        if [[ "$SOUNDCHECK_HARNESS_TEST_CASE" == startup ]]; then
          echo 'fixture: port already allocated' >&2
          exit 125
        fi
        ;;
      inspect)
        if [[ "$3" == '{{.State.Running}}' ]]; then
          echo false
        else
          echo '{"Status":"fixture-state"}'
        fi
        ;;
      logs) echo 'fixture container logs' ;;
      rm) ;;
      *) echo "Unexpected mock Docker invocation: $*" >&2; exit 99 ;;
    esac
    ;;
  curl)
    if [[ "$*" != *--dump-header* ]]; then
      if [[ "$SOUNDCHECK_HARNESS_TEST_CASE" == readiness ]]; then exit 7; fi
      exit 0
    fi
    if [[ "$*" != *'--connect-timeout 2'* || "$*" != *'--max-time 10'* ]]; then
      echo 'Mock probe expected bounded connection and request timeouts' >&2
      exit 99
    fi
    case "$SOUNDCHECK_HARNESS_TEST_CASE" in
      timeout)
        echo 'fixture: request timed out' >&2
        exit 28
        ;;
      mismatch)
        printf 'HTTP/1.1 404 Not Found\r\n\r\n'
        ;;
      *)
        printf 'HTTP/1.1 200 OK\r\nKong-Route-Name: fixture-route\r\nKong-Service-Name: fixture-service\r\nX-Kong-Upstream-Latency: 1\r\n\r\n'
        ;;
    esac
    ;;
  *) echo "Unexpected mock command: $0" >&2; exit 99 ;;
esac
