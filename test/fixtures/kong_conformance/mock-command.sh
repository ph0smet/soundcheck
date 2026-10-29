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
    printf 'oracle %s\n' "$*" >> "$SOUNDCHECK_HARNESS_TEST_LOG"
    soundcheck_expected_source=0.0.0.0
    if [[ "$1" == */ip.yaml || "$1" == */termination.yaml ]]; then
      soundcheck_expected_source=10.1.2.3
    fi
    case "$SOUNDCHECK_HARNESS_TEST_CASE" in
      oracle-failure) exit 2 ;;
      malformed-model) printf 'supported\tmaybe\tallow\n'; exit 0 ;;
    esac
    case "$5" in
      /fixture-authenticated)
        [[ "$2" == authenticated && "$8" == "$soundcheck_expected_source" && "$9" == fixture-key:valid && "${10}" == x-region:us ]] || exit 99
        ;;
      /fixture-source)
        [[ "$2" == anonymous && "$8" == 10.1.2.3 ]] || exit 99
        ;;
      /fixture-query)
        [[ "$#" -eq 8 && "$2" == anonymous && "$8" == 10.1.2.3 ]] || exit 99
        ;;
      /fixture-routing|/fixture-anonymous|/fixture-conservative|/fixture-conservative-deny|/fixture-unsupported)
        [[ "$2" == anonymous ]] ;;
      *) echo "Unexpected mock oracle request: $*" >&2; exit 99 ;;
    esac
    case "$SOUNDCHECK_HARNESS_TEST_CASE/$5" in
      model-mismatch//fixture-routing)
        printf 'supported\tdeny\tdeny\n-\t-\n'; exit 0 ;;
      matching-wrong//fixture-routing)
        printf 'supported\tallow\tallow\nwrong-route\tfixture-service\n'; exit 0 ;;
      silent-downgrade//fixture-routing)
        printf 'supported\tallow\tdeny\nfixture-route\tfixture-service\n'; exit 0 ;;
      unexpected-unknown//fixture-routing)
        printf 'unsupported\tunknown\n'; exit 0 ;;
      unsupported-accepted//fixture-unsupported)
        printf 'supported\tallow\tallow\nfixture-route\tfixture-service\n'; exit 0 ;;
      wrong-unknown//fixture-unsupported)
        printf 'unsupported\ttimeout\n'; exit 0 ;;
      conservative-dropped//fixture-conservative)
        printf 'supported\tallow\tdeny\nother-route\tfixture-service\nthird-route\tfixture-service\n'; exit 0 ;;
      duplicate-candidate//fixture-conservative)
        printf 'supported\tallow\tdeny\nfixture-route\tfixture-service\nfixture-route\tfixture-service\n'; exit 0 ;;
      conservative-may-escape//fixture-conservative)
        printf 'supported\tdeny\tdeny\nfixture-route\tfixture-service\nother-route\tfixture-service\n'; exit 0 ;;
      conservative-must-escape//fixture-conservative-deny)
        printf 'supported\tallow\tallow\nfixture-route\tfixture-service\nother-route\tfixture-service\n'; exit 0 ;;
    esac
    case "$5" in
      /fixture-unsupported) printf 'unsupported\tunknown\n' ;;
      /fixture-conservative)
        printf 'supported\tallow\tdeny\nfixture-route\tfixture-service\nother-route\tfixture-service\n' ;;
      /fixture-conservative-deny)
        printf 'supported\tallow\tdeny\nfixture-route\tfixture-service\n' ;;
      /fixture-query)
        printf 'supported\tallow\tdeny\nfixture-route\tfixture-service\n' ;;
      /fixture-anonymous)
        printf 'supported\tdeny\tdeny\nfixture-route\tfixture-service\n' ;;
      *) printf 'supported\tallow\tallow\nfixture-route\tfixture-service\n' ;;
    esac
    ;;
  docker)
    printf 'docker %s\n' "$*" >> "$SOUNDCHECK_HARNESS_TEST_LOG"
    case "$1" in
      create)
        if [[ "$*" == */ip.yaml:* || "$*" == */termination.yaml:* ]]; then
          [[ "$*" == *KONG_TRUSTED_IPS=0.0.0.0/0* &&
             "$*" == *KONG_REAL_IP_HEADER=X-Soundcheck-Client-IP* &&
             "$*" == *KONG_REAL_IP_RECURSIVE=off* ]] || exit 99
        elif [[ "$*" == *KONG_TRUSTED_IPS* ]]; then
          echo 'Fixture real-IP trust leaked into an unrelated matrix' >&2
          exit 99
        fi
        if [[ "$SOUNDCHECK_HARNESS_TEST_CASE" == collision ]]; then
          echo 'fixture: existing container name conflict' >&2
          exit 125
        fi
        printf '%064d\n' "$(grep -c '^docker create ' "$SOUNDCHECK_HARNESS_TEST_LOG")"
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
    if [[ "$*" == */fixture-source ]]; then
      [[ "$*" == *'--header X-Soundcheck-Client-IP: 10.1.2.3'* ]] || {
        echo 'Fixture source IP was not injected unchanged' >&2
        exit 99
      }
    fi
    if [[ "$SOUNDCHECK_HARNESS_TEST_CASE" == query-* ]]; then
      soundcheck_url="${!#}"
      case "$SOUNDCHECK_HARNESS_TEST_CASE" in
        query-empty-value) soundcheck_expected_query='x-stop=' ;;
        query-unrelated) soundcheck_expected_query='unrelated=yes' ;;
        query-multiple) soundcheck_expected_query='unrelated=yes&x-stop=yes' ;;
        *) soundcheck_expected_query='x-stop=yes' ;;
      esac
      [[ "$soundcheck_url" == */fixture-query"?"$soundcheck_expected_query ]] || exit 99
      [[ "$*" == *'--header X-Soundcheck-Client-IP: 10.1.2.3'* ]] || exit 99
      if [[ "$SOUNDCHECK_HARNESS_TEST_CASE" != query-unrelated ]]; then
        printf 'HTTP/1.1 418 Teapot\r\nKong-Route-Name: fixture-route\r\nKong-Service-Name: fixture-service\r\n\r\n'
        exit 0
      fi
    fi
    case "$SOUNDCHECK_HARNESS_TEST_CASE" in
      timeout)
        echo 'fixture: request timed out' >&2
        exit 28
        ;;
      malformed-response)
        printf 'Kong-Route-Name: fixture-route\r\nKong-Service-Name: fixture-service\r\nX-Kong-Upstream-Latency: 1\r\n\r\n'
        ;;
      mismatch)
        printf 'HTTP/1.1 404 Not Found\r\n\r\n'
        ;;
      matching-wrong)
        printf 'HTTP/1.1 200 OK\r\nKong-Route-Name: wrong-route\r\nKong-Service-Name: fixture-service\r\nX-Kong-Upstream-Latency: 1\r\n\r\n'
        ;;
      status-mismatch)
        printf 'HTTP/1.1 503 Service Unavailable\r\nKong-Route-Name: fixture-route\r\nKong-Service-Name: fixture-service\r\nX-Kong-Upstream-Latency: 1\r\n\r\n'
        ;;
      *)
        if [[ "$*" == */fixture-anonymous || "$*" == */fixture-conservative-deny ]]; then
          printf 'HTTP/1.1 401 Unauthorized\r\nKong-Route-Name: fixture-route\r\nKong-Service-Name: fixture-service\r\n\r\n'
        else
          if [[ "$*" == */fixture-authenticated ]]; then
            [[ "$*" == *'--header fixture-key:valid'* && "$*" == *'--header x-region:us'* ]]
          fi
          printf 'HTTP/1.1 200 OK\r\nKong-Route-Name: fixture-route\r\nKong-Service-Name: fixture-service\r\nX-Kong-Upstream-Latency: 1\r\n\r\n'
        fi
        ;;
    esac
    ;;
  *) echo "Unexpected mock command: $0" >&2; exit 99 ;;
esac
