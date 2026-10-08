#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CONFIG="$SCRIPT_DIR/kong.yaml"
PROBES="$SCRIPT_DIR/probes.tsv"
KONG_IMAGE="kong:3.9.3@sha256:ca71c5591eabaf18de96d26b7eed5e2fdb590dac141e467a779c38017e5bdf81"
CONTAINER_ID=""

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$CONTAINER_ID" ]]; then
    if [[ "$status" -ne 0 ]]; then
      echo "Kong container diagnostics ($CONTAINER_ID):" >&2
      docker inspect --format '{{json .State}}' "$CONTAINER_ID" >&2 || true
      docker logs --tail 200 "$CONTAINER_ID" >&2 || true
    fi
    docker rm --force "$CONTAINER_ID" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "$REPO_ROOT"
eval "$(opam env)"
dune build bench/kong_model_oracle.exe
ORACLE="$REPO_ROOT/_build/default/bench/kong_model_oracle.exe"
echo "Kong differential conformance image: $KONG_IMAGE"

run_flavor() {
  local flavor="$1"
  local port="$2"
  local tls_port="$3"
  local failures=0
  local container_name="soundcheck-kong-conformance-${flavor}"

  # Track only a container this invocation created. A name collision must not
  # make the exit trap remove another run's container. Keep creation separate
  # from startup so startup/port failures still leave an owned ID to clean up.
  CONTAINER_ID="$(docker create --name "$container_name" \
    --publish "127.0.0.1:${port}:8000" \
    --publish "127.0.0.1:${tls_port}:8443" \
    --volume "$CONFIG:/kong/declarative/kong.yml:ro" \
    --env KONG_DATABASE=off \
    --env KONG_DECLARATIVE_CONFIG=/kong/declarative/kong.yml \
    --env KONG_ROUTER_FLAVOR="$flavor" \
    --env KONG_ALLOW_DEBUG_HEADER=on \
    "$KONG_IMAGE")"
  docker start "$CONTAINER_ID" >/dev/null

  local ready=false
  local attempt
  for attempt in {1..30}; do
    if curl --silent --noproxy '*' --output /dev/null --max-time 2 \
        "http://127.0.0.1:${port}/not-configured"; then
      ready=true
      break
    fi
    if [[ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER_ID")" != "true" ]]; then
      break
    fi
    sleep 1
  done
  if [[ "$ready" != "true" ]]; then
    echo "Kong failed to become ready for router flavor $flavor" >&2
    return 1
  fi

  while IFS='|' read -r name scheme method path host sni header; do
    [[ -z "$name" || "$name" == \#* ]] && continue
    local host_value="127.0.0.1"
    local curl_args=(--silent --show-error --noproxy '*' \
      --connect-timeout 2 --max-time 10 --output /dev/null --dump-header - \
      --request "$method" --header "Kong-Debug: 1")
    local oracle_sni=""
    local request_url="http://127.0.0.1:${port}${path}"
    local oracle_args=()
    if [[ "$scheme" == "https" ]]; then
      local tls_name="127.0.0.1"
      if [[ "$sni" != "-" ]]; then
        tls_name="$sni"
        oracle_sni="$sni"
      fi
      request_url="https://${tls_name}:${tls_port}${path}"
      curl_args+=(--insecure --resolve "${tls_name}:${tls_port}:127.0.0.1")
    fi
    if [[ "$host" != "-" ]]; then
      host_value="$host"
      curl_args+=(--header "Host: $host")
    fi
    oracle_args=("$CONFIG" "$scheme" "$method" "$path" "$host_value" "$oracle_sni")
    if [[ "$header" != "-" ]]; then
      curl_args+=(--header "$header")
      oracle_args+=("$header")
    fi

    local response actual_status actual_route actual_service actual_upstream actual_decision expected
    if ! response="$(curl "${curl_args[@]}" "$request_url")"; then
      echo "Request failed [$flavor/$name] $scheme $method $path" >&2
      return 1
    fi
    actual_status="$(printf '%s\n' "$response" | awk \
      '/^HTTP\// { code=$2 } END { print code }')"
    actual_route="$(printf '%s\n' "$response" | awk -F ': *' \
      'tolower($1) == "kong-route-name" { sub("\\r$", "", $2); print $2 }' | tail -1)"
    actual_service="$(printf '%s\n' "$response" | awk -F ': *' \
      'tolower($1) == "kong-service-name" { sub("\\r$", "", $2); print $2 }' | tail -1)"
    actual_upstream="$(printf '%s\n' "$response" | awk -F ': *' \
      'tolower($1) == "x-kong-upstream-latency" { sub("\\r$", "", $2); print $2 }' | tail -1)"
    actual_route="${actual_route:--}"
    actual_service="${actual_service:--}"
    if [[ -n "$actual_upstream" ]]; then
      actual_decision="allow"
    else
      actual_decision="deny"
    fi
    expected="$("$ORACLE" "${oracle_args[@]}")"
    if [[ "$expected" != "${actual_decision}"$'\t'"${actual_route}"$'\t'"${actual_service}" ]]; then
      echo "MISMATCH [$flavor/$name] $scheme $method $path host=$host sni=$sni header=$header" >&2
      echo "  model: $expected" >&2
      echo "  Kong:  ${actual_decision}"$'\t'"${actual_route}"$'\t'"${actual_service} (HTTP ${actual_status})" >&2
      failures=$((failures + 1))
    else
      echo "ok [$flavor] $name"
    fi
  done < "$PROBES"

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  docker rm --force "$CONTAINER_ID" >/dev/null
  CONTAINER_ID=""
}

run_flavor traditional 18000 18443
run_flavor traditional_compatible 18001 18444
echo "Kong differential conformance passed"
