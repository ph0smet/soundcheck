#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
KONG_IMAGE="kong:3.9.3@sha256:ca71c5591eabaf18de96d26b7eed5e2fdb590dac141e467a779c38017e5bdf81"
CONTAINER_ID=""
MATRIX="${1:-all}"
EXACT_COUNT=0
CONSERVATIVE_COUNT=0
UNSUPPORTED_COUNT=0
if [[ $# -gt 1 || ( "$MATRIX" != all && "$MATRIX" != routing && "$MATRIX" != auth &&
      "$MATRIX" != supported && "$MATRIX" != boundaries ) ]]; then
  echo "Usage: run.sh [all|routing|auth|supported|boundaries]" >&2
  exit 2
fi

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ "$status" -ne 0 ]]; then
    echo "Checks completed before failure: exact=$EXACT_COUNT conservative=$CONSERVATIVE_COUNT unsupported-boundary=$UNSUPPORTED_COUNT" >&2
  fi
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
  local matrix="$4"
  local config="$5"
  local probes="$6"
  local failures=0
  local probe_count=0
  local container_name="soundcheck-kong-conformance-${flavor}"
  # Keep this array nonempty for the macOS system Bash 3.x nounset behavior.
  local matrix_environment=(--env KONG_ALLOW_DEBUG_HEADER=on)
  if [[ "$matrix" == hosts ]]; then
    # Make the compatible router's omitted Host-port default independent of
    # Docker's published port: its advertised HTTP/HTTPS ports are explicitly
    # mapped to 80/443. Request destination ports remain outside the model.
    matrix_environment+=(--env KONG_PORT_MAPS=80:8000,443:8443)
  fi

  # Track only a container this invocation created. A name collision must not
  # make the exit trap remove another run's container. Keep creation separate
  # from startup so startup/port failures still leave an owned ID to clean up.
  CONTAINER_ID="$(docker create --name "$container_name" \
    --publish "127.0.0.1:${port}:8000" \
    --publish "127.0.0.1:${tls_port}:8443" \
    --volume "$config:/kong/declarative/kong.yml:ro" \
    --env KONG_DATABASE=off \
    --env KONG_DECLARATIVE_CONFIG=/kong/declarative/kong.yml \
    --env KONG_ROUTER_FLAVOR="$flavor" \
    "${matrix_environment[@]}" \
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

  while IFS='|' read -r name scheme method path host sni principal headers expected_decision expected_route expected_service expected_status model_class flavors extra; do
    [[ -z "$name" || "$name" == \#* ]] && continue
    if [[ -n "$extra" || -z "$expected_status" ||
          ( "$scheme" != http && "$scheme" != https ) ||
          ( "$principal" != anonymous && "$principal" != authenticated ) ||
          ( "$expected_decision" != allow && "$expected_decision" != deny ) ||
          -z "$expected_route" || -z "$expected_service" ||
          ( "$expected_status" != - && ! "$expected_status" =~ ^[1-5][0-9][0-9]$ ) ||
          ( "$model_class" != exact && "$model_class" != conservative && "$model_class" != unsupported ) ||
          ( "$flavors" != both && "$flavors" != traditional && "$flavors" != traditional_compatible ) ]]; then
      echo "Invalid probe metadata [$matrix/$name]" >&2
      return 1
    fi
    [[ "$flavors" == both || "$flavors" == "$flavor" ]] || continue
    probe_count=$((probe_count + 1))
    local host_value="127.0.0.1"
    local curl_args=(--silent --show-error --noproxy '*' --path-as-is \
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
    oracle_args=("$config" "$principal" "$scheme" "$method" "$path" "$host_value" "$oracle_sni")
    if [[ "$headers" != "-" ]]; then
      local request_headers=()
      local header
      IFS=';' read -r -a request_headers <<< "$headers"
      for header in "${request_headers[@]}"; do
        if [[ "$header" != *:* ]]; then
          echo "Invalid probe header [$matrix/$name]: $header" >&2
          return 1
        fi
        curl_args+=(--header "$header")
        oracle_args+=("$header")
      done
    fi

    local response actual_status actual_route actual_service actual_upstream actual_decision expected model actual
    if ! response="$(curl "${curl_args[@]}" "$request_url")"; then
      echo "Request failed [$flavor/$matrix/$name] $scheme $method $path" >&2
      return 1
    fi
    actual_status="$(printf '%s\n' "$response" | awk \
      '/^HTTP\// { code=$2 } END { print code }')"
    if [[ ! "$actual_status" =~ ^[1-5][0-9][0-9]$ ]]; then
      echo "Invalid HTTP response [$flavor/$matrix/$name]" >&2
      return 1
    fi
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
    expected="${expected_decision}"$'\t'"${expected_route}"$'\t'"${expected_service}"
    actual="${actual_decision}"$'\t'"${actual_route}"$'\t'"${actual_service}"
    if ! model="$("$ORACLE" "${oracle_args[@]}")"; then
      echo "Model oracle failed [$flavor/$matrix/$name]" >&2
      return 1
    fi
    local model_ok=false model_kind model_may model_must model_extra
    IFS=$'\t' read -r model_kind model_may model_must model_extra <<< "${model%%$'\n'*}"
    if [[ "$model_kind" == unsupported ]]; then
      [[ "$model" == $'unsupported\tunknown' ]] || {
        echo "Invalid model response [$flavor/$matrix/$name]" >&2; return 1;
      }
      # This is a public Unknown + Unsupported boundary check, not a modeled
      # decision or evidence of differential agreement for this request.
      [[ "$model_class" != unsupported ]] || model_ok=true
    elif [[ "$model_kind" == supported && -z "$model_extra" &&
            ( "$model_may" == allow || "$model_may" == deny ) &&
            ( "$model_must" == allow || "$model_must" == deny ) &&
            "$model" == *$'\n'* &&
            ! ( "$model_must" == allow && "$model_may" == deny ) ]]; then
      local candidates="${model#*$'\n'}" candidate_route candidate_service candidate_extra
      local candidate_count=0 contains_target=false seen_candidates=$'\n'
      while IFS=$'\t' read -r candidate_route candidate_service candidate_extra; do
        if [[ -z "$candidate_route" || -z "$candidate_service" || -n "$candidate_extra" ]]; then
          echo "Invalid model candidates [$flavor/$matrix/$name]" >&2
          return 1
        fi
        if [[ "$seen_candidates" == *$'\n'"$candidate_route"$'\t'"$candidate_service"$'\n'* ]]; then
          echo "Duplicate model candidate [$flavor/$matrix/$name]" >&2
          return 1
        fi
        seen_candidates+="$candidate_route"$'\t'"$candidate_service"$'\n'
        candidate_count=$((candidate_count + 1))
        if [[ "$candidate_route" == "$actual_route" && "$candidate_service" == "$actual_service" ]]; then
          contains_target=true
        fi
      done <<< "$candidates"
      if [[ "$contains_target" == true ]]; then
        if [[ "$model_class" == exact && "$candidate_count" -eq 1 &&
              "$model_may" == "$actual_decision" && "$model_must" == "$actual_decision" ]]; then
          model_ok=true
        elif [[ "$model_class" == conservative &&
                ( "$candidate_count" -gt 1 || "$model_may" != "$model_must" ) &&
                ( "$actual_decision" != allow || "$model_may" == allow ) &&
                ( "$actual_decision" != deny || "$model_must" == deny ) ]]; then
          model_ok=true
        fi
      fi
    else
      echo "Invalid model response [$flavor/$matrix/$name]" >&2
      return 1
    fi
    # Fixed target expectations remain mandatory for every class. Conservative
    # checks require containment; unsupported checks never count as agreement.
    if [[ "$model_ok" != true || "$actual" != "$expected" ||
          ( "$expected_status" != - && "$actual_status" != "$expected_status" ) ]]; then
      echo "MISMATCH [$flavor/$matrix/$name] $scheme $method $path host=$host sni=$sni principal=$principal headers=$headers" >&2
      echo "  expected: $expected (HTTP $expected_status; model $model_class)" >&2
      echo "  model: $model" >&2
      echo "  Kong:  ${actual_decision}"$'\t'"${actual_route}"$'\t'"${actual_service} (HTTP ${actual_status})" >&2
      failures=$((failures + 1))
    else
      case "$model_class" in
        exact) EXACT_COUNT=$((EXACT_COUNT + 1)) ;;
        conservative) CONSERVATIVE_COUNT=$((CONSERVATIVE_COUNT + 1)) ;;
        unsupported) UNSUPPORTED_COUNT=$((UNSUPPORTED_COUNT + 1)) ;;
      esac
      echo "ok [$flavor/$matrix/$model_class] $name"
    fi
  done < "$probes"

  if [[ "$probe_count" -eq 0 ]]; then
    echo "No probes executed [$flavor/$matrix]" >&2
    return 1
  fi

  if [[ "$failures" -ne 0 ]]; then
    return 1
  fi
  docker rm --force "$CONTAINER_ID" >/dev/null
  CONTAINER_ID=""
}

for flavor in traditional traditional_compatible; do
  if [[ "$flavor" == traditional ]]; then
    port=18000
    tls_port=18443
  else
    port=18001
    tls_port=18444
  fi
  for matrix in routing auth paths mixed reducer category hosts boundaries; do
    case "$MATRIX/$matrix" in
      all/*|routing/routing|auth/auth|supported/paths|supported/mixed|supported/reducer|supported/category|supported/hosts|boundaries/boundaries) ;;
      *) continue ;;
    esac
    if [[ "$matrix" == routing ]]; then
      config="$SCRIPT_DIR/kong.yaml"
      probes="$SCRIPT_DIR/probes.tsv"
    else
      config="$SCRIPT_DIR/$matrix.yaml"
      probes="$SCRIPT_DIR/$matrix-probes.tsv"
    fi
    run_flavor "$flavor" "$port" "$tls_port" "$matrix" "$config" "$probes"
  done
done
echo "Kong conformance checks passed (matrix: $MATRIX; exact=$EXACT_COUNT conservative=$CONSERVATIVE_COUNT unsupported-boundary=$UNSUPPORTED_COUNT)"
