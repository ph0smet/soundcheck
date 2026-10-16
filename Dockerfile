# One image, two modes:
#   docker run -p 127.0.0.1:3000:3000 soundcheck                 -> web UI (localhost only)
#   docker run --rm -v "$PWD:/work" soundcheck verify kong.yaml -> CLI (exit codes preserved)
#
# Build with tests skipped: docker build --build-arg RUN_TESTS=0 -t soundcheck .
#
# Everything that affects a verdict is pinned: base images by multi-arch digest
# (which also freezes the opam repository snapshot used for dune and yaml), and
# Z3 to the 4.16.0 release that the repository's CI regression gate uses, checked
# against its published SHA-256.
#
# Builds natively for linux/amd64 (Intel/AMD Linux, Windows, Intel Macs) and
# linux/arm64 (Apple Silicon Macs, ARM Linux). Native builds matter: under x86
# emulation the solver can exceed its fixed 10-second deadline.

ARG OPAM_IMAGE=ocaml/opam:debian-13-ocaml-5.2@sha256:809ca99f1b28ff9471f8a1f0a41924720dbcbe232564a8a966d46003c2907aa3
ARG DEBIAN_IMAGE=debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
ARG NODE_IMAGE=node:22-trixie-slim@sha256:154ba2f4d6fec323d28e4f4bb86bba4677f1223391a1979cf521304e03a98dfa

# --- z3: the pinned solver, verified before it is unpacked ---------------------
FROM ${DEBIAN_IMAGE} AS z3

ARG TARGETARCH
ARG Z3_VERSION=4.16.0
# amd64 matches the archive and checksum pinned in .github/workflows/ci.yml.
ARG Z3_AMD64_ARCHIVE=z3-4.16.0-x64-glibc-2.39
ARG Z3_AMD64_SHA256=7288c49a5bd6dbafd7b0b0d1f65956b91672da24b08f09242919af159be3418e
ARG Z3_ARM64_ARCHIVE=z3-4.16.0-arm64-glibc-2.38
ARG Z3_ARM64_SHA256=87fcd963d3eecb0f12cf1c3ef0ad74e84a3a7bd3caed5d94445645ef94ae6274

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in \
      amd64) archive="$Z3_AMD64_ARCHIVE"; sum="$Z3_AMD64_SHA256" ;; \
      arm64) archive="$Z3_ARM64_ARCHIVE"; sum="$Z3_ARM64_SHA256" ;; \
      *) echo "No pinned Z3 build for architecture $arch (supported: amd64, arm64)." >&2; exit 1 ;; \
    esac; \
    curl --fail --location --silent --show-error --retry 3 --connect-timeout 10 --max-time 300 \
      "https://github.com/Z3Prover/z3/releases/download/z3-${Z3_VERSION}/${archive}.zip" -o /tmp/z3.zip; \
    printf '%s  %s\n' "$sum" /tmp/z3.zip | sha256sum --check --strict; \
    unzip -q /tmp/z3.zip -d /tmp/z3; \
    mkdir -p /opt/z3; \
    cp -r "/tmp/z3/${archive}/bin" /opt/z3/bin; \
    rm -rf /tmp/z3 /tmp/z3.zip; \
    test "$(/opt/z3/bin/z3 -version)" = "Z3 version ${Z3_VERSION} - 64 bit"

# --- engine: OCaml build + the dune test gate --------------------------------
FROM ${OPAM_IMAGE} AS engine

# jq and curl are used by the shell-level gate tests, as in CI.
RUN sudo apt-get update \
 && sudo apt-get install -y --no-install-recommends jq curl \
 && sudo rm -rf /var/lib/apt/lists/*
COPY --from=z3 /opt/z3 /opt/z3
ENV PATH=/opt/z3/bin:$PATH

# No `opam update`: the digest-pinned image's repository snapshot fixes the versions.
RUN opam install --yes dune yaml \
 && opam exec -- dune --version \
 && z3 -version

WORKDIR /home/opam/src
COPY --chown=opam:opam dune-project soundcheck.opam action.yml ./
COPY --chown=opam:opam core core
COPY --chown=opam:opam connectors connectors
COPY --chown=opam:opam cli cli
COPY --chown=opam:opam ci ci
COPY --chown=opam:opam mcp mcp
COPY --chown=opam:opam bench bench
COPY --chown=opam:opam scripts scripts
COPY --chown=opam:opam test test

ARG RUN_TESTS=1
# Matches CI: build in parallel, then run every test sequentially so solver-heavy
# tests do not compete for the shared solver deadline.
RUN opam exec -- dune build \
 && if [ "$RUN_TESTS" = "1" ]; then timeout 1800 opam exec -- dune test --force -j 1; fi

# --- engine-runtime: engine + z3 only, for live dev ---------------------------
# `./start.sh --dev` runs this as a long-lived container and the natively running
# Next.js dev server reaches it through docker/engine-bridge.mjs. Building this
# target skips the web stage entirely.
FROM ${DEBIAN_IMAGE} AS engine-runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends tini \
 && rm -rf /var/lib/apt/lists/*
COPY --from=z3 /opt/z3 /opt/z3
ENV PATH=/opt/z3/bin:$PATH
COPY --from=engine /home/opam/src/_build/default/cli/main.exe /usr/local/bin/soundcheck
RUN z3 -version && soundcheck profile kong --format json >/dev/null
WORKDIR /work
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sleep", "infinity"]

# --- web: Next.js standalone build, gated on the frontend checks -------------
FROM ${NODE_IMAGE} AS web

ENV NEXT_TELEMETRY_DISABLED=1
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY frontend/ ./
# Corpus pages are prerendered from the bench data at build time.
COPY bench/kong /src/bench/kong
# Copying the built engine makes this stage wait for the engine stage, so the
# frontend checks never compete for CPU with the solver-heavy `dune test` gate
# (BuildKit would otherwise run the two stages in parallel, and the solver's
# fixed deadline makes that gate timing-sensitive). It also lets the frontend
# conformance suite run against the real engine and the pinned Z3.
COPY --from=engine /home/opam/src/_build/default/cli/main.exe /opt/soundcheck/bin/soundcheck
COPY --from=z3 /opt/z3 /opt/z3
ARG RUN_TESTS=1
RUN if [ "$RUN_TESTS" = "1" ]; then \
      PATH="/opt/z3/bin:$PATH" SOUNDCHECK_TEST_BIN=/opt/soundcheck/bin/soundcheck npm run check; \
    fi \
 && SOUNDCHECK_REPO=/src NEXT_OUTPUT=standalone npm run build

# --- runtime -----------------------------------------------------------------
FROM ${NODE_IMAGE}

RUN apt-get update \
 && apt-get install -y --no-install-recommends tini \
 && rm -rf /var/lib/apt/lists/*
COPY --from=z3 /opt/z3 /opt/z3
COPY --from=engine /home/opam/src/_build/default/cli/main.exe /usr/local/bin/soundcheck
COPY --from=web /src/frontend/.next/standalone /app
COPY --from=web /src/frontend/.next/static /app/.next/static
# Standalone output omits public/ (the navbar logo lives there); copy it explicitly.
COPY --from=web /src/frontend/public /app/public
COPY bench/kong /opt/soundcheck/bench/kong
COPY --chmod=755 docker/entrypoint.sh /usr/local/bin/entrypoint

# HOSTNAME=0.0.0.0 is needed for Docker port publishing to reach the server.
# Exposure is controlled where the port is published (127.0.0.1:3000:3000), and
# the server rejects requests whose Host is not localhost unless
# SOUNDCHECK_ALLOWED_HOSTS lists it. There is no authentication: put your own
# in front before serving anyone else.
ENV PATH=/opt/z3/bin:$PATH \
    NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    SOUNDCHECK_BIN=/usr/local/bin/soundcheck \
    SOUNDCHECK_REPO=/opt/soundcheck \
    SOUNDCHECK_MAX_CONCURRENCY=4 \
    SOUNDCHECK_MAX_QUEUE=32 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

RUN z3 -version && soundcheck profile kong --format json >/dev/null

USER node
WORKDIR /work
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:3000/api/engine').then(r=>r.json()).then(s=>process.exit(s.available&&s.solver.available?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint"]
CMD ["web"]
