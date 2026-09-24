# One image, two modes:
#   docker run -p 3000:3000 soundcheck                          -> web UI
#   docker run --rm -v "$PWD:/work" soundcheck verify kong.yaml -> CLI (exit codes preserved)
#
# Build with tests skipped: docker build --build-arg RUN_TESTS=0 -t soundcheck .

# Debian 13 throughout: its z3 (4.13.x) is required. Debian 12's z3 4.8.12 never
# returns on the regex-anchored-end shadowing query, which hangs the test gate.

# --- engine: OCaml build + the dune test gate --------------------------------
FROM ocaml/opam:debian-13-ocaml-5.2 AS engine

# The solver shells out to the z3 CLI, so the test gate needs it too.
RUN sudo apt-get update \
 && sudo apt-get install -y --no-install-recommends z3 \
 && sudo rm -rf /var/lib/apt/lists/*

RUN opam install --yes dune yaml

WORKDIR /home/opam/src
COPY --chown=opam:opam dune-project soundcheck.opam ./
COPY --chown=opam:opam core core
COPY --chown=opam:opam connectors connectors
COPY --chown=opam:opam cli cli
COPY --chown=opam:opam mcp mcp
COPY --chown=opam:opam bench bench
COPY --chown=opam:opam test test

ARG RUN_TESTS=1
RUN opam exec -- dune build ./cli/main.exe \
 && if [ "$RUN_TESTS" = "1" ]; then timeout 900 opam exec -- dune test; fi

# --- engine-runtime: engine + z3 only, for live dev ---------------------------
# `./start.sh --dev` runs this as a long-lived container and the natively running
# Next.js dev server reaches it through docker/engine-bridge.mjs. Building this
# target skips the web stage entirely.
FROM debian:trixie-slim AS engine-runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends z3 tini \
 && rm -rf /var/lib/apt/lists/*
COPY --from=engine /home/opam/src/_build/default/cli/main.exe /usr/local/bin/soundcheck
WORKDIR /work
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sleep", "infinity"]

# --- web: Next.js standalone build -------------------------------------------
FROM node:22-trixie-slim AS web

ENV NEXT_TELEMETRY_DISABLED=1
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY frontend/ ./
# Corpus pages are prerendered from the bench data at build time.
COPY bench/kong /src/bench/kong
RUN SOUNDCHECK_REPO=/src NEXT_OUTPUT=standalone npm run build

# --- runtime -----------------------------------------------------------------
FROM node:22-trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends z3 tini \
 && rm -rf /var/lib/apt/lists/*

COPY --from=engine /home/opam/src/_build/default/cli/main.exe /usr/local/bin/soundcheck
COPY --from=web /src/frontend/.next/standalone /app
COPY --from=web /src/frontend/.next/static /app/.next/static
COPY bench/kong /opt/soundcheck/bench/kong
COPY --chmod=755 docker/entrypoint.sh /usr/local/bin/entrypoint

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    SOUNDCHECK_BIN=/usr/local/bin/soundcheck \
    SOUNDCHECK_REPO=/opt/soundcheck \
    PORT=3000 \
    HOSTNAME=0.0.0.0

USER node
WORKDIR /work
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:3000/api/engine').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint"]
CMD ["web"]
