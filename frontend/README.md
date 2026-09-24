# Soundcheck web

A web workspace for Soundcheck. It is a thin adapter over the `soundcheck` CLI and
its versioned JSON contract. The web layer contains no verification logic: every
verdict, counterexample and assurance finding comes from the engine unchanged.

| Screen  | What it does | Engine command |
|---|---|---|
| Audit   | Upload one config or a zip of configs. Every Kong config found is checked with each intent-free property (plus an optional frozen contract), with a live results matrix and a Markdown or PDF report. Includes a sample bundle for trying it without a config. | `soundcheck verify` per file and check |
| Verify  | Prove a property or a frozen contract over a Kong decK config. Shows the verdict, exit code, counterexample as an HTTP request, assurance findings, and highlights the offending routes in the editor. | `soundcheck verify … --format json` |
| Compare | Decision, route/service or service-target equivalence of two configs, optionally bound to a frozen contract (repair check). | `soundcheck compare … --format json` |
| Corpus  | Browse the 50 labeled cases in `bench/kong/cases`, open one in Verify, or re-run it and diff against its golden. | `soundcheck verify` |
| Profile | The versioned Kong assurance boundary: modeled, conservative and unsupported features. | `soundcheck profile kong --format json` |

## Running

### Docker (default, needs only Docker)

One image holds the engine binary, Z3 and the web server. The image build runs the
full `dune test` gate, so a failing engine never ships.

```bash
./start.sh                 # build the image, run the UI on :3000   (--port N, --skip-tests)
./stop.sh                  # stop the container (images and volumes are left alone)
```

The same image is the CLI. `soundcheck.sh` runs a short-lived container per command
with the current directory mounted, so relative paths work and the engine's exit codes
pass straight through (CI gating and `mcp` over stdio included):

```bash
./soundcheck.sh verify kong.yaml --format json
./soundcheck.sh compare before.yaml after.yaml --contract contract.yaml
docker run --rm -v "$PWD:/work" soundcheck:local verify kong.yaml   # the same, without the wrapper
```

The image uses Debian 13 because its Z3 (4.13.x) is required. Debian 12's Z3 4.8.12
never returns on one shadowing query in the corpus.

### Live development (hot reload, engine in Docker)

```bash
./start.sh --dev           # Next.js dev server on :3000 + engine container   (--port N, --skip-tests)
./stop.sh
```

The Next.js dev server runs natively, so edits under `frontend/` reload instantly with no
restart. The engine and Z3 run in a long-lived `soundcheck-engine` container built from
the image's `engine-runtime` stage (about 170 MB, no web build).
`docker/engine-bridge.mjs` stands in for the binary: the app writes its inputs under
`.run/engine-work`, which is bind-mounted into the container, and the bridge runs each
command with `docker exec`, passing exit codes through. After changing OCaml code, run
`./start.sh --dev` again: it rebuilds and swaps only the engine container while the dev
server keeps running.

Each engine call pays roughly 350 ms of `docker exec` overhead here, so the 212-check
sample audit takes about 19 s in dev mode versus about 4 s in the production image.
Running the dev server inside Docker was avoided on purpose: on Docker Desktop, file
watching across a bind mount needs polling, which the Next.js docs advise against.

### Native (local OCaml toolchain)

```bash
opam install dune yaml && brew install z3   # or: apt install z3 (see the Z3 note above)
./start.sh --native        # dune build + Next.js dev server   (--prod, --port N, --skip-engine)
./stop.sh
```

The native CLI is the dune-built binary itself (`dune exec soundcheck -- verify …`).
Runtime state (pid, port, `frontend.log`) lives in `.run/`.

In native mode without an engine the app still works read-only: the corpus and its golden results
render, and the sidebar explains what is missing.

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SOUNDCHECK_REPO` | `..` | Repository root, used for `bench/` data and engine discovery. |
| `SOUNDCHECK_BIN` | unset | Explicit engine binary. A `.js`/`.mjs` path is run with Node, so a wrapper script can front the engine. |
| `SOUNDCHECK_TIMEOUT_MS` | `60000` | Per-run time limit. |

Engine discovery order: `SOUNDCHECK_BIN`, then `_build/default/cli/main.exe`, then
`dune exec soundcheck` if `dune` is on `PATH`. The engine itself calls `z3` from `PATH`.

## HTTP API

| Route | Body | Returns |
|---|---|---|
| `POST /api/verify` | `{ config, spec }`, where `spec` is `{ mode: "property", property, pathPrefix?, method?, host?, trustedCidr? }` or `{ mode: "contract", contract }` | `{ ok: true, exitCode, report, durationMs, command }` or `{ ok: false, stage, message, exitCode }` |
| `POST /api/compare` | `{ before, after, mode, contract? }` | Same envelope with a compare or repair report |
| `POST /api/audit` | multipart form: `file` (YAML, JSON or zip) or `source=samples`; `gateway`, `pathPrefix`, `trustedCidr`, optional `contractText` | NDJSON stream: one `plan` event, a `result` event per file and check, then `done`. Input problems return 400 `{ error }` |
| `GET /api/profile` | | Assurance profile |
| `GET /api/engine` | | Engine and solver availability |

`report` is the engine's JSON, passed through verbatim (verify schema 9, compare
schema 1). `stage` separates tool errors (`parse`, exit 1; `usage`, exit 2) from
input validation (`input`) and an unavailable engine (`engine`). Verdicts such as
`violated` or `unknown` are successful responses, never errors.

## Gateways and the audit

`src/lib/gateways.ts` lists every gateway the UI knows. Kong is supported; Repose is
shown as coming soon, and Repose XML inside an uploaded zip is detected and reported as
such. Enabling a connector once the engine supports it is a status change there plus a
detection rule in `src/lib/server/audit.ts`.

The audit runs the checks that need no human intent: no anonymous access (under a
configurable prefix), rate limit on public, no shadowed routes, and Admin API not
reachable (from outside a configurable trusted block). The paired properties describe
intended functionality, which Soundcheck never infers from a config, so they run only
against an attached frozen contract. Zips are extracted in memory: at most 25 MB
uploaded, 2000 entries, 100 MB expanded and 512 KB per file; hidden files and
`__MACOSX/` are ignored, and anything unreadable is listed as skipped with a reason.
Both report formats are generated in the browser from the same report model.

## Safety

The engine is spawned without a shell. Every user value is validated against a strict
pattern before it becomes an argument, so it can never be read as a flag. Documents are
written to a private temp directory that is removed after each run. Runs are time-limited
and at most four execute at once.

There is no authentication. Treat this as a local or internal tool and do not expose it
to the public internet as-is.

## Structure

```
src/app/            routes: verify, compare, corpus, profile, api/*
src/components/     shell (nav, theme, engine status), results, editors, screens
src/lib/contract.ts TypeScript mirror of the engine's JSON contracts
src/lib/domain.ts   property catalog, verdict semantics, proof-obligation rendering
src/lib/server/     engine bridge, request validation, bench corpus reader
```

Light, dark and system themes share one token set in `src/app/globals.css`. Color is
reserved for verdicts (proved, violated, vacuous, unknown, inconsistent), and the rest of
the interface stays monochrome.
