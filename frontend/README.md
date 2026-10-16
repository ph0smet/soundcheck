# Soundcheck web

A web workspace for Soundcheck. It is a thin adapter over the `soundcheck` CLI and
its versioned JSON contract. The web layer contains no verification logic: every
verdict, counterexample and assurance finding comes from the engine unchanged.

| Screen  | What it does | Engine command |
|---|---|---|
| Audit   | Upload one config or a zip of configs. Every Kong config found is checked with each exploratory preset and, when you attach one, your reviewed frozen contract, with a live results matrix and a Markdown or PDF report. Includes a sample bundle for trying it without a config. | `soundcheck verify` per file and check |
| Verify  | Prove a property or a frozen contract over a Kong decK config. Shows the verdict, exit code, counterexample as an HTTP request, assurance findings, and highlights the offending routes in the editor. | `soundcheck verify … --format json` |
| Compare | Decision, route/service or service-target equivalence of two configs, optionally bound to a frozen contract (repair check). | `soundcheck compare … --format json` |
| Corpus  | Browse the 50 labeled cases in `bench/kong/cases`, open one in Verify, or re-run it and diff against its golden. | `soundcheck verify` |
| Profile | The versioned Kong assurance boundary: modeled, conservative and unsupported features. | `soundcheck profile kong --format json` |

## Running

### Docker (default, needs only Docker)

One image holds the engine binary, Z3 and the web server. The image build runs the
full `dune test` gate and the frontend checks, so a failing engine or adapter never
ships. Base images are pinned by digest and Z3 is the checksum-verified 4.16.0 release
used by the repository's CI, so the image verifies with the same solver as CI.

It works the same on Linux, macOS and Windows, and builds natively for both x86-64
and arm64 (Apple Silicon), picking the matching pinned Z3 build. On Windows, run the
scripts from Git Bash or WSL. The build also runs the frontend's conformance tests
against the freshly built engine. Fonts are self-hosted, so it needs no access to
Google Fonts.

```bash
./start.sh                 # build the image, run the UI on :3000   (--port N, --skip-tests)
./stop.sh                  # stop the container (images and volumes are left alone)
```

If something fails, `start.sh` says what and where, and never exits silently: an
unreachable Docker daemon gets a platform-specific hint (including the Linux docker
group case), and the build output is kept in `.run/docker-build.log`. If Docker's build
cache is corrupt (a "snapshot ... does not exist" error), it retries once with
`--no-cache`, which deletes nothing. When launched by double-click, the window stays
open on failure.

The same image is the CLI. `soundcheck.sh` runs a short-lived container per command
with the current directory mounted, so relative paths work and the engine's exit codes
pass straight through (CI gating and `mcp` over stdio included):

```bash
./soundcheck.sh verify kong.yaml --format json
./soundcheck.sh compare before.yaml after.yaml --contract contract.yaml
docker run --rm -v "$PWD:/work" soundcheck:local verify kong.yaml   # the same, without the wrapper
```

To run the image by hand, publish the port on localhost only:

```bash
docker run --rm -p 127.0.0.1:3000:3000 soundcheck:local
```

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
| `SOUNDCHECK_TIMEOUT_MS` | `60000` | Per-run time limit. A run past it is stopped (SIGTERM, then SIGKILL) and reports no verdict. |
| `SOUNDCHECK_MAX_CONCURRENCY` | `4` | Engine runs executing at once. |
| `SOUNDCHECK_MAX_QUEUE` | `32` | Runs allowed to wait for a slot. Beyond it, requests fail fast with stage `busy`. |
| `SOUNDCHECK_ALLOWED_HOSTS` | unset | Extra host names the server answers to, comma separated. `localhost`, `127.0.0.1` and `[::1]` are always allowed. |

Engine discovery order: `SOUNDCHECK_BIN`, then `_build/default/cli/main.exe`, then
`dune exec soundcheck` if `dune` is on `PATH`. The engine itself calls `z3` from `PATH`.

## HTTP API

| Route | Body | Returns |
|---|---|---|
| `POST /api/verify` | `{ config, spec }`, where `spec` is `{ mode: "property", property, pathPrefix?, method?, host?, trustedCidr? }` or `{ mode: "contract", contract }` | `{ ok: true, exitCode, report, durationMs, command, provenance }` or `{ ok: false, stage, message, exitCode }` |
| `POST /api/compare` | `{ before, after, mode, contract? }` | Same envelope with a compare or repair report |
| `POST /api/audit` | multipart form: `file` (YAML, JSON or zip) or `source=samples`; `gateway`, `pathPrefix`, `trustedCidr`, optional `contractText` | NDJSON stream: one `plan` event, a `result` event per file and check, then `done` only if every check finished. Input problems return 400 `{ error }` |
| `GET /api/profile` | | Assurance profile |
| `GET /api/engine` | | Engine and solver availability |

`report` is the engine's JSON after strict validation (verify schema 9, compare and
repair schema 1, profile schema 1). `provenance` gives the SHA-256 of every input
document, the engine's identity (executable SHA-256 and Z3 version, when the web
server can establish them) and, for frozen-contract runs, the engine's own evidence
manifest. `stage` separates tool errors (`parse`, exit 1; `usage`, exit 2) from input
validation (`input`), a missing or timed-out engine (`engine`), rejected engine output
(`protocol`), a full queue (`busy`) and a cancelled run (`cancelled`). None of these is
a verdict. Verdicts such as `violated` or `unknown` are successful responses.

## Trust boundary

The web server is a thin adapter over the CLI. Two boundaries matter, and both fail
closed.

**Engine output.** A run becomes a result only if every independent signal agrees
(`src/lib/server/accept.ts`):

1. The process exited on its own, within the time limit and the 8 MB output cap, and
   was not cancelled. A run that printed a verdict and then timed out has no verdict.
2. The exit code is one the command defines (verify: 0, 3, 4, 5, 6; compare: 0, 3, 4).
   Exit 1 and 2 are tool errors whatever stdout says.
3. stdout is exactly one JSON document that matches the versioned schema in
   `src/lib/contract.ts`: no missing or unexpected fields, a pinned `schema_version`,
   and cross-field rules such as "a counterexample is present exactly when the result
   is violated".
4. The exit code encodes the same verdict as the document.
5. The document answers the question that was asked: the same property, the requested
   comparison mode, a frozen-spec identity for contract runs and none otherwise.
6. Frozen-contract runs also write the engine's evidence bundle, whose manifest must
   hash the same config bytes, the exact report printed on stdout and the contract's
   canonical identity, and record the same verdict and assurance profile.

The TypeScript types are inferred from those validators, so each wire shape is written
down once. CI runs the validators against the real CLI for every property and
comparison mode, and against every golden report in `bench/kong/cases`.

**HTTP.** The service has no authentication and is built for one operator on their own
machine. It binds to `127.0.0.1` (`npm run dev`, `npm run start`, `./start.sh`, and the
documented `docker run -p 127.0.0.1:...`). Every request, to a page or the API, must
name an allowed host (`src/proxy.ts`), which defeats DNS rebinding, and writes from
another origin are refused. Request bodies are
size-limited while they stream, before they are buffered. The solver queue is bounded,
and a client that disconnects cancels its runs, including queued ones and an audit's
in-flight checks. Before serving anyone else, put real authentication in front and add
the host to `SOUNDCHECK_ALLOWED_HOSTS`.

## Audit semantics

The audit reports exactly one of these outcomes:

| Outcome | When |
|---|---|
| Fail | Some check found a concrete violation (or the contract is inconsistent). A violation stands even if the run did not finish. |
| Incomplete | The run was cancelled, failed, or ended early; some check never ran; or nothing was checked. Never a pass. |
| Needs review | Every check ran, but some returned unknown, vacuous or a tool error, some config uses features outside the assurance profile, or a file that may be a config was skipped (too large, unreadable, an unrecognised YAML or JSON file, or an unsupported gateway). |
| No findings (exploratory) | Every exploratory preset was proved everywhere, but no frozen contract was attached. |
| Pass | All of the above is clean and a frozen contract was attached and proved for every config. |

The built-in checks are **exploratory presets**, not specifications. Each one assumes a
policy: that everything under the chosen prefix must require authentication, that only
the chosen network may reach the Admin API, that every public route should be rate
limited, and that no route should hide another. The report states these assumptions
next to every preset. Only a human-reviewed frozen contract is a specification, so
only it can produce a Pass.

Exported reports include the completion state, the SHA-256 of the upload and of every
config, the engine and solver identity, the assurance profile, the contract digest and
its canonical identity, and the engine's evidence manifest for each contract check. A
report is a summary, not a signed artifact. For audit-grade evidence of a frozen
contract, use `soundcheck verify <config> --contract <contract> --evidence-dir <dir>`.

## Gateways and the audit

`src/lib/gateways.ts` lists every gateway the UI knows. Kong is supported; Repose is
shown as coming soon, and Repose XML inside an uploaded zip is detected and reported as
such. Enabling a connector once the engine supports it is a status change there plus a
detection rule in `src/lib/server/audit.ts`.

The audit runs the exploratory presets (see Audit semantics) and an attached frozen
contract. The paired properties describe intended functionality, which Soundcheck
never infers from a config, so they run only from a frozen contract. Zips are extracted in memory: at most 25 MB
uploaded, 2000 entries, 100 MB expanded and 512 KB per file; hidden files and
`__MACOSX/` are ignored, and anything unreadable is listed as skipped with a reason
(and counted as a coverage gap when it may be a config).
Both report formats are generated in the browser from the same report model.

## Safety

The engine is spawned without a shell. Every user value is validated against a strict
pattern before it becomes an argument, so it can never be read as a flag. Documents are
written to a private temp directory that is removed after each run. Runs are
time-limited and killed with their whole process tree, at most four execute at once,
and the wait queue is bounded. See Trust boundary for the HTTP side.

## Checks

```bash
npm run check    # lint, typecheck and tests
```

`SOUNDCHECK_TEST_BIN=../_build/default/cli/main.exe npm test` also runs the engine
conformance suite (skipped when no engine is built). CI runs it on every pull request,
and separately builds the Docker image with its full test gate and smoke-tests it.

## Structure

```
src/app/            routes: verify, compare, corpus, profile, api/*
src/components/     shell (nav, theme, engine status), results, editors, screens
src/lib/contract.ts the engine's JSON contracts as strict validators (types inferred)
src/lib/audit.ts    audit plan, completion and outcome semantics
src/lib/domain.ts   property catalog, verdict semantics, proof-obligation rendering
src/lib/server/     engine runner, output acceptance, HTTP guards, bench corpus reader
```

Light, dark and system themes share one token set in `src/app/globals.css`. Color is
reserved for verdicts (proved, violated, vacuous, unknown, inconsistent), and the rest of
the interface stays monochrome.
