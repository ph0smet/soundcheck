<p align="center">
  <img src="docs/assets/soundcheck-logo-readme.png" alt="" width="160">
</p>

<h1 align="center">Soundcheck</h1>

<p align="center">
  <strong>Proof before policy ships.</strong>
</p>

<p align="center">
  <a href="https://github.com/ph0smet/soundcheck/actions/workflows/ci.yml?query=branch%3Amain"><img src="https://github.com/ph0smet/soundcheck/actions/workflows/ci.yml/badge.svg?branch=main&amp;event=push" alt="CI status on main" height="20"></a>
  <a href="https://ocaml.org/"><img src="https://img.shields.io/badge/OCaml-5.0%2B-EC6813?logo=ocaml&amp;logoColor=white" alt="OCaml 5.0 or newer" height="20"></a>
  <a href="https://github.com/Z3Prover/z3"><img src="https://img.shields.io/badge/solver-Z3-137CBD" alt="Solver: Z3" height="20"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-009C95" alt="License: MIT" height="20"></a>
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> ·
  <a href="#see-what-counts-as-a-repair">See an example</a> ·
  <a href="#from-agent-feedback-to-ci">Agent workflows</a> ·
  <a href="docs/getting-started.md">Full walkthrough</a> ·
  <a href="#supported-model">Supported model</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

Soundcheck is a formal verifier for declarative security configuration, built for
AI-assisted changes. It helps platform and security teams check configurations
proposed by humans or AI agents against independently reviewed access requirements,
across every request represented by its supported target model.

Keep forbidden access blocked and required access available. Soundcheck returns
a solver-backed proof, a checked model-level counterexample, or an explicit
non-proof result. Agents can use that feedback to revise a candidate while the
frozen verification interface keeps the requirement fixed.

Today, Soundcheck verifies **decK-style Kong OSS 3.9.3 configurations** under the
`traditional` and `traditional_compatible` HTTP routers. Kong is the first
connector in a broader effort to verify declarative security policy across
multiple systems. The verifier is AI-model agnostic.

> [!IMPORTANT]
> A `PROVED` result applies to the stated property or frozen contract within
> Soundcheck's versioned target model and explicit assumptions. It does not
> certify a live deployment. Conservative counterexamples are investigation
> candidates, not guaranteed target replays. Unsupported verification semantics
> and inconclusive checks never produce a passing verdict.

## See what counts as a repair

Start with the access requirement. In the included
[`admin-get.yaml`](bench/kong/contracts/admin-get.yaml) contract, anonymous `GET`
requests whose paths begin with `/admin` must be denied, while authenticated
requests in the same scope must remain allowed:

```yaml
schema_version: 1
kind: authenticated-access
scope:
  path_prefix: /admin
  method: GET
```

The policy owner reviews the contract independently of the candidate
configuration. This contract distinguishes anonymous from authenticated requests;
it does not specify administrator roles or individual user permissions.

Keep that contract fixed and evaluate four configurations:

| Candidate | Result | What the result means |
| --- | --- | --- |
| [Unprotected route](bench/kong/workflows/frozen-admin/unsafe.yaml) | `violated` | Anonymous access defeats the denial requirement in the model |
| [Deny everyone](bench/kong/workflows/frozen-admin/deny-all.yaml) | `violated` | Removing all routes defeats the required-access clause |
| [Add Key Auth](bench/kong/workflows/frozen-admin/repaired.yaml) | `proved` | Both denial and required access hold within the model and assumptions |
| [Unmodeled active plugin](bench/pilot/examples/unsupported.yaml) | `unknown` | The plugin's effect cannot be verified within the supported semantics |

These are minimal synthetic verifier fixtures, not complete deployable Kong
configurations. After [setup](#quickstart), try the failure and repair with the
same contract. Output is abridged; solver-selected request details may vary.

```console
$ dune exec soundcheck -- verify \
    bench/kong/workflows/frozen-admin/unsafe.yaml \
    --contract bench/kong/contracts/admin-get.yaml
VIOLATED authenticated-access
         Conservative model-level candidate, not a guaranteed target replay:
         anonymous request GET /admin ... may be ALLOWED via route "admin-get"
$ dune exec soundcheck -- verify \
    bench/kong/workflows/frozen-admin/repaired.yaml \
    --contract bench/kong/contracts/admin-get.yaml
PROVED   authenticated-access
         Anonymous requests must be denied and authenticated requests allowed for path prefix /admin, method GET
```

The first command exits `3`; the repaired configuration exits `0`. A separate
[`compare --contract`](#configuration-comparison) check can also establish that
selected modeled behavior outside the repair's scope is preserved. Ordinary
`verify` does not perform that comparison.

## From agent feedback to CI

1. **Review the requirement.** A policy owner selects a supported contract kind,
   reviews its scope and assumptions, and approves it separately from the
   generated configuration.
2. **Verify during repair.** Start [frozen MCP](#frozen-mcp) with that contract.
   The agent submits candidate configuration, receives verification feedback,
   and can revise and retry. The tool accepts no replacement property or scope.
3. **Rerun in trusted CI.** The [GitHub Action](#github-action) independently
   verifies the candidate against the contract from the approved event commit.
   It does not trust an agent's earlier verdict. Only `proved` passes the
   verification gate; required checks and deployment controls enforce the result.

The verifier, contract selection, and CI workflow must remain outside the
candidate's control. Frozen MCP restricts its verification interface; it is not
a sandbox for an agent with permission to replace the server or workflow.
Soundcheck supplies the verifier and adapters. Model clients, prompts,
credentials, and repair orchestration remain in the external agent or caller.

## Quickstart

Soundcheck currently builds from source. You need Git, Bash,
[opam](https://opam.ocaml.org/), OCaml 5.0 or newer, Dune 3.11 or newer, the `yaml`
OCaml package, and the `z3` CLI on `PATH`. **Z3 4.16.0 is the regression-tested
baseline**; other versions may produce different timeout or `unknown` behavior.
See the [installation walkthrough](docs/getting-started.md#1-install-the-toolchain)
for solver setup.

```sh
git clone https://github.com/ph0smet/soundcheck.git
cd soundcheck

# Create or select an OCaml 5.x switch, then load it in this shell.
opam switch create . 5.2.1 --no-install
eval "$(opam env)"

opam install . --deps-only --with-test
dune build @all
```

Run the [example above](#see-what-counts-as-a-repair), then follow the
[complete getting-started guide](docs/getting-started.md) to verify your own
configuration, review a contract, inspect JSON or evidence, and connect an agent
or CI job.

## What ships today

| Capability | Current support |
| --- | --- |
| Target | Kong OSS 3.9.3 decK YAML; `traditional` and `traditional_compatible` HTTP routing |
| Verification | Six manual property templates and three parameterized frozen contract kinds |
| Verdicts | `proved`, `violated`, `vacuous`, `inconsistent`, or `unknown` |
| Comparisons | Decision, route/service, service target, and literal-path upstream URI equivalence, within their supported boundaries |
| Interfaces | CLI, schema-v9 JSON, GitHub annotations, frozen/manual MCP, and a reusable GitHub Action |
| Audit output | SMT-LIB2 emission for single queries and complete evidence bundles for frozen contracts |

Additional gateways, Kubernetes RBAC, OPA/Rego, IAM, and app-level authorization
are [future targets](#roadmap), not shipped connectors.

## What Soundcheck establishes

Schema validation checks a document's structure. Request tests exercise selected
cases. Soundcheck reasons symbolically about whether any request represented by
its supported model violates a specified requirement. It analyzes existing
target-native configuration alongside a separate contract; you keep the target's
configuration format.

The result concerns the stated requirement. It does not establish every security
property of the configuration or replace runtime enforcement. Tests remain
essential for checking that the implementation and target model behave as
expected. If the intended behavior cannot be expressed as a precise supported
property, Soundcheck cannot establish it.

## How it works

```text
 decK YAML          shared verification core
     │
     ▼          ┌─────────────────────────────────────────────┐
 Kong connector │ Decision IR → property negation → SMT-LIB2 │ → Z3
  parse + lower └───────────────────────┬─────────────────────┘
     ▲                                  │
     └──────── checked witness + config-level counterexample ┘
```

1. **Fix the requirement.** A reviewed property or frozen contract identifies
   the required behavior and its path, method, host, network scope, and
   assumptions. Frozen contracts are loaded outside the repair loop.
2. **Parse and lower.** The Kong connector parses YAML, validates Soundcheck's
   accepted fragment, and lowers supported target behavior into the shared
   decision IR. It is not a replacement for Kong's full schema validation.
3. **Encode the violation.** Soundcheck asks whether there exists a request that
   the policy allows but the contract forbids, or denies but the contract
   requires.
4. **Solve and validate.** `UNSAT` closes a policy-clause obligation in the
   modeled semantics; the separate inhabitance check must be `SAT`. Every
   decoded `SAT` witness is checked against its actual obligation, and an
   invalid witness becomes `unknown`.
5. **Lift the result.** A checked witness is reported as a principal, method,
   path, route, and service rather than raw solver values.

Soundcheck preserves the abstraction invariant:

```text
must_allow ⊆ actual_allow ⊆ may_allow
```

Safety checks use possible allowance so incomplete matching cannot hide a leak.
Functionality checks use definite allowance so an uncertain guard cannot prove
required access. That asymmetry is why a conservative model can still be sound
for both kinds of obligation.

## Understand the verdict

| Result | Meaning | Exit code |
| --- | --- | ---: |
| `proved` | All applicable inhabitance and consistency checks pass, and no modeled property or contract violation exists | 0 |
| `violated` | A validated modeled witness defeats a property or contract obligation | 3 |
| `unknown` | Unsupported semantics, solver failure/timeout, or an invalid decoded witness prevents a proof | 4 |
| `vacuous` | The required request class is empty, so no useful policy proof was established | 5 |
| `inconsistent` | Frozen must-allow and must-deny intent overlap | 6 |

Input, output, and verification errors exit `1`; invalid command usage exits
`2`. Only `proved` exits zero at the verification gate.

## Properties and frozen contracts

| Property | Kind | Question |
| --- | --- | --- |
| `no-anonymous-access` | Safety | Can an unauthenticated request reach a protected path prefix? |
| `rate-limit-on-public` | Safety | Is every anonymously reachable route covered by a general request-rate-limit plugin? |
| `no-shadowed-routes` | Structural safety | Can a permissive route intercept traffic that a stricter route was written to handle? |
| `admin-api-not-reachable` | Safety | Can an anonymous request outside a trusted address block reach a recognized Admin API target? |
| `authenticated-access` | Paired safety + functionality | Are anonymous requests denied while authenticated requests remain definitely allowed in one scope? |
| `network-restricted-access` | Paired safety + functionality | Are untrusted sources denied while authenticated requests inside a trusted IPv4 block remain definitely allowed? |
| `protected-prefix-with-public-exceptions` | Frozen safety + functionality | Is anonymous access denied outside explicit public prefixes while authenticated access and each public exception remain available? |

Manual property flags are useful for exploration. For a gate, choose one of the
three supported frozen contract kinds:
[`authenticated-access`](bench/kong/contracts/admin-get.yaml),
[`network-restricted-access`](bench/kong/contracts/internal-get.yaml), or
[`protected-prefix-with-public-exceptions`](bench/kong/contracts/api-public-health.yaml). Each pairs
denial with required access in an explicit scope; the public artifact format is
not a general-purpose specification language.

Have the policy owner review the scope and assumptions, then load the strict,
versioned artifact outside the repair loop. `--contract` rejects property and
scope overrides, and every report carries the contract's normalized identity.
Unknown artifact fields, versions, and kinds are rejected. Approval remains a
workflow responsibility; parsing a contract does not establish that it was
reviewed or captures all intended requirements.

For example, protect `/api` while keeping `/api/health` public with the
[public-exceptions workflow](bench/kong/workflows/public-exceptions/README.md).
It rejects both an exposed API and a repair that locks out health checks.
Exception prefixes are explicit, nonempty and strictly inside the protected
prefix; they share its method and host scope. Matching is literal prefix
matching: `/api/healthcheck` is also included. This kind is available through
frozen contracts, rather than additional manual property flags.

## Integrations

### Frozen MCP

Start an MCP server with the reviewed contract fixed for its lifetime:

```sh
eval "$(opam env)"
dune exec soundcheck -- mcp \
  --contract bench/kong/contracts/admin-get.yaml
```

The frozen `verify` tool accepts configuration only. An agent may repair the
configuration and retry; the interface rejects attempts to replace the property
or scope. The caller must keep the server and its startup contract outside the
agent's control. Running MCP without `--contract` remains a manual exploration
mode with mutable requirements.

### GitHub Action

The composite Action reruns verification using the contract from the immutable
PR base commit, or from the exact protected-default-branch push commit. It does
not load the contract from the candidate checkout or accept an earlier agent
verdict as evidence of success. Repository controls must establish approval of
that contract.

Use an Ubuntu 24.04 or newer runner on x86-64 or ARM64.
The Action installs checksum-verified Z3 4.16.0, shared with the regression CI,
and checks the solver version in its opam environment before verification.

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: ph0smet/soundcheck@<reviewed-full-commit-sha>
    with:
      config: kong.yaml
      contract: soundcheck-contract.yaml
```

Use a reviewed full commit SHA in a fresh, trusted job before candidate code
runs. The caller workflow, fixed contract path, and Action SHA must not be
candidate-controlled; `uses: ./` is only suitable for testing the Action. The
adapter accepts `pull_request` and non-forced, non-deleted protected-default-branch
push events and fails closed elsewhere.

Required checks, branch protection, separate contract approval, and fresh-base
reruns remain repository responsibilities. Soundcheck installs none of them.
Pinning its SHA still leaves the setup Action, system packages, and resolved
opam dependencies to review or lock separately. See the
[integration walkthrough](docs/getting-started.md#10-put-soundcheck-in-a-loop-or-gate)
for the full boundary.

### Stable JSON

On `verify`, `--format json` emits the schema-v9 verification result used by
machine consumers. Its core result, property, assurance, frozen-spec, clause,
and counterexample keys are always present and use `null` when not applicable;
`reason` appears for `unknown` and `inconsistent`. `compare` and `profile` have
separately versioned JSON schemas.

```sh
eval "$(opam env)"
dune exec soundcheck -- verify \
  bench/kong/workflows/frozen-admin/unsafe.yaml \
  --contract bench/kong/contracts/admin-get.yaml \
  --format json
```

The CLI and MCP adapter share these report semantics. The GitHub Action uses
the same verifier and exit codes with native workflow annotations.

### Configuration comparison

Compare configurations to check modeled Allow/Deny decisions, or select a
stronger observation with `--mode route-service`, `--mode service-target`, or
`--mode upstream-uri`. The last mode supports upstream URI transformation for
literal paths; regex capture transformation remains outside its proof boundary.

With `--contract`, comparison first verifies that the replacement satisfies the
frozen requirement, then checks preservation of the selected modeled behavior
outside the contract's scope. This is a separate check from ordinary `verify`.

```sh
eval "$(opam env)"
dune exec soundcheck -- compare \
  bench/kong/workflows/frozen-admin/unsafe.yaml \
  bench/kong/workflows/frozen-admin/repaired.yaml \
  --contract bench/kong/contracts/admin-get.yaml \
  --format json
```

That included example returns `valid_repair`. Incomplete predicates or
observations return `unknown` instead of an unjustified equivalence proof.

### Audit artifacts

Non-contract runs can retain the most recently executed SMT-LIB2 query with
`--emit-smt`. Inhabitance and shadowing may require more than one query, so that
file is not a complete trace. Frozen contracts reject `--emit-smt` and use
multiple ordered obligations; `--evidence-dir` writes their complete schema-v1
bundle with the normalized contract, assurance profile, report, every planned
query, execution status, digests, and provenance.

Follow the [evidence walkthrough](docs/getting-started.md#8-retain-an-evidence-bundle)
to create a bundle in a new destination. Evidence permits formula replay; it is
not an independently checked UNSAT certificate or a proof of the parser, encoder,
or target model. When unsupported semantics prevent obligation planning, the
bundle records an unavailable plan rather than invented queries.

Treat bundles as potentially sensitive: they omit raw config text but contain
the contract, report, formulas, witnesses or models, hashes, and operational
identifiers. Review them before retention or sharing.

## Supported model

The current assurance profile is `kong-traditional-http-v11`: Kong OSS 3.9.3
`traditional` and `traditional_compatible` HTTP routing. Inspect the complete
modeled, conservative, and unsupported feature lists directly:

```sh
eval "$(opam env)"
dune exec soundcheck -- profile kong --format human
```

Important boundaries include:

- Literal paths, normalized request paths, methods, lowercase exact hosts,
  exact headers, HTTP/HTTPS behavior, exact HTTPS SNI, known plugin precedence,
  top-level routes, disabled services, and default-deny behavior are modeled
  within the published profile.
- Route ordering retains only the partial order justified for both supported
  routers. Unresolved possible winners remain possible rather than being
  arbitrarily selected.
- Regex support is a bounded shared subset. Even accepted regex matches remain
  conservative because Kong's PCRE runtime can fail at its match limit.
- Unknown active HTTP plugins and unsupported relationship or regex forms make
  the whole verification result `unknown`.
- Authentication is a configuration-level guard model, not a proof of plugin
  implementations, credential stores, or identity-provider availability. It
  distinguishes anonymous from authenticated requests, not individual user
  permissions or administrator roles.
- Rate-limit verification establishes structural plugin coverage, not live
  quota behavior, datastore health, or throughput.
- Network contracts reason over the IPv4 client address supplied by Kong. The
  deployment must enforce the frozen `source_ip_integrity` assumption.
- Admin API recognition uses the declared default-port heuristic for 8001 and
  8444; it does not discover arbitrary administrative endpoints.
- Parser/lowering fidelity, the encoder, witness validator, Z3, the supported
  Kong assumptions, and trusted CI deployment remain in the trust boundary.

The [semantic evidence inventory](bench/kong/SEMANTIC-COVERAGE.md) maps every
profile feature to pinned Kong source, lowering ownership, regressions, available
target samples, and explicit gaps. It is evidence bookkeeping, not a public
result schema, a coverage percentage, or a completeness certificate.

## Testing

The repository keeps several kinds of evidence separate:

- A [labeled regression corpus](bench/kong/cases/) with reviewed expected results.
- An [independent finite refinement oracle](test/approximation_refinement_t.ml)
  for `must_allow ⊆ actual_allow ⊆ may_allow`, including deliberately broken
  controls.
- A [semantic inventory](bench/kong/SEMANTIC-COVERAGE.md) linking profile features
  to their source, regression, and target evidence, with explicit remaining gaps.
- [Pinned real-Kong conformance](bench/kong/conformance/README.md) across both
  supported router flavors, distinguishing exact, conservative, and unsupported
  observations.

These are finite checks of the implementation and abstraction rules, not a
universal proof that the target model matches every deployment.

See [Contributing: Run the checks](CONTRIBUTING.md#run-the-checks) for local test
commands, prerequisites, and serialization rules. The experimental
[advisory evaluation workflow](bench/pilot/README.md) includes synthetic examples
only; it does not establish production accuracy or autonomous repair success.
The [external-agent repair benchmark](bench/repair/README.md) evaluates submitted
candidate files against evaluator-owned frozen requirements and out-of-scope
preservation. Its synthetic controls test the evaluator; they are not live-agent
results. See the [pilot protocol](docs/evaluation/pilot-protocol.md) for the
separate authorization and review needed for deployment evaluation.

## Roadmap

Soundcheck is building a common verification workflow for declarative security
policy across API gateways, infrastructure authorization, and application access
control. Kong is the first implementation. Future connectors will bring their
own supported native formats, behavioral models, assumptions, and conformance
evidence to the shared verification core.

- **Deepen Kong assurance and usability.** Expand semantic coverage and target
  conformance, improve contract authoring and diagnostics, and evaluate useful
  coverage through small authorized deployment pilots.
- **Extend to more policy systems.** Additional gateways, Kubernetes RBAC,
  OPA/Rego, IAM, and application authorization remain future targets. Connector
  expansion follows Kong readiness and deployment feedback; each target needs
  precise properties and independently justified semantics.
- **Evaluate external agent repairs.** Use the experimental benchmark to collect
  reproducible results from external agents after inputs and requirements are
  reviewed. Model runtimes and repair orchestration remain outside the core.

The [connector shortlist](docs/evaluation/connector-selection.md) records the
criteria and a provisional Kubernetes RBAC feasibility direction. A second
connector is not implemented or committed for delivery yet.

Connectors depend on the core, and adapters share its verification semantics.
New targets may require extending the decision model. A common interface does
not yet establish portable contracts or end-to-end security across interacting
systems; those require their own models and evidence.

## Contributing

Bug reports, formalizable feature proposals, and focused pull requests are
welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md); coding agents should also
follow [AGENTS.md](AGENTS.md). Please sanitize configurations and never include
credentials, production evidence bundles, or confidential counterexamples in a
public issue.

## Design choices

Soundcheck is written in OCaml because its work is compiler-shaped: parse,
lower, encode, solve, validate, and lift. Z3 is invoked through inspectable
SMT-LIB2 text rather than language bindings. Interactive theorem proving is not
part of the runtime architecture; automated SMT fits the current decidable
policy fragment.

## License

MIT. See [LICENSE](LICENSE).
