# Soundcheck

**Proof-or-counterexample for declarative security policy.**

Soundcheck takes a policy artifact, such as an API-gateway config, and proves security
invariants over it. It returns a solver-backed verdict that no violating request exists
within the modeled semantics, or a concrete counterexample expressed in the config's
own vocabulary. Counterexamples are checked against the modeled obligation;
under conservative approximations they are candidates for investigation, not
guaranteed reproductions against a running gateway.

```
$ soundcheck verify kong.yaml
VIOLATED no-anonymous-access
         Conservative model-level candidate, not a guaranteed target replay:
         anonymous request GET /admin may be ALLOWED via route "admin-route" ...
$ echo $?
3
```

The reasoning is symbolic rather than heuristic. The question is discharged by an SMT
solver over the full modeled input space, so a `PROVED` result means there is no such
request under Soundcheck's supported semantics, not "we didn't find one." Unsupported or
uncertain behavior is reported rather than silently treated as verified.

## Why this exists

AI systems increasingly write the configuration that decides who may reach what: gateway
routes, RBAC bindings, IAM policies. These artifacts are security-critical, easy to get
subtly wrong, and reviewed by eye if they are reviewed at all.

Testing a policy samples requests from an unbounded space. It can find semantic
mistakes and validate model assumptions, but finite samples alone do not establish
absence of violations over that space. The interesting property of a policy
is universally quantified: *for all requests, X is denied.* You cannot sample your way to
that.

Soundcheck's bet is that a valuable subset of this problem can be modeled in decidable
logic and closed with automated reasoning. A finite declarative policy defines a decision
function over potentially unbounded requests, `(principal, action, resource, context) → Allow | Deny`. Results distinguish
proved, violated, vacuous, inconsistent, and unknown, leaving no place for a model's
confidence to stand in for a guarantee.

That makes it a natural fit for checking AI-generated output: the generator can be
unreliable while a separate, model-independent checker enforces the reviewed contract.
The checker, target model, solver, and deployment assumptions remain part of the trust boundary.

## How it works

```
                     ┌──────────── shared core ────────────┐
 Kong config ─┐      │  Decision IR  →  Encoder  →   Z3     │
 K8s RBAC   ──┼─ connectors ─►│ (principal,  (property        │──► UNSAT = proof
 IAM        ──┤  (parse→IR)   │  action,      negated)        │    SAT   = counterexample
 App authz  ──┘      │         resource,  ◄─ model lift ──────┤    (lifted to the
                     │         context)                       │     config's own words)
                     └────────────────────────────────────────┘
```

1. **Parse.** Syntactic parse of the config, then semantic lowering into a
   target-independent decision IR.
2. **Property.** An invariant universally quantified over all requests, for example
   `∀ req. (req.path starts with "/admin" ∧ req.principal = anonymous) ⇒ Deny`.
3. **Encode.** Emit the policy's decision logic together with the *negation* of the
   property as SMT-LIB2: does there exist a request this config allows but the property
   forbids?
4. **Solve.** Hand it to Z3. `UNSAT` means no violating request exists in the modeled
   semantics. Each decoded `SAT` request is checked against that obligation before
   use; a failed check becomes `unknown`, including in evidence traces.
5. **Lift.** Translate the checked model-level witness into the connector's vocabulary, so the output
   names a route and a service rather than a bitvector.

`--emit-smt PATH` keeps a single-property query as an audit artifact. It is plain SMT-LIB2,
so the solver obligation can be re-checked independently. The result still relies on the
fidelity of Soundcheck's Kong model and encoder. Frozen multi-query contracts use
`--evidence-dir NEW_DIRECTORY` to retain the complete obligation plan and provenance.

Multiple frontends, one IR, one solver backend, counterexamples lifted back per target.
The core is the reusable asset and connectors stay thin.

## Quickstart

Requires OCaml 5.x, dune, the `yaml` opam library, and the **`z3` CLI binary** on `PATH`
(the solver shells out to `z3 -smt2`).
The full test suite also needs Git, Bash, and `jq` for approved-contract gate tests.

Use [Z3 4.16.0](https://github.com/Z3Prover/z3/releases/tag/z3-4.16.0) to match
the regression-tested solver baseline. On Linux, extract the matching official
release and add its `bin` directory to `PATH`. The build-and-test CI job pins
Ubuntu 24.04 and the checksum-verified x64 Z3 archive; OCaml and opam dependencies
are not fully pinned. Older distro packages, including Ubuntu 24.04's Z3 4.8.12,
can time out on regex proofs under the default 10-second deadline, producing
`unknown` rather than `proved`.

```bash
brew install z3                 # macOS; Linux: official release as described above
z3 -version                    # regression baseline: 4.16.0
opam install dune yaml
dune build
dune test                       # full suite, including the 50-case corpus gate
```

Verify a config:

```bash
# default property: no anonymous access under /admin
dune exec soundcheck -- verify bench/kong/cases/admin-no-auth/config.yaml

# a different invariant
dune exec soundcheck -- verify bench/kong/cases/public-no-rate-limit/config.yaml \
  --property rate-limit-on-public

# machine-readable, for CI
dune exec soundcheck -- verify kong.yaml --format json

# native GitHub Actions annotation, with the config attached to the finding
dune exec soundcheck -- verify kong.yaml --contract contract.yaml --format github

# verify against a human-confirmed, immutable functionality contract
dune exec soundcheck -- verify kong.yaml \
  --contract bench/kong/contracts/admin-get.yaml --format json

# keep the proof obligation for audit, then re-check it yourself
dune exec soundcheck -- verify kong.yaml --emit-smt query.smt2
z3 -smt2 query.smt2

# retain every frozen-contract query, execution status, and provenance
mkdir -p evidence
dune exec soundcheck -- verify kong.yaml --contract contract.yaml \
  --evidence-dir evidence/run-001 --format json

# inspect the exact Kong semantics Soundcheck models
dune exec soundcheck -- profile kong --format json
```

```
usage: soundcheck verify <config.yaml> [--contract CONTRACT.yaml]
                                       [--evidence-dir NEW_DIRECTORY]
                                       [--property P] [--path-prefix PREFIX]
                                       [--method METHOD] [--host HOST]
                                       [--format human|json] [--emit-smt PATH]
  --property     no-anonymous-access (default) | rate-limit-on-public
                 | no-shadowed-routes | admin-api-not-reachable
                 | authenticated-access | network-restricted-access
  --path-prefix  path scope for access properties (default /admin)
  --trusted-cidr trusted IPv4 block; required for network-restricted-access
                 (admin-api-not-reachable default 127.0.0.1/32)
  --method       exact method for paired contracts (default all)
  --host         exact host for paired contracts (default all)
  --format       human (default) | json
  --emit-smt     write a single-property SMT-LIB2 query to PATH (not contracts)
  --evidence-dir write an audit bundle to a new directory; requires --contract

usage: soundcheck profile kong [--format human|json]

usage: soundcheck mcp [--contract CONTRACT.yaml]
```

Network-restricted intent also freezes the trusted block and requires an explicit
acknowledgement that the deployment—not Soundcheck—protects Kong's derived client IP:

```yaml
schema_version: 1
kind: network-restricted-access
scope:
  path_prefix: /internal
  method: GET
  host: internal.example
  trusted_cidr: 10.0.0.0/8
assumptions:
  source_ip_integrity: externally-enforced
```

`--contract` cannot be combined with property or scope flags. Contract files are
strict, versioned artifacts; unknown fields, versions, and kinds are rejected:

```yaml
schema_version: 1
kind: authenticated-access
scope:
  path_prefix: /admin
  method: GET                 # optional; omission means every method
  host: admin.example         # optional; omission means every host
```

Exit codes are designed to gate a pipeline: `0` proved, `1` input/output or verification
error, `2` usage,
`3` violated, `4` unknown, `5` vacuous, `6` inconsistent contract.

`soundcheck profile kong` publishes the complete, versioned support boundary behind
the shorter `assurance` assessment in each verification report. Its modeled,
conservative, and unsupported feature lists let humans, CI systems, and agents inspect
what a `proved` result means without reading the implementation. Use `--format json`
for the stable machine-readable profile schema.

Kong normalizes incoming request paths before routing. Soundcheck therefore reasons
over the same post-normalization path domain: percent triplets are canonicalized,
non-reserved bytes are decoded, dot segments are removed, and duplicate slashes are
merged. Literal route paths and contract/property prefixes must already be normalized,
matching Kong's route-schema requirement; invalid inputs fail with a suggested canonical
path. For explicit format 1.1/2.1 inputs, the parser first applies Kong's legacy path
migration, including implicit regex detection and percent decoding. Format 3.0
and omitted-format partial configs use only a leading `~` as the regex marker;
punctuation such as `/a+b` remains a literal prefix.

Exact route-header criteria are modeled case-insensitively, including repeated
request values. Any header-value list containing `~*` is conservative: traditional
recognizes singleton regex lists while traditional_compatible recognizes each value.
Route ordering retains only a partial order justified for both flavors.

HTTP and HTTPS routing are modeled separately where Kong's behavior differs.
HTTPS-only routes reject matching HTTP requests, while exact SNI criteria are
enforced for HTTPS but ignored for HTTP route selection and priority. Wildcard SNI
remains conservative because its availability depends on Kong's router flavor.

## The JSON contract

`--format json` emits a stable schema. It is the universal integration point, consumed
identically by CI, the MCP tool, and eventually the repair loop.

```json
{
  "result": "violated",
  "schema_version": 9,
  "property": "no-anonymous-access",
  "assurance": {
    "profile": "kong-traditional-http-v11",
    "status": "within_profile",
    "findings": []
  },
  "frozen_spec": null,
  "clause": null,
  "counterexample": {
    "principal": "anonymous",
    "action": "GET",
    "path": "/admin",
    "host": "",
    "scheme": "https",
    "sni": "api.example",
    "headers": [],
    "source_ip": "0.0.0.0",
    "route": "admin-route",
    "service": "admin-api",
    "shadowed_route": null,
    "shadowed_service": null
  }
}
```

Every key is emitted unconditionally, `null` when absent, so a consumer never has to
probe for existence. `assurance` identifies the versioned connector semantics and
whether this config stayed within them, triggered conservative over-approximation, or
contained an unsupported construct. Findings use stable codes plus service/route
locations. Frozen runs populate `frozen_spec` with the artifact schema,
kind, and normalized canonical content, binding the verdict to the reviewed input.
Manual property runs emit `null`. `shadowed_route` is populated only by
`no-shadowed-routes`, which
names two routes: a possible modeled winner and the one written to handle it.
`host` and `source_ip` are meaningful only where the config or property constrains
them; elsewhere the solver picked them freely.

`authenticated-access` is a frozen two-clause contract: anonymous requests in
the selected path/method/host scope must be denied, and authenticated requests in
that same scope must be definitely allowed. Omitting `--method` or `--host` means
all methods or all hosts; Soundcheck never infers intended functionality from the
config being repaired. Contract reports identify the failing clause as
`must_deny` or `must_allow`. Because a contract is checked with several solver
queries, `--emit-smt` currently rejects it rather than emitting an incomplete
audit artifact. Use `--evidence-dir` with the frozen contract file instead.

`network-restricted-access` is also paired: every request outside the trusted CIDR
must be denied, while authenticated requests inside it must be definitely allowed.
The latter preserves useful service rather than accepting a deny-all repair. Soundcheck
models the client IP Kong supplies to the policy decision; it does not inspect
`real_ip_header`, `trusted_ips`, or the surrounding proxy topology. The required
`source_ip_integrity: externally-enforced` assumption makes that boundary part of the
reviewed and frozen contract identity instead of leaving it implicit.

On success, `"result": "proved"` with `"counterexample": null`. If a property's
forbidden request class is empty, Soundcheck instead returns `"result": "vacuous"`;
this is not a proof about the config and exits nonzero. A config outside the supported
fragment gets `"result": "unknown"` with a `"reason"` naming the routes responsible,
never a quiet pass. Both are verdicts rather than tool errors: the MCP tool returns
them as normal results so an agent can rewrite the offending config and re-verify.
Property correction is available only in manual mode; a frozen specification
requires separate approval outside the repair loop.

## Evidence bundles

`soundcheck verify kong.yaml --contract contract.yaml --evidence-dir evidence/run-001`
creates a schema v1 audit bundle alongside the usual report. The parent directory must
already exist; an existing destination file, directory, or symlink is rejected. The
option requires a frozen `--contract` and cannot be combined with `--emit-smt`. It is
available on `verify`; comparisons and MCP calls retain their existing interfaces.

The bundle contains `contract.json` (normalized frozen artifact),
`assurance-profile.json` (complete semantic profile), `report.json` (the unchanged
schema v9 verdict), and `queries/<obligation-id>.smt2` for every planned obligation.
`manifest.json` binds these files with SHA-256 and records:

- `schema_version: 1`, the final `result`, and each artifact's relative `path` and `sha256`.
- `config.sha256` and `config.size_bytes`, computed over the exact bytes verified.
  The config content and its filesystem path are not copied.
- `soundcheck.executable_sha256`, `soundcheck.ocaml_version`, and
  `soundcheck.report_schema_version`, identifying the actual verifier build.
- `solver.name`, `solver.version`, and `solver.version_error`. If the version command
  fails, `version` is `null` and the error is retained.
- `obligation_plan.status` (`complete` or `unavailable`) and `reason`.
- Ordered `obligations`, each with `id`, `phase` (`inhabitance`, `consistency`, `clause`),
  related `clauses`, query artifact, `execution`, `solver_result`, `model`, and `reason`.

An executed obligation records the checked result `sat`, `unsat`, or `unknown`.
SAT includes a validated abstract request model; a decoded SAT that fails its
obligation is recorded as unknown, with its validation reason and no witness. An unexecuted
obligation has `execution: "not_executed"` and null result, model, and reason, but its
query remains present. SAT for inhabitance establishes a nonempty request class;
SAT for consistency or a policy clause instead prevents a proof. Interpret each
query using its phase rather than treating every SAT as a policy violation.

These are reproducible audit artifacts, not independently checked proof certificates.
Re-running Z3 checks the retained formula, not the fidelity of Kong lowering. No
independent UNSAT-certificate checker is shipped.

Verification keeps its short-circuit order and existing exit codes. A config rejected
as unsupported before lowering still produces an `unknown` bundle, with an unavailable
plan, the rejection reason, and no invented queries. Parse and usage errors produce no
bundle. Evidence I/O errors exit `1`, including when verification itself proved.

Directories and files are created privately and exclusively. The fully written
manifest is published last as the completion marker; a failed write can leave an
incomplete new directory without it. Serialization and file ordering are deterministic
for identical input traces. SAT witnesses are solver-selected and may differ between
solver builds. Re-check any retained query directly:

```sh
z3 -smt2 evidence/run-001/queries/<obligation-id>.smt2
```

## Using it against AI-generated config

Two enforcement layers, meant to be used together.

**Soft, in-loop: MCP.** `soundcheck mcp --contract CONTRACT.yaml` loads the
human-confirmed contract once at startup. Its `verify` tool exposes only `config`;
property and scope fields are absent from discovery and rejected at runtime, so the
agent can repair the config but cannot weaken the specification. The counterexample
then identifies the request that defeats the current draft. Running `soundcheck mcp`
without a contract preserves the manual, mutable property interface for exploration,
but that mode does not enforce spec-freeze.

The regression workflow starts the real MCP process with the reviewed
[`admin-get.yaml`](bench/kong/contracts/admin-get.yaml) contract and submits four
attempts through one server lifetime:

| Attempt | Expected result | Repair signal |
|---|---|---|
| [`unsafe.yaml`](bench/kong/workflows/frozen-admin/unsafe.yaml) | `violated` / `must_deny` | anonymous `GET /admin` reaches `admin-get` |
| [`repaired.yaml`](bench/kong/workflows/frozen-admin/repaired.yaml) | `proved` | both contract clauses hold |
| [`deny-all.yaml`](bench/kong/workflows/frozen-admin/deny-all.yaml) | `violated` / `must_allow` | authenticated `GET /admin` has no route |
| repaired config plus a replacement property | tool error | frozen verification accepts only `config` |

Every verification report must carry the same canonical frozen-spec identity. The
acceptance test drives `soundcheck mcp --contract ...` over stdio rather than calling
the verifier in-process, so it also pins contract loading and the public MCP boundary.

**Hard, at the gate: CI.** The same binary runs in CI or a pre-apply hook and blocks on
non-zero exit, regardless of what any agent did or claimed. Enforcement requires
a trusted, required workflow that cannot be edited or bypassed by that agent;
an exit code alone does not establish repository protection.

In GitHub Actions, `--format github` emits a workflow-command annotation. Failed
clauses, counterexample route/service, frozen-spec identity, assurance profile,
and uncertainty findings are included when available. Non-proof outcomes retain
their normal non-zero exit codes, so the annotation and branch-protection gate
cannot disagree.

The reusable Action accepts a candidate configuration and the repository-relative
path of the approved contract. On a PR it reads that contract from the immutable
event `pull_request.base.sha`, never from the candidate checkout. On a non-forced,
non-deleted push it accepts only the protected default branch and reads the event's
exact `after` commit. Other events, including `pull_request_target`, `merge_group`,
and manual dispatch, fail closed.

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: ph0smet/soundcheck@<reviewed-full-commit-sha>
    with:
      config: kong.yaml
      contract: soundcheck-contract.yaml
```

Replace the placeholder with a reviewed immutable commit SHA. Run this in a
fresh Ubuntu job with no prior candidate-code execution. The Action rejects a
preexisting workspace `_opam`, disables automatic opam pinning and caches, and
builds dependencies/verifier from its own Action sources. It uses a private
temporary copy of the approved Git blob and preserves the verifier's exit code.

Protection of the base branch, separate review of contract changes, the trusted
workflow and fixed contract-path input, required checks, and rerunning against
an updated base remain deployment responsibilities. A candidate-controlled
workflow or `uses: ./` is not an approval boundary; the latter is used only to
test this Action's implementation in this repository. No branch rules are
installed automatically. OCaml/setup actions and dependencies are not a fully
pinned supply chain.

Both surfaces are thin adapters over the same verification implementation, with
consistency regressions across CLI, MCP, and evidence. Soundcheck is also consumable
directly as an OCaml library.

## Properties

Properties are **core templates, not gateway-specific checks**. Each is written once
against the shared decision IR, so it applies to every connector that lowers into it.

| Property | Status | Question it answers |
|---|---|---|
| `no-anonymous-access` | shipped | Can any unauthenticated request reach a protected path prefix? |
| `rate-limit-on-public` | shipped | Is every anonymously-reachable route covered by a general request-rate limiting plugin? |
| `no-shadowed-routes` | shipped | Does a permissive route intercept traffic a stricter route was written to handle? |
| `admin-api-not-reachable` | shipped | Can an *anonymous* request from outside a trusted address block reach a route proxying the Admin API? |
| `authenticated-access` | shipped | Are anonymous requests denied while authenticated requests remain definitely allowed in one explicit scope? |
| `network-restricted-access` | shipped | Are requests outside a trusted IPv4 block denied while authenticated requests inside it remain definitely allowed? |

`rate-limit-on-public` is encoded with a reduced-reachability filter on allow rules: the
solver is asked whether a request is reachable *specifically via an unthrottled rule*.
This fits a structural question into the same per-request existential the engine already
emits, with no second query engine, and auth-required routes fall out as exempt for free
since an anonymous request cannot reach them in the first place.
Only `rate-limiting` and `rate-limiting-advanced` establish this general coverage.
Response rate limiting depends on upstream usage headers, while GraphQL rate limiting
covers query cost; both remain visible as conservative findings rather than false proofs.

`admin-api-not-reachable` is scoped to agree with Kong's own hardening guide, which
sanctions two protections for the Admin API: restrict the network, or put the route behind
an auth plugin. Requiring the violating request to be *anonymous* exempts both for free:
an ip-restricted route's guard cannot hold for an outside address, and an auth-required
route's guard cannot hold for an anonymous caller. Without that, the property would report
a violation on the exact configuration Kong documents as correct.

`no-shadowed-routes` is the one property that takes **no parameter**. The others ask a
question you have to know to ask: `--path-prefix /admin` only finds holes under `/admin`,
which on a large config is most of the problem. Shadowing instead reads intent out of the
config, since attaching an auth plugin to a route is the operator declaring it sensitive,
and asks whether that guard actually covers the traffic the route's own match would
accept:

```
∃ req.  selected_i(req) ∧ may_match_k(req) ∧ may_guard_i(req) ∧ ¬must_guard_k(req)
```

A model-level candidate that permissive rule `i` may serve, while rule `k`'s
protection is not established for it. It is asked once per candidate pair rather than once
per config, since it quantifies over *which rule serves* a request rather than over
requests alone. Pairs are pruned only by justified rank, distinct identity, or a
sufficient guard-implication check; unrelated guards still require a solver query.
The first validated satisfiable pair is reported with both routes named.

## Targets

| Target | Status | Notes |
|---|---|---|
| **Kong** (decK YAML) | shipped | Routes, services, and auth / rate-limiting plugin detection |
| App-level authz, tenant isolation | planned | Connector #2; expected to refine the IR from v0 to v1 |
| Kubernetes RBAC | planned | |
| OPA / Rego | planned | Decidable fragment only, rest rejected explicitly |

Adding a target means writing a parser and a counterexample lifter. The encoder and solver
are untouched, and the property templates above come along for free.

## Scope and current limits

This is an early project and the boundaries are worth stating plainly.

- **The current target is Kong OSS 3.9.3, both `traditional` and
  `traditional_compatible`.** The shared profile is intentionally narrower than
  either router. It is not a certification of all Kong releases, editions,
  deployment settings, or arbitrary plugins.
- **Possible and definite access are different.** Safety uses an upper bound on
  allowed requests; functionality uses a lower bound. Incomplete matches cannot
  suppress other routes, and incomplete guards cannot prove required access.
  A selected route's failing guard denies; it does not reroute to a fallback.
  Tied possible denying routes must not hide possible allowing routes.
- **Route order is a common partial order.** Criterion count is retained where
  justified. Detailed path order is used only when all active routes have
  identical non-path criteria. Request-global reducers, differing category/header
  precedence, out-of-range packed priorities, SNI, and absent tie-break data
  prevent stronger claims. Unresolved winners remain possible, not arbitrarily
  selected. Exact equivalence rejects unresolved behavior.
- **Regex support is bounded and conservative.** Accepted syntax uses ASCII
  literals/positive classes, grouping, grouped alternation, and supported
  quantifiers. Source length is limited to 2,048 bytes, nesting to 32, numeric
  repetition bounds to 64, and expanded syntax cost to 512. These are
  compile-complexity limits, not a runtime guarantee or a request-length limit.
  End `$`, shorthand classes such as `\\d`, dot, negated classes, non-ASCII
  atoms, top-level alternation, backreferences, lookarounds, ambiguous escapes,
  and unsafe name rewrites fail closed. Arbitrary UTF-8 request suffixes are
  not forbidden to make the model appear exact. Even accepted regexes remain
  possible matches because Kong's PCRE runtime can fail at its match limit.
  They neither suppress other routes nor establish definite functionality.
- **Host, header and SNI boundaries are explicit.** Exact lowercase hosts without
  route ports and exact case-insensitive header values are modeled. Wildcard
  hosts use an upper bound; route host ports are unconstrained because Kong may
  synthesize an omitted request port. Both are incomplete. Uppercase hosts,
  regex headers, wildcard SNI, and stream source/destination criteria remain
  conservative. Exact SNI is enforced on HTTPS and bypassed for HTTP selection.
- **Request paths are post-normalization.** Percent triplets, decoded non-reserved
  bytes, dot segments, and duplicate slashes follow the modeled Kong domain.
  Legacy format migration precedes validation. This is not a full HTTP parser
  or a validation of every Kong schema constraint.
- **`no-shadowed-routes` reports structure, not intent.** A deliberate public
  `/admin/health` exception can be reported. Findings require review and are not
  automatic vulnerability claims. Ambiguous route identities fail closed.
- **Admin API recognition is a port heuristic** for 8001/8444, including URL
  shorthand and explicit service targets. Non-default Admin ports are not
  recognized. A proof covers recognized targets only, not discovery of every
  administrative endpoint.
- **Source addresses are IPv4 values supplied by Kong's client-IP derivation.**
  Trusted proxy configuration is an external assumption, explicitly frozen for
  network contracts. Unknown allow-list entries weaken the entire allow
  restriction; unknown deny entries are not treated as definite enforcement.
  Invalid/IPv6 CIDRs prevent definite allowance.
- **Plugin support is a named, configuration-level model.** Unknown active HTTP
  plugins fail the whole config as unsupported: they may change routing,
  enforcement or upstream targets. This is not a proof of plugin implementations.
  Rate-limit presence establishes structural coverage, not live quota behavior.
  Runtime quota cannot prove functionality. Anonymous fallback and conditional
  termination are also conservative; unconditional request termination denies.
- **Plugin scope and disabled services matter.** Enabled plugin precedence and
  HTTP-subsystem activation are modeled. Disabled services contribute no routes.
  Consumer/consumer-group plugins, unresolved nested plugin relationships, and
  non-string references fail closed. Ordinary consumer credentials do not become
  an invented principal model.
- **Top-level routes participate in routing.** String service references resolve
  to declared services. Service-less winners deny upstream access; unmodeled
  references cannot silently disappear.
- **Comparisons need exact modeled observations.** The four strengths compare
  decisions, route/service identity, service targets, and upstream URI. Literal
  route URI transformations are supported; regex transformations and incomplete
  predicates return unknown. An order-only finding can still prove equivalence
  when complete predicates establish identical requested observations or disjoint
  alternatives. A proof is relative to the selected strength and scope.
- **The trust boundary is explicit.** Parser/lowering, encoder, concrete validator,
  Z3, supported target assumptions, and trusted gate deployment are not formally
  verified here. Passing tests and target probes are important evidence, not a
  universal soundness proof.

## Testing

`bench/kong/cases/` holds 50 labeled regression cases with reviewed
`expected.json` artifacts. Profile v11 deliberately changes previous unsupported
regex claims to unknown, marks shared-order/runtime approximations, and rejects
unmodeled plugins. The original configs are retained; expectations are justified
in the [hardening execution plan](docs/plans/2026-10-kong-hardening.md), not regenerated
merely to make a suite green.

The suite includes strict YAML/contract input rejection, solver process and
string decoding failures, malformed-model injection, obligation-level witness
checks, all four comparison modes, and frozen CLI/MCP/evidence consistency.
An independent finite refinement oracle enumerates 91,200 worlds and checks
`must_allow ⊆ actual_allow ⊆ may_allow`; deliberate broken controls must fail.
This checks the abstraction rules, not every Kong behavior.

`test/regex_agree.ml` cross-checks the generic concrete matcher and SMT encoding.
`test/regex_boundary_t.ml` separately pins the narrower connector boundary.
Neither agreement between two readers of the same IR nor lifecycle mocks counts
as independent target conformance.

The pinned real-Kong harness checks fixed target observations in both flavors,
distinguishing exact model agreement, conservative bounds, and unsupported cases.
Unsupported rows must produce public `unknown` with an unsupported assessment;
they are boundary checks, never counted as exact model agreement. Wrong target
observations, missing possible winners, invalid bounds, and silent class changes fail.

`dune test --force` runs the local suite and corpus. CI also runs real-Kong
conformance. `bash scripts/check.sh full` runs both locally with Docker;
`bash scripts/check-commit.sh <revision>` independently checks a committed revision
in a clean worktree without Docker. Gate tests use synthetic local Git repositories
and real verifier end-to-end checks; they do not install remote branch protection.

## Repo layout

```
core/          shared engine, the reusable asset
  ir.ml          decision model: match_/guard/priority, principal, action, resource
  property.ml    invariant templates (one query over requests)
  shadowing.ml   no-shadowed-routes: candidate rule pairs (one query per pair)
  regex.ml       regex AST: parser, SMT translation, concrete matcher
  smt_encode.ml  IR + property → SMT-LIB2
  solve.ml       Z3 orchestration + model extraction
  witness.ml     obligation-level validation of decoded SAT requests
  cidr.ml        IPv4 blocks: parsing, membership, bitvector encoding
  report.ml      Report.t + human/JSON serializers (the stable contract)
  evidence.ml    frozen-contract audit bundles, manifest, and provenance
  sha256.ml      portable byte-exact artifact and executable digests
connectors/    thin frontends (parse→IR, lift counterexample→config vocabulary)
  kong/          decK YAML, first connector
    fragment.ml    reject unsupported configuration semantics
    regex_boundary.ml  shared-router regex language and complexity limits
    path_normalization.ml  Kong request domain and literal-path validation
cli/           soundcheck verify, soundcheck profile, soundcheck mcp
mcp/           soundcheck mcp, JSON-RPC 2.0 over stdio
bench/         labeled corpus + regression gate
```

Connectors depend on core. **Core never depends on connectors.**

## Roadmap

The immediate focus is trustworthy Kong-first verification before public promotion.
Frozen MCP acceptance, the assurance profile, paired contracts, configuration
comparison, CI integration, and evidence bundles are implemented. Semantic hardening
and independently justified target conformance govern their supported boundary;
passing the existing corpus alone is not sufficient acceptance.

Real-gateway differential conformance runs in CI and is also available locally
with Docker. It checks fixed target observations and model bounds against pinned Kong OSS 3.9.3 under
both supported router flavors; see [`bench/kong/conformance/`](bench/kong/conformance/).
Security-decision equivalence compares two Kong configs over every modeled request
and returns either equivalence, a concrete distinguishing request, or unknown when
the model cannot support an exact comparison:

```sh
soundcheck compare before.yaml after.yaml --format json
```

Use `--mode route-service` for the stronger comparison that also requires the
same selected route and service. Explicit, unique route names are required for
that mode.

Use `--mode service-target` to additionally preserve the selected service's
normalized protocol, host, port, and base path. Both Kong's `url` shorthand and
explicit service target fields are supported.

Use `--mode upstream-uri` for the strongest comparison. It also proves that the
per-request URI sent upstream is unchanged after applying the matched literal
route prefix, `strip_path`, `path_handling`, and Kong's slash-joining rules.
Regex route-path transformation is rejected as unknown rather than approximated.

Bind comparison to the same immutable contract used by a repair loop to prove
both that the replacement satisfies the intent and that decisions outside its
path/method/host scope did not change:

```sh
soundcheck compare before.yaml after.yaml --contract contract.yaml --format json
```

All comparison modes compose with `--contract` to preserve their observations
outside the frozen repair scope.

With `--contract`, `--emit-smt` writes the outside-scope preservation query; the
multi-query contract result remains embedded in the comparison report.

The next development priorities are continuous target conformance, semantic
acceptance for every supported feature, small authorized deployment pilots, and
usability improvements informed by that feedback. A deterministic repair benchmark
with structured feedback for external agent and RLVR systems follows verifier
hardening and representative evaluation; it is not the immediate next milestone.

Soundcheck remains a model-independent verifier. External agents and optional downstream
orchestrators may generate or repair configurations through its interfaces, but model
clients and training infrastructure are not part of the verification core. Additional
connectors follow after the Kong verifier is ready for public promotion.

## Design notes

Written in OCaml because this is compiler work, parse and lower and encode and lift, which
is OCaml's home turf. Z3 is the automated solver backend, reached through SMT-LIB2 text
rather than language bindings. That keeps the boundary inspectable and replaceable, and
makes single-property obligations artifacts you can read.

Interactive theorem proving is not part of the runtime architecture. Automated SMT
fits the supported policy fragment; future meta-verification of critical semantics
or proof certificates is a separate question.

## License

MIT. See [LICENSE](LICENSE).
