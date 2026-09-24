# Soundcheck

**Proof-or-counterexample for declarative security policy.**

Soundcheck takes a policy artifact, such as an API-gateway config, and proves security
invariants over it. It returns a solver-backed verdict that no violating request exists
within the modeled semantics, or a concrete counterexample expressed in the config's
own vocabulary.

```
$ soundcheck verify kong.yaml
VIOLATED no-anonymous-access
         anonymous request GET /admin is ALLOWED via route "admin-route"
         (service "admin-api") — no authentication plugin is attached at route,
         service, or global scope.
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

Testing a policy samples a handful of requests from an unbounded space. That is fine for
catching typos and useless for establishing absence. The interesting property of a policy
is universally quantified: *for all requests, X is denied.* You cannot sample your way to
that.

Soundcheck's bet is that a valuable subset of this problem can be modeled in decidable
logic and closed with automated reasoning. Declarative policy reduces to a finite decision
function, `(principal, action, resource, context) → Allow | Deny`. Results distinguish
proved, violated, vacuous, inconsistent, and unknown, leaving no place for a model's
confidence to stand in for a guarantee.

That makes it a natural fit for checking AI-generated output: the generator can be
unreliable so long as the checker is not.

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
   semantics. `SAT` means the satisfying assignment is itself a concrete counterexample.
5. **Lift.** Translate the SMT model back into the connector's vocabulary, so the output
   names a route and a service rather than a bitvector.

`--emit-smt PATH` keeps a single-property query as an audit artifact. It is plain SMT-LIB2,
so the solver obligation can be re-checked independently. The result still relies on the
fidelity of Soundcheck's Kong model and encoder; multi-query contracts do not yet emit a
complete evidence bundle.

Multiple frontends, one IR, one solver backend, counterexamples lifted back per target.
The core is the reusable asset and connectors stay thin.

## Quickstart

Requires OCaml 5.x, dune, the `yaml` opam library, and the **`z3` CLI binary** on `PATH`
(the solver shells out to `z3 -smt2`).

```bash
brew install z3                 # or: apt install z3
opam install dune yaml
dune build
dune test                       # runs the 50-case corpus regression gate
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

# inspect the exact Kong semantics Soundcheck models
dune exec soundcheck -- profile kong --format json
```

```
usage: soundcheck verify <config.yaml> [--contract CONTRACT.yaml]
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

Exit codes are designed to gate a pipeline: `0` proved, `1` parse error, `2` usage,
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
path. Regex route paths remain authored regex patterns and are not rewritten.

Exact route-header criteria are modeled case-insensitively, including repeated
request values and Kong's header-count priority rule. A sole header value beginning
with `~*` is Kong's regex form; it remains a conservative profile finding rather
than being treated as an exact string.

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
    "profile": "kong-traditional-http-v10",
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
names two routes: the one that serves the request and the one written to handle it.
`host` and `source_ip` are meaningful only where the config or property constrains
them; elsewhere the solver picked them freely.

`authenticated-access` is a frozen two-clause contract: anonymous requests in
the selected path/method/host scope must be denied, and authenticated requests in
that same scope must be definitely allowed. Omitting `--method` or `--host` means
all methods or all hosts; Soundcheck never infers intended functionality from the
config being repaired. Contract reports identify the failing clause as
`must_deny` or `must_allow`. Because a contract is checked with several solver
queries, `--emit-smt` currently rejects it rather than emitting an incomplete
audit artifact.

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
them as normal results so an agent can correct the property or rewrite the offending
route and re-verify.

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
non-zero exit, regardless of what any agent did or claimed. This is where the actual
guarantee lives. A prompt is not an enforcement mechanism; an exit code is.

In GitHub Actions, `--format github` emits a workflow-command annotation. Failed
clauses, counterexample route/service, frozen-spec identity, assurance profile,
and uncertainty findings are included when available. Non-proof outcomes retain
their normal non-zero exit codes, so the annotation and branch-protection gate
cannot disagree.

The reusable Action accepts only a configuration and a reviewed frozen contract:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: ph0smet/soundcheck@v1
    with:
      config: kong.yaml
      contract: soundcheck-contract.yaml
```

The initial Action targets Ubuntu/Linux, installs OCaml and Z3, builds the
version of Soundcheck pinned by the Action reference, and emits native GitHub
annotations. Pin an immutable commit SHA for the strongest supply-chain
guarantee; use the `v1` tag when automatic compatible fixes are preferred. The
Action intentionally exposes no property or scope inputs, so a generated repair
cannot substitute or weaken the reviewed contract.

Both surfaces are thin adapters over one core, so they cannot drift apart in what they
consider verified. Soundcheck is also consumable directly as an OCaml library.

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
∃ req.  selected_i(req) ∧ match_k(req) ∧ guard_i(req) ∧ ¬guard_k(req)
```

A request the higher-ranked rule `i` serves and lets through, which rule `k` was written
to handle and would have stopped. It is asked once per candidate pair rather than once
per config, since it quantifies over *which rule serves* a request rather than over
requests alone. Pairs are pruned statically (rank, strictly weaker guard, distinct
routes) and the first satisfiable one is reported with both routes named.

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

- **HTTP routing is modelled over normalized path, method, host, exact headers,
  protocol, and exact SNI.** Stream `sources`/`destinations` remain out of scope.
  A route carrying an unmodelled criterion is given a rank incomparable with
  every other route, so it neither suppresses nor is suppressed. Upstream-URI
  comparison models `strip_path` and `path_handling` for literal route paths;
  regex-path transformation fails closed. A route whose host contains uppercase
  is also left incomparable, since the server lowercases the request Host.
- **Route priority is derived from prefix length only.** Routing is winner-takes-all, as a
  real gateway does it, but Kong also ranks on the number of match criteria, which is not
  modelled. Rather than guess an order, unmodelled cases are left as **ties**, and a tie
  means "order unknown" rather than "same rank". The two properties then treat ties in
  opposite directions, both away from a false proof: reachability admits every tied rule
  as selectable (over-approximating what is reachable), while shadowing treats a tie as a
  candidate (over-approximating what might be shadowed, since the config does not
  determine which route wins).
- **`no-shadowed-routes` reports structure, not intent.** It finds guards that do not cover
  what they appear to cover, and that shape is occasionally deliberate. A public
  `/admin/health` for load balancers is the usual example. It is therefore opt-in via
  `--property` and never part of a default run, and its findings are worth reviewing
  rather than treating as automatic vulnerabilities.
- **Regex paths are modelled for the regular subset; the rest is rejected, not
  approximated.** Literals, `.`, character classes, `?`/`*`/`+`, bounded repetition,
  alternation and grouping translate to `str.in_re`. Backreferences are not regular at
  all, and possessive quantifiers and atomic groups change the accepted language
  (`a*+a` never matches `aa`), so those report `unknown` naming the route and the
  construct. Rejection is whole-config: the route we cannot model may be the one that
  decides the property.
- **Route ranking follows Kong's own two layers.** Routes are grouped into categories by
  which criteria they use, and categories are walked by criteria *count* first, so a
  route matching on path and method outranks one matching on path alone whatever their
  paths look like. Within a category the order is `submatch_weight` (a regex path raises
  it, so a regex route outranks a prefix route however long the prefix), then
  `regex_priority`, then path length. `created_at` breaks Kong's remaining ties and is
  absent from a declarative config, so rules equal on everything above it stay tied.
  A rule whose match criteria include something unmodelled is left unordered against
  everything, so it neither suppresses nor is suppressed.
- **Request-path normalization is modelled.** Symbolic request paths are restricted to
  Kong's normalized URI domain, while non-normalized literal route paths are rejected
  with their normalized replacement. This keeps proofs and witnesses inside the request
  language Kong actually hands to its router.
- **The Admin API is recognised by upstream port** (8001 and 8444, Kong's defaults). A
  gateway on a non-default admin port is not recognised, and `admin-api-not-reachable`
  then stays quiet about it. That is the *false-negative* direction for this one property,
  which is why the port list is documented rather than buried.
- **Source addresses are IPv4 and are the connection peer.** `ip-restriction` reads the
  raw connection address and ignores `X-Forwarded-For`, so behind a load balancer every
  request appears to come from the balancer; the model inherits that. IPv6 and malformed
  entries are dropped from the modeled guard and reported as conservative findings,
  which weakens the restriction and therefore over-reports.
- **Auth and rate-limiting plugins are recognised by name.** A custom or unlisted plugin
  is not counted, so a route it protects is treated as open and reported as violated. That
  errs toward a false alarm rather than a false clean bill, which is the direction this
  tool should fail in, but it does mean unusual setups need the list extended.
- **Authentication bypass settings are not mistaken for enforcement.** A configured
  anonymous Consumer leaves failed authentication reachable, while Key Auth and JWT
  with `run_on_preflight: false` allow anonymous `OPTIONS` requests. Anonymous Consumer
  references are conservatively treated as valid because their identities are not yet resolved.
- **Global plugins and plugin precedence are modelled.** A relationship-free root
  `plugins:` entry applies globally. Kong selects the most specific enabled configuration
  for a plugin name in route+service → route → service → global order. Root plugins may
  target nested routes and services by string name. Consumer-scoped and non-string
  references remain unsupported rather than being mistaken for global.
- **Top-level routes participate in routing.** String `service` references resolve to
  their declared service, while service-less routes win selection normally and deny
  upstream access with Kong's 503 behavior. Non-string service references remain unsupported.
- **Unconditional `request-termination` denies upstream access.** A configured trigger
  is conservative because Kong checks both header and query-parameter presence, and query
  parameters are not yet in the IR.
- Anything outside the supported fragment should surface as `unknown` with a reason rather
  than as a quiet pass. Keeping that boundary explicit is a design rule, not a nicety.

## Testing

`bench/kong/cases/` holds 50 labeled cases, each a config plus a golden `expected.json`
produced by the engine and hand-checked against intent. They span the real
misconfiguration shapes: a missing plugin, service versus route-level auth inheritance, an
open sibling route, a method-specific gap (`GET` guarded, `POST` open), a leak in a second
service, a non-auth plugin mistaken for auth, an auth plugin left `enabled: false`, and the
rate-limit variants.

The rest pin boundaries from *both* sides, which is where the value is. A guarded route
outranking an open catch-all must come out `proved`, since that arrangement is correct and
reporting it would be a false alarm. A shadowed route must be found whether the shadowing
route strictly outranks it or merely ties with it. A regex route must be verified when its
pattern is in the subset and `unknown` when it is not. The guarded regex case must
come out `proved`, which is what stops the encoder passing by over-approximating every
pattern to "anything". One case turns on a single `$`: with it the languages are disjoint
and nothing is shadowed, without it the open route swallows a guarded path.

`test/regex_agree.ml` is a differential test rather than a golden one. For each pattern it
compares `Regex.matches_full` against Z3's answer for `str.in_re`, because the verifier
relies on both readings agreeing: the encoder to find counterexamples, the matcher to
confirm they are genuine. A one-character error in the translation is caught by several
cases at once.

`dune test` verifies every case in-process and diffs against its golden, failing on any
mismatch. It runs on every PR via GitHub Actions.

## Repo layout

```
core/          shared engine, the reusable asset
  ir.ml          decision model: match_/guard/priority, principal, action, resource
  property.ml    invariant templates (one query over requests)
  shadowing.ml   no-shadowed-routes: candidate rule pairs (one query per pair)
  regex.ml       regex AST: parser, SMT translation, concrete matcher
  smt_encode.ml  IR + property → SMT-LIB2
  solve.ml       Z3 orchestration + model extraction
  cidr.ml        IPv4 blocks: parsing, membership, bitvector encoding
  report.ml      Report.t + human/JSON serializers (the stable contract)
connectors/    thin frontends (parse→IR, lift counterexample→config vocabulary)
  kong/          decK YAML, first connector
    fragment.ml    decidability boundary: reject what the encoder cannot model
    path_normalization.ml  Kong request domain and literal-path validation
cli/           soundcheck verify, soundcheck profile, soundcheck mcp
mcp/           soundcheck mcp, JSON-RPC 2.0 over stdio
bench/         labeled corpus + regression gate
```

Connectors depend on core. **Core never depends on connectors.**

## Roadmap

The immediate focus is Kong-first depth: demonstrate the frozen MCP workflow end to end,
publish a versioned assurance profile, expand the paired contract catalogue, improve
semantic coverage, and differentially validate the model against real Kong behavior.

Real-gateway differential conformance is available as an opt-in Docker check. It
compares Soundcheck's concrete routing decision with pinned Kong OSS 3.9.3 under
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

Both stronger modes compose with `--contract` to preserve their observations
outside the frozen repair scope.

With `--contract`, `--emit-smt` writes the outside-scope preservation query; the
multi-query contract result remains embedded in the comparison report.

Full routing/upstream equivalence follows, along with CI/PR productization and
reproducible evidence.

Soundcheck remains a model-independent verifier. External agents and optional downstream
orchestrators may generate or repair configurations through its interfaces, but model
clients and training infrastructure are not part of the verification core. Additional
connectors follow after the Kong verifier is ready for public promotion.

## Design notes

Written in OCaml because this is compiler work, parse and lower and encode and lift, which
is OCaml's home turf. Z3 is the automated solver backend, reached through SMT-LIB2 text
rather than language bindings. That keeps the boundary inspectable and replaceable, and
makes single-property obligations artifacts you can read.

Interactive theorem proving is deliberately avoided. The design premise is that this
problem class does not need it.

## License

MIT. See [LICENSE](LICENSE).
