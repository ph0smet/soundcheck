# Soundcheck

**Proof-or-counterexample for declarative security policy.**

Soundcheck takes a policy artifact, such as an API-gateway config, and proves security
invariants over it. It returns either a machine-checkable proof that no violating request
exists, or a concrete counterexample expressed in the config's own vocabulary.

```
$ soundcheck verify kong.yaml
VIOLATED no-anonymous-access
         anonymous request GET /admin is ALLOWED via route "admin-route"
         (service "admin-api") — no authentication plugin is attached to the
         route or its service.
$ echo $?
3
```

The reasoning is exact rather than heuristic. The question is discharged by an SMT solver
over the full input space, so a `PROVED` result means there is no such request, not "we
didn't find one." Recognising which plugins provide authentication is a known-name lookup,
and that lookup is the one place judgement enters. Everything after it is solving.

## Why this exists

AI systems increasingly write the configuration that decides who may reach what: gateway
routes, RBAC bindings, IAM policies. These artifacts are security-critical, easy to get
subtly wrong, and reviewed by eye if they are reviewed at all.

Testing a policy samples a handful of requests from an unbounded space. That is fine for
catching typos and useless for establishing absence. The interesting property of a policy
is universally quantified: *for all requests, X is denied.* You cannot sample your way to
that.

Soundcheck's bet is that this particular problem is decidable and therefore worth closing
completely rather than approximating. Declarative policy reduces to a finite decision
function, `(principal, action, resource, context) → Allow | Deny`. Reasoning over it is an
SMT query that terminates with a definite answer. There is no proof search that might fail
to converge, and no place for a model's confidence to stand in for a guarantee.

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
4. **Solve.** Hand it to Z3. `UNSAT` means no violating request exists, which is a proof.
   `SAT` means the satisfying assignment is itself a concrete counterexample.
5. **Lift.** Translate the SMT model back into the connector's vocabulary, so the output
   names a route and a service rather than a bitvector.

`--emit-smt PATH` keeps the generated query as an audit artifact. It is plain SMT-LIB2, so
the proof obligation can be re-checked independently, by a different solver if you like,
and nothing about the result requires trusting Soundcheck.

Multiple frontends, one IR, one solver backend, counterexamples lifted back per target.
The core is the reusable asset and connectors stay thin.

## Quickstart

Requires OCaml 5.x, dune, the `yaml` opam library, and the **`z3` CLI binary** on `PATH`
(the solver shells out to `z3 -smt2`).

```bash
brew install z3                 # or: apt install z3
opam install dune yaml
dune build
dune test                       # runs the 34-case corpus regression gate
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

# keep the proof obligation for audit, then re-check it yourself
dune exec soundcheck -- verify kong.yaml --emit-smt query.smt2
z3 -smt2 query.smt2
```

```
usage: soundcheck verify <config.yaml> [--property P] [--path-prefix PREFIX]
                                       [--format human|json] [--emit-smt PATH]
  --property     no-anonymous-access (default) | rate-limit-on-public
                 | no-shadowed-routes | admin-api-not-reachable
  --path-prefix  prefix for no-anonymous-access (default /admin)
  --trusted-cidr for admin-api-not-reachable (default 127.0.0.1/32)
  --format       human (default) | json
  --emit-smt     write the SMT-LIB2 query to PATH and keep it (audit artifact)
```

Exit codes are designed to gate a pipeline: `0` proved, `1` parse error, `2` usage,
`3` violated, `4` unknown.

## The JSON contract

`--format json` emits a stable schema. It is the universal integration point, consumed
identically by CI, the MCP tool, and eventually the repair loop.

```json
{
  "result": "violated",
  "schema_version": 2,
  "property": "no-anonymous-access",
  "counterexample": {
    "principal": "anonymous",
    "action": "GET",
    "path": "/admin",
    "source_ip": "0.0.0.0",
    "route": "admin-route",
    "service": "admin-api",
    "shadowed_route": null,
    "shadowed_service": null
  }
}
```

Every key is emitted unconditionally, `null` when absent, so a consumer never has to
probe for existence. `shadowed_route` is populated only by `no-shadowed-routes`, which
names two routes: the one that serves the request and the one written to handle it.
`source_ip` is meaningful only for properties that constrain it; elsewhere the solver
picked it freely.

On success, `"result": "proved"` with `"counterexample": null`. A config outside the
supported fragment gets `"result": "unknown"` with a `"reason"` naming the routes
responsible, never a quiet pass. That is a verdict rather than an error: the MCP tool
returns it as a normal result too, so an agent can rewrite the offending route and
re-verify.

## Using it against AI-generated config

Two enforcement layers, meant to be used together.

**Soft, in-loop: MCP.** `soundcheck mcp` serves the verifier as a Model Context Protocol
tool over stdio, so an agent can call `verify` while drafting a config and self-correct
before handing anything over. The counterexample is the useful part. It tells the model
exactly which request defeats its output, which is a far stronger repair signal than
"this looks wrong."

**Hard, at the gate: CI.** The same binary runs in CI or a pre-apply hook and blocks on
non-zero exit, regardless of what any agent did or claimed. This is where the actual
guarantee lives. A prompt is not an enforcement mechanism; an exit code is.

Both surfaces are thin adapters over one core, so they cannot drift apart in what they
consider verified. Soundcheck is also consumable directly as an OCaml library.

## Properties

Properties are **core templates, not gateway-specific checks**. Each is written once
against the shared decision IR, so it applies to every connector that lowers into it.

| Property | Status | Question it answers |
|---|---|---|
| `no-anonymous-access` | shipped | Can any unauthenticated request reach a protected path prefix? |
| `rate-limit-on-public` | shipped | Is every anonymously-reachable route covered by a rate-limiting plugin? |
| `no-shadowed-routes` | shipped | Does a permissive route intercept traffic a stricter route was written to handle? |
| `admin-api-not-reachable` | shipped | Can an *anonymous* request from outside a trusted address block reach a route proxying the Admin API? |

`rate-limit-on-public` is encoded with a reduced-reachability filter on allow rules: the
solver is asked whether a request is reachable *specifically via an unthrottled rule*.
This fits a structural question into the same per-request existential the engine already
emits, with no second query engine, and auth-required routes fall out as exempt for free
since an anonymous request cannot reach them in the first place.

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

- **Routing is modelled over path and method only.** Host, header and SNI matching, along
  with `strip_path` and `path_handling`, are out of scope for v0. A route carrying one of
  those is therefore given a rank incomparable with every other route, so it neither
  suppresses nor is suppressed. That is not caution: ignoring a routing constraint makes
  `match_` an over-approximation, which is harmless where it appears positively but not
  where it appears *negated* in the suppression term, and an over-approximated suppressor
  hides whatever sits below it. Surveying Kong's own repositories found hosts on ~64% of
  routes, so this is a common shape rather than a corner case.
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
- **Request-path normalization is not modelled, which costs precision rather than
  soundness.** Kong normalizes the request URI (percent-decoding, dot-segment removal,
  slash merging) before matching, but does *not* normalize declared route paths.
  Soundcheck's symbolic path ranges over all strings, so it considers paths Kong would
  never hand the router. Because the encoding is pointwise and our matching agrees with
  Kong's at every normalized path, a proof still covers every real request; what can
  happen is the reverse: a witness that is not a normalized path, or a finding through a
  route like `/admin/%2e%2e/secret` that Kong could never match. False alarms, not missed
  violations.
- **The Admin API is recognised by upstream port** (8001 and 8444, Kong's defaults). A
  gateway on a non-default admin port is not recognised, and `admin-api-not-reachable`
  then stays quiet about it. That is the *false-negative* direction for this one property,
  which is why the port list is documented rather than buried.
- **Source addresses are IPv4 and are the connection peer.** `ip-restriction` reads the
  raw connection address and ignores `X-Forwarded-For`, so behind a load balancer every
  request appears to come from the balancer; the model inherits that. IPv6 entries are
  rejected by the CIDR parser rather than ignored, and an unparseable entry is dropped
  from the guard, which weakens it and so over-reports.
- **Auth and rate-limiting plugins are recognised by name.** A custom or unlisted plugin
  is not counted, so a route it protects is treated as open and reported as violated. That
  errs toward a false alarm rather than a false clean bill, which is the direction this
  tool should fail in, but it does mean unusual setups need the list extended.
- Anything outside the supported fragment should surface as `unknown` with a reason rather
  than as a quiet pass. Keeping that boundary explicit is a design rule, not a nicety.

## Testing

`bench/kong/cases/` holds 34 labeled cases, each a config plus a golden `expected.json`
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
cli/           soundcheck verify
mcp/           soundcheck mcp, JSON-RPC 2.0 over stdio
bench/         labeled corpus + regression gate
```

Connectors depend on core. **Core never depends on connectors.**

## Roadmap

**Near term.** `admin-api-not-reachable`, the last of the four planned templates, which
needs a new symbolic dimension (source zone) and the IR's so-far-unused `context` field.
Route ranking for regex paths, so those configs stop falling back to a flat union, most
likely by asking the solver about language inclusion rather than inventing a number.
Richer prefix ranking too, so fewer pairs fall back to a tie.

**After that.** A reusable GitHub Action with PR annotations, then connector #2 for
app-level authz and tenant isolation, which is expected to refine the IR from v0 to v1.
Kubernetes RBAC follows.

**Phase 2.** A generate-verify-repair loop driven by the same JSON counterexample, under a
spec-freeze rule: the loop may change the config, never the property. No weakening the
spec to make failing output pass.

## Design notes

Written in OCaml because this is compiler work, parse and lower and encode and lift, which
is OCaml's home turf. Z3 is the proof kernel, reached through SMT-LIB2 text rather than
language bindings. That keeps the backend swappable, since CVC5 speaks the same dialect,
and it makes every proof obligation an artifact you can read.

Interactive theorem proving is deliberately avoided. The design premise is that this
problem class does not need it.

## License

MIT. See [LICENSE](LICENSE).
