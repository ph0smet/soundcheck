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
dune test                       # runs the 16-case corpus regression gate
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
  --path-prefix  prefix for no-anonymous-access (default /admin)
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
  "property": "no-anonymous-access",
  "counterexample": {
    "principal": "anonymous",
    "action": "GET",
    "path": "/admin",
    "route": "admin-route",
    "service": "admin-api"
  }
}
```

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
| `no-shadowed-routes` | planned | Does a permissive route intercept traffic a stricter route was written to handle? |
| `admin-api-not-reachable` | planned | Is the admin surface reachable from an untrusted network zone? |

`rate-limit-on-public` is encoded with a reduced-reachability filter on allow rules: the
solver is asked whether a request is reachable *specifically via an unthrottled rule*.
This fits a structural question into the same per-request existential the engine already
emits, with no second query engine, and auth-required routes fall out as exempt for free
since an anonymous request cannot reach them in the first place.

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
  with `strip_path` and `path_handling`, are out of scope for v0.
- **Matching is currently a flat union** rather than the winner-takes-all priority order a
  real gateway applies. This is a sound over-approximation, so it will not miss a
  violation, but it can flag one the gateway would in practice route elsewhere. The
  ordered encoding that fixes this is also the prerequisite for `no-shadowed-routes`.
- **Regex paths are not modelled, and are rejected rather than approximated.** Paths are
  encoded as literal prefixes, so a config containing a regex route (a leading `~`, or
  pre-3.0 metacharacters) is refused as an unsupported fragment and reports `unknown`
  naming the route. Rejection is whole-config: the route we cannot model may be the one
  that decides the property. Translating the decidable subset to `str.in_re` is future
  work; backreferences and lookaround will stay rejected permanently.
- **Auth and rate-limiting plugins are recognised by name.** A custom or unlisted plugin
  is not counted, so a route it protects is treated as open and reported as violated. That
  errs toward a false alarm rather than a false clean bill, which is the direction this
  tool should fail in, but it does mean unusual setups need the list extended.
- Anything outside the supported fragment should surface as `unknown` with a reason rather
  than as a quiet pass. Keeping that boundary explicit is a design rule, not a nicety.

## Testing

`bench/kong/cases/` holds 16 labeled cases, each a config plus a golden `expected.json`
produced by the engine and hand-checked against intent. They span the real
misconfiguration shapes: a missing plugin, service versus route-level auth inheritance, an
open sibling route, a method-specific gap (`GET` guarded, `POST` open), a leak in a second
service, a non-auth plugin mistaken for auth, an auth plugin left `enabled: false`, and the
rate-limit variants. Three more pin the fragment boundary from both sides: regex paths
(explicit and pre-3.0 implicit) must report `unknown`, while ordinary punctuation like dots
and percent-escapes must still verify.

`dune test` verifies every case in-process and diffs against its golden, failing on any
mismatch. It runs on every PR via GitHub Actions.

## Repo layout

```
core/          shared engine, the reusable asset
  ir.ml          decision model: principal, action, resource, context, decision
  property.ml    invariant templates
  smt_encode.ml  IR + property → SMT-LIB2
  solve.ml       Z3 orchestration + model extraction
  report.ml      Report.t + human/JSON serializers (the stable contract)
connectors/    thin frontends (parse→IR, lift counterexample→config vocabulary)
  kong/          decK YAML, first connector
cli/           soundcheck verify
mcp/           soundcheck mcp, JSON-RPC 2.0 over stdio
bench/         labeled corpus + regression gate
```

Connectors depend on core. **Core never depends on connectors.**

## Roadmap

**Near term.** The winner-takes-all selection encoding, then the two remaining property
templates, `no-shadowed-routes` and `admin-api-not-reachable`. Widening the supported
path fragment to the decidable subset of regex, so those configs get a verdict instead
of `unknown`.

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
