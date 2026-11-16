# Ordered RBAC policy changes

`rbac sequence` checks an explicitly ordered plan of Role, ClusterRole,
RoleBinding or ClusterRoleBinding operations against a complete original
inventory. Schema 1 supports creation/update; schema 2 also supports deletion
and selected access requirements throughout the transition. It authorizes each operation using the state immediately
before that operation, verifies the final access requirements, and preserves
modeled decisions outside the approved scope after every step. Only
`valid_sequence` passes the gate.

The [runnable synthetic workflow](../bench/kubernetes-rbac/workflows/policy-sequences/README.md)
removes two independent Secret grants while retaining ConfigMap and Pod access.
It includes a final-valid candidate that temporarily breaks Pod access; the
sequence gate catches that intermediate regression.

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac check-contract \
  bench/kubernetes-rbac/workflows/policy-sequences/contract.json
dune exec soundcheck -- rbac sequence \
  bench/kubernetes-rbac/workflows/policy-sequences/before.json \
  bench/kubernetes-rbac/workflows/policy-sequences/repaired.json \
  --contract bench/kubernetes-rbac/workflows/policy-sequences/contract.json \
  --format json
```

`check-contract` reviews declared structure and intent. Its successful exit is
not a verification gate. The sequence command accepts `human`, `json` and
`github` output, and `--evidence-dir NEW_DIRECTORY` for private audit artifacts.
Inspect its boundary with `soundcheck profile kubernetes-rbac-policy-sequence`.

## Freeze one ordered plan

The schema-1 `kubernetes-rbac-policy-sequence` contract contains an
`actor`, an ordered `steps` array, and unchanged nested access `requirements`:

```json
{
  "schema_version": 1,
  "kind": "kubernetes-rbac-policy-sequence",
  "actor": "deployer",
  "steps": [
    {
      "operation": "update-existing",
      "target": {"kind": "Role", "namespace": "team-a", "name": "app-reader"}
    },
    {
      "operation": "update-existing",
      "target": {"kind": "Role", "namespace": "team-a", "name": "app-reader-secondary"}
    }
  ],
  "requirements": "Replace with an independently reviewed access-contract object"
}
```

The last value above is a placeholder; the runnable example contains a complete
access contract. Existing access versions 1–10 retain their original request
domains and canonical identities. The actor is an exact username in that
contract's trusted identities, with fixed groups throughout the plan.

There must be 1–16 steps, each naming a distinct target. Schema 1 accepts
`create` or `update-existing`; schema 2 also accepts `delete-existing`.
Cluster-scoped targets use `namespace: null`.
The original inventory and final candidate determine every intermediate state:
install the next create/update target's final object in the preceding inventory,
or remove the target for deletion. Candidate
List order cannot change the frozen operation order. Canonical contract identity
preserves step order. The candidate cannot supply arbitrary intermediate versions.

Every state must meet the existing complete, strict snapshot boundary. Untargeted
objects remain equal after map-key normalization; arrays, metadata and accepted
fields are preserved. Each update changes typed rules or subjects. Unsupported
boundaries include duplicate targets, no-ops, metadata-only updates, changing
`roleRef`, aggregate targets, `system:masters` actors, missing role references,
stale aggregates, patch/apply/bulk deletion, create-on-update, impersonation and multiple
actors. The current per-operation coverage limits remain enforced; excessive
input/work yields unknown rather than a truncated check.

## Retire policies while retaining required access

Schema 2 adds a required `invariants` array of unique names of existing clauses
in the nested access requirements. An empty array selects none. For example:

```json
{
  "schema_version": 2,
  "kind": "kubernetes-rbac-policy-sequence",
  "actor": "deployer",
  "steps": [
    {"operation": "create", "target": {"kind": "Role", "namespace": "team-a", "name": "replacement-reader"}},
    {"operation": "create", "target": {"kind": "RoleBinding", "namespace": "team-a", "name": "replacement-app"}},
    {"operation": "delete-existing", "target": {"kind": "RoleBinding", "namespace": "team-a", "name": "old-app"}},
    {"operation": "delete-existing", "target": {"kind": "Role", "namespace": "team-a", "name": "old-reader"}}
  ],
  "invariants": ["configmaps-required"],
  "requirements": "Replace with the complete reviewed access contract containing configmaps-required"
}
```

The [runnable retirement workflow](../bench/kubernetes-rbac/workflows/policy-retirement/README.md)
contains that complete contract. It retains ConfigMap access while replacing a
Role and binding and removing Secret access. Replacing objects under new names
keeps all targets distinct. Every derived inventory must resolve all references,
so bindings must be removed before their referenced roles. Same-name
remove/recreate is unsupported.

An invariant is the exact named clause, with the same trusted identities,
groups, request domain and meaning as its final requirement. It must hold in
**S0 and every resulting state S1…Sn**. A selected clause that is already false
in the original inventory fails at state 0; a requirement being repaired from
an initial violation should remain final-only. Unknown or duplicate clause
names fail closed. Selection does not widen the approved change scope. The
canonical identity sorts the invariant-name set, while checks follow the nested
clause order. Schema 1 continues to reject this field.

The gate validates the whole plan and all states, authorizes the operations,
checks final access/preservation, checks selected invariants in state order, then
checks remaining intermediate preservation. It reports the failed execution
phase, which need not be the earliest defect in chronological migration order.
An `invariant_failed` result uses phase `state_invariants`; `failing_step: 0`
identifies the original state and a positive number identifies the state after
that completed step. Violated, vacuous and inconsistent invariant checks exit
3, 5 and 6; unsupported or inconclusive checks return `unknown` and exit 4.

Schema-2 reports and outer evidence use version 2 and profile
`kubernetes-rbac-v1.34-policy-sequence-v2`. Invariant reports bind the whole
sequence contract and describe selected-clause checks, not complete final access.
They retain checked witnesses and skipped obligations. Every state is saved in
the private evidence bundle alongside its digest, planned queries and results.
Existing schema-1 reports and identities remain unchanged.

```sh
dune exec soundcheck -- profile kubernetes-rbac-policy-sequence-v2 --format json
```

The unversioned sequence profile command continues to describe schema 1. Both
versions use the same `rbac sequence`, frozen MCP tool and trusted-base Action
mode. Actor, order, invariant selection, nested requirements, scope and baseline
remain outside candidate control.

Deletion uses ordinary default DELETE options and is conditional on **complete
visible removal** before the next step. A successful request with pending
deletion is not that state. Strict metadata excludes finalizers, owner references
and deletion timestamps. The model does not establish admission, garbage
collection, controller reconciliation, concurrency safety or atomic deployment.
See the [approved schema-2 scope](plans/2026-11-rbac-retirement-migrations.md).

## What a passing sequence establishes

Each create/update step requires the initial grant plus explicit bind/escalate
or full native-policy coverage from its immediately preceding state. A schema-2
delete step requires only its initial named `delete` grant; its target must
exist before and be absent afterward. The
[current single-operation semantics](rbac-policy-changes.md#read-the-authorization-evidence)
apply at every step. Prior authorized edits may grant or remove later authority;
a write cannot authorize itself using its proposed grants. Coverage retains
unknown/custom rule strings independently of the nested access catalogue.

Every state after an edit must preserve the original inventory's modeled
Allow/NoOpinion decisions outside the one frozen change scope. Preservation
covers the nested contract's entire supported domain and every frozen identity,
including permissions absent from its access clauses. The final state must also
satisfy every access clause. In schema 1, intermediate states may still violate
final access requirements inside the approved scope while a staged repair is in
progress. Schema 2 applies the same rule to clauses not selected as invariants;
selected clauses must also hold at the original and every intermediate state.

The model assumes each prior write succeeds and becomes visible before the next
operation, without intervening writes or controller reconciliation. It does not
establish successful mutation, live cache freshness, admission, runtime effects,
atomic deployment, rollback or composed-authorizer decisions. An unmet RBAC
prerequisite is not a guarantee of denial by every API-server configuration.

## Results and evidence

A schema-1 contract produces outer report schema 1 and profile
`kubernetes-rbac-v1.34-policy-sequence-v1`; a schema-2 contract produces report
schema 2 and the `-v2` profile. The gate first checks the entire
structural plan and its derived inventories, then authorizes steps in frozen
order. If those pass, it runs the unchanged final access/preservation comparison,
then schema-2 selected invariants, then intermediate preservation in order. A
failure reports its execution `phase` and one-based `failing_step` (state 0 for
an original-state invariant failure); this phase order need not identify the
earliest defect in chronological transition order.

| Result | Meaning | Exit |
| --- | --- | --- |
| `valid_sequence` | All required sequence obligations passed | 0 |
| `authorization_failed` | A step lacks a modeled RBAC prerequisite | 3 |
| `contract_failed` | Final access requirements do not prove | 3, or 5/6 for vacuous/inconsistent |
| `invariant_failed` (schema 2) | A selected clause fails in the original or a resulting state | 3, 5 or 6 |
| `out_of_scope_regression` | A validated final or intermediate decision difference exists outside scope | 3 |
| `unknown` | Unsupported plan, solver failure/timeout or invalid witness | 4 |

Reports bind exact input hashes, the whole frozen contract, every derived state,
per-step authorization, unchanged final comparison reports, schema-2 invariant
checks and intermediate preservation outcomes. Skipped stages are explicit. Native authorization is a
deterministic policy check; access/preservation obligations use the shared SMT
backend and validated model witnesses.

`--evidence-dir` creates a new private local directory. Sequence evidence stores
the **full original, intermediate and final snapshots** in `states/`; earlier
access/change bundles only hashed their input snapshots. It also includes state
hashes, authorization records, prefix formulas/results, the unchanged final
comparison bundle and provenance from the selected solver. Review these snapshot
contents before sharing evidence. The manifest is written last and every payload
is hashed. Existing output directories are never overwritten. These are
formula replay materials, not independently checked UNSAT certificates or proof
of the target model.

## Keep inputs fixed in MCP and CI

```sh
dune exec soundcheck -- mcp --connector kubernetes-rbac \
  --contract bench/kubernetes-rbac/workflows/policy-sequences/contract.json \
  --baseline bench/kubernetes-rbac/workflows/policy-sequences/before.json
```

The server captures the contract and baseline at startup, then exposes only
`sequence` with `{ "config": "...complete candidate List..." }`. Actor, groups,
step order, targets, requirements, scope and baseline cannot be supplied in tool
arguments. Changing or deleting the source files after startup does not change
the session's frozen inputs.

The GitHub Action adds PR-only `mode: sequence` with
`connector: kubernetes-rbac`. Use the reviewed full Action commit SHA and fixed
paths selected by the trusted workflow. The helper reads the whole sequence
contract from the immutable PR base commit, and the baseline from the same
config path in that commit. Candidate contract edits cannot change the actor,
order or scope. Push events and missing original inventories fail closed.
Trusted workflow/action sources, separate contract approval, required checks,
fresh-base reruns and deployment controls remain external prerequisites.

The [submitted-repair evaluator](../bench/repair/RBAC.md) also accepts frozen
sequence tasks. Its synthetic attempts validate accounting and the gate; they do
not measure live-agent success or a real deployment pilot. The
[approved scope](plans/2026-11-rbac-ordered-changes.md) records the semantic choices
and independent native conformance requirements.
