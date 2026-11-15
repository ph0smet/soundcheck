# Ordered RBAC policy changes

`rbac sequence` checks an explicitly ordered plan of Role, ClusterRole,
RoleBinding or ClusterRoleBinding creations and updates against a complete
original inventory. It authorizes each operation using the state immediately
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

The separate schema-1 `kubernetes-rbac-policy-sequence` contract contains an
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

There must be 1–16 steps, each naming a distinct target. Each operation is
`create` or `update-existing`; cluster-scoped targets use `namespace: null`.
The original inventory and final candidate determine every intermediate state:
install only the next target's final object in the preceding inventory. Candidate
List order cannot change the frozen operation order. Canonical contract identity
preserves step order. The candidate cannot supply arbitrary intermediate versions.

Every state must meet the existing complete, strict snapshot boundary. Untargeted
objects remain equal after map-key normalization; arrays, metadata and accepted
fields are preserved. Each update changes typed rules or subjects. Unsupported
boundaries include duplicate targets, no-ops, metadata-only updates, changing
`roleRef`, aggregate targets, `system:masters` actors, missing role references,
stale aggregates, patch/apply/delete, create-on-update, impersonation and multiple
actors. The current per-operation coverage limits remain enforced; excessive
input/work yields unknown rather than a truncated check.

## What a passing sequence establishes

Each step requires the initial create/update grant plus explicit bind/escalate
or full native-policy coverage from its immediately preceding state. The
[current single-operation semantics](rbac-policy-changes.md#read-the-authorization-evidence)
apply at every step. Prior authorized edits may grant or remove later authority;
a write cannot authorize itself using its proposed grants. Coverage retains
unknown/custom rule strings independently of the nested access catalogue.

Every state after an edit must preserve the original inventory's modeled
Allow/NoOpinion decisions outside the one frozen change scope. Preservation
covers the nested contract's entire supported domain and every frozen identity,
including permissions absent from its access clauses. The final state must also
satisfy every access clause. Intermediate states may still violate final access
requirements inside the approved scope while a staged repair is in progress.
Owners must review whether that intermediate behavior is acceptable.

The model assumes each prior write succeeds and becomes visible before the next
operation, without intervening writes or controller reconciliation. It does not
establish successful mutation, live cache freshness, admission, runtime effects,
atomic deployment, rollback or composed-authorizer decisions. An unmet RBAC
prerequisite is not a guarantee of denial by every API-server configuration.

## Results and evidence

The outer report has schema 1 and profile
`kubernetes-rbac-v1.34-policy-sequence-v1`. The gate first checks the entire
structural plan and its derived inventories, then authorizes steps in frozen
order. If those pass, it runs the unchanged final access/preservation comparison,
then checks intermediate preservation in order. A failure reports its execution
`phase` and one-based `failing_step`; this phase order need not identify the
earliest defect in chronological transition order.

| Result | Meaning | Exit |
| --- | --- | --- |
| `valid_sequence` | All required sequence obligations passed | 0 |
| `authorization_failed` | A step lacks a modeled RBAC prerequisite | 3 |
| `contract_failed` | Final access requirements do not prove | 3, or 5/6 for vacuous/inconsistent |
| `out_of_scope_regression` | A validated final or intermediate decision difference exists outside scope | 3 |
| `unknown` | Unsupported plan, solver failure/timeout or invalid witness | 4 |

Reports bind exact input hashes, the whole frozen contract, every derived state,
per-step authorization, unchanged final comparison reports and intermediate
preservation outcomes. Skipped stages are explicit. Native authorization is a
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
