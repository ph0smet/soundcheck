# Verify an RBAC policy change

`rbac change` checks whether a frozen caller has the modeled authority to submit
one RBAC policy change, then verifies its access requirements and preservation
scope. For example, a deployer may be allowed to remove an application's Secret
access while preserving its ConfigMap and Pod access. Having `update` permission
on the Role alone does not authorize adding permissions the deployer cannot grant.

This combines two checks with different meanings:

1. A deterministic check of Kubernetes v1.34.0's RBAC write prerequisites:
   initial `create`/`update`, followed by explicit `bind`/`escalate` or full policy
   coverage using the caller's **original** permissions. Schema 2 also supports
   ordinary named `delete`, which needs the initial grant without a bind,
   escalate or coverage requirement.
2. The existing solver-backed access-contract and repair-preservation checks,
   using the nested contract's fixed identities and request domain.

Passing both returns `valid_change`. This does not establish successful API
mutation, admission, storage validity under live state, workload behavior or
permission under a composed authorization chain.

For multiple ordered edits, use the separate
[`rbac sequence` contract and gate](rbac-policy-sequences.md). It checks authority
from each preceding state and preserves out-of-scope decisions after every edit;
the schema-1 single-operation contract keeps its original semantics.

## Run the synthetic example

From the repository root, after [setup](../README.md#quickstart):

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac check-contract \
  bench/kubernetes-rbac/workflows/policy-changes/contract.json
dune exec soundcheck -- rbac change \
  bench/kubernetes-rbac/workflows/policy-changes/before.json \
  bench/kubernetes-rbac/workflows/policy-changes/repaired.json \
  --contract bench/kubernetes-rbac/workflows/policy-changes/contract.json \
  --format json
```

The independently selected actor is `deployer`, updating Role
`team-a/app-reader`. The actor may update that Role and already holds the
ConfigMap and Pod read permissions retained in the repair. The application must
retain ConfigMap access and lose Secret access. Its existing Pod access lies
outside the approved change scope and must be preserved.

Use another candidate from the same directory to see the separate failure stages:

| Candidate | Result | Exit | Meaning |
| --- | --- | --- | --- |
| `repaired.json` | `valid_change` | 0 | Authority, access requirements and preservation pass |
| `authorization-failed.json` | `authorization_failed` | 3 | Proposed delete permission is not covered by the actor's original authority |
| `contract-failed.json` | `contract_failed` | 3 | The authorized edit removes required ConfigMap access |
| `out-of-scope-regression.json` | `out_of_scope_regression` | 3 | The access clauses hold, but unapproved Pod access is lost |
| `before.json` | `unknown` | 4 | No typed rule change; no-op updates are outside this profile |

These are synthetic complete snapshots under an explicit completeness
assumption, not deployment measurements. `check-contract` reviews structure and
declared intent; its successful exit is not a verification result.

For external-agent attempts, the [submitted-repair evaluator](../bench/repair/RBAC.md#policy-change-repair-evaluation)
freezes this whole operation contract and baseline before reading candidate
files. Its two-task synthetic suite includes an attempted self-escalation and
reports authorization, requirements and preservation outcomes separately.

## Freeze the operation separately from the candidate

The change contract has its own schema version and kind:

```json
{
  "schema_version": 1,
  "kind": "kubernetes-rbac-policy-change",
  "actor": "deployer",
  "operation": "update-existing",
  "target": {"kind": "Role", "namespace": "team-a", "name": "app-reader"},
  "requirements": {"...": "a complete existing kubernetes-rbac-access contract"}
}
```

The `requirements` value above is a placeholder; use the
[runnable contract](../bench/kubernetes-rbac/workflows/policy-changes/contract.json)
for its full shape. Access schemas **1–10** retain their original canonical
identities, profiles and preservation domains. The new outer schema is not
access schema 11. The actor must exactly match a nested trusted identity; groups
are taken only from that frozen identity. A policy owner must review those
groups and establish inventory completeness independently.

Both inputs are complete strict JSON Kubernetes Lists. Schema 1 supports
`create` and `update-existing` on Role, ClusterRole, RoleBinding or
ClusterRoleBinding. Schema 2 also accepts `delete-existing`. Cluster-scoped
targets require `namespace: null`. Creation
requires absence before and presence after; update requires presence in both.
The target's name is fixed and supports Kubernetes RBAC path-segment names such
as `system:controller:example`.

Only the target may change. List item order and JSON map-key order may differ;
all other objects must retain their full content, including metadata and array
order. An update must change typed rules or subjects. Rule/subject array order
and duplicates are retained when deciding whether a real change occurred.
Target labels and annotations may accompany that change. Binding `roleRef`
changes, metadata-only/no-op updates, aggregate ClusterRole targets and actors
in `system:masters` are unsupported. Existing non-target aggregates must remain
complete and already resolved in both snapshots.

Patch, apply, bulk deletion, create-on-update, impersonation, multi-object sequences,
controller reconciliation and concurrent/live state are outside this profile.
Unsupported input or an exceeded work limit yields `unknown`.

## Retire one policy object

A schema-2 contract keeps the same fields and adds `delete-existing`:

```json
{
  "schema_version": 2,
  "kind": "kubernetes-rbac-policy-change",
  "actor": "deployer",
  "operation": "delete-existing",
  "target": {"kind": "RoleBinding", "namespace": "team-a", "name": "old-app"},
  "requirements": {"...": "a complete existing kubernetes-rbac-access contract"}
}
```

The target must exist in the original inventory and be absent from the candidate.
Every unrelated object must remain unchanged. Deletion checks the caller's
`delete` permission on that exact resource, namespace and **name**, using only
the original inventory. It does not require the permissions contained in the
removed Role or referenced by the removed binding. Create/update retain their
existing bind/escalate or coverage checks.

Both inventories must still resolve every role reference. Remove bindings before
their referenced roles; aggregate targets remain unsupported. The operation
models ordinary default DELETE options and assumes completed removal, not merely
an accepted deletion request. Finalizers, owner references and deletion timestamps
are outside the strict metadata subset. Unsafe deletion options, admission,
garbage collection, concurrent edits and controller reconciliation are not modeled.

Run the [synthetic retirement example](../bench/kubernetes-rbac/workflows/policy-retirement/README.md):

```sh
dune exec soundcheck -- rbac change \
  bench/kubernetes-rbac/workflows/policy-retirement/delete-before.json \
  bench/kubernetes-rbac/workflows/policy-retirement/delete-after.json \
  --contract bench/kubernetes-rbac/workflows/policy-retirement/delete-contract.json \
  --format json
dune exec soundcheck -- profile kubernetes-rbac-policy-change-v2 --format json
```

Schema-2 reports and outer evidence use version 2 and profile
`kubernetes-rbac-v1.34-policy-change-v2`. Existing schema-1 reports, canonical
identities and profiles are unchanged. The nested access and comparison reports
retain their existing format. `profile kubernetes-rbac-policy-change` inspects
version 1; the explicit `-v2` selector inspects the new profile.

## Read the authorization evidence

The initial create request has an **empty authorization name**, even when the
new object has a name. Update uses the URL target name. Role `escalate` checks
use those same coordinates. Binding `bind` checks use the referenced role's
name and the **binding's namespace**, including a namespaced RoleBinding that
references a ClusterRole. All grants and referenced rules come from the original
snapshot; a candidate cannot authorize itself by inserting a new grant.

Without explicit `bind` or `escalate`, the actor's effective rules must cover
every proposed policy rule. This native policy relation includes arbitrary API
groups, resources, verbs, wildcard rules and URLs. It does not discard rules
outside the nested access contract's catalogue. Different atomic obligations
may be covered by different whole owner rules. A finite list of current
resources cannot cover a proposed wildcard.

For schema-1 contracts, the outer JSON report uses schema **1**, kind
`kubernetes-rbac-policy-change` and profile
`kubernetes-rbac-v1.34-policy-change-v1`. Its `authorization` contains the initial
and special request attributes, granting rule indices, and, when needed,
coverage atom counts and missing rules. Indices are zero-based. Effective owner
rules are ordered by original ClusterRoleBindings first, then RoleBindings in
the operation namespace, retaining binding and rule order. Missing atoms retain
their proposed rule index and atom index within that rule. They are policy
obligations, not concrete request counterexamples.

`special` is null if the initial grant is absent or the operation is deletion.
`coverage` is null for deletion, if the initial grant is absent, or if explicit
special authority suffices. `verification`
is null when authorization did not succeed; otherwise it retains the unchanged
schema-10 candidate and comparison reports. A solver failure returns `unknown`;
vacuous and inconsistent requirements remain visible in the nested report and
exit 5 and 6. Only `valid_change` exits zero.

Executed analysis is bounded by 100,000 input values, 8 MiB input string bytes,
100,000 proposed atoms, 8 MiB expanded atom string bytes and 10 million
conservative comparison units. Bounds are checked before expansion; diagnostics
are never truncated to produce an authorization decision. Explicit authority
skips the native coverage stage. Snapshot parsing retains its separate limits.

## Keep inputs fixed in MCP and CI

```sh
dune exec soundcheck -- mcp --connector kubernetes-rbac \
  --contract bench/kubernetes-rbac/workflows/policy-changes/contract.json \
  --baseline bench/kubernetes-rbac/workflows/policy-changes/before.json
```

This contract selects a distinct MCP mode exposing only `change`. Its sole tool
argument is `config`, the candidate snapshot string. Actor, target, operation,
nested requirements and baseline are captured at startup and cannot be
replaced through the tool. Access-contract MCP modes remain unchanged.

In a trusted pull-request job:

```yaml
- uses: actions/checkout@v4
- uses: ph0smet/soundcheck@<reviewed-full-commit-sha>
  with:
    connector: kubernetes-rbac
    mode: change
    config: rbac-snapshot.json
    contract: approved-policy-change.json
```

The Action extracts the **whole change contract** and the original snapshot
from the same immutable PR base commit. The baseline uses the same `config`
path; there is no candidate-controlled baseline/ref override. This mode rejects
push events. Trusted action/workflow sources, fixed input paths, separate
contract approval, required checks and fresh-base reruns remain external
prerequisites. See the [Action boundary](../README.md#github-action).

## Save evidence and check conformance

Append `--evidence-dir /tmp/soundcheck-policy-change-evidence` to `rbac change`,
using a new destination. The private outer bundle (schema 1 or 2, matching the
change contract) binds the exact
before/after bytes by SHA-256, canonical change contract, profile, report and
verifier provenance. When executed, `verification/` contains the unchanged
comparison evidence with every planned query, solver outcome and validated SAT
model. Unexecuted stages remain explicit; evidence collection never reruns the
verification. Invalid contracts cannot produce frozen evidence.

The manifest hashes every payload and is published last. Existing destinations
are never overwritten. Bundles support audit and formula replay; they are not
independently checked UNSAT certificates or a proof of the target model.

The [native conformance corpus](../bench/kubernetes-rbac/policy-changes/README.md)
checks the pinned production authorizer, policy-based storage guards and native
policy coverage independently. It uses fixture storage and does not contact a
cluster. See the [approved scope](plans/2026-11-rbac-policy-changes.md) for the
semantic boundary and acceptance requirements.

The [retirement and migration scope](plans/2026-11-rbac-retirement-migrations.md)
records schema-2 deletion semantics and its separate pinned native acceptance.
