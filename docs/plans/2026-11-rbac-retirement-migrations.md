# RBAC retirement and migration

Sourav approved this next implementation batch on 2026-11-15 after PR #80:
policy deletion, mixed ordered migrations, and selected access requirements
throughout the transition, including adapters, evidence and native evaluation.
Deliver one feature branch; present the tested diff before committing.

## Versioned contracts and transitions

Keep access contracts 1–10, policy-change/sequence schema 1, their canonical
identities and results unchanged. Add schema 2 to both outer contract kinds.
Schema-2 changes accept `create`, `update-existing` and `delete-existing`.
Deletion requires an existing target before the operation and its absence after
it. Unrelated objects retain their complete normalized content. All four policy
kinds are supported; aggregate targets remain unsupported.

Schema-2 sequences retain one trusted actor and 1–16 distinct targets. They mix
the three operations, deriving every state from the original and final inventory
in the frozen order. A delete removes its target; other operations install that
target's final object. No candidate-controlled intermediate versions or order
are accepted. Every inventory remains complete and passes the existing strict
parser, reference resolution and aggregate consistency checks. Remove bindings
before their referenced roles; replacement policies use new names. Same-name
delete/recreate, repeated targets, roleRef mutation, patch/apply, bulk deletion,
multiple actors, impersonation, automatic ordering and rollback are not included.

## Deletion authorization and model boundary

Authorize each operation exclusively from its immediately preceding state.
Kubernetes v1.34.0's four `pkg/registry/rbac/*/policybased/storage.go` wrappers
embed `rest.StandardStorage` and override create/update, not delete. Ordinary
named deletion therefore requires the initial `delete` grant on the exact kind,
namespace and name; it does not require bind, escalate or policy coverage.
The existing create/update prerequisites remain unchanged.

Model ordinary default DELETE options only. The native basis also includes
apiserver v0.34.0's `pkg/endpoints/handlers/delete.go`,
`pkg/registry/generic/registry/store.go` and `pkg/registry/rest/delete.go`.
Unsafe deletion options have a separate authorization path and are excluded.
Existing strict metadata excludes finalizers, owner references and deletion
timestamps. A modeled removal is conditional on successful complete deletion
being visible before the next step, without concurrent writes or controller
reconciliation. This does not establish storage success, admission, garbage
collection, API-server final authorization or an atomic live deployment.

## Requirements throughout the transition

Schema-2 sequences require an `invariants` array of unique names of existing
clauses in their nested `requirements`. An empty array selects none. Unknown
names fail closed; canonical identity sorts this set. Verification follows the
nested clause order. Referencing existing clauses keeps the frozen identities,
groups, request domain, catalogue and clause meaning identical by construction.
It also avoids independently supplied contexts or contradictory duplicate intent.

Every selected clause must hold at S0 and each resulting state S1…Sn. A baseline
that already violates a selected invariant fails: owners must leave repair goals
that need an initial violation in the final-only requirements. Unselected clauses
are still required at Sn. Out-of-scope decisions at every post-step state must
still equal S0 for the entire frozen request domain and all trusted identities.
Selecting invariants never expands the approved change scope. Clause inhabitance,
consistency, witness validation and unknown handling use the existing shared core.

Run stages in this explicit order: validate the whole plan and all states;
authorize all operations in order; verify final access and preservation; verify
selected invariants at S0…Sn in order; verify remaining intermediate preservation.
Failures identify their execution phase, not necessarily the earliest defect in
chronological transition order. `state_invariants` failures use state/step 0 for
S0, otherwise the one-based completed step. A checked violated/vacuous/inconsistent
invariant yields `invariant_failed`; solver or unsupported failure yields unknown.
Only `valid_sequence` exits zero. Existing schema-1 stage ordering is unchanged.

## Reports, evidence and adapters

Use outer report/evidence schema 2 and assurance profiles ending in `-v2` for new
contracts. Preserve schema-1 outputs and profiles. Invariant reports bind the
whole outer sequence canonical identity and distinguish selected-clause checking
from complete final access verification. Retain planned queries, executed checked
results, skipped obligations, all state hashes and private full state snapshots.
Evidence is replay material, not an independently checked UNSAT certificate.

Keep CLI/MCP/CI thin. MCP retains startup contract/baseline and accepts candidate
config only. PR-only CI reads actor, order, invariant selection, requirements,
scope and baseline from the immutable approved base. Add explicit v2 profile
inspection and useful contract review. Submitted-repair summary format 5 applies
when a schema-2 change/sequence task occurs; existing formats 1–4 stay unchanged.
Count every attempt, including failures after a success, from a single gate run.

## Independent acceptance

Freeze native inputs and expectations before production comparison. Exercise all
four deletion kinds, named grants, namespace boundaries, no unnecessary special
permission, missing/remaining targets, unrelated deletion, forbidden metadata,
strict references, aggregate effects, bounds and unsupported operations. Native
fixture storage must actually remove accepted targets and independently rebuild
the resolver after each accepted operation.

Include replacement-before-removal, availability-breaking order, initial broken
invariants, temporary in-scope grants/losses, retained final-only repairs, final
requirement failures, and actor-authority removal affecting later operations.
Replay validated invariant and preservation witnesses against pinned native RBAC.
Exercise solver failures/invalid witnesses, exact frozen identities, complete
evidence, adapter tampering, evaluator mismatch rejection and legacy compatibility.
Run full regressions and every pinned Kubernetes suite on the integrated source.
Each later commit must independently pass clean-worktree checks. Public benchmark
v2, live-agent campaigns and deployment pilots remain separate evaluations.
