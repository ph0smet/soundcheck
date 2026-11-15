# Ordered policy-change conformance

This frozen synthetic corpus checks schema-1 `kubernetes-rbac-policy-sequence`
against Kubernetes v1.34.0. One actor and 1–16 distinct create/update-existing
targets define a conditional sequence. The original and final inputs determine
every intermediate object state; candidate List order cannot change operation
order. Existing single-write and access-contract semantics remain unchanged.

The reference constructs its own states from the frozen inputs. It validates
the entire structural plan before any authorization, resolves every binding
using native `GetRoleReferenceRules`, and checks aggregate fixed points using
the pinned production aggregation controller. Then each accepted write advances
the fixture inventory. The next write constructs a fresh native RBAC resolver
from that preceding state and calls the actual request filters, initial RBAC
authorizer, policybased storage wrapper, `RulesFor`/`Covers` and native strategy
validation. Production intermediate states never supply the native reference.

This is fixture persistence under an explicit successful-visible-write
assumption. It does not establish admission, concurrent state, informer freshness,
real persistence, rollback, atomicity or successful deployed mutations.

`inputs.json` freezes 232 artifacts before production comparison:

- 41 sequences and 69 executed native write guards, including all four kinds
  and both operations with implicit policy coverage, explicit bind/escalate,
  and absent initial permission as one-step compatibility controls.
- Grant-then-use and revoke-then-fail, reversed order, changed role-reference
  coverage, a self-escalation attempt, candidate item-order independence and
  the 16-step boundary.
- Staged scoped repair that still violates final requirements at an early
  prefix, final access failure, final preservation failure, and temporary
  out-of-scope permission gain/loss that disappears by the final state.
- 22 structural controls: missing/forward references, stale intermediate
  aggregation, duplicate/too many targets, unsupported operations, no-ops,
  changed roleRef, unrelated mutations, and frozen contract tampering. A late
  unsupported step is rejected before an earlier ungranted authorization.

The production consumer checks each native authorization stage and rule origin,
the frozen whole contract, exact endpoint inputs, independently reconstructed
state contents, evidence hashes, and every executed/skipped obligation. Final
requirements are checked only at the endpoint. Every post-state must preserve
the original modeled decisions outside the same frozen change scope.

Four validated witnesses are replayed against native RBAC on the independently
constructed baseline and offending state (eight native decisions). Three prove
preservation changes, including a lost permission with no candidate granting
rule; one establishes the retained prohibited final access. Nine adversarial
consumer tests reject corrupted identities, order, states, stage outcomes,
coverage evidence, witness dimensions/origins, and incomplete receipts.

Run `bash bench/kubernetes-rbac/conformance/run.sh` for all historical and new
suites. The standalone `run_policy_sequences.py` accepts `--reference`,
`--module-metadata`, `--soundcheck`, `--z3` and `--output`. `--native-only`
checks frozen native expectations without the CLI or solver. Corpus regeneration
is an explicit `generate.py --module-cache ...` preparation step and never part
of acceptance. `source-pins.json` and runtime function/module linkage retain the
same native write guards plus the aggregation controller and selector sources.

The suite records and rechecks input, source, executable and upstream-source
hashes. Evidence is finite synthetic conformance, not a deployment benchmark,
live-agent evaluation or universal proof of target-model correctness.
