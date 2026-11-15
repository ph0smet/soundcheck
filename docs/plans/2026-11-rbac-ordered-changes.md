# Ordered RBAC policy changes

Sourav selected ordered multi-object RBAC changes on 2026-11-15, after merged
PR #79, and approved this bounded scope, intermediate-state obligations and new
frozen format before implementation.
Deliver one feature branch with coherent commits. Existing access schemas 1–10
and single-change schema 1 keep their identities, results and meaning.

## Frozen sequence and deterministic states

Introduce a separate schema-1 `kubernetes-rbac-policy-sequence` contract with
one `actor`, an ordered `steps` array, and unchanged nested access `requirements`.
Each step contains `operation` (`create` or `update-existing`) and an exact
`target` (Role, ClusterRole, RoleBinding or ClusterRoleBinding; namespace and
name). The actor must be one of the nested contract's trusted identities;
username and groups stay fixed throughout the sequence.

Accept 1–16 steps with distinct target keys. This first slice cannot revisit a
target. The final candidate and original inventory determine every intermediate
state: start with the original inventory, then insert or replace only the next
frozen target with its object from the final candidate. The candidate cannot
supply a different order, extra intermediate objects or arbitrary intermediate
object versions. Canonical identity preserves the exact step-array order.
Untargeted objects must retain their complete normalized JSON content, preserving
array order and metadata as the single-change gate does. Input List item order
does not determine operation order.

Every state must satisfy the existing complete, strict snapshot boundary. Create
requires target absence before its step; update-existing requires presence and a
typed rule/subject change. Keep the existing restrictions on no-op/metadata-only
updates, roleRef changes, aggregate targets and `system:masters` actors. A binding
cannot precede the creation of its referenced role. No patch/apply/delete,
create-on-update, impersonation, multiple actors or automatically reordered plan
is included. All current native policy-coverage limits remain enforced per step;
sequence overflow fails closed without truncation.

## Authorization and state obligations

For states S0 (original), S1, …, Sn (final), authorize operation i exclusively
against S(i−1). Use the existing initial request plus explicit bind/escalate or
full-policy coverage checks, including reference resolution in S(i−1). A write
cannot authorize itself with its own proposed grants. A prior authorized write
may legitimately grant or remove the authority needed for a later write.

The approved state obligations are:

- Every Si, i > 0, must preserve S0's modeled Allow/NoOpinion decisions outside
  the one frozen approved change scope, for every frozen identity and supported
  request in the nested access contract's domain.
- The final Sn must satisfy every frozen access clause. Intermediate states may
  still violate final requirements inside the approved scope while a staged
  repair is in progress. This is explicit in the review, profile and report;
  it does not claim all intermediate states satisfy final access requirements.

Thus a final repair that restores an unrelated workflow after temporarily
breaking it fails preservation. A repair that needs several scoped edits before
all final clauses hold can pass. Requiring final clauses after the first edit
would exclude that staged repair; checking preservation only at the endpoint
would miss temporary out-of-scope changes.

This is a conditional sequence model: each prior write is assumed to succeed
and become visible before the next check, with no intervening writes or
controller reconciliation. It does not establish atomic deployment, informer
freshness, successful mutations, rollback, admission, runtime effects or the
decision of a composed authorization chain. Existing aggregate consistency is
checked independently at each state; no aggregate target or reconciliation
simulation is introduced.

## Gate, evidence and adapters

Validate the whole structural plan and all derived inventories first, then
authorize steps in frozen order, stopping at the first unmet prerequisite or
unknown. After all authorization checks pass, run the existing final access and
preservation comparison unchanged. If it proves, check the remaining intermediate
preservation obligations against S0 in sequence order. Only all required stages
passing produces `valid_sequence` and exits zero. Other outer outcomes distinguish
authorization failure, final contract failure, preservation regression and
unknown; identify the responsible execution phase, step and unexecuted later
obligations. This stage order need not report the earliest defect in chronological
transition order: an authorization or final-contract failure precedes checking
an intermediate preservation failure.

Add a preservation-only helper in the RBAC connector using shared encoding,
solver and witness validation. Do not manufacture a successful intermediate
access report to satisfy the existing comparison-evidence protocol. Keep final
comparison reports/traces unchanged; sequence-owned evidence binds prefix
preservation queries, validated results, state digests, the whole ordered
contract, exact input bytes and tool provenance. Evidence records are replay
material, not independently checked UNSAT certificates.

Expose `rbac sequence BEFORE AFTER --contract SEQUENCE.json`, human/JSON/GitHub
output, contract review, and private evidence. Frozen MCP exposes a config-only
`sequence` tool with immutable startup contract and baseline. Add PR-only CI
`mode: sequence`, reading the entire contract and baseline from the same approved
base commit. Reuse existing access/single-change adapters without changing their
dispatch or outputs. Extend the submitted-repair evaluator with an explicitly
versioned sequence/mixed summary; retain existing formats 1–3 for their existing
task sets and account for every submitted attempt.

## Independent acceptance and delivery

The native basis remains pinned Kubernetes v1.34.0: the
[role wrapper](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/rbac/role/policybased/storage.go),
[binding wrapper](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/rbac/rolebinding/policybased/storage.go),
corresponding cluster-scoped wrappers, and
[rule resolver](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/rbac/validation/rule.go).
Use actual initial authorization, policy storage wrappers and native strategies
against fixture storage. Independently construct and advance the native inventory
after each accepted operation, rebuilding the resolver from that state; never
take Soundcheck's derived states or expected decisions as the oracle.

Freeze native inputs/expectations before production comparison. Include:

- All four target kinds, create/update-existing, implicit coverage and explicit
  bind/escalate; grant-then-use and revoke-then-fail distinguish prior-state
  authority from original-only or final-state authority.
- Self-escalation cannot bootstrap the current write. Newly created/updated
  roles affect later binding checks. Reversing order changes the relevant
  native prerequisite or makes the sequence unsupported.
- Final-valid plans with temporary out-of-scope grants or losses fail; staged
  in-scope repairs need satisfy final access only at Sn. Replay validated
  preservation witnesses against native RBAC for S0 and the offending Si.
- Missing references, stale intermediate aggregates, duplicate targets, bounds,
  no-ops, unauthorized extra mutations and frozen order/actor tampering fail
  closed. Solver errors and invalid witnesses cannot produce success.
- CLI/MCP/trusted-base CI use the same gate. Evidence hashes and executed/skipped
  stages agree with the single run. The evaluator binds the full outer identity,
  inputs and all stage outcomes, retaining failures after successful attempts.
- A one-step sequence agrees with the existing single-change gate's stage
  decisions, apart from the new outer kind/result. Existing contract identities,
  adapter outputs and evaluator formats 1–3 remain compatible.

Suggested coherent commits: connector gate/evidence; adapters and synthetic
workflow; independent native conformance; submitted-repair evaluation/docs.
Run focused tests during implementation, full regressions and all pinned native
suites for acceptance. Present the tested diff before committing; every later
commit independently passes the clean-worktree checks. No new public benchmark,
live-agent campaign or deployment pilot is part of this engineering batch.
