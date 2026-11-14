# Authorization for one RBAC policy change

Sourav approved implementation of the proposed role/binding authorization batch
on 2026-11-14, following PR #78. Deliver one feature branch with coherent commits.
Pinned Kubernetes v1.34.0 source review establishes the following bounded scope.
Existing access contract schemas 1–10, profiles and report formats retain their
meaning. Public benchmark v2 remains frozen outside this repository.

## Frozen operation and inventory

A separate schema-1 `kubernetes-rbac-policy-change` contract contains:

- `actor`: an exact username in the nested requirements' frozen identities;
- `operation`: `create` or `update-existing`;
- `target`: exact Role, ClusterRole, RoleBinding or ClusterRoleBinding kind,
  namespace (null for cluster scope), and explicit object name;
- `requirements`: an unchanged, independently reviewed access contract.

CLI inputs are complete original and proposed snapshots. The proposed snapshot
may change only the named target; creation requires absence before and presence
after, and update requires presence in both. Object order and JSON map-key order
do not matter. Array order and every other object's JSON content must remain
unchanged; representation changes to unrelated objects are not authorized.
Binding updates cannot alter roleRef. Updates must change typed role rules or
binding subjects, preserving array order and duplicates when checking change.
Metadata-only and no-op updates are unsupported, excluding the native GC-only
shortcut. Labels/annotations may accompany a supported target spec change.

Both snapshots must meet the existing strict, complete, already-resolved
inventory boundary. Target aggregate ClusterRole writes and `system:masters`
actors are unsupported. Existing aggregates may remain if the complete proposed
snapshot stays consistent without modifying other objects. No patch, apply,
delete, create-on-update, impersonation or multi-object sequence is implied.
Authentication, inventory completeness and a static pre-operation view are
external assumptions; this does not simulate races or asynchronous controllers.

## Native prerequisites

Use the actor's original-snapshot permissions exclusively, including self-edits
and referenced role lookup. First require the initial create/update RBAC grant.
Create authorization has an empty name; update-existing uses the target name.

For roles, require explicit `escalate` on the URL resource/name/namespace, or
native policy-rule coverage of every proposed rule by the actor's original
effective rules in that scope. On create, the escalate name is empty even when
the body has a name. For bindings, require explicit `bind` on the referenced
role's kind/name in the binding's namespace, or full coverage of that referenced
original role. A namespaced binding to a ClusterRole uses the binding namespace
for the bind check; this is not a cluster-resource request from the access model.

Coverage reproduces Kubernetes' finite policy-rule relation. It must retain
unknown/custom API strings, all verbs, wildcards, literal resourceNames, URLs and
duplicate atoms. Different atomic obligations may be covered by different whole
owner rules. The access request catalogue cannot discard obligations or stand
in for native policy coverage. Missing coverage is reported as atomic policy
rules with source indices, not fabricated request counterexamples.

Published deterministic work limits for executed analysis: 100,000 input values,
8 MiB input string bytes, 100,000 proposed atoms, 8 MiB expanded atomic string
bytes and 10 million conservative comparison units. Explicit authority skips
coverage, as in the native implementation. Check
cardinality and arithmetic before expansion; exceeding a limit is unknown,
never truncation or a negative authorization decision.

## Composite gate and adapters

The new policy-change report is separate from existing report schema 10. It
distinguishes a valid change, unmet authorization, failed access requirements,
out-of-scope regression and unknown/unsupported. The authorization stage is a
deterministic target-policy check, not an SMT proof. Only after it succeeds run
the existing solver-backed requirement and repair-preservation checks. Retain
their original reports, profiles, contract identities and traces unchanged.
Only the successful composite gate exits zero.

Permission to submit a change does not establish successful API mutation,
admission, storage validity under live state, endpoint availability or a composed
authorization-chain decision. A missing RBAC grant is an unmet modeled
prerequisite, not a guarantee of final denial by every API-server configuration.

Expose `rbac change BEFORE AFTER --contract CHANGE.json`, human/JSON/GitHub output,
and a private evidence bundle binding exact inputs, frozen contract, native guard
decisions and the nested comparison evidence. Frozen MCP captures contract and
baseline at startup and accepts candidate config only. CI `mode: change` is
RBAC/PR-only and reads both the whole change contract and original config from
the same immutable approved base commit. Candidate bytes cannot change actor,
target, operation, requirements, preservation scope or original inventory.

## Independent acceptance

Freeze native source pins and independently justified cases before comparing
production. Exercise actual RequestInfo/authorizer projection, native RBAC,
RulesFor/Covers and all four policybased storage wrappers with deterministic
terminal storage fixtures and native validation. Separate unsupported source
boundaries from an unmet authorization prerequisite. Native acceptance does not
contact a cluster or establish successful deployment.

Include initial-vs-special name/scope checks, implicit permission coverage,
explicit bind/escalate, foreign/custom rule strings, wildcard and named rules,
URL coverage, multiple grants, self-edits, roleRef immutability, unsupported
aggregates/bypass identities, malformed/partial inventory and extra mutations.
Verify frozen MCP and approved-base CI tamper resistance, full evidence hashes,
and valid/unsafe/regressing synthetic workflow examples. Existing suites and
expectations remain intact. Each commit passes clean-worktree build and forced
full regressions; final acceptance includes all pinned native suites.
