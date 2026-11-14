# Policy-change authorization conformance

This finite synthetic corpus checks the version-1
`kubernetes-rbac-policy-change` gate against pinned Kubernetes v1.34.0 sources.
It adds no permissions to the access-request domains of schemas 1–10.

A contract freezes one actor from its access requirement's trusted identities,
one named Role, ClusterRole, RoleBinding or ClusterRoleBinding, and `create` or
`update-existing`. Both snapshots are complete strict Lists. Only the target
may change. Update requires an order-sensitive change to typed rules or subjects;
metadata-only/no-op updates, changed binding roleRefs, aggregate targets,
`system:masters`, patches, apply and create-on-update are outside version 1.

## Independent reference

The native oracle uses the actual request-info and authorization filters,
RBAC authorizer, all four `policybased.Storage` wrappers, `DefaultRuleResolver`,
`ConfirmNoEscalation` and `Covers`. Its terminal fixture store evaluates the
wrapped update against the old object and invokes the native strategy's
validation. Equal fixture resource versions are supplied only after the
authorization guard, for native update validation. It does not contact storage
or model concurrency, admission, persistence or a successful deployed change.

All authority comes from the **before** snapshot. Initial POST authorization
and `escalate` use an empty authorization name; update-existing uses the URL
name. `bind` targets the referenced role's name and the binding's namespace,
including a namespaced RoleBinding referring to a ClusterRole. Initial write
permission remains necessary when `bind` or `escalate` is granted.

Implicit authorization checks every proposed policy rule, including arbitrary
verbs, future API groups, resources and non-resource URLs. No access catalogue
filters these rules. Native coverage splits the proposed rules into atomic
obligations and compares them with the actor's full rules. Enumerating today's
resources or verbs cannot cover a wildcard policy obligation. Missing atoms
are policy evidence, not fabricated request counterexamples.

The reference records full initial/special request attributes, native
`RuleAllows` grant indices, raw actor/reference rules, exact coverage operands
and missing atoms, and whether the native storage guard was passed. The
production comparison checks the same coordinates, grant origins, atom counts,
missing rule/atom indices and decisions. Solver-backed access requirements and
preservation remain separate from this deterministic prerequisite check.

Native unit controls also establish why excluded cases need separate treatment:
GC-only and identical updates can bypass escalation checks; metadata and rule
order changes do not automatically qualify. Aggregate roles require universal
resource **and** URL authority absent a privileged bypass. Binding roleRef
immutability still applies after an explicit authorization bypass.

## Frozen acceptance

`generate.py` explicitly prepares `inputs.json`; acceptance never regenerates
or repairs expected answers. Its 424 artifacts seal 92 authorization cases and
18 structural rejection controls before production comparison. They cover:

- All four object kinds and both supported operations, initial denial, explicit
  bind/escalate, empty policies and implicit full-rule coverage.
- Named initial versus special authorization, namespace boundaries, group and
  ServiceAccount subjects, unbound roles, existing resolved aggregates and an
  attempted self-edit that would grant its own escalation authority.
- Wildcard non-enumeration, subresources, literal resource names, split grants,
  one missing cross-product atom, and resource/non-resource URL separation.
- Four authorized binding edits prepared to exercise downstream access failure,
  preservation failure, an approved change and an unapproved change. The
  deterministic reference certifies only their authorization prerequisite;
  the composed CLI/adapter acceptance checks their solver-backed outcomes.

Eleven adversarial consumer tests reject corrupted attributes, skipped stages,
rule provenance, atom evidence, types, counters, module/function linkage,
unsupported-boundary responses and input hashes. The runner records and rechecks
input, source, module-source and executable hashes around execution.

`source-pins.json` pins the registry guards, strategies, resolver, comparator,
validation, filters and relevant handler/server boundaries. Effective module
versions are Kubernetes v1.34.0 and staging modules v0.34.0. Go's `-trimpath`
filename for component-helpers retains its upstream `v0.0.0` requirement; the
reference separately requires the v0.34.0 replacement and matching source hashes.
No new Go dependency or production dependency is introduced.

Run `bash bench/kubernetes-rbac/conformance/run.sh` for historical and new
acceptance together. `run_policy_changes.py --native-only` checks the frozen
native expectations without the production adapter or Z3. Its ordinary mode
also requires the dedicated deterministic `policy_change_oracle.exe` adapter and
`--soundcheck` CLI. It accepts an optional `--z3` executable, runs the four
frozen composed cases and replays their three counterexamples through native
RBAC on before/after inputs (six decisions). The deterministic adapter itself
does not invoke Z3. Neither mode is a deployment benchmark, completeness audit, live-cluster test
or universal proof of Kubernetes model correctness.
