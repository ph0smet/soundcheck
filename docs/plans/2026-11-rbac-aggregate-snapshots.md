# Already-resolved aggregated ClusterRoles

The next approved roadmap item is aggregated ClusterRoles, following PR #71.
The first slice accepts a bounded subset of complete desired RBAC inventories:
every aggregate must already contain exactly the permissions derived from its
selectors. Existing contract schemas 1–4, canonical requirements and report
schema 10 remain unchanged. The expanded input boundary selects profile suffix
`-v3`. Preparation, CLI, MCP, CI and comparison use the same mandatory reader.

## Semantic boundary

The pinned Kubernetes v1.34.0
[controller](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/controller/clusterroleaggregation/clusterroleaggregation_controller.go)
copies stored rules from label-selected ClusterRoles, excluding itself. The
[authorizer resolver](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/rbac/validation/rule.go)
reads stored rules. Accepting a desired aggregate with empty or stale rules
without checking its selectors could therefore produce a misleading proof.

- Require the complete ClusterRole inventory and labels, including unbound
  contributors, as well as all applicable bindings and referenced roles.
  Completeness is an external assumption; reference resolution cannot prove it.
- Validate matchLabels and matchExpressions with In, NotIn, Exists and
  DoesNotExist. Requirements within a selector are conjunctive; selectors are
  alternatives. An empty selector matches all roles. A missing label satisfies
  NotIn. Unknown fields, invalid keys/values/operators or cardinalities fail.
- Missing/null aggregationRule is ordinary policy. A nonnull aggregationRule
  requires at least one selector. Self-matches are ignored; all other aggregate
  dependency cycles are unsupported, including unbound cycles.
- Derive full expected rules recursively from nonaggregate leaves. Never use
  stored aggregate rules as seeds. Every aggregate's stored typed rule set must
  equal that result, including rules outside the quantified resource domain and
  non-resource URLs. Reject both missing grants and stale additional grants.
- Equality ignores ordering/duplicates within membership lists and rule lists;
  it does not merge structurally different but authorization-equivalent rules.
  Retain original policy bytes, fields and rule positions for verification and
  evidence. No implicit reconciliation, materialization or field removal.

For an acyclic graph, induction from nonaggregate leaves establishes agreement
between stored and recursively selected permissions under fixed inventory and
labels. It does not establish live convergence time, rollout safety, future
changes, successful apply, authentication or admission. Cycles are excluded
because native controller ordering can preserve or remove initially stored
grants; choosing an empty least fixed point would not model that behavior.

When an aggregate is present, limit inputs to 512 ClusterRoles, 1,024 selector
units (one per selector, matchLabel pair, expression and expression value), and
100,000 resolved child-rule contributions summed over dependency edges. Exceeding
a limit rejects the input; it never truncates the policy. Ordinary inventories
retain their existing limits. Fragment preparation checks structure; only the
complete assembled inventory can be checked for aggregate consistency.

## Acceptance

Freeze synthetic expected grants before execution. Check strict selector
validation and matching, nested aggregates, self-only/empty results, stale rules
in either direction, non-domain and URL mismatches, cycles, full-input checking,
work limits, duplicate normalization, original evidence indices and preservation.
Preparation/inventory must retain all aggregate policy across source boundaries.
Frozen adapters must reject unsupported candidates and baselines consistently.

Use Kubernetes' production selectors/controller and authorizer independently of
Soundcheck. Retain the distinction between native validity/reconciliation and
Soundcheck's narrower acceptance. Finite comparisons and witness replays are
conformance evidence, not universal correctness proofs. Existing fixture 18 is
retained unchanged: its empty aggregate selects nothing and is now supported.
New stale-aggregate controls replace its previous use as a blanket rejection.
The same no-match input in preparation fixture 35 is also retained unchanged and
now accepted; a separate stale preparation fixture preserves rejection coverage.

Public benchmark data remains external. Owner-reviewed deployment inputs and
measured authoring effort remain pending; this work does not substitute for them.
