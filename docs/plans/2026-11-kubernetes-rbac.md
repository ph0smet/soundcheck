# First Kubernetes RBAC connector

Approved scope: turn the local synthetic feasibility benchmark into a limited
connector, with focused feature commits on one branch. Sourav will open and
merge the pull request. The initial profile is pinned to Kubernetes v1.34.0.

The supported decision is whether RBAC grants a named `get` request for a core
ConfigMap or Secret. It covers complete static desired snapshots of Roles,
ClusterRoles, RoleBindings and ClusterRoleBindings. The contract freezes the
identity/group context and the assertion of snapshot completeness separately
from candidate configuration. Resolving all references alone cannot establish
that a snapshot includes every applicable binding.

The first input format is one strict JSON Kubernetes `v1/List`, including
validated name/namespace/label/annotation metadata. General YAML, live exports
with additional metadata, aggregation controllers, admission, mutation,
list/watch, subresources and privilege-escalation paths remain unsupported.
Missing references, duplicate identities, malformed and unknown fields produce
`unknown`. Accepted metadata is checked locally against the pinned API's
constraints; conformance testing is not a substitute for per-input validation.

Core extension: named principals and optional typed object coordinates, using
the shared condition encoder, solver, witness validation and frozen contracts.
RBAC lowers each complete grant into an equal-priority allow rule's match,
with an unconditional guard. This yields the exact additive union for both
possible and definite allowance. Core non-allowance is lifted as `NoOpinion`;
it is not a claim of final denial by a composed API-server authorizer chain.

Frozen contracts pair `must_allow` and `must_not_grant` clauses and optionally
identify the only request classes whose decisions a repair may change.
Verification checks the candidate against the fixed clauses. Comparison first
verifies the candidate, then checks decision preservation outside that approved
change scope. It quantifies over the fixed identities and all supported valid
namespace/name strings, not merely the finite conformance request matrix.

Public CLI entry points are `soundcheck rbac verify`, `soundcheck rbac compare`,
and `soundcheck profile kubernetes-rbac`. Report schema 10 carries exact object
coordinates, fixed groups and opaque granting-rule identifiers; existing Kong
fields retain their meaning. Evidence model schema changes are coordinated with
its consumers. RBAC MCP, GitHub Action and web UI integration are later work.

Acceptance includes the unwanted Secret grant, deny-all repair, valid repair,
remaining cluster/group grant, named restrictions, wildcard/literal boundaries,
and unrelated operator regression. Ordinary `dune test` stays Go/network-free.
A separate harness executes the pinned production Kubernetes authorizer on
the original fixture bytes and replays counterexamples. Every feature commit
receives clean-worktree regression validation; the integrated branch receives
upstream RBAC and existing Kong conformance checks.
