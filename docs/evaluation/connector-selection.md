# Choosing connector #2

This is an engineering shortlist, not a shipped connector or a conclusion from
deployment pilots. Kong remains the only implemented target. The
[Kubernetes RBAC source study](kubernetes-rbac-exploration.md) outlines a possible
static-grant subset, shared-core changes and an upstream-authorizer experiment.
That experiment and validation with authorized representative inputs remain
pending; the source study does not establish user demand or deployment readiness.

| Candidate | Useful first requirement | Semantic work and independent evidence |
| --- | --- | --- |
| Kubernetes RBAC | A named workload retains required access in its namespace without receiving specified access in another namespace. | Add subjects/groups, resources, API groups, verbs and namespaces. Establish a complete explicit policy snapshot and compare decisions with a pinned Kubernetes authorizer. |
| Envoy HTTP RBAC | Preserve an explicit client allowlist and deny unwanted callers across selected routes. | Model ALLOW/DENY behavior, request/connection identity, route overrides and filter ordering. Exercise a pinned Envoy process. |
| AWS IAM | Restrict selected actions/resources while preserving declared required access. | Bound applicable policy types, context keys and principals first. Independent evaluation must cover their interactions; one policy file alone does not describe all effective permissions. |

The preference for Kubernetes is an inference from scope and testability, not a
market-demand finding. Its additive permissions and explicit role/binding
objects offer a focused starting point. Aggregated roles and implicit/default
bindings require explicit treatment in the input snapshot. A denial claim must
also account for other authorization mechanisms. These boundaries follow the
[Kubernetes RBAC documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).

Envoy offers a nearby gateway target, but its HTTP RBAC filter can be overridden
or disabled per route; enforcement and shadow policies are distinct. A connector
must include the effective filter/route context, not only an isolated rule.
See the [Envoy RBAC filter documentation](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/rbac_filter).

IAM has a broader initial modeling burden: applicable policies combine using
different union/intersection rules, with explicit denials taking precedence.
See [AWS policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html).

Before committing to an implementation:

1. Obtain authorized representative inputs and independently written paired
   denial/required-access requirements. Record unsupported cases and authoring
   effort through the [pilot protocol](pilot-protocol.md).
2. Pin a target version, its relevant source rules and an executable independent
   decision oracle. Define the initial supported subset and fail-closed cases.
3. Execute an unsafe → deny-all → valid-repair acceptance scenario, including
   preservation of behavior outside the approved repair scope. The RBAC study
   supplies a source-derived example, not executable conformance evidence.
4. Review the minimal shared-core changes. Do not encode Kubernetes identities
   as Kong's anonymous/authenticated bit or assume contracts are portable.

Only after that evidence should the project announce connector #2 as selected
for delivery. These selection criteria and the source study support a provisional
feasibility recommendation; they make no multi-target support claim.
