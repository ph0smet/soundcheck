# Kubernetes RBAC named write authorization

After PR #65, Sourav approved the next bounded batch: `update`, `patch` and
`delete` authorization for core ConfigMaps and Secrets, alongside the existing
reads, with repair preservation, frozen workflows and independent Kubernetes
conformance. Deliver separate coherent commits on `feat/rbac-write-access`;
Sourav opens and merges the PR. Real deployment evaluation follows implementation
and requires authorized inputs and independently owner-reviewed requirements.

## Contract and model boundary

Contract schema 3 retains the schema-2 fields and adds the three named write
verbs. Its profile is `kubernetes-rbac-v1.34-read-write-v1`. Schemas 1 and 2 keep
their canonical forms, profile documents, request domains and preservation
meaning. Profile inspection defaults to version 1; version 3 is explicit.

Get/update/patch/delete require nonempty DNS-valid namespace and object name.
Only list/watch support the empty effective name and all-namespace endpoint.
For named writes, `names: null` means all supported named requests; a nonempty
name list means exactly those names. `namespace: null` remains a collection
endpoint selector, never a wildcard for all namespaced writes. Create,
deletecollection, other resources, subresources and non-DNS names stay outside.

RBAC's literal `resourceNames` and additive grant semantics apply unchanged.
Empty and literal-star entries cannot grant supported named writes. The request
name comes from the path, not a selector or request body. Preservation for v3
quantifies over all six verbs, even if the clauses mention only a subset; change
scope must authorize each changed verb, identity, resource, namespace and name.

This models the initial resource-request RBAC Allow/NoOpinion decision, not
successful API execution or object mutation. Payload fields, object existence,
preconditions, admission and additional operation-specific authorization are
outside the model. In particular, server-side-apply PATCH can additionally
require create authorization, and malformed-object deletion can require a
separate unsafe-delete authorization. A static grant is not a successful write;
preserving grants does not preserve object contents. Snapshot completeness,
identity/groups, supported input forms and the other existing assumptions hold.

No shared core/solver or stable report/evidence schema change is needed. The
experimental repair benchmark selects its existing format 2 for either v2 or
v3 tasks and retains exact format-1 behavior for v1-only tasks. Its trusted
per-task profiles continue to come from evaluator-frozen contracts.

## Delivery and acceptance

1. Versioned contracts, named-write domain/lowering, precise report/profile
   language, preservation and focused semantic regressions.
2. CLI/evidence, immutable MCP, approved-base Action and submitted-repair
   acceptance, plus runnable synthetic repair examples.
3. Independent pinned Kubernetes request parsing/authorization comparison,
   concrete/SMT decisions and counterexample replay. Retain existing named-get,
   preparation and read conformance expectations and result counts.

Tests distinguish verbs, names, local/cluster/group grants, wildcard and empty
resourceNames, exact versus all-name requirements, broken required writes,
inconsistent intent, incomplete fixes and out-of-scope read/write regressions.
Raw PUT/PATCH/DELETE cases verify path-derived attributes, query independence
and rejection of collection deletion and other outside-domain requests. Only
supported named requests can become accepted witnesses. Each commit receives
clean-worktree build and full regression checks.

## Deployment evaluation follow-up

Keep real inputs and results private and separate from the synthetic corpus.
Freeze authorized inventory, complete-snapshot and identity assumptions,
requirements, verifier/solver versions and input digests before evaluation.
Measure supported coverage and unknown reasons, requirement-authoring effort,
runtime, independently adjudicated findings and diagnostic usefulness. Retain
unsupported cases in the denominator. No live cluster access, mutation, external
agent run or production-quality claim follows from synthetic acceptance.
