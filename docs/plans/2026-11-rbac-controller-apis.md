# Controller API authorization and explicit bootstrap supplements

Sourav approved this combined Kubernetes batch on 2026-11-14 after reviewing
the inventory-readiness, controller-API and paired-contract proposal. Deliver it
on one feature branch with separate coherent commits. Public benchmark v2 stays
frozen outside the repository; this batch does not authorize a live deployment
or agent evaluation. Native source review fixes the following bounded scope.

## Schema 10

Preserve schemas 1–9, their canonical contracts, profiles and request domains.
Schema 10 retains every schema-9 resource/URL class and the independently frozen
custom catalogue. Add six fixed entries:

| API group | Resource | Subresource | Initial operations |
| --- | --- | --- | --- |
| admissionregistration.k8s.io | validatingwebhookconfigurations | empty | get, list, watch, create, update, patch, delete, deletecollection |
| admissionregistration.k8s.io | mutatingwebhookconfigurations | empty | get, list, watch, create, update, patch, delete, deletecollection |
| apiextensions.k8s.io | customresourcedefinitions | empty | get, list, watch, create, update, patch, delete, deletecollection |
| apiextensions.k8s.io | customresourcedefinitions | status | get, update, patch |
| authorization.k8s.io | subjectaccessreviews | empty | create |
| authentication.k8s.io | tokenreviews | empty | create |

These are cluster-scoped: authorization namespace is empty and contract
namespace is null. RoleBindings cannot grant these requests, including bindings
to ClusterRoles. Names retain the existing bounded authorization domains:
base create/deletecollection have empty name, list/watch empty or effective
selector name, other operations nonempty DNS-subdomain names up to 253 bytes.
CRD/status always has a nonempty name. The review APIs support create only,
with empty authorization name regardless of names or subjects in the body.
Unsupported operations reject rather than becoming proven non-grants.

The fixed catalogue grows from 31 entries / 223 operation classes to
37 entries / 252 classes. No new SSA, PUT branch or custom subresource is added.
The original eight-base SSA and Service/Endpoints PUT domains remain unchanged.
Native API groups cannot be supplied through the custom-resource catalogue.

The new assurance profile is `kubernetes-rbac-v1.34-controller-apis-v1`.
Profile JSON retains schema 6 and report JSON schema 10; contract schema 10 is
an explicit opt-in to the larger preservation domain. Preserve decisions for
every fixed identity and every supported class, including classes absent from
clauses. Existing operation-specific change scopes do not widen implicitly.

## Initial caller authorization is distinct from API effects

SubjectAccessReview checks whether the caller may submit the review. Its body
selects a possibly different subject/request, and its status reports that
review's authorization result. TokenReview checks whether the caller may submit
a token for authentication; the returned authenticated identity/status is not
the caller's identity. Neither result is modeled as an extra prerequisite or
permission granted by the review. They are create-only, nonpersistent APIs.

Webhook/CRD permissions do not establish admission outcomes, conversion behavior,
schema validity, successful mutation, CRD lifecycle or controller effects. CRD
body name validation (`plural.group`) is distinct from bounded URL authorization
names. This batch does not model bind/escalate, impersonation, workload effects,
review response contents or a complete API-server authorization chain.

## Explicit offline bootstrap packs

Add `rbac bootstrap --kubernetes-version 1.34.0 --pack NAME` with repeatable
explicit pack selection and an optional exclusive receipt file. Supported packs:
`cluster-admin`, `view`, `auth-delegator`, and
`extension-apiserver-authentication-reader`. No defaults, bindings, identity
inference, live discovery, automatic missing-role repair or runtime downloads.

Pin and independently regenerate the upstream source objects, licence and
provenance. The view pack includes its selector and required bootstrap
contributors; its materialized rules must come from the native aggregation
controller over the pinned bootstrap inventory. It describes a bootstrap-only
assumption, never observed installed policy. Existing inventory assembly checks
the entire union, rejecting duplicates, conflicting supplied roles, unresolved
references and aggregation made stale by additional contributors.

The embedded pack has no Go/network runtime dependency. Unsupported versions,
empty/duplicate/unknown selections fail closed. Receipts bind requested packs,
dependency objects, upstream version/source pins, embedded data and exact output
bytes, and explicitly state that completeness and installed state were not
established. Keep receipt and source hash semantics consistent with existing
offline workflows. CRD metadata remains a separately reviewed input prepared
with `rbac catalogue`, not inferred from the RBAC being repaired.

## Independent acceptance and delivery

Reference Kubernetes v1.34.0 and pinned v0.34.0 staging modules. Freeze source
digests and independently derived inputs before comparing production. Exercise
actual REST scope, APIInstaller operation discovery, RequestInfo and native
authorizer attributes/RBAC; execute native review REST handlers with controlled
review/authentication results to demonstrate the caller/body distinction.
The installer reference uses native REST types and strategies with fixture
object factories. It does not initialize persistent stores or contact etcd;
route/authorization conformance does not establish storage or admission effects.

Require positive/negative domain controls, exact API group/subresource matching,
wildcards, empty resourceNames, group and binding combinations, schema-9
exclusions, concrete/SMT/native agreement, typed counterexample replay and
preservation regressions on resources/identities omitted from clauses. Corrupt
reference evidence must fail consumer validation. Keep historical fixtures and
expectations intact; adding a new supported version only advances explicit
unknown-future-version controls.

Provide paired synthetic controller requirements and repair examples across CLI,
frozen MCP, approved-base CI, evidence and submitted-repair evaluation. Include
required-access loss, leftover grants and unrelated-controller regressions.
Every commit must pass clean-worktree build and full forced regressions, followed
by all existing and new native conformance suites. Do not claim a new public
benchmark outcome from synthetic acceptance tests or rewrite benchmark-v2 data.
