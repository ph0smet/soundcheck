# Controller API authorization conformance

This synthetic corpus adds independent acceptance for schema 10,
`kubernetes-rbac-v1.34-controller-apis-v1`. It retains the schema-9 contract
shape and adds six fixed entries / 29 operation classes:

| API group | Resource | Initial operations |
| --- | --- | --- |
| admissionregistration.k8s.io | validatingwebhookconfigurations | get, list, watch, create, update, patch, delete, deletecollection |
| admissionregistration.k8s.io | mutatingwebhookconfigurations | get, list, watch, create, update, patch, delete, deletecollection |
| apiextensions.k8s.io | customresourcedefinitions | get, list, watch, create, update, patch, delete, deletecollection |
| apiextensions.k8s.io | customresourcedefinitions/status | get, update, patch |
| authorization.k8s.io | subjectaccessreviews | create |
| authentication.k8s.io | tokenreviews | create |

All six entries are cluster scoped. Initial POST authorization uses an empty
name, independent of metadata or a reviewed subject in the body. CRD object-body
name validation is different from the bounded authorization-name domain. These
classes do not add compound SSA/PUT operations or promise successful API calls.

## Independent reference

The pinned Kubernetes v1.34.0 / apiserver and apiextensions-apiserver v0.34.0
sources in `source-pins.json` determine expected scopes and operations. The Go
reference uses the actual native REST types and strategies, with object factories
in fixture stores, and runs `APIGroupVersion.InstallREST`. The exact resulting
36 routes, discovery verbs, cluster scopes and false create-on-update flags are
checked. Storage is not contacted, and constructor storage options, validation,
admission and object mutation effects are not simulated.

Every request point is projected through native `RequestInfo` and
`GetAuthorizerAttributes`, then the production RBAC authorizer over the original
policy objects. Full caller, groups, verb, group/version, resource/subresource,
name, namespace, path and request-kind tuples are checked before comparing
decisions to the independent expectations and Soundcheck's concrete/SMT readers.
Literal URL controls cover list/watch name selectors and collection writes.

The review controls run the real installed SubjectAccessReview and TokenReview
HTTP handlers behind native request classification and RBAC authorization. Only
the *reviewed* authorization/authentication service uses a deterministic fixture.
An authorized caller receives a review response even when the reviewed subject
is denied or the token is unauthenticated; an ungranted caller gets 403 before
the review service runs. Soundcheck verifies the initial caller grant, not the
review response, token validity, arbitrary body identity or downstream effect.

## Frozen acceptance

`generate.py` is an explicit preparation tool, never an acceptance-time repair.
`inputs.json` seals 211 generated artifacts before production comparison:

- 164 requests and 21 source-derived policy experiments: 3,444 native/concrete/SMT
  comparisons, including fixed groups, resourceNames, local bindings and wildcard
  group/resource/subresource boundaries.
- 48 requirement/preservation scenarios: 9,388 finite native decisions, including
  all 29 new operation classes, required-access loss, valid repair, unmentioned
  operator permissions, old custom/URL preservation and schema-9 domain controls.
- Eight review-handler controls distinguish initial caller authorization from the
  body's authorization/authentication result.
- Full production acceptance additionally requires 53 outside-domain rejections,
  29 schema-9 exclusions, six clause witnesses and eight preservation witnesses.
  Each witness is checked against its exact frozen obligation and replayed through
  native Kubernetes. A preservation witness must change the native decision.

Seven adversarial consumer tests reject missing cases, corrupted counts, changed
inputs, incorrect module/function linkage, altered scopes/routes, body/caller
mixing, coerced booleans, weakened frozen contracts and malformed witnesses.
The runner binds inputs, reference source hashes, module metadata, runtime
linkage and binary hashes before execution and rechecks them afterward.

Run the complete historical and new suites with
`bash bench/kubernetes-rbac/conformance/run.sh`. The new runner is
`bench/kubernetes-rbac/conformance/run_controller_apis.py`; `--native-only`
validates the frozen expectations without using the Soundcheck binary or Z3.
Native-only results do not satisfy the full production acceptance counters.

The reference-only Go graph adds the versions selected by the pinned upstream
modules for the real API installer and CRD strategy: cel-go 0.26.0, cel.dev/expr
0.24.0, antlr4-go/antlr/v4 4.13.0, go-strcase 1.3.0, x/exp at 8a7402abbf56 and
the already-pinned cobra 1.9.1. These are not shipped verifier dependencies.

This is a finite synthetic conformance suite, not a live deployment benchmark,
an owner-approved requirements set or a universal proof of the target model.
No public benchmark inputs or results are included here.
