# Nonresource rule coexistence acceptance

This synthetic suite verifies that valid nonresource rules can coexist with
resource rules while Soundcheck continues to quantify only core ConfigMaps and
Secrets. It does not add URL requests to any contract or assurance domain.
No public deployment inputs, installed-state claims, or external pilot results
are included.

`contract.json` is a fixed schema-3 paired contract: `app` must get
`team-a/configmaps/settings` and must have no get grant on `team-a/secrets`.
Its change scope is empty, so comparison requires preservation over the entire
modeled resource domain for all four explicitly supplied identities. Groups are
trusted empty input sets; they are not authentication findings.

`../conformance/run_nonresource.py` constructs the independently authored
synthetic cases before starting either analyzer. `inputs.json` pins their exact
serialized bytes, the fixed contract, and the unchanged existing preparation
fixture `36-nonresource-rule-control.json`. The runner records original,
prepared, request, and tool hashes and rechecks them before declaring completion.

The native expectations come from pinned Kubernetes v1.34.0:

- `pkg/apis/rbac/validation/validation.go:103`: a positive URL-array length
  selects a nonresource rule. Such rules require a nonempty verb array, occur
  only in ClusterRoles, and cannot contain nonempty API-group, resource, or
  resource-name arrays. Nil and empty slices have the same validation behavior.
  URL and verb strings receive no additional validation here.
- `plugin/pkg/auth/authorizer/rbac/rbac.go:178`: resource requests use resource
  matching, while nonresource requests use URL matching. Valid URL-only rules
  cannot grant modeled resource requests.
- `pkg/apis/rbac/v1/evaluation_helpers.go:26`: verbs and API groups match
  exact literals or `*`; resource `*` still matches both modeled resources.
  No URL pattern is interpreted by this suite's resource expectation checker.
- `pkg/registry/rbac/validation/rule.go:179`: RoleBindings participate only in
  the requested namespace, and a RoleBinding can resolve a ClusterRole with its
  complete rule list. Source rule indices are unchanged by coexistence.

Accepted cases include URL-only ClusterRoles through either binding kind,
unusual native-valid strings, absent/null/empty resource fields on URL rules,
separate URL/resource rules, and absent/null/empty URL fields on wildcard
resource rules in both Roles and ClusterRoles. Resource matrices cover six
verbs, both resources, multiple identities, named/empty collection requests,
and local/foreign/unseen/all-namespace scopes. They compare original native,
prepared native, connector, and production-SMT decisions and exact grant labels.
Original resource rules at indices 1 and 3 must retain those trace indices.

Malformed mixed rules, Role URL rules, unbound invalid roles, missing verbs,
empty resource rules, and wrong field/element types must fail native validation,
connector parsing, preparation, and verification. Rejected preparation must
produce neither snapshot bytes nor a receipt. Every CLI result is checked for
its complete response shape, frozen contract identity, assurance, ordered failing
clause, witness scope, and exact grant trace before native witness replay.

The source-retention audit checks the complete AST, and the independent native
typed-policy comparator checks all authorization fields. Separate negative
controls alter or drop a URL rule: the whole-policy comparator must reject
equality even though every resource matrix decision stays the same. The native
URL permission changes, while resource-only repair preservation must still
succeed. This distinction is intentional and is not a URL preservation claim.
Native `/healthz` requests supply `resourceRequest:false`; the connector boundary
probe removes the unsupported `path` field and requires rejection specifically
at `resourceRequest`.

Run through the repository conformance harness, or invoke the runner with
`--reference`, `--model`, `--soundcheck`, `--module-metadata`, `--output`, and
optionally `--z3`. Checker-only tests use
`python3 -m unittest test_nonresource_runner.py` from `../conformance` and need
neither Go nor Z3. Finite comparisons and witness replays are not a universal
proof of the parser, lowering, or encoder.
