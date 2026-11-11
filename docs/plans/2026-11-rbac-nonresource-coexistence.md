# RBAC non-resource rule coexistence

This implements the approved P1 inventory expansion: accept native non-resource
rules alongside resource permissions without expanding verification to URL
requests. It addresses a public-pilot input boundary; the external pilot's frozen
inputs and results are unchanged. No live cluster or new deployment evaluation
is part of this work.

## Native validation and separation

Kubernetes v1.34.0's
[ValidatePolicyRule](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/apis/rbac/validation/validation.go#L103)
selects the rule domain by `len(nonResourceURLs) > 0`. URL rules require a
ClusterRole, nonempty verbs, and empty API-group/resource/resource-name lists.
Absent, null and empty arrays have zero length; `[""]` does not. When the URL
list is empty, API groups and resources must be nonempty, as for existing resource
rules. Type-check fields before using the selected domain. Unsupported fields,
invalid arrays/elements and malformed unbound roles still reject the snapshot.

The pinned validator does not constrain individual URL or verb strings. Preserve
them literally, including empty or unusual wildcard strings, without deriving a
URL matcher from API comments. No URL syntax validity, HTTP parsing, reachability
or authorization claim is added.

The native
[RuleAllows](https://github.com/kubernetes/kubernetes/blob/v1.34.0/plugin/pkg/auth/authorizer/rbac/rbac.go#L178)
resource branch uses API groups and resources, never URLs. A valid URL-only rule
has empty resource predicates and cannot grant a resource request. Represent the
two rule domains explicitly in the connector and lower URL rules to a false
match. Retain their slots so existing `/rules/N` evidence identifies original
source positions. Do not filter them out before indexing. A RoleBinding may
resolve a ClusterRole containing both kinds; namespace scope applies to its
resource grants. Validation uses role kind, not binding kind.

## Profiles and provenance

All four assurance IDs advance from suffix `-v1` to `-v2` to identify the broader
accepted snapshot boundary. Add an explicit exclusion for URL authorization and
URL preservation. Existing contract schemas 1–4, canonical contracts, supported
request domains, profile document shapes 1/2, report schema 10 and existing
evidence/preparation/inventory/inspection formats are unchanged.

The OCaml library's `Snapshot.rule` changes from a resource-only record to
`Resource of resource_rule | Non_resource of nonresource_rule`. Library callers
that inspect rule records must match the constructor; serialized policy and
report formats do not acquire this internal representation.

Preparation and inventory preserve the full original policy AST except their
already approved metadata transformations. URL-only changes alter input/output
hashes even when resource decisions and preservation are unchanged. A subject
match still does not imply an effective modeled grant; inspection rule counts
remain total source-rule counts. `resourceRequest: false` remains unsupported.

## Acceptance obligations

Use native validation and independently chosen decisions for both binding kinds,
separate URL/resource rules, original rule indexes, resource wildcards with
empty/null URL lists, arbitrary literal URL strings, namespaced/mixed/malformed
rule rejection and unbound invalid roles. Preserve old canonical-contract hash
regressions. Test verification and resource comparison across contracts 1–4,
CLI/MCP/trusted-base gates and evidence with the revised profiles.

Native conformance compares original/prepared typed inventories plus native,
concrete and production-SMT resource decisions. It must show that URL-only native
access can exist while resource access is absent, and that changing only URLs
can change native URL access while resource preservation succeeds. A whole-policy
comparison must catch dropped/changed URL rules despite equal resource decisions.
Validate each reported witness against its exact frozen clause and native decision.

Existing preparation fixture 36 stays byte-for-byte unchanged. Its valid unbound
URL ClusterRole now prepares successfully; the original unsafe resource grant
still violates the fixed contract, so repair preservation is not reached. This
deliberate supported-boundary change is the reason to revise its expectation.
Finite synthetic checks are implementation evidence, not a proof of universal
target conformance or safety of arbitrary running deployments.
