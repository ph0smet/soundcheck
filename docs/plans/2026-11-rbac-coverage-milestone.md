# Static RBAC coverage and repair verification

Sourav approved this combined feature and benchmark-v2 scope on 2026-11-13.
The batch preserves schemas 1–8 and adds one schema-9 contract with a frozen
resource catalogue, explicit resource/URL request classes and conditional PUT
prerequisites. Each feature carries tests and ships through coherent commits in
one branch. Public configurations and benchmark results remain external.

## Frozen domains

Schema 9 retains the existing eight base resources, eight subresources and all
99 initial/SSA combinations. It adds these base resources for initial request
authorization only:

- Core ServiceAccounts, Events, Namespaces, PersistentVolumeClaims and
  PersistentVolumes.
- `events.k8s.io` Events; `apps` ReplicaSets, StatefulSets and DaemonSets;
  `batch` Jobs and CronJobs; `coordination.k8s.io` Leases.
- `networking.k8s.io` Ingresses and IngressClasses; `storage.k8s.io` StorageClasses.

The initial operations are get, list, watch, create, update, patch, delete and
deletecollection. New entries do not automatically acquire SSA or subresources.
Only Services and Endpoints acquire `update-existing` (named update) and
`update-missing` (named update AND named create). These labels describe HTTP PUT
under hypothetical existing/missing storage branches, not observed object state.
Native permissions may come from different bindings but share the caller and
target coordinates. This adds 124 fixed combinations, for 223 in schema 9.

Named Namespace endpoints have authorization namespace equal to target name.
This differs from ordinary cluster resources. Represent that equality explicitly
in the generic IR. Named operations require DNS1123 labels of at most 63 bytes
in both coordinates. Collection list/watch have empty namespace and empty or
DNS-subdomain effective name (including an exact-name field selector); collection
writes have empty namespace and name. Contract `namespace` selectors describe
the authorization attribute, so named Namespace scopes use a nonempty selector;
collection scopes use null. Pinned RequestInfo and native RBAC must validate the
same-namespace RoleBinding and collection-binding distinction independently.

The other resource/name bounds and selector meanings stay unchanged. A model
domain is a conditional authorization domain; it does not assert that a request
body is valid, an object exists or a handler successfully executes.

## Explicit custom-resource catalogue

Schema 9 requires a top-level `custom_resources` array, which may be empty.
Each row has exactly `api_group`, `resource`, `scope` (`Namespaced` or `Cluster`)
and `subresources` (a duplicate-free subset of `status` and `scale`). Limit the
catalogue to 64 base entries. Groups/plurals are validated literal DNS names;
native API groups cannot be redefined as custom resources. Duplicate entries and
conflicting scope claims reject. Order is normalized into the frozen identity.

Base entries support initial operations only; explicit status/scale entries
support get/update/patch. The catalogue is reviewed independently of candidate
RBAC and may be prepared from pinned CRD metadata. Candidate policies cannot
replace or shrink it. All entries participate in preservation, even when absent
from clauses. Wildcards quantify only the frozen catalogue; future APIs, CRD
lifecycle, custom schemas, admission, conversion and controller effects are not
inferred. Evidence retains the exact catalogue in the canonical contract.

## Resource and non-resource clauses

Schema 9 requires `request_kind` on clauses and change scopes. `resource` retains
schema-8 subject, operation, API group, resource, subresource, namespace and names
fields. `non_resource` instead has subject, operation and `paths`, with exactly
one selector: `{"exact":"/version"}` or `{"prefix":"/healthz"}`. The two wire
shapes are disjoint; irrelevant fields reject. Both kinds share the independently
frozen identity context and paired must_allow/must_not_grant requirements.

URL operations are lowercase HTTP get/head/post/put/patch/delete/options; HEAD
does not alias GET. The supported path domain is absolute ASCII paths with
unreserved characters in nonempty segments, optional trailing slash, no dot or
dot-dot segments, escaping, query or fragment syntax. `/` is supported. Filter
out paths that pinned RequestInfo classifies as resource requests: `/api/v/r...`
and `/apis/g/v/r...`; discovery paths such as `/api/v1` remain non-resource.
The model makes no claim about endpoint existence or HTTP success. Exact
selectors outside this domain reject. Prefix selectors intersect the domain;
empty intersections are vacuous, not permission proofs.

Native nonResourceURL grants use exact matching or a prefix obtained by removing
all trailing stars. Preserve arbitrary source strings; unsupported path syntax
cannot accidentally widen their match. Only ClusterRoleBindings grant these
empty-namespace requests. Resource rules and URL rules cannot grant across the
request-kind boundary, including wildcard rules. URL witnesses use report path
and absent object coordinates; report schema 10 remains unchanged.

## Preservation and integration

Preservation quantifies all frozen identities, all fixed and custom resource
classes and all supported URL classes, including dimensions without clauses.
Approved scopes exclude only their exact request-kind/operation domain. Ordinary
update and update-existing remain distinct, as do patch and apply-existing.
Named-create changes can affect both apply-missing and update-missing: permission
to change one never implicitly permits changing the other. Compound prohibition
means at least one prerequisite lacks a grant, not separately prohibiting both.

CLI/library/evaluation, contract review, evidence, immutable MCP, trusted-base CI
and submitted-repair evaluation use the same contract semantics. A schema-9
profile identifies the fixed catalogue and the frozen contract as the source of
custom entries. Coverage diagnostics distinguish observed rule references from
reviewed requirements and explicitly disclose wildcard coverage limits.

## Independent acceptance

Freeze source-derived expectations before comparing production results. Native
reference paths execute RequestInfo and authorizer attribute extraction, native
RBAC, and actual UpdateResource/Store.Update for PUT. No adapter may manually
select the create-validation callback. Service allocation/body validation may
fail before extra authorization; a handler/store/strategy fixture omitting those
REST hooks is not a complete Service execution test. HTTP 404/422/conflict and
other unrelated errors remain control outcomes or reference failures, never
RBAC NoOpinion. Keep the existing Service name/body boundary visible.

Require concrete/SMT/native agreement, independently frozen positive and negative
controls, typed witness replay, source/module/runtime/input digests, strict
consumer audits, legacy canonical/profile goldens, adapter tampering tests and
cross-feature preservation cases. Every commit independently passes the clean
worktree build/regression checks; all previous conformance suites remain required.
The generic IR change also requires Kong regression/conformance validation.

Benchmark v2 first captures unchanged original contracts on main 6875743, then
separately tests expanded requirements, preregistered holdout projects, labeled
mutations/repairs and scale cases. Pin KubeLinter default/configured comparisons
and use native Kubernetes as the decision reference. Keep unsupported/error cases
in denominators; measure authoring effort honestly and never equate warning
counts with repair correctness or declare public hypotheses owner-reviewed.
Baseline/final runs use fresh external directories and preserve original evidence.

Privilege-escalation transitions, impersonation, unsafe deletion, newer-version
exec/token checks, admission, network-policy behavior, workload effects, live
clusters and live external-agent evaluation remain outside this milestone.
