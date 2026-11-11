# Kubernetes RBAC practical workflows

The original URL-rule rejection below is superseded by
[non-resource coexistence](2026-11-rbac-nonresource-coexistence.md). Current
preparation retains valid URL-only ClusterRole rules under profile revision 2.

After merging PR #63, Sourav chose preparation of JSON exports and CI repair
preservation ahead of broader RBAC semantics. Deliver two focused feature
commits on `feat/rbac-workflows`, with clean-worktree regression validation for
each. The named-get profile, strict verification input, frozen contract schema,
report schema and evidence formats keep their meaning.

## Explicit snapshot preparation

`rbac prepare EXPORT.json [--receipt NEW_FILE]` is offline preprocessing of one
strict JSON `v1/List`. It never contacts a cluster, filters objects/rules, fills
identities/namespaces, or approves a contract. It preserves the policy and
name/namespace/labels/annotations. The unchanged snapshot reader must accept
the entire result before any snapshot is emitted.

Discarded metadata is an allowlist, checked before removal: string UID,
resourceVersion and selfLink; nonnegative int64 generation; null or bounded
RFC3339 creationTimestamp. Timestamp acceptance validates Gregorian dates in
years 0001..9999, seconds 0..59, uppercase T/Z, optional 1..9 fractional digits,
and numeric offsets with hours below 24 and minutes below 60.

Only inert lifecycle forms are accepted: empty generateName, null deletion
fields, and null/empty ownerReferences, finalizers and managedFields. List
metadata permits string resourceVersion/selfLink, empty continue and null/zero
remainingItemCount. Unknown or malformed fields, active lifecycle data and
pagination markers fail closed. Aggregation, non-resource rules, duplicates and
missing references retain the original profile boundary. General YAML, typed
lists and individual objects are separate future input work.

The optional private, exclusively created receipt binds exact original and
prepared bytes, object count and sorted removed-field paths. Prepared bytes
include one trailing newline. Receipt schema 1 explicitly records that neither
verification nor completeness was established; it is not a verification bundle.
The snapshot remains an analysis artifact, not a deployment-ready manifest.

The pinned [ObjectMeta/ListMeta types](https://github.com/kubernetes/apimachinery/blob/v0.34.0/pkg/apis/meta/v1/types.go)
and [RBAC authorizer](https://github.com/kubernetes/kubernetes/blob/v1.34.0/plugin/pkg/auth/authorizer/rbac/rbac.go)
justify the bookkeeping/policy distinction. Independent acceptance compares
original and prepared typed policies and decisions through the upstream decoder
and authorizer, then concrete/SMT decisions and witness replay. Deliberately
changed policies must defeat that comparison.

Acquisition success, completeness and cross-resource snapshot stability remain
external requirements. Empty continuation can also mean a last page alone;
selectors and omitted resources cannot be inferred from bytes. Pinned
[`kubectl get` printing](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/kubectl/pkg/cmd/get/get.go)
can emit collected items before returning retrieval errors. Check the export
command's exit status. Ordinary cluster exports can still contain unsupported
aggregated/default roles; never remove them merely to obtain a proof.

## Trusted PR repair gate

The Action adds `mode: verify|repair`, default `verify`. Repair is supported only
for `connector: kubernetes-rbac` on pull requests. Both the contract and baseline
are regular blobs from the immutable event base commit; the baseline path is the
same fixed `config` path used for the candidate checkout. No baseline/ref override
or fallback to verification is available. The Action calls existing `rbac compare`.

Repair mode rejects push events: the current push contract source is the event's
after commit, whose config cannot establish preservation from the prior state.
Existing protected-default-branch push verification remains supported. Mode,
connector, config path, contract path and verifier/workflow sources are trusted
policy selections. Required checks and fresh-base reruns remain external.

Acceptance covers approved-blob sourcing under candidate edits, invalid modes,
missing/non-regular baselines, both temporary files and cleanup, contract failure,
valid repair and unrelated operator regression. Hosted smoke replaces one fixed
candidate path while retaining that path's original base blob. Comparison of
unchanged fixtures with themselves is insufficient evidence for preservation.
