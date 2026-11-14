# Explicit bootstrap reference packs

`soundcheck rbac bootstrap` emits selected upstream Kubernetes policy for use as
an **explicit inventory assumption**. It does not inspect missing role references,
contact a cluster, add bindings, infer groups or establish installed policy.

The current catalogue is pinned to Kubernetes **v1.34.0 with upstream default
feature gates**. It has four packs:

| Pack | Emitted objects |
| --- | --- |
| `cluster-admin` | `ClusterRole/cluster-admin` |
| `view` | `ClusterRole/view` and its `system:aggregate-to-view` contributor |
| `auth-delegator` | `ClusterRole/system:auth-delegator` |
| `extension-apiserver-authentication-reader` | The same-named Role in `kube-system` |

Specify each needed pack explicitly. Unknown versions, unknown packs, duplicate
selections and an empty selection reject. Object order is canonical; the receipt
also records the caller's requested order and every dependency. Selection is
offline and requires neither Go nor Z3 in the installed verifier.

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac bootstrap --kubernetes-version 1.34.0 \
  --pack view --pack auth-delegator --receipt bootstrap-receipt.json \
  > bootstrap.json
shasum -a 256 bootstrap.json
```

Use a new receipt filename. The command emits one JSON `v1/List`; the receipt
binds its exact bytes including the final newline, the full embedded source
catalogue, upstream module/commit, effective feature-gate profile, selected
objects and preparation transformations. Successful selection exits zero; it
is not a verification gate. Source/argument errors exit 2; I/O errors exit 1.

Review the result against authorized exports from your deployment. Only then
add it as another source to an existing `rbac inventory` plan:

```json
{
  "id": "reviewed-bootstrap",
  "path": "bootstrap.json",
  "format": "json",
  "sha256": "<replace-with-the-reviewed-file-sha256>",
  "source_type": "bootstrap-reference",
  "source_version": "Kubernetes v1.34.0 upstream defaults"
}
```

The other sources still retain every supplied RBAC object. Neither this command
nor inventory assembly overwrites a same-named role. Duplicate identities reject
even when their bytes agree. Missing references not covered by an explicitly
selected pack still reject. Installed default roles can be customized or extended;
use their actual exported policy in that case instead of a same-name reference.

## Aggregated `view` is a bounded bootstrap assumption

The native generator checks `view`'s selectors against all 68 roles returned by
the pinned `ClusterRoles()` plus `ControllerRoles()` registry. It then runs the
production aggregation controller on that independently checked closure. The
pack retains `view`'s aggregation selector, materialized rules and matching
unbound contributor. It never replaces the aggregate with a plain role.

`DynamicResourceAllocation=true` affects the pinned contributor's rules and is
recorded explicitly. All selected rules and metadata are preserved, including
references outside the verifier's current authorization domain. Full registry
hashes detect a different effective default configuration during regeneration.

Supplying another role labelled `aggregate-to-view=true` can make the bootstrap
materialization stale. Ordinary inventory validation rejects that union; the
selection command does not reconcile or silently remove the added policy. Review
and supply the real already-resolved aggregate and complete contributor inventory.
The packs cannot establish that an omitted contributor does not exist live.

## CRD metadata is a separate reviewed input

RBAC manifests often name custom resources without including their CRDs. The
bootstrap packs do not invent that metadata. Acquire a separate, version-pinned
CRD bundle from an authorized export or the reviewed release of the controller:

```sh
dune exec soundcheck -- rbac catalogue reviewed-crds.yaml --input-format yaml \
  --receipt crd-catalogue-receipt.json > custom-resources.json
```

If the bundle contains other objects, choose `--crd-only` explicitly and review
the exclusions. Review group, plural, scope and served status/scale availability,
then copy the approved catalogue into the independently frozen access contract.
Do not derive it from the candidate RBAC rules being repaired. The command checks
the whole parsed input; a malformed mixed YAML bundle can still reject. A separate
CRD-only JSON export is an explicit alternative input with its own provenance,
not permission to drop malformed objects silently. Keep the raw source and
record the source/version and extraction process alongside the receipt.

## Reproducibility and independent acceptance

The derived policy uses Kubernetes' Apache-2.0 license; see
[KUBERNETES-LICENSE](KUBERNETES-LICENSE). [provenance.json](provenance.json) binds
the selected registry, source and artifact checksums. No public benchmark inputs
or results are included here.

Build the pinned reference oracle using the
[conformance instructions](../conformance/README.md), then check the source data
and its compiled OCaml embedding without changing either:

```sh
python3 bench/kubernetes-rbac/bootstrap-packs/generate.py \
  --reference _build/rbac-conformance/reference-oracle --check
```

The native conformance suite regenerates the complete artifact and audits all
15 nonempty pack combinations. Kubernetes independently decodes each original
and prepared manifest and compares full typed rules, selectors, labels and
annotations. Adversarial receipt tests reject altered hashes, dependency claims,
versions, feature gates and completeness assertions. Library/CLI checks exercise
missing references, collisions, custom aggregate contributors and receipt writes.
