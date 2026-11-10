# Explicit RBAC manifest preparation

This implements the approved practical-input slice: rendered YAML streams,
individual objects, generic/typed Lists, explicit namespace context and auditable
selection. The authorization model, frozen contracts and verification reports
are unchanged. The previous `rbac prepare EXPORT.json` behavior and schema-1
receipt remain compatible; broader preparation requires `--input-format`.

## Input and fidelity boundary

`--input-format json` reads one strict JSON value; there is no YAML fallback.
`--input-format yaml` reads every event through stream end into the exact-number
JSON representation. UTF-8, 16 MiB, 128 nesting levels, 4,096 documents and
250,000 nodes bound the reader. Empty YAML documents are accounted for; explicit
null is an invalid resource, and comments before the first explicit document
are a preamble rather than an extra document.

The pinned Kubernetes path uses YAML 1.1 resolution. Exact boolean/null spellings
retain their native types; canonical decimal int64 tokens retain their exact
values without a float intermediate. Quoted/block text and ordinary plain strings,
including quantities, version text and timestamps, stay strings. Other numeric
spellings/ranges, floats, explicit tags, anchors/aliases, merge keys, non-string
keys, duplicate decoded keys, invalid Unicode and NUL-producing escapes reject.
This applies even inside excluded resources. The source-span NUL guard accounts
for the OCaml YAML binding's C-string truncation; checking decoded strings alone
would miss the suffix. No Kong dependency or parser change is introduced.

References: [Kubernetes YAML serializer](https://github.com/kubernetes/apimachinery/blob/v0.34.0/pkg/runtime/serializer/json/json.go),
[pinned YAML conversion](https://github.com/kubernetes-sigs/yaml/blob/v1.6.0/yaml.go),
and the repository's existing [scalar-fidelity record](2026-10-yaml-scalar-fidelity.md).

## Selection and defaults

Retain all four native RBAC object kinds. Flatten only generic `v1/List` and the
four RBAC v1 typed Lists, with pagination validation at every container. Typed
items inherit kind/API version only when both are absent or empty strings;
partial or conflicting types reject. Generic List items require explicit types.
This restriction is narrower than the pinned upstream
[unstructured decoder](https://github.com/kubernetes/apimachinery/blob/v0.34.0/pkg/apis/meta/v1/unstructured/helpers.go),
which also permits heterogeneous explicit item types.

Only `--rbac-only` permits non-RBAC objects to be excluded. Unknown native RBAC
kinds/versions, RBAC kinds with conflicting API groups and unsupported List/`items`
wrappers reject, so their children cannot silently disappear. Kubernetes's
unstructured decoder recognizes `items` even without a `List` kind suffix. Excluded resources
receive input fidelity checks, not Kubernetes resource-schema validation. Zero
selected objects is an error in this new mode. Retained objects pass the unchanged
snapshot reader, including unbound roles, duplicate identities and unresolved
role references. Existing metadata/rule boundaries stay intact.

`--namespace NAME` fills absent/empty Role/RoleBinding metadata namespaces and
never overrides explicit namespaces. It is trusted defaulting context, not a
deployment fact or confinement restriction. Cluster objects and subject fields
are unchanged. Existing ServiceAccount matching uses a RoleBinding's effective
namespace; ClusterRoleBinding subjects still require one explicitly. Additional
upstream API-group defaults are deliberately not added.

References: [request namespace defaulting](https://github.com/kubernetes/apiserver/blob/v0.34.0/pkg/registry/rest/meta.go),
[subject matching](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/rbac/validation/rule.go),
[RBAC defaults](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/apis/rbac/v1/defaults.go).

## Schema-2 preparation receipt

Keep schema-1 identity/profile/hash/byte-count/object-count/removal/assurance
fields, changing only `schema_version` to 2 in the new opt-in mode. Add:

- `input_format`, `document_count`, `selection`, `namespace_context`.
- `retained_objects`: `source_path` and zero-based `snapshot_index`.
- `excluded_objects`: `source_path`, `apiVersion`, `kind`.
- `list_wrappers`: `path`, `apiVersion`, `kind`, `item_count`.
- `empty_documents`: original document paths.
- `defaulted_fields`: each `path` and inserted string `value`.

Source paths start at `documents[i]` and descend through `.items[j]`; metadata
removals name the original location. The receipt contains no removed metadata
values or policy content. Exact input/output hashes bind those external artifacts.
Both verification/completeness flags remain false. Parse and validate everything
before publishing a snapshot or receipt. Receipt files retain exclusive creation
and owner-only permissions, with no overwrite. No cluster, renderer or solver is
invoked by preparation.

## Acceptance obligations

Ordinary regression checks cover old preparation/receipt compatibility, typed
inference/defaulting/projection, unsupported inventory retention, complete-stream
failures, scalar precision, NUL/Unicode source guards, bounds and CLI publication
behavior. Independent conformance decodes ORIGINAL fixtures with the pinned
Kubernetes reader before comparing retained data, upstream typed policy inventories,
receipt provenance, reference/connector/SMT decisions and frozen-contract outcomes.
Receipt corruption controls must fail. Kubernetes's line-oriented chunk reader
can count a comment preamble differently from YAML documents; explicit empty
document fixtures avoid confusing those indices in the receipt audit.

These synthetic cases establish bounded acceptance evidence, not general YAML
compatibility, universal parser correctness, workload validation, complete cluster
inventory, or production deployment evaluation. Public benchmark inputs/results
remain outside the repository.
