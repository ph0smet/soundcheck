# Collection writes: synthetic Kubernetes RBAC conformance

This corpus checks opt-in contract schema 6 against Kubernetes v1.34.0. It adds
`create` and `deletecollection` initial authorization to schema 5's fixed eight
resource/group pairs. The inputs are synthetic, not an owner-reviewed deployment
or a comparison with a linter. No cluster is contacted and no API writes occur.

Both new verbs have an **empty effective authorization name** at the collection
endpoint. A create body containing `metadata.name` or `metadata.generateName`
does not supply that name to initial authorization. A collection DELETE with
`fieldSelector=metadata.name=settings` still has an empty authorization name;
GET/list/watch interpret that selector differently. These are authorization
attributes, not a model of which objects will be created or deleted.

Namespaced collection writes require a nonempty namespace in the supported
request domain. Nodes use an empty authorization namespace. Named POST and
all-namespace mutation paths are observed as explicit boundary controls and
rejected by the model. Successful parsing/authorization does not promise that a
route exists, a body or selector is valid, or an operation succeeds.

The [campaign](../conformance/run_collection_writes.py) reuses schema 5's frozen
catalogue and fixture builders, while keeping schema 6's request validator and
literal expectations separate. [inputs.json](inputs.json) pins all 119 generated
inputs, including expected decisions and comparison outcomes, before any
analyzer runs. The runner refuses changed, extra or missing pins. Original
policy bytes go to the pinned native authorizer without model normalization.

The standalone [contract.json](contract.json) requires Pod creation and a
ConfigMap read in `team-a`, and forbids bulk Pod deletion there. Its approved
change scope permits changing only that bulk-deletion decision. The corpus has:

- 20 policy matrices with 320 requests each: 6,400 literal/native/concrete/SMT
  comparisons. They cover exact/wildcard/wrong API groups and resources,
  `create` versus `deletecollection` versus named `delete`, local/cluster binding
  scope, additive grants, trusted groups, and already-resolved aggregates.
- Literal `resourceNames` controls: omitted or `[]` is unrestricted; `[""]`
  matches an empty authorization name; `["settings"]` and `["*"]` do not.
  A rule containing an empty-string name must not be discarded as restrictive.
- 19 contract and repair cases, including loss of required creation while reads
  still work, namespace include/exclude scopes, Node creation, and successful
  narrow repairs. Matched schema-5/schema-6 contracts show that changes solely
  to an unmentioned operator's Node creation or EndpointSlice bulk deletion are
  outside schema 5's preservation universe and detected by schema 6.
- 116 native URL/body shapes under four name-rule policies: 464 attribute and
  decision comparisons. Bodies include explicit names, generated names and
  malformed text. Selector controls include exact, repeated and malformed
  fields/labels; selector parsing flags are checked independently of RBAC.
- 36 schema-6 domain rejections (13 direct and 23 URL boundary controls), plus
  all 60 new-verb matrix requests rejected under the unchanged schema 5.
- Native/concrete/SMT replay of every contract and preservation witness, checking
  its frozen identity, exact resource discriminator, empty name, namespace,
  reported clause, approved-change boundary and actual decision difference.

The independent target behavior comes from pinned production
[`RequestInfo`](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/endpoints/request/requestinfo.go),
[authorization attribute projection](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go),
[API route installation](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/endpoints/installer.go),
[`RuleAllows`](https://github.com/kubernetes/kubernetes/blob/v1.34.0/plugin/pkg/auth/authorizer/rbac/rbac.go),
[exact name matching](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/apis/rbac/v1/evaluation_helpers.go),
and [binding resolution](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/rbac/validation/rule.go).
The reference-only URL adapter accepts an optional raw string body; it does not
parse it or substitute body fields for authorization attributes.

Run the complete pinned suite from the repository root:

```sh
bash bench/kubernetes-rbac/conformance/run.sh
```

Results appear in `_build/rbac-conformance/collection-writes/results.json`, with
frozen inputs, raw subprocess output, SMT matrices and witness replays under the
sibling `artifacts/` directory. Failed runs retain diagnostics and never report
completion. Input, imported campaign source, reference source/pins and binary
hashes are checked for mutation. Finite agreement is not a universal proof of
encoder or target-model correctness.

After the suite materializes its inputs, replay the narrow repair with:

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac compare \
  _build/rbac-conformance/collection-writes/artifacts/contracts/minimal-bulk-delete-repair/baseline.json \
  _build/rbac-conformance/collection-writes/artifacts/contracts/minimal-bulk-delete-repair/snapshot.json \
  --contract bench/kubernetes-rbac/collection-writes/contract.json \
  --format json
```

The expected result is `proved`: required creation and reads remain, bulk Pod
deletion loses its grant, and every modeled decision outside the approved change
scope is preserved. This concerns initial RBAC Allow/NoOpinion, not final API
denial, admission, execution, object contents or controller/workload effects.
