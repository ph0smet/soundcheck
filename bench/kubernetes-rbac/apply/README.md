# Server-side apply authorization corpus

This synthetic campaign freezes schema-8 expectations against Kubernetes
**v1.34.0** / apiserver **v0.34.0**, before comparing production decisions.
It is an authorization experiment, not a public-deployment benchmark.

The two new operation classes are conditional scenarios:

| Operation | Native authorization requirements |
| --- | --- |
| `apply-existing` | Named `patch` |
| `apply-missing` | Named `patch`, then named `create` for the same identity and target |

The corpus does not discover whether an object exists. The caller freezes the
operation class in the contract. Only the eight existing **base** resources gain
these operations; all 83 schema-7 initial-authorization classes retain their
meaning. The complete schema-8 catalogue contains 99 resource/operation pairs.

The additional `create` check uses the nonempty URL name. A matching named
create grant can therefore complete SSA without authorizing collection POST,
whose initial authorization name is empty. Independent roles may supply the
two grants. A literal RBAC verb named `apply-missing` supplies neither grant.

## Independent reference

The new `rbac-oracle --apply-reference` mode invokes the pinned native
`WithRequestInfo` and `WithAuthorization` filters, `PatchResource`, field manager,
each resource's actual create/update strategies, and `genericregistry.Store`.
Native `DryRunnableStorage.GuaranteedUpdate` runs the generic store's callback,
which selects the existing/create branch and invokes validation. The local storage fixture implements
only `Get` and `Versioner`; it never chooses a callback, writes storage, starts
an API server, or contacts a cluster. Existing objects have both UID and
resourceVersion; missing objects have neither.

The deliberately valid synthetic bodies use `dryRun=All`, a fixed field
manager, `force=true`, and `NewDeducedTypeConverter`. Force avoids fixture field
ownership conflicts. The reference does not reproduce the full OpenAPI field
schema, admission chain, resource-specific REST allocation hooks, or deployment
effects. Its HTTP status observations demonstrate the bounded handler path,
not general request-body validity or operation success. The domain of
authorization names is wider than some body-validation domains (for example,
Service names); a failed body-validation replay must never be relabeled an
RBAC `NoOpinion` result.

The trace records every **executed** authorizer call with the full tuple,
alongside handler-entry/storage-read controls. Initial patch failure prevents
the create call. Soundcheck's human prerequisite diagnostics evaluate required
grants and are explicitly not execution traces. Native errors fail the campaign;
they cannot become passing denials. Initial legacy operations retain the
existing native RBAC attribute-query reference, without an API-success claim.

`--apply-reference-info` records compiled module versions and runtime method
source linkage. The consumer requires the pinned filters, handler, store,
dry-run implementation, and all eight strategy methods. `source-pins.json`
binds 28 upstream source files, including the native SSA integration test.

## Coverage and reproducibility

- 1,650 requests cover all 99 classes and both frozen identities, with named,
  empty-name collection, fresh-name, namespace, fresh-namespace, and
  all-namespaces collection representatives.
- 29 independent policy experiments produce **47,850** native/concrete/SMT
  comparisons, including conditional-stage checks on the native path.
- 39 contract/preservation scenarios produce **86,922** native finite checks.
  They retain functionality, distinguish named create from collection create,
  and preserve all context identities and operation classes. Changing an
  intermediate grant without changing a complete modeled decision is explicitly
  permitted by the preservation model.
- The full run additionally checks rejected requests, schema-7 exclusion of SSA,
  and concrete/native/SMT replay of reported contract/preservation witnesses.
  Finite agreement is not a proof that the implementation is correct universally.

`inputs.json` binds all **195** generated artifacts, including literal expected
verdicts/stages, contracts, input policies, catalogue, and method linkage. The
runner writes a `before-execution.json` receipt with input, source, module, and
binary hashes before starting an executable, and verifies stability afterward.
Exact counters, case inventories, execution mode, schemas, attributes, and
errors are checked by the consumer; `test_apply_runner.py` rejects corrupted
evidence independently of the verifier.

After building the pinned reference as described by the conformance runner:

```sh
python3 bench/kubernetes-rbac/conformance/run_apply.py \
  --native-only \
  --reference _build/rbac-conformance/reference-oracle \
  --module-metadata _build/rbac-conformance/kubernetes-module.json \
  --output _build/rbac-conformance/apply-native/results.json
```

For production comparison, omit `--native-only` and provide `--model`,
`--soundcheck`, and optionally `--z3`, as for the existing suites. Do not rewrite
expected outcomes to make production pass. `generate.py --kubernetes-source
PATH` is an explicit maintainer operation to freeze reviewed synthetic inputs
and independently acquired pinned native sources; conformance does not call it.

SSA subresources, PUT create-on-update, unsafe deletion, admission, and live
state inference remain excluded. In particular, Service status strategy
inheritance deserves its own native experiment; passing `forceAllowCreate=false`
alone does not establish that a subresource can never take a creation branch.
