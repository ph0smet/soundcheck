# Offline RBAC preparation controls

These are synthetic controls for explicit preparation of one JSON `v1/List`.
They are derived from the existing [RBAC fixture corpus](../fixtures/), with
known bookkeeping fields and inert lifecycle fields added. They are not live
cluster exports, deployment evidence or agent evaluation results.

The intended access policy stays fixed: the workload needs its ConfigMap grant,
must have no payments Secret grant, and a repair must preserve unrelated
permissions. Policy fields, labels and annotations must survive preparation
unchanged. The paired contract and identity context remain in
[`frontend-access.json`](../contracts/frontend-access.json); preparation does
not read or change them.

Try the source-only preparation command:

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac prepare \
  bench/kubernetes-rbac/preparation/fixtures/01-export-unsafe.json
```

Standard output is the prepared snapshot, not a verification result. The
optional `--receipt NEW_FILE` records exact original/prepared byte hashes,
sizes, removed field paths and object count. Both
`verification_performed` and `completeness_established` remain false.
For verification or comparison, explicitly pass the resulting snapshot to the
existing RBAC workflow.

The numbered fixtures include:

| Controls | Expected preparation |
| --- | --- |
| Unsafe, required-access loss, valid repair, remaining cluster/group grants, operator regression, exact-name leak and a NUL-bearing verb | Prepared; the original modeled behavior is retained |
| An already strict snapshot and an empty snapshot | Prepared; no invented objects or grants |
| Empty aggregate with no selected contributors (fixture 35) | Prepared; its original policy is retained |
| Invalid types, negative/overflowing generation, an invalid calendar date, duplicate keys and trailing documents | Rejected |
| Nonempty generateName, active deletion/ownership/finalizer/managed-field metadata | Rejected |
| Nonempty continuation token or remaining item count | Rejected as an explicitly incomplete page |
| Missing role references and unsupported aggregate states | Rejected; normalization cannot erase unsupported policy |
| Valid URL-only ClusterRole (fixture 36) | Prepared with its full rule retained; the existing Secret grant still violates the resource contract |
| Typed lists, duplicate objects and missing namespaces | Rejected |

`cases.json` pins each original fixture hash, upstream-adapter validity,
preparation outcome, exact removed-field paths and subsequent verifier
expectations. A reference-valid input can still be outside preparation's
supported scope. This distinction is deliberate: API validity does not establish
snapshot completeness or supported verification semantics.

## Independent acceptance

Run the existing explicit reference command:

```sh
bash bench/kubernetes-rbac/conformance/run.sh
```

The preparation runner adds checks without changing the original 29-case suite:

1. Decode, default and validate the **original bytes** with pinned Kubernetes
   v1.34.0 types. Invalid metadata cannot be laundered by removing it first.
2. Run the actual preparation CLI and validate its exact-byte receipt. Check
   independently that the resulting JSON is the original AST minus only the
   inventory's fixed removal paths. Empty metadata containers, object/rule
   order, strings, labels and annotations must remain.
3. Decode the prepared input independently with the same pinned upstream code.
   Compare its typed role/binding inventory with the original, retaining
   subjects, references, all rule fields, aggregation, labels and annotations.
4. Compare original Kubernetes decisions, prepared Kubernetes decisions,
   Soundcheck's concrete decisions and its production SMT encoding for every
   request in the fixed matrix.
5. Run real verification and repair comparison. Replay every reported
   counterexample through both original and prepared upstream snapshots, and
   through the connector/SMT path. Preservation witnesses must remain outside
   the approved change scope and demonstrate an actual before/after change.
6. Reject deliberately corrupted preparations: a dropped binding, widened
   resource names, changed subject, changed annotation, and an added `watch`
   permission. The added verb intentionally leaves the named-`get` matrix
   unchanged; typed-inventory comparison must still catch it.

Results are separate at `_build/rbac-conformance/preparation/results.json`.
The original suite retains `_build/rbac-conformance/results.json`. The combined
command must exit zero; a successful original matrix alone does not establish
preparation conformance. Both reports retain input and executable hashes and
check that their inputs stayed unchanged.

The checked-in corpus contains eleven accepted and twenty-one rejected preparation
controls. The current matrix supplies 3,300 four-way preparation comparisons,
eight contract-witness replay requests and two preservation-side replay requests.
Each replay checks both original and prepared upstream inputs. These finite
checks support the implementation; they are not an independently checked proof
of the preparer, parser, encoder or deployed authorization behavior.

## Boundaries

Only one strict JSON `v1/List` is accepted. There is no typed-list conversion,
general YAML input, namespace inference, Kubernetes client, pagination fetching,
object selection or controller execution. Explicit nonempty pagination markers
are rejected, but empty markers do not establish that every applicable binding
was supplied.

A complete cluster export can contain stale or cyclic aggregates that remain
outside the verifier's profile. Already-resolved acyclic aggregates must satisfy
the [complete-policy consistency check](../../../docs/kubernetes-rbac.md#already-resolved-aggregated-clusterroles).
Valid URL-only ClusterRole rules are retained
and have no resource-request grants; their URL authorization is not verified.
Preparation does not remove objects merely because they appear unrelated to the
current contract. The separate [coexistence suite](../nonresource/README.md)
checks malformed resource/URL mixtures and namespaced URL-rule rejection.
It does not establish that applying a partial manifest deletes omitted live
bindings. The existing complete-snapshot and trusted-identity assumptions still
apply.
