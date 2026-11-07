# Kubernetes RBAC

Soundcheck checks paired access requirements and repair preservation for a
bounded static RBAC profile. CLI and library workflows share the decision IR,
encoder, Z3 backend and witness validation with the Kong connector.

## Try the workflow

Build using the [quickstart](../README.md#quickstart), then run from the repo root:

```sh
eval "$(opam env)"
dune exec soundcheck -- profile kubernetes-rbac
dune exec soundcheck -- rbac verify \
  bench/kubernetes-rbac/fixtures/01-unsafe.json \
  --contract bench/kubernetes-rbac/contracts/frontend-access.json --format json
```

The example requires `system:serviceaccount:frontend:frontend-sa` to have `get`
access to every valid named ConfigMap in `frontend`, without a `get` grant for
any named Secret in `payments`. The unsafe snapshot violates that requirement
and exits `3`. Its counterexample names the identity, namespace, resource,
object name, groups and granting binding/role/rule. Solver-selected names vary.

```sh
dune exec soundcheck -- rbac compare \
  bench/kubernetes-rbac/fixtures/01-unsafe.json \
  bench/kubernetes-rbac/fixtures/03-valid-repair.json \
  --contract bench/kubernetes-rbac/contracts/frontend-access.json --format json
```

This exits `0`: the replacement meets both clauses and preserves decisions
outside the approved change scope. `verify` alone does not check preservation.

| Candidate fixture | Expected behavior |
| --- | --- |
| `01-unsafe.json` | Unwanted Secret grant violates the contract |
| `02-delete-workload-grants.json` | Required ConfigMap access is lost; repair fails |
| `03-valid-repair.json` | Contract holds and other decisions are preserved |
| `04-leftover-cluster-grant.json` | Another ClusterRoleBinding still grants access |
| `05-group-grant.json` | Group membership still grants access |
| `16-operator-regression.json` | Workload contract holds; comparison catches the operator's lost permission |

These are synthetic snapshots, not production or live-agent evaluation results.

## Frozen contract

Start from the complete [example contract](../bench/kubernetes-rbac/contracts/frontend-access.json).
The strict JSON schema requires:

- `schema_version: 1` and `kind: "kubernetes-rbac-access"`.
- `context`: schema version 1, `snapshot_complete: true`, and nonempty unique
  usernames with exact, duplicate-free group lists.
- `clauses`: uniquely named `must_allow` and `must_not_grant` requirements, with
  at least one of each. Every clause selects a declared `subject`, one
  `namespace`, a `resource` (`configmaps` or `secrets`), and `names` (`null` for
  all valid names, or a nonempty list of literal names).
- `change_scope`: the only request classes whose decisions a repair may change,
  using the same subject/namespace/resource/names selectors. An empty list
  requires complete decision preservation within the profile.

The verb is always `get`, the API group core (`""`), and the subresource empty.
Unknown versions and scope fields are rejected. RBAC rule `resourceNames: ["*"]`
is literal, whereas rule verbs, API groups and resources support `"*"` wildcards.

Review and protect the contract and baseline independently of the candidate.
The CLI accepts no identity/group/property/scope overrides. Reports carry the
canonical frozen contract, including its context and approved change scope.
This does not sandbox an agent that can replace those files or the verifier.

## Supported profile

`kubernetes-rbac-v1.34-get-v1` references Kubernetes v1.34.0 and supports:

- One strict JSON Kubernetes `v1/List` of RBAC v1 Roles, ClusterRoles,
  RoleBindings and ClusterRoleBindings. JSON is also valid YAML; general YAML
  syntax and multiple documents are not accepted.
- Explicit object names/namespaces and validated labels/annotations. Other
  metadata, including live-export bookkeeping, is outside the first input format.
- Exact User, Group and ServiceAccount subjects. An omitted ServiceAccount
  namespace defaults to its RoleBinding's namespace; ClusterRoleBindings
  require it explicitly. User/Group and roleRef API groups must be explicit.
- Additive grants, local and cluster role references, namespace-scoped bindings,
  cluster-wide bindings, literal resourceNames and supported wildcards.
- Named `get` requests for core ConfigMaps/Secrets. Namespaces are DNS1123 labels
  of 1..63 bytes; object names are DNS1123 subdomains of 1..253 bytes.

All supplied objects are checked, including unbound roles and unrelated
bindings. Malformed input, unknown fields, duplicate identities, missing
references, aggregation rules and nonResourceURLs return `unknown`. Escaped
NULs remain distinct; duplicate JSON keys, invalid Unicode and trailing data
are rejected. Unsupported forms are never silently discarded.

**Completeness is an external assumption.** Resolving every supplied role
reference does not establish that all applicable bindings were included. The
input describes complete desired policy state: applying a partial manifest
does not delete omitted live bindings. Deployment reconciliation must establish
the state that was verified.

**No grant is not final denial.** The decision is RBAC `Allow` versus
`NoOpinion`. Other authorizers, authentication, impersonation, admission, object
existence, aggregation/reconciliation controllers, mutation and escalation
checks are outside the model. Restrictions on `get` do not rule out Secret
exposure through `list`, `watch`, pod creation or other indirect paths.

Preservation ranges over all supported valid namespace/name strings for the
frozen identities, not just namespaces present in the input. It excludes
identities, verbs, resources and control planes outside the profile.

## Output and integrations

Both RBAC commands emit report schema 10. Violations include `object_request`,
`identity_groups` and `granting_rules`; legacy HTTP fields are empty/null.
Preservation uses a `must_preserve` clause with before/after RBAC decisions in
its description. Only `proved` exits `0`; violation/unknown/vacuous/inconsistent
exit `3`/`4`/`5`/`6`. I/O and usage failures exit `1` and `2`.

RBAC exposes CLI and library workflows. MCP, the reusable Action, the web UI
and `--evidence-dir` remain Kong-specific. The conformance harness retains its
synthetic SMT queries and target replays; this is not a user-facing RBAC bundle.

## Validation

Ordinary `dune test` runs parser, core, contract, preservation and CLI regressions
without Go or network access. The [reference harness](../bench/kubernetes-rbac/conformance/README.md)
compares concrete and production SMT decisions with Kubernetes' actual pinned
authorizer, on original input bytes, and replays CLI witnesses. Finite agreement
is implementation evidence, not proof of parser/encoder correctness or a live
cluster guarantee.
