# Static RBAC coverage conformance

This synthetic corpus checks contract schema 9 against pinned Kubernetes
v1.34.0 and apiserver v0.34.0. It is separate from public deployment evaluation;
its hypotheses and mutations are deliberately constructed, not owner intent.

The fixed builtin catalogue has 223 resource/operation classes: the prior 99,
eight initial authorization verbs over 15 additional base resources, and four
conditional PUT classes for Services and Endpoints. Two explicitly reviewed
custom resources, each with status and scale, add 28 classes. Seven HTTP methods
cover canonical nonresource paths. Every resource/operation class includes both
frozen identities. The matrix has 4,146 requests and 24 policy experiments:
99,504 native/concrete/SMT comparisons. Forty-seven contract scenarios also
exercise frozen preservation; their finite native checks total 228,030.

These are initial authorization attribute classes, not a claim that every HTTP
route is installed. For example, RequestInfo maps DELETE `/api/v1/namespaces`
to `deletecollection`, while Namespace REST does not expose DeleteCollection.
Neither an initial grant nor a compound prerequisite proof establishes API
success, admission acceptance, valid request bodies, object existence or effects.

## Independent reference

The reference imports Kubernetes implementation code under its Apache-2.0
license; it does not implement RBAC rule resolution itself.

- `--coverage-urls` executes native `WithRequestInfo` and
  `GetAuthorizerAttributes`, then native RBAC. The complete authorization tuple
  is checked, including path, resource/nonresource classification, namespace,
  name, API group/version, subresource and frozen username/groups.
- The new builtin scopes are independently checked by calling their real
  native strategy `NamespaceScoped()` methods. This object-scope property does
  not override Namespace's special request attributes: a named Namespace URL
  uses its name as both `Namespace` and `Name`; a selected collection URL has
  an empty `Namespace`. The corpus distinguishes their RoleBinding resolution.
- Custom resource scope/subresources are trusted contract inputs. They are not
  inferred from RBAC policy or dynamically discovered, and the reference does
  not claim a particular custom API server's handlers are installed.
- `--put-reference` executes native RequestInfo, the authorization filter,
  `UpdateResource`, the real Service/Endpoints strategies, generic `Store.Update`
  and native `DryRunnableStorage`. Only storage Get/Versioner state is a fixture.
  The adapter never chooses or invokes the create-validation callback manually.
  Existing-object PUT checks update; missing-object PUT additionally checks named
  create against the same target and caller. Grants may come from different roles.
- PUT and SSA reference bodies are fixed valid examples. Service allocation
  hooks and admission are not installed in this handler/store experiment.
  Body validation and authorizer errors remain visible reference failures;
  they cannot be counted as RBAC NoOpinion. A Service authorization name such as
  `a.b` demonstrates that the authorization domain can exceed the body-name domain.

Native unit controls include all four PUT grant combinations, resourceNames,
separate grants, wrong bodies, missing-object PUT on the other six old base
resources, named Namespace versus field-selected collections, nonresource
discovery roots versus resource URLs, and custom namespaced/cluster routes.
Existing SSA and subresource reference modes retain their frozen semantics.

## Frozen inputs and acceptance

`inputs.json` hashes 204 generated artifacts, including independently authored
policies, expected decisions, contracts, change scopes, request matrices and
native function-linkage expectations. `source-pins.json` binds the upstream
sources. The input generator invokes no verifier or solver. Regeneration is an
explicit maintainer operation after semantic review, never a response to a
disagreement with Soundcheck.

The runner first binds input, runner, compiled binary and upstream source hashes
in `before-execution.json`. It checks linked Kubernetes module versions and
function/source locations. It requires complete exact case inventories and
counts, unchanged inputs/binaries, and replays every clause and preservation
counterexample through the native path. Finite native observations validate
fixture expectations; the Soundcheck CLI separately checks the symbolic frozen
contracts and preservation domains.

Required full acceptance includes six clause counterexample replays, six
preservation replays, 41 explicit domain rejections and 159 schema-8 exclusions.
The evidence-consumer unit suite corrupts attributes, branch stages, HTTP status,
frozen contracts, custom scope, request kinds, source linkage and completion
inventories to ensure malformed or partial evidence cannot pass.

Run this suite with the repository's complete conformance command:

```sh
bench/kubernetes-rbac/conformance/run.sh
```

Native-only development is available through `run_coverage.py --native-only`
with explicit `--reference`, `--module-metadata` and `--output` paths. It never
counts production agreement, domain rejections or witness replays as completed.
Generated results belong under `_build/` or an external evaluation directory.

The scope and public contract are specified in
[`docs/plans/2026-11-rbac-coverage-milestone.md`](../../../docs/plans/2026-11-rbac-coverage-milestone.md).
