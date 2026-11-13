# Conditional RBAC authorization for server-side apply

After PR #75, Sourav approved this bounded schema-8 scope on 2026-11-12:
retain every schema-7 initial request class and add server-side apply (SSA)
for the eight existing base resources. Preserve schemas 1–7 without changing
their canonical identities, profiles or quantified domains. The shared IR,
solver and report schema 10 stay unchanged.

## Contract and decision model

Schema 8 requires `operation` instead of `verb` in every clause and approved
change scope. Existing verb strings remain operation IDs. Two additional IDs
denote **hypothetical object-state branches**, not observed cluster state:

| Operation | Required RBAC checks for the same caller and target |
| --- | --- |
| `apply-existing` | Named `patch` |
| `apply-missing` | Named `patch` AND named `create` |

Both require a nonempty URL target name and `subresource: ""`. Resources are
core ConfigMaps, Secrets, Pods, Services, Endpoints and Nodes, apps Deployments,
and discovery.k8s.io EndpointSlices. Nodes require `namespace: null`; the other
seven require nonempty namespace scopes. Existing DNS bounds and literal
namespace/name set or complement selectors remain in force. SSA empty-name
selectors reject. The full catalogue has 99 resource/operation combinations:
the previous 83 plus two SSA classes over each of the eight base resources.

For a native authorization verb v, let G_v be the additive union of applicable
RBAC grants evaluated at the operation's identity, groups and target coordinates.
The two predicates are G_patch and G_patch AND G_create. The latter create check
uses the **same nonempty name**, unlike ordinary collection `create`, whose
initial authorization name remains empty. Different roles may grant each stage.
No extra `get` or `update` permission is required by this model.

`must_allow` on `apply-missing` requires both grants; `must_not_grant` requires
at least one prerequisite to lack a grant. It must not be rewritten into two
independent prohibitions. Lack of a prerequisite is projected to `NoOpinion`;
this is not an explicit RBAC deny or a final API-server decision.

Repair preservation quantifies every initial and SSA operation class for every
frozen identity, even dimensions absent from clauses. Approved changes exclude
only their exact operation class. Ordinary `patch` and `apply-existing` share
an authorization predicate but remain distinct classes: approving a change to
one does not implicitly approve the other. Preservation concerns aggregate
operation decisions, not every intermediate grant. For example, changing named
create while patch remains ungranted does not change `apply-missing`.

## Lowering and explanations

Keep native grant predicates in the connector. Derive SSA rules by specializing
their action coordinate to each native check and composing unions of grants,
avoiding a quadratic cross-product of granting rules. The complete compound
predicate belongs in an exact rule match, with an unconditional guard and the
same additive Allow semantics. Do not restrict the internal named-create check
using the standalone empty-name collection-create domain.

Report `action` values are operation IDs. Successful SSA explanations identify
the actual binding/rule contributors with `patch:` and `create:` prefixes;
synthetic derived-rule IDs must not masquerade as source grants. Failed compound
operations have no complete grant set and explain the missing prerequisites in
their human/GitHub note; ordinary report JSON does not serialize that note.
Preservation witness descriptions include baseline and candidate stages.

Profile `kubernetes-rbac-v1.34-apply-v1` uses profile JSON schema 5. Each resource
domain enumerates operations with `operation`, `checks` (native verb strings),
`object_state` (null for initial requests, `existing` or `missing` for SSA),
`name_domain` and `namespace_domain`. State is a hypothetical branch condition.
Contracts, CLI evaluation requests, review, evidence, immutable MCP, trusted-base
CI and the submitted-repair evaluator use the same frozen operation semantics.
Schema-8 evaluation requests use `operation`; schemas 1–7 retain `verb`.

## Independent target basis

Kubernetes v1.34.0's [SSA documentation](https://v1-34.docs.kubernetes.io/docs/reference/using-api/server-side-apply/#access-control-and-permissions)
describes patch permission and the additional create requirement when missing.
The pinned [PATCH handler](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/patch.go#L203)
constructs additional create attributes from the original caller and URL target,
including its nonempty name. SSA sets forceAllowCreate. The real
[generic store](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go)
chooses create validation on its missing-object path, after object transformation
and create validation prerequisites. Existing objects use update validation.
The native [integration test](https://github.com/kubernetes/kubernetes/blob/v1.34.0/test/integration/apiserver/apply/apply_test.go#L4865)
independently exercises missing patch, missing create and successful authorization.

Reference conformance must execute actual RequestInfo, authorization filter,
PatchResource, native resource strategies/field management, generic Store.Update
and DryRunnableStorage with deterministic storage state. Only storage Get and
version metadata are fixtures; an adapter must not manually select or invoke the
create authorization callback. Existing fixtures have consistent UID and resource
version; missing fixtures have neither. This tests handler/store authorization,
not complete resource REST execution such as Service allocation.
Fixtures use valid bodies, `dryRun=All`, `force=true` and the native field manager
with a deduced type converter; admission and full installed OpenAPI field schemas
are not exercised. The authorization-name domain is broader than some body-name
validators (notably Services). A body-validation failure during replay must stay
visible as a reference failure, never become an RBAC `NoOpinion` result.

Freeze independent inputs and source-derived expectations before comparing with
Soundcheck. Bind results to source/module/input/tool hashes and reject incomplete
or mismatched evidence. Check all resource branches, permission combinations,
separate-role grants, literal resourceNames, namespace/group/identity isolation,
initial patch short-circuiting and invalid body/target controls. Compare native,
concrete and SMT decisions; replay contract and preservation witnesses natively.
Include unmentioned identities/operations, partial and deny-all repairs, exact
scope coupling, strict rejected selectors and unchanged legacy goldens. Exercise
all adapters and same-schema/downgrade tampering. Full regressions and previous
native suites remain required; eventual coherent commits each need clean-worktree
validation.

## Boundary

The result verifies conditional RBAC prerequisites. It does not observe object
existence, establish a successful API operation, model other authorizers, body
validity, field ownership conflicts, admission, races, controller effects or
indirect privilege escalation. Supported initial operations retain their previous
initial-authorization-only meaning. No request bodies or cluster state enter the
production verifier. SSA subresources, PUT create-on-update, unsafe deletion,
newer exec checks and token-audience checks require separate scopes and evidence.
Public benchmark artifacts remain external and unchanged; no live cluster or
live-agent evaluation is part of this implementation.
