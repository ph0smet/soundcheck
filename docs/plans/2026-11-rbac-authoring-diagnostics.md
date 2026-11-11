# RBAC contract authoring and diagnostics

This implements the approved P1 authoring/diagnostics slice after non-resource
coexistence. It adds an offline review aid and an independently specified synthetic
walkthrough. It does not add authorization semantics, contract schemas, generated
intent, workload parsing, authentication discovery or a deployment pilot.

## Contract-only review

`soundcheck rbac check-contract CONTRACT.json` delegates to a connector-library
renderer using the existing strict `Contract_spec` reader. It accepts a regular
local file, at most 16 MiB, and emits human text only. No candidate, flags that
replace intent, solver, cluster, file writes or new machine report schema are
involved. Exit 0 means structural acceptance, 2 invalid input/usage and 1 I/O
failure. It must not be substituted for a verification gate.

The review displays the contract-selected profile as information, raw and
canonical hashes as distinct identities, exact declared users/groups, clauses in
their original order and normalized approved-change scopes separately. Supplied
strings are quoted and control characters escaped. Counts measure artifact size,
not elapsed authoring effort. Descriptions reuse existing scope meanings without
changing verification reports. The no-verification statement is prominent:
inhabitation, consistency, access and preservation remain unchecked. For example,
structural acceptance must not hide the absence of a consistency check.

## Diagnostic boundary

Improve rejected-input field paths and messages for unknown identities,
namespace/name selectors, version-specific verbs, resources, completeness
assertions, duplicate identities/objects, aggregation and unresolved role
references. Preserve accepted inputs, canonical ordering/hashes, all four
assurance IDs and existing report/receipt schemas. Preserve complete missing-role
lists and source provenance. Explain how to supply reviewed input; never suggest
weakening requirements, fabricating identity groups, deleting unrelated grants,
stripping aggregation or asserting completeness just to pass.

## Independent example

The v4 example's requirement precedes its snapshots: the workload may get only
`settings` in `team-a` and `team-b`. The caller ServiceAccount lives in `platform`.
The paired complement clauses cover other names and other nonempty namespaces;
those exact forbidden classes are the only approved changes. A separate operator
has no approved changes. Trusted group memberships are supplied explicitly.

Expected controls are unsafe broad grants, a narrow valid repair, removed required
access, a retained broad group grant and an operator-only preservation regression.
The clauses cover ConfigMap get; comparison preserves all other modeled decisions
for both identities. The Deployment excerpt is manual context, not verifier input
or an assertion that a workload actually authenticates with those credentials.

Acceptance includes contract-reader compatibility and canonical identities,
literal escaping, no-solver CLI operation, unchanged verification failure behavior,
and runtime checks of the fixed example outcomes. Native Kubernetes comparisons
check the example's request decisions and reported witnesses. Real human authoring
time, operator-reviewed intent and real deployment evaluation remain pending.
