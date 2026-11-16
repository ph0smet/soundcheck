# RBAC review workspace and transition stress

Sourav approved this addition on 2026-11-16 with “go ahead”, following the
proposal to combine the planned RBAC UI and bounded transition stress coverage
with the retirement/migration batch. Deliver on `feat/rbac-retirement-migrations`
in one PR with coherent commits. Present the combined tested diff before committing.

## Existing engine, explicit review

Add an RBAC workspace to the existing local Next.js application. Support frozen
access verification, before/after repair comparison, single policy changes and
ordered policy sequences, including retirement schema 2. Invoke the existing CLI;
do not add policy evaluation, intent inference or target semantics in TypeScript.
Keep the Kong interfaces and their strict acceptance boundary intact.

The operator supplies a reviewed contract and, when required, an original
snapshot. A structural review displays the engine's contract review, identities,
approved change scope, actor/order/invariants and selected assurance profile.
Review is not a proof. Lock the reviewed contract/baseline in the workspace while
editing candidates; replacing either explicitly invalidates the review and results.
This local UI is not an independent approval authority or a required CI gate.

Use exact input digests, current engine identity, strict versioned report shapes,
exit/result agreement and the engine's evidence to bind a run to its inputs.
Unknown versions, mismatched contracts/profiles, missing or corrupt evidence,
timeouts, cancelled runs and incomplete output never become a passing result.
Retain existing host/origin guards, bounded input/output and engine queue limits.
Do not persist private RBAC documents in browser storage by default or accept
arbitrary server paths. Evidence downloads must be bounded and contain only the
current invocation's validated private bundle, with safe relative paths.

## Review and presentation

Show the actual access verdict or outer repair/change/sequence outcome. Present
RBAC witnesses using identities/groups, API/resource coordinates and granting
rules, including URL requests and compound operation outcomes. `NoOpinion` is
absence of an RBAC grant, never a final API-server denial.

For sequences, show the declared order and per-state authorization, selected
invariants from S0 onward, final requirements and out-of-scope preservation.
Follow the engine's execution phases; a reported failure need not be the earliest
chronological defect. Distinguish checked, failed, skipped and not-selected
obligations. Never reconstruct a proof or infer a skipped success in the UI.

Expose the validated report, input provenance, assurance boundary and evidence
for inspection/download. Include existing synthetic workflow examples, labeled
as demonstrations. Keep a result attached to the exact run input; edits mark it
stale, cancellation clears the active run, and late responses cannot replace a
newer result. Use the established responsive, keyboard-accessible UI components.

## Deterministic transition stress

Add a repository harness using synthetic schema-2 sequences and independently
constructed expected outcomes. Vary inventory size, trusted identities, clauses
and ordered step count within the supported 1–16 limit. Include valid migrations,
temporary access loss/forbidden grants, revoked actor authority, preservation
regressions and explicit unsupported-boundary controls. Freeze generated inputs,
expected results and resource budgets before invoking the verifier.

Record every attempted run, exit code, result, duration, exact inputs and tool
identity. Timeouts/errors are retained as incomplete observations, never dropped
from timing or correctness accounting. Provide a small regression tier and an
explicit larger local tier with finite run/time/output budgets. Timings describe
these constructions; they establish neither worst-case scalability nor deployment
or live-agent performance. Do not change the frozen external public benchmark v2.

## Acceptance

Exercise all four UI modes against the real current CLI, including failed and
unknown outcomes, invariant S0 and intermediate failures, URL/compound witnesses,
old outer contracts and current access profiles. Test report/exit/input/evidence
tampering, unknown schemas, cancellation/stale-response handling and HTTP limits.
Run frontend lint, type checking, tests and production build; inspect the running
workspace on desktop and a narrow viewport. Run the stress smoke/full bounded
tiers, independently verify their frozen expectations and receipts, and run the
integrated repository regressions. Reuse the completed native semantics evidence
if engine sources remain identical; any engine fix requires relevant revalidation.

Owner-reviewed pilots, historical deployment studies and live-agent campaigns
still need their external inputs. Impersonation, multiple actors, repeated targets,
policy patch/apply and runtime effects remain outside this approved addition.
