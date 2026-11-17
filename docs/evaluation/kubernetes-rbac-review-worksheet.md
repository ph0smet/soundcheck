# Kubernetes RBAC pilot review worksheet

Copy privately for an authorized [RBAC pilot](kubernetes-rbac-pilot.md). This is
a human review aid, not a machine-readable contract or approval mechanism. Keep
completed forms and deployment data outside this repository.

## Inventory and authority

- Case ID, owner and sample-selection reason:
- Private authorization reference; permitted processing, retention and sharing:
- Kubernetes version, export/source dates and completeness basis:
- Original input/snapshot digests; preparation, inventory and bootstrap receipts:
- Applicable bindings, role references and aggregate contributors accounted for:
- Trusted usernames/groups and independent source for those attributes:
- Reviewed custom API catalogue and source identity, if used:
- Missing, unsupported or semantically changed/sanitized inputs:

## Approved intent

- Access profile; raw and canonical contract digests:
- Requirement owner/reviewer, approval reference and date:
- Required access, forbidden grants and rationale:
- Preserved identities/operations and exact allowed change scope:
- Baseline digest; frozen actor and targets/order if checking policy changes:
- Selected invariants required at S0 and every resulting state, if applicable:
- Requirements outside the model and unchecked deployment assumptions:

## Execution and independent review

- Verifier revision, solver version, selected profile and execution environment:
- Every scheduled input/candidate, digest, report, stderr and exit code:
- Evidence location and sharing classification:
- Outcome and phase: access / preservation / authorization / invariant / unknown:
- Independently expected behavior and the evidence supporting it:
- Owner assessment: intended behavior / confirmed requirement violation /
  possible model defect / unsupported / unresolved / no modeled violation found:
- Useful witness coordinates and granting rules, or missing diagnostic context:
- Separate target validation authorization and result, or “not run”:
- Proposed follow-up and whether it requires a new approved task:

## Effort and usefulness

- Inventory assembly and identity-review time:
- Requirement authoring and approval time:
- Result interpretation and repair-review time:
- Solver/run durations, recorded separately from human effort:
- Useful findings or avoided regressions and the owner's supporting explanation:
- Unexpressed requirements, unusable diagnostics and workflow friction:
- Existing review-process comparison, only where independently supported:

## Completion and sharing

- All selected cases retained, including unknowns, errors and unattempted cases:
- Sample size, selection bias and unresolved assumptions stated:
- Synthetic, public-derived and owner-reviewed deployment evidence distinguished:
- No live deployment, atomic rollout or autonomous-agent claim inferred:
- Exact public summary and any attached artifacts reviewed for sensitive data:
- Owner for follow-up, retention and deletion:
