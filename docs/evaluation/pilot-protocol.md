# Advisory deployment pilot protocol

The existing [local pilot runner](../../bench/pilot/README.md) and
[review worksheet](../../bench/pilot/review-worksheet.md) are the implementation
for this activity. A runnable synthetic exercise is already provided; it is
not a completed deployment pilot. This protocol defines what additional
evidence is required before reporting real deployment results.

The approved delivery scope uses synthetic inputs only. A real pilot remains
pending separately authorized configurations and owner-reviewed requirements;
this protocol does not authorize access to deployment data.

## Intake and frozen intent

Use a small explicitly authorized set of local Kong configurations. Keep the
configuration inventory, processing permission, owner identities, retention and
sharing decisions outside this repository. Record how each configuration was
selected, its Kong version/router, and whether credentials were removed. A
sanitized input may differ semantically from its deployed original; review and
record any consequential changes rather than assuming sanitization is neutral.

Have the policy owner state the intended denial and required access before
examining repair candidates. Author and review a supported contract separately
from the configuration. Record its canonical digest and approval privately.
Check relevant environmental assumptions, including source-IP integrity when
using a network contract. Explicitly record unexpressed requirements, such as
upstream destination or end-to-end availability; a proof of access decisions
does not establish them.

Create an explicit manifest using the existing `authorized-deployment`
provenance label only when justified. The runner cannot validate that label or
the approval record. Retain every selected case, including unsupported ones.
No partner outreach, deployment access, gateway requests or uploads are part
of the local runner or automatically authorized by a manifest.

## Execution and review

Run the existing pilot sequentially in advisory mode with stable local inputs
and the tested solver. Record the verifier revision, solver version, profile,
configuration and contract digests. Keep the minimized summary local until its
contents have been reviewed for sharing. Request richer CLI reports or evidence
bundles separately where permitted; they can contain sensitive information.

Use the worksheet for independent adjudication of each outcome. Distinguish
confirmed intended behavior, confirmed modeling defects, approximation
candidates, unsupported semantics and unresolved findings. A modeled violation
is not automatically a deployed vulnerability. If target replay is needed,
obtain the separate permission and controlled setup it requires; otherwise
record that it was not performed. Record authoring and review time explicitly,
rather than deriving them from solver time.

## Evaluation record and exit criteria

A complete pilot record identifies the authorized sample and frozen intent,
all scheduled outcomes, assumptions checked or outstanding, independently
adjudicated findings, unsupported/unexpressed requirements, authoring/review
effort, and concrete workflow feedback. Do not report a false-alarm or missed-
finding rate without an independently labeled reference set. Keep unknowns
and processing errors in the denominator. State sample selection and size;
one pilot is evidence about its inputs, not general production accuracy.

Use that record to prioritize useful contracts, diagnostics and conformance
work, and inform [connector selection](connector-selection.md). A synthetic
fixture run, an evaluator implementation, or a passing CI job does not complete
this protocol. The [repair benchmark](../../bench/repair/README.md) is a separate
evaluation of submitted candidates and should not be presented as deployment
feedback.
