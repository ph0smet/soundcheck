# Ordinary RBAC retirement and migration reference

This corpus freezes schema-2 ordinary `delete-existing` operations, mixed distinct-
target plans and named access clauses required throughout the transition. It uses
Kubernetes v1.34.0 request classification, initial RBAC, unchanged policy storage
wrappers, and generic `Store.Delete`/`rest.BeforeDelete` with fixture persistence.
Deletion uses empty DeleteOptions and complete snapshots without finalizers,
owners or deletion timestamps. A successful HTTP authorization is not a live
mutation or informer-visibility guarantee.

Expected decisions and state obligations are declared in `run_policy_retirement.py`
and sealed by `inputs.json` before comparison. The generator is an explicit
maintenance operation and is never run by acceptance. Native states are rebuilt
from frozen inputs independently of Soundcheck. All selected invariant state
samples and lifted negative witnesses replay against the real RBAC authorizer.
These finite checks supplement the versioned model; they are not a deployment
pilot, universal proof, or independently checked UNSAT certificate.

The suite covers named deletion (including empty/wrong names), all four policy
kinds, namespace/group authority, replacement-before-retirement, temporary access
loss and gain, baseline invariant failure, final-only repair goals, incomplete
revocation, actor authority loss, grant-then-use, and the 16-operation bound.
Strict reference, metadata, operation and immutable-invariant controls fail closed.
