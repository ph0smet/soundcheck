# Aggregate snapshot conformance inputs

These are synthetic acceptance controls, not deployment evaluations. The fixed
contract requires `app` to get `team-a/configmaps/settings` without granting
Secret get in that namespace. Only that Secret access class may change during
repair. The separate `operator` identity's modeled decisions must be preserved.

[`run_aggregation.py`](../conformance/run_aggregation.py) declares 34 policies
and their independent expected grants. `inputs.json` pins every generated input
and expected-rule artifact by exact byte count and SHA-256. Changing a fixture
requires reviewing its expectations and pins; the runner never updates pins.
`contract.json` is frozen independently of candidates.

The campaign includes label equality, all four selector expression operators,
AND/OR selection, missing versus empty labels, self-selection, nested roles,
empty results, unbound aggregate roles, reordered/duplicate rules, URL rules,
other resources/API groups, stale materializations, cycles and invalid selectors.
Fifteen snapshots are supported; nineteen are rejected by the bounded model.
API-valid rejected snapshots are distinguished from malformed native input.

The independent reference runs Kubernetes v1.34.0's **production aggregation
controller** with an in-memory client and informer. It does not compute the
connector's dependency graph. A separate reference-only copy starts each
aggregate with a sentinel rule, and the runner requires observing a controller
update for every aggregate before its predeclared expected rule sets are reached.
This exercises empty outputs as well as nested propagation. The source policies
are never overwritten. Seeded snapshots, native applies and the captured native
permission state are retained as artifacts. The fake storage increments resource
versions on every native apply so informer update events re-enqueue dependent
roles. A deterministic parent-before-child unit check exercises that propagation.

Supported cases additionally compare 272 requests each against independent
fixture expectations, the native RBAC authorizer, concrete connector evaluation
and production SMT. Preparation must retain the full native-typed policy.
Reported contract and preservation witnesses replay against native authorization.
The stale-empty control demonstrates how native aggregation adds a grant absent
from stored empty rules. A separate safety control retains required ConfigMap
access but omits a selected Secret grant: the controller adds forbidden access
that trusting the stale stored rules would miss. Two repair comparisons distinguish
an approved narrowing from loss of the unrelated operator's access.

Run through `bash bench/kubernetes-rbac/conformance/run.sh`, or invoke the Python
runner with the same reference/model/CLI/module-metadata/Z3 arguments. The runner
records input/tool hashes and checks all campaign counters before marking success.

This establishes finite target agreement for the fixed fixtures. Reaching an
expected state in the in-memory controller is not a proof of live convergence,
timing, intermediate-state safety, API mutation effects, inventory completeness,
or correct authentication. URL permissions and other resource domains remain
outside Soundcheck's verified request domain even though their full policy rules
must be retained and checked when validating aggregation consistency.
