# URL repair with controller and custom API preservation

These are synthetic, complete desired snapshots and independently specified
example requirements, not a deployment audit. `app` must read its leader Lease
and Widget and access `/healthz`, without a grant for `/metrics`. The separate
`operator` must retain its existing Widget status permission even though that
permission is absent from the access clauses.

Run from the repository root after building:

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac catalogue \
  bench/kubernetes-rbac/workflows/static-coverage/widgets.yaml --input-format yaml
dune exec soundcheck -- rbac coverage \
  bench/kubernetes-rbac/workflows/static-coverage/unsafe.json \
  --contract bench/kubernetes-rbac/workflows/static-coverage/contract.json
dune exec soundcheck -- rbac verify \
  bench/kubernetes-rbac/workflows/static-coverage/unsafe.json \
  --contract bench/kubernetes-rbac/workflows/static-coverage/contract.json --format json
# violated, exit 3: GET /metrics has an RBAC grant

dune exec soundcheck -- rbac compare \
  bench/kubernetes-rbac/workflows/static-coverage/unsafe.json \
  bench/kubernetes-rbac/workflows/static-coverage/repaired.json \
  --contract bench/kubernetes-rbac/workflows/static-coverage/contract.json --format json
# proved, exit 0: access requirements and all other modeled decisions preserved
```

`operator-regression.json` satisfies the explicit access clauses, so `verify`
proves them. Comparing it with `unsafe.json` fails preservation: the operator's
custom-resource status grant disappeared outside the approved `/metrics` change.
The frozen catalogue covers status even without a status clause. Removing it from
the candidate's copy of the contract cannot bypass a trusted frozen MCP/CI gate.

The catalogue command extracts the example CRD's API metadata for review. It
neither validates the full CRD nor changes the already-frozen contract. The
coverage command likewise reviews the domain and rule references without proving
access. These model-level checks assume complete policy, trusted identities and
correct frozen metadata; they do not establish live endpoint or deployment safety.
