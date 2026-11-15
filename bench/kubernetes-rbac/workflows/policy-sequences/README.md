# Frozen ordered RBAC repair

This synthetic workflow removes two independently bound Secret grants from
`app`. `deployer` may update the two named roles and already covers their proposed
ConfigMap/Pod permissions. The frozen contract orders `app-reader` first, then
`app-reader-secondary`. Each write uses the permissions in its preceding state.

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac sequence \
  bench/kubernetes-rbac/workflows/policy-sequences/before.json \
  bench/kubernetes-rbac/workflows/policy-sequences/repaired.json \
  --contract bench/kubernetes-rbac/workflows/policy-sequences/contract.json \
  --format json
```

The repaired candidate passes. After its first edit, the secondary role still
grants Secrets; final requirements hold after the second edit. ConfigMap access
remains required, and existing Pod access is preserved outside the approved
Secret-change scope at every state.

| Candidate | Expected result |
| --- | --- |
| `repaired.json` | `valid_sequence` |
| `authorization-failed.json` | Uncovered Deployment delete rule fails authorization at step 1 |
| `contract-failed.json` | Final state loses required ConfigMap access |
| `out-of-scope-regression.json` | Final state loses unapproved Pod access |
| `intermediate-regression.json` | Final state restores Pod access, but step 1 temporarily loses it |
| `before.json` | Unsupported no-op plan |

`reverse-contract.json` reverses the approved order. Under that separate contract,
`intermediate-regression.json` passes because the secondary role receives Pod
access before the first role loses it. The candidate cannot change the contract
or select this order inside the frozen MCP/CI workflow.

The separate `transient-gain-contract.json`, `transient-gain-before.json` and
`transient-gain-after.json` control activates a binding before restricting its
role. Final access is correct, but step 1 temporarily grants Secrets outside the
empty approved change scope; intermediate preservation rejects it.

For private evidence, append `--evidence-dir /tmp/rbac-sequence-evidence` with a
new private local output directory. Sequence evidence stores full original,
intermediate and final snapshot contents in `states/`. For config-only repair
feedback, start:

```sh
dune exec soundcheck -- mcp --connector kubernetes-rbac \
  --contract bench/kubernetes-rbac/workflows/policy-sequences/contract.json \
  --baseline bench/kubernetes-rbac/workflows/policy-sequences/before.json
```

The only tool is `sequence`; its input is the complete replacement configuration.
The server keeps its startup actor, ordered targets, requirements and original
inventory. In trusted PR CI, select `connector: kubernetes-rbac` and
`mode: sequence`, with the contract and baseline taken from the approved base.

See the [sequence boundary](../../../../docs/rbac-policy-sequences.md).
These fixtures are implementation checks, not live-agent, deployment or
public-benchmark results.
