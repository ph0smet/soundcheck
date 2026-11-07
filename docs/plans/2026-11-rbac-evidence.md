# Kubernetes RBAC evidence

Sourav approved verification and repair-comparison evidence on 2026-11-08,
as two focused feature commits on `feat/rbac-evidence`. This adds audit artifacts
to the existing named-get profile; it does not expand RBAC semantics or add
MCP, Action, web UI, live-cluster or model-runtime integration.

Verification exposes the shared contract engine's complete trace from the same
execution that produces the report. `rbac verify --evidence-dir` reuses evidence
schema 2 and the existing exclusive writer. Kong schema-2 bytes and consumers
remain unchanged. All planned queries are retained, including unexecuted ones;
only validated models may enter traces. Unsupported snapshots have no plan;
invalid contracts cannot produce a frozen bundle.

Comparison adds a separate schema-3 manifest with operation `repair_comparison`.
It binds exact before/after byte digests and sizes, the frozen contract, assurance
profile, provenance, candidate-contract report and final report. Its plan includes
candidate obligations and a distinct preservation query, prepared before solving.
Preservation executes only after a candidate proof; otherwise it remains explicitly
unexecuted. If parsing/lowering prevents planning, the candidate report is absent
and the plan unavailable. The collector reads each snapshot once and never reruns
verification for evidence. A complete comparison proof requires both a candidate
proof and executed UNSAT preservation.

The manifests are published last into new private directories. Payload and write
failures cannot produce a successful CLI exit or a completion manifest. Raw
snapshots are omitted, but the retained contract, formulas and witnesses may be
sensitive. Evidence supports formula replay; it is not an independently checked
proof certificate or a replay against a running Kubernetes cluster.

Acceptance covers deterministic payloads, hashes for every artifact/input,
complete ordered plans and explicit skipped/unavailable stages, replay of saved
formulas, exact identity/object witnesses, rejected bad solver models, solver
unknown/error outcomes, CLI output and exit compatibility, and existing-destination
and interrupted-write behavior. Existing Kong evidence goldens must stay byte
identical. Each feature commit receives clean-worktree regression validation.
