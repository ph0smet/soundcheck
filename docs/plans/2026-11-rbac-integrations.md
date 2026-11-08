# Kubernetes RBAC integration batch

Sourav authorized the next roadmap batch after merging RBAC evidence in PR #62
on 2026-11-08. Deliver frozen MCP, the reusable Action and a submitted-repair
benchmark as separate coherent commits on `feat/rbac-integrations`. The existing
static named-get profile, frozen contract schema, report schema and evidence
formats keep their meaning. YAML input, broader verbs/resources, web UI support,
live deployment pilots and running external models are outside this batch.

## Frozen MCP

`mcp --connector kubernetes-rbac --contract FILE [--baseline FILE]` reads the
operator's contract and optional supported baseline once before serving. Tool
calls accept only candidate snapshot text; `verify` checks the contract and
`compare` additionally checks preservation against the retained baseline.
Comparison is unavailable without a baseline. An unsafe baseline is permitted;
unsupported snapshots are rejected at startup. No tool can substitute identity
context, requirements, baseline, solver or output paths. The thin adapter uses
the existing connector and reports without independent verification semantics.

The new mode uses strict JSON without a YAML round-trip, exact request IDs and
bounded newline framing. It follows the existing MCP 2024-11-05 handshake.
Valid non-proof outcomes remain normal reports; protocol/argument failures are
errors. Existing valid Kong startup modes remain supported. Acceptance includes
interactive startup-file mutation/deletion, discovery, candidate repair cases,
unchanged byte payloads, duplicate keys/invalid UTF-8/NUL handling, and oversized
message recovery.

## GitHub Action

Add a trusted `connector` selector, defaulting to Kong for compatibility. RBAC
dispatch verifies the candidate against the same immutable approved-commit
contract mechanism. It performs contract verification, not baseline preservation.
Native annotations describe typed object requests. Keep context restrictions,
trusted Action source, isolated build and checksummed Z3 unchanged. Acceptance
covers invalid selectors, spec weakening, bad/successful candidates and annotations.
Hosted smoke steps reuse the single Action build for both connectors.

## Submitted RBAC repairs

An explicit RBAC benchmark entrypoint preserves the existing Kong evaluator's
format. Freeze all evaluator-owned contracts and baseline bytes before loading
submission metadata. Each attempt supplies only a candidate and invokes the
existing comparison once. Summaries bind exact inputs and canonical contracts,
retain both stage outcomes and explicit failures, and omit raw reports, witnesses
and diagnostics. Unsupported inputs must not invent an executed candidate check.

Synthetic controls exercise unchanged access, deny-all, remaining cluster/group
grants, operator regression, unsupported input and a valid repair. They establish
evaluator behavior, not autonomous-agent success. Missing attempts, metadata
overrides, file failures and forged/incoherent results cannot earn acceptance.
Each final commit must pass the complete clean-worktree regression suite.
