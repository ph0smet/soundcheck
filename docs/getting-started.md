# Getting started

This guide takes you from a source checkout to a frozen-contract proof, a
counterexample, and the main integration outputs. Its commands use checked-in
fixtures, but opam dependency resolution is not locked and solver-selected
witnesses can vary.

Soundcheck currently verifies decK-style Kong configurations for Kong OSS 3.9.3
under the `traditional` and `traditional_compatible` HTTP routers. Read
[Supported model and limits](../README.md#supported-model) before treating a
result as a deployment claim.

## 1. Install the toolchain

You need Git, Bash, [opam](https://opam.ocaml.org/), OCaml 5.0 or newer, Dune
3.11 or newer, the `yaml` OCaml package, and the `z3` CLI on `PATH`.

Soundcheck's regression baseline is Z3 4.16.0. Other releases may work, but can
produce different timeout or `unknown` behavior. To match the tested solver,
download the matching archive from the
[official Z3 4.16.0 release](https://github.com/Z3Prover/z3/releases/tag/z3-4.16.0)
and add its `bin` directory to `PATH`.

```sh
git clone https://github.com/ph0smet/soundcheck.git
cd soundcheck

# Skip this if you already selected a compatible OCaml 5.x switch.
opam switch create . 5.2.1 --no-install
eval "$(opam env)"

opam install . --deps-only --with-test
dune build @all
```

Confirm the solver and inspect the model you are about to rely on:

```sh
z3 -version
eval "$(opam env)"
dune exec soundcheck -- profile kong --format human
```

The profile command should report `kong-traditional-http-v11` and separate its
modeled, conservative, and unsupported semantics.

## 2. Start from reviewed intent

The walkthrough uses minimal synthetic verifier fixtures, not complete
deployable Kong configurations. Their reviewed intent is
[`bench/kong/contracts/admin-get.yaml`](../bench/kong/contracts/admin-get.yaml).
It is a strict schema-v1 `authenticated-access` contract requiring:

- anonymous `GET` requests under `/admin` to be denied; and
- authenticated `GET` requests in the same scope to be definitely allowed.

The contract is the reviewed intent. A repair loop may change the configuration,
but it must not change this artifact or replace its scope with CLI flags.

The repository also includes
[`internal-get.yaml`](../bench/kong/contracts/internal-get.yaml), a
`network-restricted-access` example with a frozen trusted IPv4 block and an
explicit `source_ip_integrity: externally-enforced` deployment assumption.

## 3. Get a counterexample

Verify the deliberately unsafe
[`unsafe.yaml`](../bench/kong/workflows/frozen-admin/unsafe.yaml):

```sh
eval "$(opam env)"
dune exec soundcheck -- verify \
  bench/kong/workflows/frozen-admin/unsafe.yaml \
  --contract bench/kong/contracts/admin-get.yaml
```

The command exits `3` and reports the failed `must_deny` clause. Abridged output:

```text
VIOLATED authenticated-access
         Conservative model-level candidate, not a guaranteed target replay: anonymous request GET /admin over http may be ALLOWED via route "admin-get" (service "admin-api") — the modeled guard permits this forbidden request.
         Assurance: kong-traditional-http-v11 (within_profile)
```

This is a checked witness in Soundcheck's model. The conservative wording matters:
where the target semantics are over-approximated, investigate the candidate
against the real deployment rather than treating it as a guaranteed replay.

## 4. Verify the repair

The included
[`repaired.yaml`](../bench/kong/workflows/frozen-admin/repaired.yaml) adds Kong
Key Auth to the same route:

```sh
eval "$(opam env)"
dune exec soundcheck -- verify \
  bench/kong/workflows/frozen-admin/repaired.yaml \
  --contract bench/kong/contracts/admin-get.yaml
```

Abridged expected result and exit code:

```text
PROVED   authenticated-access
         Anonymous requests must be denied and authenticated requests allowed for path prefix /admin, method GET
         Assurance: kong-traditional-http-v11 (within_profile)
```

```sh
echo $?
# 0
```

`PROVED` means the applicable request classes were inhabited, intent-consistency
checks passed, and no modeled policy-clause violation existed within the stated
profile and assumptions. It does not prove Kong itself, the parser, encoder,
Z3, plugin implementations, or the deployment environment.

## 5. See why deny-all is not a repair

A safety-only check can accept a configuration that blocks everyone. The paired
contract also requires intended authenticated access:

```sh
eval "$(opam env)"
dune exec soundcheck -- verify \
  bench/kong/workflows/frozen-admin/deny-all.yaml \
  --contract bench/kong/contracts/admin-get.yaml
```

The command exits `3` with a `must_allow` violation because no modeled route
definitely serves authenticated `GET /admin`.

## 6. Use your own config

Point the same frozen contract at a decK-style YAML file:

```sh
eval "$(opam env)"
dune exec soundcheck -- verify path/to/kong.yaml \
  --contract bench/kong/contracts/admin-get.yaml
```

Create a separate reviewed contract when your intended path, method, host, or
network boundary differs. Frozen contract files reject unknown fields, versions,
and kinds. `--contract` cannot be combined with `--property`,
`--path-prefix`, `--method`, `--host`, or `--trusted-cidr`.

For exploration without a frozen artifact, use a manual property:

```sh
eval "$(opam env)"
dune exec soundcheck -- verify \
  bench/kong/cases/admin-no-auth/config.yaml \
  --property no-anonymous-access \
  --path-prefix /admin
```

Manual mode is useful for learning and diagnosis, but it is not a spec-freeze
boundary: the caller remains able to change the property and scope.

## 7. Consume stable JSON

```sh
eval "$(opam env)"
dune exec soundcheck -- verify \
  bench/kong/workflows/frozen-admin/unsafe.yaml \
  --contract bench/kong/contracts/admin-get.yaml \
  --format json
```

The schema-v10 verification report always emits its core keys, using `null` when
a field does not apply. The conditional `reason` key appears for `unknown` and
`inconsistent`; comparison and profile JSON use separate schemas. A verification
report includes:

- `result` and `property`;
- the assurance profile, status, and findings;
- the normalized frozen-spec identity;
- the failed clause, when applicable; and
- the checked principal, action, path, host, scheme, source IP, route, and
  service counterexample fields.

Exit status remains authoritative for gating:

| Exit | Meaning |
| ---: | --- |
| 0 | proved |
| 1 | input/output or verification error |
| 2 | invalid command usage |
| 3 | violated |
| 4 | unknown |
| 5 | vacuous |
| 6 | inconsistent contract |

Only `0` is a successful gate.

## 8. Retain an evidence bundle

Frozen contracts require several ordered solver queries. Retain all of them with
`--evidence-dir`:

```sh
mkdir -p evidence
eval "$(opam env)"
dune exec soundcheck -- verify \
  bench/kong/workflows/frozen-admin/repaired.yaml \
  --contract bench/kong/contracts/admin-get.yaml \
  --evidence-dir evidence/run-001 \
  --format json
```

The destination must be a new path. A complete bundle contains:

- `contract.json`, `assurance-profile.json`, and `report.json`;
- `queries/<obligation-id>.smt2` for every planned obligation; and
- `manifest.json` with hashes, tool/solver provenance, the obligation plan,
  execution status, decoded models, and final verdict.

The manifest is written last as the completion marker. The bundle supports
formula replay, but is not an independently checked UNSAT certificate and does
not establish the fidelity of Kong lowering.

Treat a bundle as potentially sensitive. It omits the raw config text, but it
contains the frozen contract, report, formulas, witnesses or models, hashes, and
operational identifiers. Review it before retention or sharing.

A non-contract run can instead retain its most recently executed formula with
`--emit-smt query.smt2`, then replay that file with `z3 -smt2 query.smt2`.
Because inhabitance and shadowing can execute multiple queries, this is not a
complete run trace. Paired contracts reject `--emit-smt`.

## 9. Check repair scope

Contract verification proves the replacement meets the intent. Comparison can
also prove that modeled behavior outside the contract scope did not change:

```sh
eval "$(opam env)"
dune exec soundcheck -- compare \
  bench/kong/workflows/frozen-admin/unsafe.yaml \
  bench/kong/workflows/frozen-admin/repaired.yaml \
  --contract bench/kong/contracts/admin-get.yaml \
  --format json
```

The included pair returns `valid_repair`. Without `--contract`, comparison
checks all modeled decisions. Stronger `--mode` values additionally preserve:

- `route-service`: selected route and service identity;
- `service-target`: normalized upstream protocol, host, port, and base path;
- `upstream-uri`: the request-dependent literal-path transformation.

Unresolved routing or incomplete observations produce `unknown`.

## 10. Put Soundcheck in a loop or gate

For an agent repair loop, freeze the contract when the MCP server starts:

```sh
eval "$(opam env)"
dune exec soundcheck -- mcp \
  --contract bench/kong/contracts/admin-get.yaml
```

The exposed `verify` tool then accepts configuration only. The agent can respond
to a counterexample without gaining an interface for changing the property.

For the hard enforcement layer, use the
[GitHub Action](../README.md#github-action) from a reviewed full commit SHA. Run
it in a fresh trusted job before candidate code; the caller workflow, fixed
contract path, and Action SHA must not be candidate-controlled. `uses: ./` is a
test mechanism, not an approval boundary. The adapter accepts only
`pull_request` and non-forced, non-deleted protected-default-branch push events,
reading the contract from the immutable event commit. Other events fail closed.
Branch protection, required checks, separate contract review, and fresh-base
reruns remain external responsibilities; the Action installs none of them.
The Action uses Ubuntu 24.04 or newer on x86-64 or ARM64 and installs
checksum-verified Z3 4.16.0, the same release used by regression CI.
It also checks the solver version selected by its opam environment.
Pinning Soundcheck by SHA still leaves the setup Action, system packages, and
resolved opam dependencies transitively unpinned; review or lock those separately
when the deployment requires it.

## Troubleshooting

### `Program 'soundcheck' not found`

From a source checkout, keep the `--` separator:

```sh
dune exec soundcheck -- verify ...
```

Also load the selected switch with `eval "$(opam env)"`.

### A proof becomes `unknown`

Read the reason and assurance findings first. Common causes are an unsupported
plugin or relationship, regex syntax outside the bounded fragment, solver
failure, or timeout. Run `soundcheck profile kong` through `dune exec` to
inspect the exact boundary. Do not remove unsupported policy behavior merely to
obtain a green result unless that change is independently correct.

### Z3 times out on a regression fixture

Check `z3 -version`. The regression baseline is 4.16.0; older distribution
packages can time out on regex obligations under the unchanged solver deadline.

### A literal path or scope is rejected

Soundcheck reasons over Kong-normalized request paths. Literal route paths and
contract prefixes must already be normalized. Follow the canonical replacement
in the error rather than changing the expected verdict.

### Evidence creation fails

The parent directory must exist, but the exact `--evidence-dir` destination
must not. Existing files, directories, and symlinks are rejected.

## Next steps

- Review the [properties and frozen contracts](../README.md#properties-and-frozen-contracts).
- Inspect the [full assurance profile](../README.md#supported-model).
- Read the [semantic evidence inventory](../bench/kong/SEMANTIC-COVERAGE.md).
- Run the [local checks](../README.md#testing).
- See [CONTRIBUTING.md](../CONTRIBUTING.md) before proposing changes.
