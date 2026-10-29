# Protect an API while keeping its health prefix public

The independently reviewed [contract](../../contracts/api-public-health.yaml)
requires three things for `GET /api*`: anonymous access outside `/api/health*`
is denied, authenticated access remains allowed throughout, and anonymous
health access remains allowed. These are literal prefixes, not exact endpoints:
`/api/healthcheck` is also public. Choose prefixes deliberately; an exact-path
exception is not part of this contract kind.

From the repository root:

```sh
eval "$(opam env)"
dune exec soundcheck -- verify \
  bench/kong/workflows/public-exceptions/repaired.yaml \
  --contract bench/kong/contracts/api-public-health.yaml
```

| Candidate | Expected result | Reason |
| --- | --- | --- |
| `unsafe.yaml` | `violated` | Anonymous requests reach the protected portion. |
| `deny-all.yaml` | `violated` | Required authenticated access is lost. |
| `locked-health.yaml` | `violated` | Authenticated access works, but public health access is lost. |
| `repaired.yaml` | `proved` | All three requirements hold within the supported model. |

The new kind is loaded through `--contract`, including frozen MCP, the GitHub
Action and the web contract editor. Exception prefixes are a nonempty list of
distinct normalized prefixes strictly inside the protected prefix. Every
exception inherits the same optional method and host scope. Canonical identity
sorts the list, so reordering it does not change the frozen requirement.

Ordinary verification does not preserve behavior outside that scope. Check a
repair separately when that matters:

```sh
dune exec soundcheck -- compare \
  bench/kong/workflows/public-exceptions/unsafe.yaml \
  bench/kong/workflows/public-exceptions/repaired.yaml \
  --contract bench/kong/contracts/api-public-health.yaml
```

This example should be a `valid_repair`: it also preserves modeled security
decisions outside the complete `/api` + `GET` scope, including `/status`.
The fixtures are synthetic workflow examples, not deployment evidence. An
authenticated principal retains the existing credential-validity abstraction;
the result does not prove an upstream application's health or availability.
