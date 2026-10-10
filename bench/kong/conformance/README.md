# Real-Kong differential conformance

This harness sends independently authored requests through pinned Kong OSS
3.9.3 and checks fixed decision, selected-route, selected-service, and optional
HTTP-status expectations. It runs both supported router flavors:
`traditional` and `traditional_compatible`. Soundcheck's concrete IR evaluator
supplies possible identities and may/must allowance bounds, not target truth.

The default matrix contains **188 observations: 82 exact, 36 conservative,
and 70 unsupported-boundary checks**. These classes are deliberately separate:

- **Exact:** one modeled identity; may and must both equal the target decision.
- **Conservative:** the actual identity belongs to the modeled candidates and
  `must_allow <= actual_allow <= may_allow`. Multiple identities or unequal
  decision bounds must demonstrate actual model imprecision.
- **Unsupported:** public verification returns `unknown` with `unsupported`
  assurance. No modeled decision agreement is claimed; a timeout cannot pass.

Every class also checks its independently fixed target tuple and any specified
status. Unexpected mutual agreement fails. A row cannot silently change class.
Passing this finite matrix does not prove conformance for every configuration
or every feature in the assurance profile.

| Matrix | Focus | Exact | Conservative | Unsupported |
| --- | --- | ---: | ---: | ---: |
| routing | Original routing/SNI expectations plus regex boundary probes | 0 | 0 | 54 |
| auth | Credentials and effective plugin configuration | 40 | 6 | 0 |
| paths | Literal paths, accepted regexes, path priority | 14 | 10 | 0 |
| mixed | Methods, hosts, headers, protocols, SNI, service-less routes | 26 | 6 | 0 |
| reducer | Request-global traditional route reduction | 0 | 4 | 0 |
| category | Cross-flavor category precedence | 2 | 4 | 0 |
| hosts | Effective ports and empty wildcard matches | 0 | 6 | 0 |
| boundaries | Unicode, final LF, top-level alternation | 0 | 0 | 16 |

The routing fixture retains its original 18 requests and adds nine path probes.
Because it contains regexes outside the shared supported fragment, its entire
configuration is unsupported; those 54 observations are not model-agreement
passes. Separate supported configurations exercise exact and conservative
semantics. Accepted path regexes remain incomplete because target runtime
failure is not modeled, even when their character language is supported.

Docker is intentionally not part of `dune test`. Run the harness locally with:

```sh
bash scripts/check.sh conformance
```

For focused edit loops, `bash bench/kong/conformance/run.sh` accepts `routing`,
`auth`, `supported` (paths, mixed, reducer, category, hosts), or `boundaries`.
Each selection still runs both flavors. The default `all` and CI run all eight
matrices; focused runs do not replace the complete conformance gate.

Prerequisites are the existing opam environment with Dune and the `yaml`
dependency, Z3, curl, and a running Docker daemon. The wrapper does not install
dependencies. The first run may download the pinned image. Run only one harness
at a time on a host: it uses fixed container names and localhost ports 18000,
18001, 18443, and 18444. Existing same-name containers are not removed on a name
collision; startup fails and their owner must resolve the conflict.

The Kong image is pinned by version and multi-platform digest. Each flavor uses
eight sequential containers; at most one harness container runs at a time.
The hosts matrix explicitly pins `port_maps=80:8000,443:8443` so compatible
routing's advertised destination port does not depend on Docker's published
port. That destination-port dimension is intentionally absent from the model.
The configured
upstream is Kong's own Admin API status endpoint, keeping the test independent
of external services and additional containers. A mismatch reports the router
flavor, probe request, and both observations. HTTP probes have bounded timeouts.
Failures print the owned container's state and recent logs before cleanup;
cleanup never deliberately removes a container this invocation did not create.
The normal `dune test` gate checks this harness's success and failure lifecycle
with mocked commands, including ownership-safe cleanup. Those tests do not run
Docker or validate Kong semantics; the real-container comparisons remain separate.

## Independent expectations and identity boundary

Rows are pipe-delimited despite the historical `.tsv` filename:

```text
name|scheme|method|path|host|sni|principal|headers|decision|route|service|status|model-class|flavors
```

Use `-` for absent fields and `;` between headers. Literal `|` and `;` inside
fields are not supported. `flavors` is `both`, `traditional`, or
`traditional_compatible`; flavor-specific rows encode independently justified
differences, not outputs blessed after running Soundcheck.

The principal is explicitly `anonymous` or `authenticated`. Missing/invalid
keys, including keys sent under the wrong effective plugin's header name, are
anonymous; a valid key at the effective plugin is authenticated. An anonymous
Consumer fallback does not authenticate failed credentials. These labels come
from the authored fixtures and target semantics, never the model verdict or
HTTP response. All keys and identities in `auth.yaml` are public synthetic data.
This tests several credential outcomes' abstraction; Soundcheck does not verify
credential stores, expiry, identity-provider availability, or Consumer policy.

`allow` means Kong reached an upstream, observed via the upstream-latency
header, not HTTP 2xx. Some routing suffixes produce an upstream 404; `-` disables
only the optional status assertion. Authentication rejection requires 401;
configured termination requires 418. A plugin or protocol denial can still
have a selected route; an unmatched request has no route.

The internal oracle protocol reports bounds and candidate identities or
`unsupported\tunknown`; it is not a public result-schema change. A possible
incomplete match includes a no-route candidate unless another complete match
guarantees selection. It delegates selection and allowance to the shared IR.

The 21 Docker-free checks include wrong model-only, target-only, mutually
agreeing and HTTP-status observations; oracle errors; malformed/duplicate
candidates; missing probes; improper class substitution; identity escape; and
both may/must bound escapes. These test harness enforcement, not Kong semantics.

## Source basis

Kong is pinned to 3.9.3, source commit
`a643428bc4d5397152164a63bcc0f8bc65fce69d`. Expectations draw on:

- [Traditional routing](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/router/traditional.lua)
  and [compatible transformation](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/router/transform.lua):
  explicit modern regex markers, literal path length versus regex priority,
  reduction/category differences, mixed regex-header arrays, and wildcard hosts.
  Traditional plain-host final lookup uses raw/no-port forms, not its earlier
  synthesized port; compatible can use the effective destination port.
- [Compatible request fields](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/router/fields.lua)
  and [request handling](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/runloop/handler.lua):
  explicit Host ports and advertised destination-port mapping.
- [Key-auth](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/plugins/key-auth/handler.lua)
  and its [defaults](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/plugins/key-auth/schema.lua):
  key names, invalid/missing keys, explicit anonymous fallback and OPTIONS bypass.
- [Plugin lookup](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/runloop/plugins_iterator.lua)
  and [request termination](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/plugins/request-termination/handler.lua):
  route/service/global precedence, disabled-plugin fallthrough and key-auth
  before termination. Distinct header names expose configuration selection.

PCRE2 versus the pinned ATC/Rust regex implementation explains the boundary
fixtures' Unicode, final-LF and anchoring differences. Their target observations
remain useful even though the shared profile rejects those languages. Literal
`+` tests use explicit format 3.0; legacy 1.1/2.1 migration has separate source-
justified regressions. See the [execution plan](../../../docs/plans/2026-10-kong-hardening.md)
for the narrowed profile, independent refinement oracle, and acceptance record.

## CI gate

The `CI` workflow runs the `Kong conformance (3.9.3)` job on every pull request
and push to `main`. It runs both router flavors sequentially using the same
wrapper, with a 20-minute job timeout. Missing dependencies, startup errors,
request failures, and observation mismatches fail the job; conformance is not
an optional or `continue-on-error` step.

Combined harness output is retained as the `kong-conformance-logs` artifact for
seven days, including on failure when the harness step ran. Earlier setup
failures remain visible in the job log. A failing job marks CI unsuccessful;
requiring this check before merge is a separate repository branch-protection
setting, not configured by this workflow.
