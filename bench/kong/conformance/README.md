# Real-Kong differential conformance

This harness sends independently authored requests through pinned Kong OSS
3.9.3 and checks fixed decision, selected-route, selected-service, and optional
HTTP-status expectations. It runs both supported router flavors:
`traditional` and `traditional_compatible`. Soundcheck's concrete IR evaluator
supplies possible identities and may/must allowance bounds, not target truth.

The default matrix contains **346 observations: 216 exact, 60 conservative,
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
| auth | Credentials, effective plugin configuration and HTTP subsystem selection | 60 | 6 | 0 |
| paths | Literal paths, accepted regexes, path priority | 14 | 10 | 0 |
| mixed | Methods, hosts, headers, protocols, SNI, disabled services, service-less routes | 46 | 8 | 0 |
| reducer | Request-global traditional route reduction | 0 | 4 | 0 |
| category | Cross-flavor category precedence | 2 | 4 | 0 |
| hosts | Effective ports and empty wildcard matches | 0 | 6 | 0 |
| boundaries | Unicode, final LF, top-level alternation | 0 | 0 | 16 |
| ip | IPv4 restrictions, boundaries, effective plugin scopes | 48 | 0 | 0 |
| termination | Header/query triggers, scopes, earlier authentication/IP denial | 10 | 22 | 0 |
| oss-auth | Basic/JWT credential validity, JWT preflight, protected/public prefixes | 36 | 0 | 0 |

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
The additional selectors `ip`, `termination`, and `oss-auth` run their individual
matrices; `plugins` runs `auth` plus these three new matrices.
Each selection still runs both flavors. The default `all` and CI run all eight
original matrices plus the three plugin matrices; focused runs do not replace
the complete conformance gate.

Prerequisites are the existing opam environment with Dune and the `yaml`
dependency, Z3, curl, and a running Docker daemon. The wrapper does not install
dependencies. The first run may download the pinned image. Run only one harness
at a time on a host: it uses fixed container names and localhost ports 18000,
18001, 18443, and 18444. Existing same-name containers are not removed on a name
collision; startup fails and their owner must resolve the conflict.

The Kong image is pinned by version and multi-platform digest. Each flavor uses
eleven sequential containers; at most one harness container runs at a time.
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

The additional HTTP cases use the existing `auth` and `mixed` matrices:

- Disabled-service routes are omitted before selection. A more specific,
  restrictive disabled route must not hide an enabled open fallback; a path
  served only by a disabled service has no selected route. These catch treating
  disabled services as live routing candidates.
- Key Auth with plugin `protocols: [http]` or `[https]` runs on both HTTP and HTTPS
  requests because both select the HTTP subsystem. Missing and valid credentials
  are checked on both schemes. Distinct route/service key headers on the opposite
  scheme detect accidental fallback to the service's plugin configuration.
- Literal header names and values are case-insensitive. Repeated values are
  checked with a match first, a match last, no match and an absent header. Testing
  both orders catches implementations that examine only one repeated value.
- A configured uppercase host literal misses the sampled lowercase request
  host. A second, lowercase alias on the same route matches the target, while
  Soundcheck retains incomplete matching and both possible routing identities.
  Exact misses and a conservative positive observation are recorded separately;
  neither makes uppercase-host handling an exact feature. Raw mixed-case request
  Host normalization and combinations with ports/wildcards are not sampled.

These expectations come from the pinned routing, plugin iterator and request
handler sources below. They add finite observations, without changing lowering,
the assurance profile or any public result schema.

Rows are pipe-delimited despite the historical `.tsv` filename:

```text
name|scheme|method|path|host|sni|principal|headers|decision|route|service|status|model-class|flavors|source-ip[|query]
```

Use `-` for absent fields and `;` between headers. Literal `|` and `;` inside
fields are not supported. `flavors` is `both`, `traditional`, or
`traditional_compatible`; flavor-specific rows encode independently justified
differences, not outputs blessed after running Soundcheck.

The source-IP field is mandatory; the following query field is optional. `source-ip` is `-` for matrices without a source-IP
observation and a canonical dotted-decimal IPv4 address for every `ip` and
`termination` row. Prefixes, ports, IPv6, leading-zero octets, malformed values,
omitted source fields, and a source address on an unrelated matrix fail the
harness. The internal model oracle receives exactly that address; old matrices
use the irrelevant `0.0.0.0` placeholder. The IP matrices inject the same field
as `X-Soundcheck-Client-IP`, and their owned loopback containers explicitly set
`trusted_ips=0.0.0.0/0`, `real_ip_header=X-Soundcheck-Client-IP`, and
`real_ip_recursive=off`. This deliberately synthetic trust setup tests an
externally supplied derived-client-IP assumption. It is **not** a production
trust configuration or evidence that a deployment prevents source spoofing.

The reserved source header cannot be supplied in authored headers. Probe header
names are restricted to ASCII letters, digits, hyphens and underscores. Request
paths containing literal `?` or `#` are rejected. The optional sixteenth field
supplies a separate transport query for the `termination` matrix only; omitted,
empty, or `-` means no query. It accepts literal ASCII `name=value` pairs separated
by `&`, with letters, digits, underscores and hyphens in names/values. Values may
be empty; names may not. Escapes, whitespace, fragments and URL/glob syntax are
rejected. The harness appends this query to the quoted curl URL while passing
only the original normalized path to the model. Query state remains unmodeled;
query-trigger probes establish the conservative bound on observed allow/deny,
not exact symbolic query semantics.

The principal is explicitly `anonymous` or `authenticated`. Missing/invalid
keys, including keys sent under the wrong effective plugin's header name, are
anonymous; a valid key at the effective plugin is authenticated. An anonymous
Consumer fallback does not authenticate failed credentials. These labels come
from the authored fixtures and target semantics, never the model verdict or
HTTP response. All credentials and identities in the auth fixtures are public
synthetic data. The standalone Basic Auth and JWT fixtures do not combine
providers; the fixed HS256 JWT has no expiry/not-before claim requirement.
This tests several credential outcomes' abstraction; Soundcheck does not verify
credential stores, expiry, identity-provider availability, or Consumer policy.
Both providers include malformed and well-formed incorrect credentials. The
wrong Basic password retains the existing fixture username. The bad JWT keeps
the valid token's header and claims but uses an HS256 signature made with a
different public fixture secret. These exercise credential validation failures,
not merely malformed-token rejection.

The same matrix includes route-scoped Key Auth on `/api` and a longer public
`/api/health` route. Probes exercise protected anonymous denial, valid credential
allowance, and public prefix access. Literal-prefix matching also permits
`/api/health/ready` and `/api/healthy`; this is intentionally not an exact-path or
path-segment exception. These finite target observations support the routing
and authentication model used by public-exceptions contracts; contract-wide
proof obligations retain their separate tests.

`allow` means Kong reached an upstream, observed via the upstream-latency
header, not HTTP 2xx. Some routing suffixes produce an upstream 404; `-` disables
only the optional status assertion. Authentication rejection requires 401;
configured termination requires 418. A plugin or protocol denial can still
have a selected route; an unmatched request has no route.

The internal oracle protocol reports bounds and candidate identities or
`unsupported\tunknown`; it is not a public result-schema change. A possible
incomplete match includes a no-route candidate unless another complete match
guarantees selection. It delegates selection and allowance to the shared IR.

The 49 Docker-free harness checks include wrong model-only, target-only, mutually
agreeing and HTTP-status observations; oracle errors; malformed/duplicate
candidates; missing probes; improper class substitution; identity escape; and
both may/must bound escapes. Source controls also reject malformed/missing
addresses, reserved headers, query-as-path and invalid matrix selection; targeted
mutants omit source injection, substitute the oracle source, or change the
trusted real-IP header. A focused selector must run both and only the selected
matrix's router instances. Fourteen additional query controls test literal/empty
and multiple values, malformed syntax, query in the wrong matrix, omitted query
transport and accidental query leakage into the modeled path. Separately,
22 Docker-free oracle checks cover
address parsing and propagation. These test protocol/model enforcement, not
independent Kong semantics.

## Source basis

Kong is pinned to 3.9.3, source commit
`a643428bc4d5397152164a63bcc0f8bc65fce69d`. Expectations draw on:

- [Traditional routing](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/router/traditional.lua)
  and [compatible transformation](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/router/transform.lua):
  explicit modern regex markers, literal path length versus regex priority,
  reduction/category differences, mixed regex-header arrays, and wildcard hosts.
  Both routers fold literal header names/values and consider repeated values;
  their configured literal host lookup preserves case.
  Traditional plain-host final lookup uses raw/no-port forms, not its earlier
  synthesized port; compatible can use the effective destination port.
- [Compatible request fields](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/router/fields.lua)
  and [request handling](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/runloop/handler.lua):
  explicit Host ports, advertised destination-port mapping, and omission of
  routes belonging to disabled services before router construction.
- [Key-auth](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/plugins/key-auth/handler.lua)
  and its [defaults](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/plugins/key-auth/schema.lua):
  key names, invalid/missing keys, explicit anonymous fallback and OPTIONS bypass.
- [Plugin lookup](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/runloop/plugins_iterator.lua)
  and [request termination](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/plugins/request-termination/handler.lua):
  route/service/global precedence, disabled-plugin fallthrough and key-auth
  before termination. The iterator selects enabled plugin protocols by subsystem,
  not individual request scheme. Distinct header names expose configuration selection.
- [IP restriction](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/plugins/ip-restriction/handler.lua)
  checks deny before a nonempty allow list over `binary_remote_addr`.
  [Runtime configuration](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong.conf.default)
  documents how trusted peers and the configured real-IP header determine that
  derived address. Distinct CIDRs expose combined route/service, route, service,
  global precedence, and disabled-plugin fallthrough.
- [Conditional termination](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/plugins/request-termination/handler.lua)
  returns early when its trigger is absent from both headers and query. Its
  priority follows Key Auth and IP restriction. Header-trigger probes check
  actual allow/deny behavior while retaining the model's conservative bounds;
  query-trigger presence (including an empty value) and an unrelated query are
  also sampled. A prior modeled auth/IP denial can still have exact denying bounds.
- [Basic Auth](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/plugins/basic-auth/access.lua)
  rejects missing/invalid credentials, including a correct username with the wrong
  password; [JWT](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/plugins/jwt/handler.lua)
  validates a token, rejects a valid-format signature made with the wrong secret,
  or follows its configured OPTIONS bypass.

PCRE2 versus the pinned ATC/Rust regex implementation explains the boundary
fixtures' Unicode, final-LF and anchoring differences. Their target observations
remain useful even though the shared profile rejects those languages. Literal
`+` tests use explicit format 3.0; legacy 1.1/2.1 migration has separate source-
justified regressions. See the [hardening acceptance record](../../../docs/plans/2026-10-kong-hardening.md)
for the narrowed profile, independent refinement oracle, and acceptance record.

Remaining gaps include the rest of the recognized authentication list,
Enterprise-only plugins, provider/credential availability, expiry behavior,
Consumer scope and multiple-provider identity semantics; richer query forms; and
runtime rate-limit exhaustion, counters and storage failures. The presence of
an accepted plugin name is not evidence that this finite OSS matrix exercised
it. No quota/functionality guarantees or broader v11 claims are added here.

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
