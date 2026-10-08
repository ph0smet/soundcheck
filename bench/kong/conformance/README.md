# Real-Kong differential conformance

This harness sends a fixed request matrix through a pinned Kong OSS
3.9.3 container and through Soundcheck's concrete IR evaluator, then compares
the decision, selected route, and selected service. It runs both supported
router flavors: `traditional` and `traditional_compatible`.

The matrix covers literal and regex paths, methods, hosts, exact headers, route
priority, service-less routes, default denial, HTTP/HTTPS protocol selection,
exact SNI, and Kong's HTTP bypass of SNI matching: 18 probes per router flavor,
36 comparisons total. Plugin execution and authenticated credential scenarios
remain a follow-up slice. Passing this fixed routing matrix does not establish
conformance for every feature in the assurance profile or close the outstanding
semantic-hardening findings.

Docker is intentionally not part of `dune test`. Run the harness locally with:

```sh
bash scripts/check.sh conformance
```

Prerequisites are the existing opam environment with Dune and the `yaml`
dependency, Z3, curl, and a running Docker daemon. The wrapper does not install
dependencies. The first run may download the pinned image. Run only one harness
at a time on a host: it uses fixed container names and localhost ports 18000,
18001, 18443, and 18444. Existing same-name containers are not removed on a name
collision; startup fails and their owner must resolve the conflict.

The Kong image is pinned by version and multi-platform digest. The configured
upstream is Kong's own Admin API status endpoint, keeping the test independent
of external services and additional containers. A mismatch reports the router
flavor, probe request, and both observations. HTTP probes have bounded timeouts.
Failures print the owned container's state and recent logs before cleanup;
cleanup never deliberately removes a container this invocation did not create.
The normal `dune test` gate checks this harness's success and failure lifecycle
with mocked commands, including ownership-safe cleanup. Those tests do not run
Docker or validate Kong semantics; the real-container comparisons remain separate.

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
