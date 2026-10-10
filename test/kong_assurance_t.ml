open Soundcheck_kong

let parse source =
  match Parse.parse_string source with
  | Ok config -> config
  | Error error -> failwith error

let codes assessment = List.map (fun (finding : Assurance.finding) -> finding.code) assessment.Assurance.findings

let expect_status expected assessment =
  if assessment.Assurance.status <> expected then
    failwith
      (Printf.sprintf "expected assurance status %s, got %s"
         (Assurance.string_of_status expected)
         (Assurance.string_of_status assessment.Assurance.status))

let contains haystack needle =
  let haystack_length = String.length haystack in
  let needle_length = String.length needle in
  let rec search offset =
    offset + needle_length <= haystack_length
    && (String.sub haystack offset needle_length = needle || search (offset + 1))
  in
  needle_length = 0 || search 0

let () =
  if Assurance.profile.id <> "kong-traditional-http-v11"
     || Assurance.profile.version <> 11
  then failwith "assurance profile identity changed";

  let within =
    parse
      "services: [{name: api, routes: [{name: exact, paths: [/admin], methods: [GET], hosts: [admin.example], plugins: [{name: key-auth}]}]}]"
    |> Assurance.assess
  in
  expect_status Assurance.Within_profile within;

  let conservative =
    parse
      "services: [{name: api, routes: [{name: headers, paths: [/admin], headers: {x-role: ['~*^admin']}, hosts: [Admin.Example], plugins: [{name: ip-restriction, config: {allow: ['2001:db8::/32']}}]}]}]"
    |> Assurance.assess
  in
  expect_status Assurance.Conservative conservative;
  let conservative_codes = codes conservative in
  List.iter
    (fun code ->
      if not (List.mem code conservative_codes) then
        failwith ("missing conservative finding: " ^ code))
    [ "route-header-regex"; "uppercase-host";
      "invalid-ip-cidr" ];

  let unknown_plugin =
    parse "services: [{name: api, plugins: [{name: custom-auth}], routes: [{name: open, paths: [/admin]}]}]"
    |> Assurance.assess
  in
  expect_status Assurance.Unsupported unknown_plugin;
  if codes unknown_plugin <> [ "unrecognized-plugin" ] then
    failwith "unmodeled plugin must fail closed with a precise finding";

  let unsupported =
    parse
      "services: [{name: api, routes: [{name: backref, paths: ['~/(a+)\\1']}]}]"
    |> Assurance.assess
  in
  expect_status Assurance.Unsupported unsupported;
  if not (List.mem "unsupported-path-regex" (codes unsupported)) then
    failwith "unsupported regex finding missing";

  let expected_json =
    {|{"schema_version":1,"id":"kong-traditional-http-v11","connector":"kong","version":11,"target":"Kong OSS 3.9.3 traditional/traditional_compatible HTTP routing","modeled":[{"code":"literal-path-prefix","description":"literal HTTP path-prefix matching"},{"code":"normalized-request-path","description":"Kong-normalized request-path domain and literal route validation"},{"code":"regular-path-regex","description":"bounded shared ASCII-atom regex language; matching remains an upper bound"},{"code":"http-method","description":"HTTP method matching"},{"code":"lowercase-host","description":"lowercase exact Host matching without an explicit route port"},{"code":"exact-header-match","description":"case-insensitive exact HTTP header matching, including repeated values"},{"code":"http-https-protocol","description":"HTTP subsystem selection and HTTPS-only rejection"},{"code":"exact-sni","description":"exact SNI matching for HTTPS and Kong's HTTP bypass"},{"code":"shared-route-priority","description":"common criterion-count order; detailed path order only with identical non-path predicates"},{"code":"known-auth-plugins","description":"authentication requirement from Soundcheck's known plugin list"},{"code":"auth-preflight-bypass","description":"Key Auth and JWT OPTIONS bypass when run_on_preflight is false"},{"code":"general-request-rate-limit","description":"request-rate coverage from rate-limiting and rate-limiting-advanced"},{"code":"ipv4-ip-restriction","description":"IPv4 ip-restriction allow and deny guards over Kong's derived client IP"},{"code":"request-termination","description":"unconditional request-termination denial with Kong plugin precedence"},{"code":"global-plugin-scope","description":"global plugins with route-over-service-over-global precedence"},{"code":"plugin-subsystem","description":"plugin protocols activate the HTTP subsystem, not an individual request scheme"},{"code":"disabled-service","description":"disabled services and their routes are excluded from routing"},{"code":"root-route-service-plugin-scope","description":"root plugins scoped by string route/service references"},{"code":"top-level-route","description":"top-level routes with string service references or denying no-service behavior"},{"code":"default-admin-ports","description":"Admin API recognition on default ports 8001 and 8444"},{"code":"default-deny","description":"denying fallthrough when no route matches; a failing guard denies without rerouting"}],"conservative":[{"code":"route-created-at-tie","description":"created_at is absent from decK and unresolved route order remains tied"},{"code":"shared-route-order","description":"overlapping possible winners are not ordered unless both router flavors justify suppression"},{"code":"regex-match-runtime","description":"regex engine match-limit failures may remove a match; regex candidates never suppress or establish definite allowance"},{"code":"rate-limit-runtime","description":"quota and rate-limit runtime state cannot establish definite allowance"},{"code":"route-header-regex","description":"regex header values are over-approximated and the route is left incomparable"},{"code":"wildcard-sni","description":"wildcard SNI depends on router flavor and is over-approximated"},{"code":"route-stream-match","description":"source/destination criteria are over-approximated and the route is left incomparable"},{"code":"uppercase-host","description":"uppercase route hosts are left incomparable because request hosts are lowercased"},{"code":"wildcard-host","description":"wildcard Host semantics differ; a possibly empty wildcard is only an upper bound"},{"code":"host-port","description":"effective Host ports are not modeled; port-bearing route hosts are unconstrained and incomplete"},{"code":"invalid-ip-cidr","description":"unmodeled restrictions use may/must bounds; mixed unknown allow entries do not narrow possible allowance"},{"code":"conditional-request-termination","description":"triggered request-termination depends on unmodeled query parameters"},{"code":"auth-anonymous-fallback","description":"authentication anonymous fallback is over-approximated without resolving Consumers"},{"code":"response-rate-limit-dependency","description":"response rate limiting depends on upstream usage headers outside the config"},{"code":"graphql-rate-limit-scope","description":"GraphQL query-cost limiting does not establish general HTTP request-rate coverage"}],"unsupported":[{"code":"unsupported-path-regex","description":"non-regular or untranslated regex constructs make the whole result unknown"},{"code":"unrecognized-plugin","description":"unmodeled plugins can alter routing, guards or upstream targets; whole-config verification fails closed"},{"code":"nested-plugin-reference","description":"explicit nested plugin relationships are not resolved"},{"code":"consumer-scoped-plugin","description":"consumer-scoped plugins require a richer principal identity model"},{"code":"non-string-plugin-reference","description":"non-string root plugin references are not resolved"},{"code":"non-string-route-service-reference","description":"non-string top-level route service references are not resolved"}]}|}
  in
  let json = Assurance.profile_json () in
  if json <> expected_json then failwith "Kong assurance profile JSON changed";
  let expected_human =
    {|KONG ASSURANCE PROFILE  kong-traditional-http-v11
Connector: kong
Profile version: 11
Target: Kong OSS 3.9.3 traditional/traditional_compatible HTTP routing

Modeled:
  - literal-path-prefix: literal HTTP path-prefix matching
  - normalized-request-path: Kong-normalized request-path domain and literal route validation
  - regular-path-regex: bounded shared ASCII-atom regex language; matching remains an upper bound
  - http-method: HTTP method matching
  - lowercase-host: lowercase exact Host matching without an explicit route port
  - exact-header-match: case-insensitive exact HTTP header matching, including repeated values
  - http-https-protocol: HTTP subsystem selection and HTTPS-only rejection
  - exact-sni: exact SNI matching for HTTPS and Kong's HTTP bypass
  - shared-route-priority: common criterion-count order; detailed path order only with identical non-path predicates
  - known-auth-plugins: authentication requirement from Soundcheck's known plugin list
  - auth-preflight-bypass: Key Auth and JWT OPTIONS bypass when run_on_preflight is false
  - general-request-rate-limit: request-rate coverage from rate-limiting and rate-limiting-advanced
  - ipv4-ip-restriction: IPv4 ip-restriction allow and deny guards over Kong's derived client IP
  - request-termination: unconditional request-termination denial with Kong plugin precedence
  - global-plugin-scope: global plugins with route-over-service-over-global precedence
  - plugin-subsystem: plugin protocols activate the HTTP subsystem, not an individual request scheme
  - disabled-service: disabled services and their routes are excluded from routing
  - root-route-service-plugin-scope: root plugins scoped by string route/service references
  - top-level-route: top-level routes with string service references or denying no-service behavior
  - default-admin-ports: Admin API recognition on default ports 8001 and 8444
  - default-deny: denying fallthrough when no route matches; a failing guard denies without rerouting

Conservative:
  - route-created-at-tie: created_at is absent from decK and unresolved route order remains tied
  - shared-route-order: overlapping possible winners are not ordered unless both router flavors justify suppression
  - regex-match-runtime: regex engine match-limit failures may remove a match; regex candidates never suppress or establish definite allowance
  - rate-limit-runtime: quota and rate-limit runtime state cannot establish definite allowance
  - route-header-regex: regex header values are over-approximated and the route is left incomparable
  - wildcard-sni: wildcard SNI depends on router flavor and is over-approximated
  - route-stream-match: source/destination criteria are over-approximated and the route is left incomparable
  - uppercase-host: uppercase route hosts are left incomparable because request hosts are lowercased
  - wildcard-host: wildcard Host semantics differ; a possibly empty wildcard is only an upper bound
  - host-port: effective Host ports are not modeled; port-bearing route hosts are unconstrained and incomplete
  - invalid-ip-cidr: unmodeled restrictions use may/must bounds; mixed unknown allow entries do not narrow possible allowance
  - conditional-request-termination: triggered request-termination depends on unmodeled query parameters
  - auth-anonymous-fallback: authentication anonymous fallback is over-approximated without resolving Consumers
  - response-rate-limit-dependency: response rate limiting depends on upstream usage headers outside the config
  - graphql-rate-limit-scope: GraphQL query-cost limiting does not establish general HTTP request-rate coverage

Unsupported:
  - unsupported-path-regex: non-regular or untranslated regex constructs make the whole result unknown
  - unrecognized-plugin: unmodeled plugins can alter routing, guards or upstream targets; whole-config verification fails closed
  - nested-plugin-reference: explicit nested plugin relationships are not resolved
  - consumer-scoped-plugin: consumer-scoped plugins require a richer principal identity model
  - non-string-plugin-reference: non-string root plugin references are not resolved
  - non-string-route-service-reference: non-string top-level route service references are not resolved|}
  in
  let human = Assurance.profile_human () in
  if human <> expected_human then failwith "Kong assurance profile human output changed";

  let report =
    match
      Verify.run ~property:(Verify.No_anonymous_access "/admin")
        "services: [{name: api, routes: [{name: headers, paths: [/admin], headers: {x-role: ['~*^admin']}}]}]"
    with
    | Ok report -> report
    | Error error -> failwith error
  in
  (match report.Soundcheck_core.Report.assurance with
   | Some assurance
     when assurance.profile = "kong-traditional-http-v11"
          && assurance.status = Soundcheck_core.Report.Conservative -> ()
   | _ -> failwith "verification report omitted assurance assessment");
  let report_json = Soundcheck_core.Report.to_json report in
  if not (contains report_json "\"schema_version\":9")
     || not (contains report_json "\"code\":\"route-header-regex\"")
  then failwith "report JSON omitted assurance identity or finding";
  let human = Soundcheck_core.Report.to_human report in
  if not (contains human "Assurance: kong-traditional-http-v11 (conservative)")
     || not (contains human "route-header-regex")
  then failwith "human report omitted assurance assessment"
