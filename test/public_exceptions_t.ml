open Soundcheck_core
open Soundcheck_kong

let ok = function Ok value -> value | Error message -> failwith message
let check label condition = if not condition then failwith label

let artifact ?(extras = "") ?(method_ = "GET") prefixes =
  Printf.sprintf
    "schema_version: 1\nkind: protected-prefix-with-public-exceptions\nscope:\n  path_prefix: /api\n  method: %s\n  host: API.EXAMPLE\n  public_path_prefixes: %s\n%s"
    method_ prefixes extras

let spec = ok (Contract_spec.parse_string (artifact "[/api/status, /api/health]"))
let property = Contract_spec.to_property spec
let verify config = ok (Verify.run ~property config)

let config ?(protected = "plugins: [{name: key-auth}]")
    ?(health = "") ?(status = "") ?(extra = "") ?(host = "hosts: [api.example]")
    ?(method_ = "methods: [GET]") () =
  Printf.sprintf
    {|services:
  - name: api
    routes:
      - name: protected
        paths: [/api]
        %s
        %s
        %s
      - name: health
        paths: [/api/health]
        %s
        %s
        %s
      - name: status
        paths: [/api/status]
        %s
        %s
        %s
%s
|} method_ host protected method_ host health method_ host status extra

let expect_violation name source =
  let report = verify source in
  match report.result, report.clause with
  | Report.Violated witness, Some clause when clause.name = name -> witness
  | _ -> failwith (name ^ ": " ^ Report.to_human report)

let expect_parse_error source =
  match Contract_spec.parse_string source with
  | Error _ -> ()
  | Ok _ -> failwith ("accepted invalid exception contract: " ^ source)

let () =
  let canonical = Contract_spec.canonical_json spec in
  check "exception ordering or host case changes identity"
    (canonical = Contract_spec.canonical_json
       (ok (Contract_spec.parse_string (artifact "[/api/health, /api/status]"))));
  check "canonical identity cannot round-trip"
    (canonical = Contract_spec.canonical_json (ok (Contract_spec.parse_string canonical)));
  let report = verify (config ()) in
  check "independent public exceptions must prove" (report.result = Report.Proved);
  let leaked = expect_violation "protected-anonymous-access-denied" (config ~protected:"" ()) in
  check "safety witness must be anonymous outside every exception"
    (leaked.principal = "anonymous"
     && String.starts_with ~prefix:"/api" leaked.path
     && not (String.starts_with ~prefix:"/api/health" leaked.path)
     && not (String.starts_with ~prefix:"/api/status" leaked.path));
  let blocked = expect_violation "authenticated-access-allowed" "services: []\n" in
  check "deny-all must lose authenticated access" (blocked.principal = "authenticated");
  List.iter
    (fun (name, source, prefix) ->
      let witness = expect_violation name source in
      check "public functionality witness must be anonymous inside its exception"
        (witness.principal = "anonymous" && String.starts_with ~prefix witness.path))
    [ ("public-access-allowed-1", config ~health:"plugins: [{name: key-auth}]" (), "/api/health");
      ("public-access-allowed-2", config ~status:"plugins: [{name: key-auth}]" (), "/api/status") ];
  let restricted = config ~health:"protocols: [https]" () |> verify in
  check "partial public functionality cannot prove" (restricted.result <> Report.Proved);
  let conservative = config ~health:"plugins: [{name: rate-limiting, config: {minute: 5}}]" () |> verify in
  check "quota-dependent public access cannot prove" (conservative.result <> Report.Proved);
  let unsupported = config ~health:"plugins: [{name: custom-unmodeled-plugin}]" () |> verify in
  (match unsupported.result with Report.Unknown _ -> () | _ -> failwith "unsupported public plugin must be unknown");
  let overlapping = ok (Contract_spec.parse_string (artifact "[/api/health, /api/health/ready, /api/status]")) in
  check "overlapping public prefixes are compatible"
    ((ok (Verify.run ~property:(Contract_spec.to_property overlapping) (config ()))).result = Report.Proved);
  let _, trace = ok (Verify.run_with_trace ~property (config ())) in
  check "frozen contract must produce evidence obligations" (Option.is_some trace);
  List.iter (fun prefixes -> expect_parse_error (artifact prefixes))
    [ "[]"; "null"; "[/api]"; "[/elsewhere]"; "[/api/health, /api/health]";
      "[/api/../health]"; "[/api/health, 42]"; "[/api/%68ealth]"; "{/api/health: true}" ];
  expect_parse_error (artifact ~extras:"assumptions: {}\n" "[/api/health]");
  expect_parse_error
    "schema_version: 1\nkind: protected-prefix-with-public-exceptions\nscope: {path_prefix: /api}\n";
  expect_parse_error
    "schema_version: 1\nkind: authenticated-access\nscope: {path_prefix: /api, public_path_prefixes: [/api/health]}\n";
  List.iter (fun public_path_prefixes ->
    match Verify.run ~property:(Verify.Protected_prefix_with_public_exceptions
      { path_prefix = "/api"; method_ = Some "GET"; host = None; public_path_prefixes }) (config ()) with
    | Error _ -> () | Ok _ -> failwith "typed API bypassed exception validation")
    [ []; ["/api"]; ["/other"]; ["/api/health"; "/api/health"] ];
  (* Public routes remain limited to the owner-reviewed GET/host scope; no
     allowance for a different method/host is accidentally required. *)
  let out = {|      - name: outside
        paths: [/outside]
        methods: [GET]
|} in
  let comparison_spec = { spec with host = None } in
  let before = config ~protected:"" ~host:"" ~extra:out () in
  let after = config ~host:"" ~extra:out () in
  let valid = ok (Compare.run_repair ~contract:comparison_spec before after) in
  check ("valid repair should preserve out-of-scope decisions: " ^ Compare.repair_to_json valid)
    (valid.result = Compare.Valid_repair);
  let regression = ok (Compare.run_repair ~contract:comparison_spec before (config ~host:"" ())) in
  (match regression.result with Compare.Out_of_scope_regression _ -> () | _ -> failwith "outside-scope change was accepted");
  (* Kong route hosts also match a raw Host with a port suffix. An exact frozen
     host is narrower, so changing those other hosts is outside its scope. *)
  let host_regression = ok (Compare.run_repair ~contract:spec (config ~protected:"" ()) (config ())) in
  (match host_regression.result with
   | Compare.Out_of_scope_regression witness ->
     check "host boundary witness escaped the intended test"
       (witness.request.host <> "api.example"
        && String.starts_with ~prefix:"api.example:" witness.request.host)
   | _ -> failwith "exact frozen host must not silently include port-suffixed hosts");
  let other_methods = ok (Compare.run_repair ~contract:comparison_spec
    (config ~protected:"" ~host:"" ~method_:"" ())
    (config ~host:"" ~method_:"" ())) in
  (match other_methods.result with
   | Compare.Out_of_scope_regression witness ->
     check "method boundary witness must be outside GET" (witness.request.method_ <> "GET")
   | _ -> failwith "GET contract must not permit changes to other methods inside /api");
  let heterogeneous = config ~extra:{|      - name: different-criteria
        paths: [/outside]
|} () |> verify in
  check "unresolved ordering must not prove public availability"
    (heterogeneous.result <> Report.Proved);
  let frozen = Contract_spec.bind_report spec report in
  check "new contract provenance missing" (frozen.frozen_spec = Some (Contract_spec.report_identity spec));
  print_endline "public exception contracts: passed"
