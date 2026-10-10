open Soundcheck_core
open Soundcheck_kong

let failures = ref []
let checks = ref 0
let check label condition =
  incr checks;
  if not condition then failures := label :: !failures

let contains text fragment =
  let rec loop index =
    index + String.length fragment <= String.length text
    && (String.sub text index (String.length fragment) = fragment || loop (index + 1))
  in
  loop 0

let read_file path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
      really_input_string channel (in_channel_length channel))

(* The executable doubles as an explicit faulty solver. Untargeted obligations
   still go to the real Z3, so a later-phase regression cannot accidentally stop
   at a bad inhabitance model. The forged values are well-typed SMT responses;
   these tests exercise semantic validation, not protocol rejection. *)
let () =
  if Array.length Sys.argv > 1 && Sys.argv.(1) = "-smt2" then begin
    let source = read_file Sys.argv.(2) in
    if not (contains source (Sys.getenv "SOUNDCHECK_WITNESS_QUERY")) then
      Unix.execv (Sys.getenv "SOUNDCHECK_WITNESS_REAL_Z3") Sys.argv;
    print_endline "sat";
    if contains source "(get-value" then begin
      let headers =
        String.split_on_char '\n' source
        |> List.filter_map (fun line ->
               if String.starts_with ~prefix:"(declare-const header_" line then
                 match String.split_on_char ' ' line with
                 | _ :: symbol :: _ -> Some ("(" ^ symbol ^ " false)")
                 | _ -> None
               else None)
        |> String.concat " "
      in
      Printf.printf
        "((path %S) (method %S) (is_anon %s) (src_ip #x0a000001) (host %S) (scheme %S) (sni \"\") %s)\n"
        (Sys.getenv "SOUNDCHECK_WITNESS_PATH")
        (Sys.getenv "SOUNDCHECK_WITNESS_METHOD")
        (Sys.getenv "SOUNDCHECK_WITNESS_ANON")
        (Sys.getenv "SOUNDCHECK_WITNESS_HOST")
        (Sys.getenv "SOUNDCHECK_WITNESS_SCHEME") headers
    end;
    exit 0
  end

let real_z3 =
  String.split_on_char ':' (Sys.getenv "PATH")
  |> List.find_map (fun directory ->
         let path = Filename.concat directory "z3" in
         if Sys.file_exists path then Some path else None)
  |> Option.get

let mock_binary =
  if Filename.is_relative Sys.executable_name then
    Filename.concat (Sys.getcwd ()) Sys.executable_name
  else Sys.executable_name

let with_fake ?(path = "/admin") ?(method_ = "GET") ?(host = "example.com")
    ?(scheme = "http") ?(anonymous = true) ~only action =
  let directory = Filename.temp_file "soundcheck-witness-" "" in
  Sys.remove directory;
  Unix.mkdir directory 0o700;
  let binary = Filename.concat directory "z3" in
  Unix.symlink mock_binary binary;
  let variables =
    [ "PATH", directory ^ ":" ^ Sys.getenv "PATH";
      "SOUNDCHECK_WITNESS_REAL_Z3", real_z3;
      "SOUNDCHECK_WITNESS_QUERY", only;
      "SOUNDCHECK_WITNESS_PATH", path;
      "SOUNDCHECK_WITNESS_METHOD", method_;
      "SOUNDCHECK_WITNESS_HOST", host;
      "SOUNDCHECK_WITNESS_SCHEME", scheme;
      "SOUNDCHECK_WITNESS_ANON", string_of_bool anonymous ]
  in
  let previous = List.map (fun (name, _) -> name, Sys.getenv_opt name) variables in
  Fun.protect
    ~finally:(fun () ->
      List.iter (fun (name, value) ->
          Unix.putenv name (Option.value ~default:"" value)) previous;
      Sys.remove binary;
      Unix.rmdir directory)
    (fun () ->
      List.iter (fun (name, value) -> Unix.putenv name value) variables;
      action ())

let rule ?(guard = Ir.True) ?(rank = 1) ?(match_complete = true)
    ?(guard_complete = true) id : Ir.rule =
  { id; match_ = Path_prefix "/admin"; match_complete; guard; guard_complete;
    priority = { comparable = true; key = [rank] }; decision = Allow;
    rate_limited = false; targets_admin = false }

let policy rules : Ir.policy = { request_domain = True; rules; default = Deny }
let scope = Ir.And [Ir.Path_prefix "/admin"; Ir.Is_anonymous]
let deny = Contract.must_deny ~name:"deny" ~description:"deny anonymous" scope
let allow = Contract.must_allow ~name:"allow" ~description:"allow anonymous" scope
let allow_authenticated =
  Contract.must_allow ~name:"allow-auth" ~description:"allow authenticated"
    (Ir.And [Ir.Path_prefix "/admin"; Ir.Requires_auth])
let contract clauses : Contract.t = {name = "test"; description = "test"; clauses}

let invalid_contract label phase policy clauses only path =
  let outcome, trace =
    with_fake ~only ~path (fun () ->
        Contract_verify.run_with_trace policy (contract clauses))
  in
  check (label ^ " result")
    (match outcome with Contract_verify.Unknown reason ->
       contains reason "witness" | _ -> false);
  let entry =
    List.find_opt (fun entry -> entry.Contract_verify.obligation.phase = phase) trace
  in
  check (label ^ " trace")
    (match entry with
     | Some { execution = Contract_verify.Executed (Solve.Unknown reason); _ } ->
       contains reason "witness"
     | _ -> false);
  let rec stopped = function
    | [] -> false
    | {Contract_verify.execution = Executed (Solve.Unknown _); _} :: rest ->
      List.for_all (fun entry -> entry.Contract_verify.execution = Not_executed) rest
    | _ :: rest -> stopped rest
  in
  check (label ^ " skips remaining obligations") (stopped trace)

let config ?(routes = "  - name: admin\n    paths: [/admin]\n") ?(plugins = "")
    ?(url = "http://example.com") () =
  "_format_version: '3.0'\nservices:\n- name: backend\n  url: " ^ url ^ "\n  routes:\n"
  ^ routes ^ plugins

let parse text = match Parse.parse_string text with Ok value -> value | Error e -> failwith e
let model : Solve.model =
  {path = "/admin"; method_ = "GET"; is_anon = true; src_ip = 0x0a000001l;
   host = "example.com"; scheme = "http"; sni = ""; headers = []}

let verify_unknown label only config property =
  let result = with_fake ~only (fun () -> Verify.run ~property config) in
  check label (match result with
      | Ok { Report.result = Unknown reason; _ } -> contains reason "witness"
      | _ -> false)

let semantic_validation () =
  let request = Witness.request_of_model model in
  check "model conversion keeps every request dimension"
    (request = Ir.{principal = Anonymous; action = "GET"; resource = "/admin";
       context = []; source = 0x0a000001l; host = "example.com";
       scheme = "http"; sni = ""});
  let checked label predicate expected candidate =
    let result = Witness.validate ~obligation:label predicate (Solve.Violated candidate) in
    check label (match result with
        | Solve.Violated actual -> expected && actual = candidate
        | Solve.Unknown _ -> not expected
        | Solve.Proved -> false)
  in
  let cidr = match Cidr.parse "10.0.0.0/8" with Ok c -> c | Error e -> failwith e in
  let conditions =
    Ir.And [Path_prefix "/admin"; Method_is "GET"; Is_anonymous;
            Host_matches (Regex.Lit "example.com"); Scheme_is "http";
            Sni_is ""; Source_in cidr; Header_has ("x-role", "admin")]
  in
  let header_model = {model with headers = ["x-role", "admin"]} in
  let in_scope = Witness.condition ~domain:Ir.True conditions in
  checked "all request predicates are satisfied" in_scope true header_model;
  List.iter (fun (label, candidate) -> checked label in_scope false candidate)
    [ "wrong path", {header_model with path = "/other"};
      "wrong method", {header_model with method_ = "POST"};
      "wrong principal", {header_model with is_anon = false};
      "wrong source", {header_model with src_ip = 0l};
      "wrong host", {header_model with host = "other.example"};
      "wrong scheme", {header_model with scheme = "https"};
      "wrong sni", {header_model with sni = "other.example"};
      "missing header", model ];
  checked "domain required separately from scope"
    (Witness.condition ~domain:(Ir.Method_is "POST") scope) false model;
  checked "evaluation failure is unknown" (fun _ -> invalid_arg "bad evaluator") false model;
  check "validation exception diagnostics remain valid UTF-8"
    (match Witness.validate ~obligation:"bad \xff label"
             (fun _ -> invalid_arg "bad \xff evaluation") (Solve.Violated model) with
     | Solve.Unknown reason -> String.is_valid_utf_8 reason
     | _ -> false);
  check "unknown solver result remains unknown"
    (Witness.validate ~obligation:"not evaluated" (fun _ -> assert false)
       (Solve.Unknown "timeout") = Solve.Unknown "timeout");
  check "unsat remains proved"
    (Witness.validate ~obligation:"not evaluated" (fun _ -> assert false) Solve.Proved = Solve.Proved);

  let open_rule = rule "open" in
  let guarded = rule ~rank:2 ~guard:Ir.Requires_auth "guarded" in
  let safety = Property.no_anonymous_access ~path_prefix:"/admin" in
  checked "safety accepts allowing winner" (Witness.property (policy [open_rule]) safety) true model;
  checked "safety rejects suppressed allowing rule"
    (Witness.property (policy [open_rule; guarded]) safety) false model;
  checked "incomplete match does not suppress possible witness"
    (Witness.property (policy [open_rule; {guarded with match_complete = false}]) safety) true model;
  checked "safety rejects guard failure"
    (Witness.property (policy [guarded]) safety) false model;
  checked "safety rejects out-of-domain candidate"
    (Witness.property {(policy [open_rule]) with request_domain = Ir.Scheme_is "https"} safety)
    false model;
  let limited = {open_rule with rate_limited = true} in
  checked "structural rate-limit filter required"
    (Witness.property (policy [limited]) Property.rate_limit_on_public) false model;
  checked "structural admin-target filter required"
    (Witness.property (policy [open_rule]) (Property.admin_api_not_reachable ~trusted:cidr))
    false {model with src_ip = 0l};
  checked "structural admin-target witness accepted"
    (Witness.property (policy [{open_rule with targets_admin = true}])
       (Property.admin_api_not_reachable ~trusted:cidr)) true {model with src_ip = 0l};
  checked "must-deny retains structural filter"
    (Witness.clause (policy [limited])
       (Contract.must_deny ~reach_via:(fun r -> not r.Ir.rate_limited)
          ~name:"rate" ~description:"rate" scope)) false model;
  checked "default allow remains possible when no route matches"
    (Witness.property {(policy []) with default = Ir.Allow} safety) true model;
  checked "matching guarded route prevents allow default"
    (Witness.property {(policy [guarded]) with default = Ir.Allow} safety) false model;

  checked "must-allow accepts no-route denial" (Witness.clause (policy []) allow) true model;
  checked "must-allow rejects all-allow winner" (Witness.clause (policy [open_rule]) allow) false model;
  checked "must-allow accepts uncertain match"
    (Witness.clause (policy [{open_rule with match_complete = false}]) allow) true model;
  checked "must-allow accepts uncertain guard"
    (Witness.clause (policy [{open_rule with guard_complete = false}]) allow) true model;
  checked "must-allow accepts rejecting alternative"
    (Witness.clause (policy [open_rule; {guarded with priority = open_rule.priority}]) allow)
    true model;
  let pair = Shadowing.{shadowing = open_rule; shadowed = {guarded with priority = open_rule.priority}} in
  checked "shadowing valid overlap" (Witness.shadowing (policy [pair.shadowing; pair.shadowed]) pair)
    true model;
  checked "shadowing guard rejection required"
    (Witness.shadowing (policy [pair.shadowing; pair.shadowed]) pair)
    false {model with is_anon = false};
  let nonmatching = {pair with shadowed = {pair.shadowed with match_ = Ir.Path_prefix "/else"}} in
  checked "shadowing requires shadowed match"
    (Witness.shadowing (policy [nonmatching.shadowing; nonmatching.shadowed]) nonmatching) false model;
  checked "shadowing requires selected shadowing rule"
    (Witness.shadowing (policy [open_rule; guarded]) pair) false model;
  let incomplete_guard = {pair with shadowed = {pair.shadowed with guard = Ir.True; guard_complete = false}} in
  checked "shadowing uses conservative must guard"
    (Witness.shadowing (policy [incomplete_guard.shadowing; incomplete_guard.shadowed]) incomplete_guard)
    true model;

  let opened = policy [open_rule] and closed = policy [] in
  checked "decision comparison valid disagreement"
    (Witness.decision_difference opened closed) true model;
  checked "decision comparison requires comparison scope"
    (Witness.decision_difference ~when_:(Ir.Not scope) opened closed) false model;
  let outside p = {p with Ir.request_domain = Ir.Or []} in
  checked "decision comparison requires one admitted domain"
    (Witness.decision_difference (outside opened) (outside closed)) false model;
  checked "domain difference is a modeled decision difference"
    (Witness.decision_difference opened (outside opened)) true model;
  let label (r : Ir.rule) = r.id in
  let renamed = policy [{open_rule with id = "renamed"}] in
  let route_difference = Witness.route_difference ~left_label:label ~right_label:label in
  checked "route comparison validates selected labels" (route_difference opened renamed) true model;
  checked "route comparison rejects same selected labels" (route_difference opened opened) false model;
  checked "route comparison ignores unselected labels"
    (route_difference opened (policy [open_rule; {(rule "absent") with match_ = Ir.Path_prefix "/else"}]))
    false model;
  checked "route comparison includes denied route selection"
    (route_difference (policy [{open_rule with decision = Ir.Deny}]) closed) true model;
  checked "route comparison requires scope"
    (route_difference ~when_:(Ir.Not scope) opened renamed) false model;
  checked "upstream comparison validates selected values"
    (route_difference ~left_value:(fun _ -> Smt_encode.Literal "/one")
       ~right_value:(fun _ -> Smt_encode.Literal "/two") opened opened) true model;
  checked "upstream comparison rejects equal evaluated terms"
    (route_difference ~left_value:(fun _ -> Smt_encode.Request_path)
       ~right_value:(fun _ -> Smt_encode.Concat [Literal "/"; Drop_prefix 1]) opened opened)
    false model;
  checked "upstream comparison cannot use values from unselected rules"
    (route_difference ~left_value:(fun _ -> Smt_encode.Literal "/one")
       ~right_value:(fun _ -> Smt_encode.Literal "/two") closed closed) false model

let real_solver_witnesses () =
  let open_policy = policy [rule "open"] in
  let guarded = policy [rule ~guard:Ir.Requires_auth "guarded"] in
  let accepts label predicate query =
    let result = Solve.check query |> Witness.validate ~obligation:label predicate in
    check label (match result with Solve.Violated _ -> true | _ -> false)
  in
  accepts "real Z3 inhabitance"
    (Witness.condition ~domain:Ir.True scope)
    (Smt_encode.condition_query ~name:"inhabitance" ~description:"test" scope);
  accepts "real Z3 consistency"
    (Witness.condition ~domain:Ir.True scope)
    (Smt_encode.overlap_query deny allow);
  accepts "real Z3 safety" (Witness.clause open_policy deny)
    (Smt_encode.contract_clause_query open_policy deny);
  accepts "real Z3 functionality" (Witness.clause guarded allow)
    (Smt_encode.contract_clause_query guarded allow);
  let pair = Shadowing.{shadowing = rule "open";
                        shadowed = rule ~guard:Ir.Requires_auth "guarded"} in
  let paired = policy [pair.shadowing; pair.shadowed] in
  accepts "real Z3 shadowing" (Witness.shadowing paired pair)
    (Smt_encode.shadowing_query paired pair);
  let before = config () in
  let secured = config ~plugins:"  plugins:\n  - name: key-auth\n" () in
  let renamed = config ~routes:"  - name: renamed\n    paths: [/admin]\n" () in
  let redirected = config ~url:"http://elsewhere.example" () in
  let retained = config ~routes:
      "  - name: admin\n    paths: [/admin]\n    strip_path: false\n" () in
  List.iter (fun (mode, after, distinguish) ->
      check "real Z3 comparison witness accepted"
        (match Compare.run ~mode before after with
         | Ok {Compare.result = Different witness; _} -> distinguish witness
         | _ -> false);
      check "real Z3 equal policies remain equivalent"
        (match Compare.run ~mode before before with
         | Ok {Compare.result = Equivalent; _} -> true
         | _ -> false))
    [ Compare.Security_decision, secured,
      (fun w -> w.Compare.request.is_anon && w.before.decision = Ir.Allow
                && w.after.decision = Ir.Deny);
      Route_service, renamed,
      (fun w -> w.Compare.before.route = Some "admin" && w.after.route = Some "renamed");
      Service_target, redirected,
      (fun w -> w.Compare.before.service_target <> w.after.service_target);
      Upstream_uri, retained,
      (fun w -> w.Compare.before.upstream_uri <> None && w.after.upstream_uri <> None
                && w.before.upstream_uri <> w.after.upstream_uri) ];
  let frozen = match Contract_spec.parse_string
      "schema_version: 1\nkind: authenticated-access\nscope: {path_prefix: /admin, method: GET}\n" with
    | Ok value -> value | Error e -> failwith e
  in
  List.iter (fun mode ->
      let result = with_fake ~only:"equivalence:" (fun () ->
          Compare.run_repair ~z3:mock_binary ~mode ~contract:frozen before secured)
      in
      check "frozen repair rejects difference inside approved scope"
        (match result with Ok {Compare.result = Repair_unknown reason; _} ->
           contains reason "witness" | _ -> false))
    [Compare.Security_decision; Route_service; Service_target; Upstream_uri];
  let outside_domain = with_fake ~only:"equivalence:" ~scheme:"ftp" (fun () ->
      Compare.run before secured) in
  check "comparison rejects outside connector domain"
    (match outside_domain with Ok {Compare.result = Unknown reason; _} ->
       contains reason "witness" | _ -> false)

let adapter_consistency () =
  let source = config ~plugins:"  plugins:\n  - name: key-auth\n" () in
  let call ?contract source =
    let request = Printf.sprintf
        {|{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"verify","arguments":{"config":%S}}}|}
        source in
    match Soundcheck_mcp.Server.handle_line ?contract request with
    | Some response -> response | None -> failwith "missing MCP response"
  in
  let report property =
    match Verify.run ~z3:mock_binary ~property source with
    | Ok report -> report | Error e -> failwith e
  in
  with_fake ~only:"; property:" (fun () ->
      let expected = report (Verify.No_anonymous_access "/admin") |> Report.to_json in
      let response = call source in
      check "legacy JSON is Unknown without counterexample"
        (contains expected {|"result":"unknown"|}
         && contains expected {|"counterexample":null|});
      check "manual MCP structured report equals library JSON"
        (contains response ("\"structuredContent\":" ^ expected)));
  let frozen = match Contract_spec.parse_string
      "schema_version: 1\nkind: authenticated-access\nscope: {path_prefix: /admin, method: GET}\n" with
    | Ok value -> value | Error e -> failwith e in
  with_fake ~only:"contract clause:" (fun () ->
      let expected = report (Contract_spec.to_property frozen)
        |> Contract_spec.bind_report frozen |> Report.to_json in
      let response = call ~contract:frozen source in
      check "frozen JSON is Unknown without unchecked clause counterexample"
        (contains expected {|"result":"unknown"|}
         && contains expected {|"counterexample":null|}
         && contains expected {|"clause":null|});
      check "frozen MCP structured report equals bound library JSON"
        (contains response ("\"structuredContent\":" ^ expected)));
  with_fake ~only:"equivalence:" (fun () ->
      let result = Compare.run source source |> function
        | Ok value -> Compare.to_json value | Error e -> failwith e in
      check "comparison JSON excludes rejected witness"
        (contains result {|"result":"unknown"|}
         && contains result {|"witness":null|}))

let () =
  semantic_validation ();
  real_solver_witnesses ();
  adapter_consistency ();
  invalid_contract "inhabitance" Contract_verify.Inhabitance
    (policy []) [deny] "property preflight:" "/outside";
  invalid_contract "consistency" Contract_verify.Consistency
    (policy [rule "open"]) [deny; allow_authenticated]
    "safety/functionality request-class overlap" "/admin";
  invalid_contract "must-deny" Contract_verify.Clause
    (policy [rule ~guard:Ir.Requires_auth "secured"]) [deny]
    "contract clause:" "/admin";
  invalid_contract "must-allow" Contract_verify.Clause
    (policy [rule "open"]) [allow] "contract clause:" "/admin";

  let secured = config ~plugins:"  plugins:\n  - name: key-auth\n" () in
  verify_unknown "legacy safety rejects guarded model" "; property:"
    secured (Verify.No_anonymous_access "/admin");
  let outside =
    with_fake ~only:"property preflight:" ~path:"/outside" (fun () ->
        Verify.run ~property:(Verify.No_anonymous_access "/admin") (config ()))
  in
  check "legacy inhabitance rejects out-of-class model"
    (match outside with Ok {Report.result = Unknown _; _} -> true | _ -> false);
  let shadowing =
    config ~routes:
      "  - name: open\n    paths: [/admin/x]\n  - name: guarded\n    paths: [/admin]\n    plugins:\n    - name: key-auth\n" ()
  in
  verify_unknown "shadowing requires both route matches" "; property: no-shadowed-routes"
    shadowing Verify.No_shadowed_routes;

  List.iter (fun mode ->
      let result =
        with_fake ~only:"equivalence:" (fun () -> Compare.run ~mode (config ()) (config ()))
      in
      check "comparison rejects agreeing forged model"
        (match result with Ok {Compare.result = Unknown reason; _} ->
           contains reason "witness" | _ -> false))
    [Compare.Security_decision; Route_service; Service_target; Upstream_uri];

  let disjoint =
    config ~routes:
      "  - name: secured\n    paths: [/admin]\n    methods: [GET]\n    plugins:\n    - name: key-auth\n  - name: open\n    paths: [/admin]\n    methods: [POST]\n" ()
  in
  let exact = with_fake ~only:"route-order-determinism" (fun () ->
      Compare.run disjoint disjoint)
  in
  check "exact-policy preflight rejects nonoverlap model"
    (match exact with Ok {Compare.result = Unknown reason; _} ->
       contains reason "witness" | _ -> false);

  let wrong_method = parse (config ~routes:
      "  - name: wrong\n    paths: [/admin]\n    methods: [POST]\n  - name: correct\n    paths: [/admin]\n    methods: [GET]\n" ()) in
  check "lift uses method" ((Lift.counterexample wrong_method model).route = Some "correct");
  let wrong_host = parse (config ~routes:
      "  - name: wrong\n    paths: [/admin]\n    hosts: [other.example]\n  - name: correct\n    paths: [/admin]\n    hosts: [example.com]\n" ()) in
  check "lift uses host" ((Lift.counterexample wrong_host model).route = Some "correct");
  let suppressed = parse (config ~routes:
      "  - name: lower\n    paths: [/]\n  - name: winner\n    paths: [/admin]\n" ()) in
  check "lift uses precedence" ((Lift.counterexample suppressed model).route = Some "winner");
  let denying_guard = parse (config ~routes:
      "  - name: closed\n    paths: [/admin]\n    plugins:\n    - name: ip-restriction\n      config: {allow: [192.0.2.0/24]}\n  - name: open\n    paths: [/admin]\n" ()) in
  check "lift rejects guard failure" ((Lift.counterexample denying_guard model).route = Some "open");
  let limited = parse (config ~routes:
      "  - name: limited\n    paths: [/admin]\n    plugins:\n    - name: rate-limiting\n      config: {minute: 10}\n  - name: unlimited\n    paths: [/admin]\n" ()) in
  check "lift respects structural property"
    ((Lift.counterexample ~reach_via:Property.rate_limit_on_public.reach_via limited model).route
     = Some "unlimited");
  let duplicate_names = parse
      "services: [{name: one, routes: [{name: admin, paths: [/admin]}]}, {name: two, routes: [{name: admin, paths: [/admin]}]}]" in
  check "lift does not invent duplicate-name service ownership"
    ((Lift.counterexample duplicate_names model).service = None);
  let incomplete = policy [rule ~match_complete:false "uncertain-match"] in
  let lifted = Lift.functionality_counterexample (parse (config ())) incomplete model in
  check "incomplete match is not no route"
    (lifted.route = Some "uncertain-match" && not (contains lifted.note "no route"));
  let incomplete = policy [rule ~guard_complete:false "uncertain-guard"] in
  let lifted = Lift.functionality_counterexample (parse (config ())) incomplete model in
  check "incomplete guard is not no route"
    (lifted.route = Some "uncertain-guard" && not (contains lifted.note "no route"));
  let incomparable = { (rule ~rank:9 "a") with priority = {comparable = false; key = [9]} } in
  let other = { (rule ~rank:1 "b") with priority = {comparable = false; key = [1]} } in
  let note = (Lift.shadowing_counterexample (parse (config ()))
      Shadowing.{shadowing = incomparable; shadowed = other} model).note in
  check "incomparable priorities do not outrank" (not (contains note "outranks"));
  check "lift identifies modeled candidate" (contains (Lift.counterexample wrong_method model).note "model");

  match List.rev !failures with
  | [] -> Printf.printf "All %d witness validation checks passed.\n" !checks
  | labels ->
    List.iter (fun label -> Printf.eprintf "[FAIL] %s\n" label) labels;
    failwith (Printf.sprintf "%d witness checks failed" (List.length labels))
