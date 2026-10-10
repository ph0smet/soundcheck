open Soundcheck_core
open Soundcheck_kong

let failures = ref []
let check name okay = if not okay then failures := name :: !failures

let request : Ir.request =
  { principal = Anonymous; action = "GET"; resource = "/admin/reports";
    context = []; source = 0l; host = "api.example"; scheme = "http"; sni = "" }

let rule ?(rank = 1) ?(complete = true) ?(guard = Ir.True) id decision : Ir.rule =
  { id; match_ = Path_prefix "/admin"; match_complete = complete; guard;
    guard_complete = true;
    priority = { comparable = true; key = [ rank ] }; decision;
    rate_limited = false; targets_admin = false }

let policy ?(default = Ir.Deny) rules : Ir.policy =
  { request_domain = True; rules; default }

let not_proved label property source =
  match Verify.run ~property source with
  | Ok { Report.result = Report.Proved; _ } -> check label false
  | Ok _ -> ()
  | Error error -> failwith error

let unsupported label property source =
  match Verify.run ~property source with
  | Ok { Report.result = Report.Unknown _;
         assurance = Some { status = Report.Unsupported; _ }; _ } -> ()
  | Ok _ -> check label false
  | Error error -> failwith error

let () =
  (* An uncertain denying winner cannot veto another possible allowing winner.
     These are alternatives, not simultaneously executing firewall rules. *)
  check "tied deny hides possible allowance"
    (Ir.evaluate (policy [ rule "open" Allow; rule "closed" Deny ]) request = Allow);
  check "incomplete high match suppresses real winner"
    (Ir.evaluate
       (policy [ rule "open" Allow; rule ~rank:2 ~complete:false "possible" Deny ])
       request = Allow);
  check "failed guard falls through to default allow"
    (Ir.evaluate (policy ~default:Allow [ rule ~guard:(Or []) "closed" Allow ])
       request = Deny);
  check "different priority shapes compare before length check"
    (not (Ir.outranks { comparable = true; key = [ 2 ] }
            { comparable = true; key = [ 1; 10 ] }));
  check "incomplete high match incorrectly prunes shadowing pair"
    (List.exists (fun (pair : Shadowing.pair) -> pair.shadowing.id = "open")
       (Shadowing.candidates
          (policy [ rule "open" Allow;
                    rule ~rank:2 ~complete:false ~guard:Requires_auth "possible" Allow ])));
  let paired = Verify.Authenticated_access
      { path_prefix = "/admin"; method_ = None; host = None } in
  not_proved "conditional termination manufactured definite allowance" paired
    {|services: [{name: api, routes: [{name: admin, paths: [/admin], plugins:
       [{name: key-auth}, {name: request-termination, config: {trigger: stop}}]}]}]|};
  unsupported "unknown plugin must be explicitly unsupported"
    (Verify.No_anonymous_access "/admin")
    {|services: [{name: api, routes: [{name: admin, paths: [/admin], plugins:
       [{name: key-auth}, {name: custom-policy}]}]}]|};
  not_proved "disabled service hides open fallback"
    (Verify.No_anonymous_access "/admin/reports")
    {|services:
 - name: open
   routes: [{name: fallback, paths: [/admin]}]
 - name: disabled
   enabled: false
   routes: [{name: inactive, paths: [/admin/reports], plugins: [{name: key-auth}]}]
|};
  unsupported "nested consumer plugin must be explicitly unsupported"
    (Verify.No_anonymous_access "/admin")
    {|services: [{name: api, routes: [{name: admin, paths: [/admin], plugins:
       [{name: key-auth, consumer: alice}]}]}]|};
  not_proved "stream-only plugin treated as HTTP enforcement"
    (Verify.No_anonymous_access "/admin")
    {|plugins: [{name: ip-restriction, protocols: [tcp], config: {deny: [0.0.0.0/0]}}]
services: [{name: api, routes: [{name: admin, paths: [/admin]}]}]|};
  List.iter (fun plugin ->
    unsupported "consumer-nested policy must be explicitly unsupported" paired
      ("consumers: [{username: bob, plugins: [{name: " ^ plugin ^ "}]}]\n"
       ^ "services: [{name: api, routes: [{name: admin, paths: [/admin], plugins: [{name: key-auth}]}]}]"))
    [ "request-termination"; "custom-policy" ];
  unsupported "consumer-group nested policy must be explicitly unsupported" paired
    {|consumer_groups: [{name: operators, plugins: [{name: request-termination}]}]
services: [{name: api, routes: [{name: admin, paths: [/admin], plugins: [{name: key-auth}]}]}]|};
  (* Pinned Kong traditional synthesizes a default port before Host matching;
     compatible wildcard string predicates also permit an empty wildcard.
     Raw-host nonempty-wildcard matching previously hid the open winner. *)
  List.iter (fun (route_host, request_host) ->
    let source = Printf.sprintf
      "services: [{name: api, routes: [{name: host-open, paths: [/admin], hosts: ['%s']}, {name: fallback-auth, paths: [/admin], plugins: [{name: key-auth}]}]}]"
      route_host in
    let property = Verify.Authenticated_access
        { path_prefix = "/admin"; method_ = Some "GET"; host = Some request_host } in
    (match Verify.run ~property source with
     | Ok { Report.result = Report.Violated _;
            assurance = Some { status = Report.Conservative; _ }; _ } -> ()
     | _ -> check ("host bound omitted possible open route: " ^ route_host) false);
    let config = match Parse.parse_string source with Ok c -> c | Error e -> failwith e in
    let lowered = Lower.to_policy config in
    let host_rule = List.find (fun (r : Ir.rule) -> r.id = "host-open") lowered.rules in
    check "uncertain host remained suppressing or omitted a real match"
      (not host_rule.match_complete && not host_rule.priority.comparable
       && Ir.matches host_rule.match_ { request with host = request_host }))
    [ "api.example:80", "api.example"; "example.*", "example." ];
  List.iter (fun consumer ->
    match Verify.run ~property:paired
      (consumer ^ "\nservices: [{name: api, routes: [{name: admin, paths: [/admin], plugins: [{name: key-auth}]}]}]") with
    | Ok { Report.result = Report.Proved; _ } -> ()
    | _ -> check "ordinary consumer without plugin rejected" false)
    [ "consumers: [{username: bob}]"; "consumers: [{username: bob, plugins: []}]" ];
  if !failures <> [] then failwith (String.concat "; " (List.rev !failures));
  print_endline "approximation boundary checks passed"
