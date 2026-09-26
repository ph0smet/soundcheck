open Soundcheck_core

let priority key = Ir.{ comparable = true; key = [ key ] }

let route ?(guard = Ir.True) ?(rank = 1) ?(match_complete = true) id =
  Ir.{ id;
       match_ = Path_prefix "/admin";
       match_complete;
       guard;
       priority = priority rank;
       decision = Allow;
       rate_limited = false;
       targets_admin = false }

let required_anonymous =
  Contract.must_allow ~name:"anonymous-admin-must-work"
    ~description:"Anonymous admin traffic remains functional"
    (Ir.And [ Ir.Path_prefix "/admin"; Ir.Is_anonymous ])

let safety_anonymous =
  Contract.must_deny ~name:"anonymous-admin-denied"
    ~description:"Anonymous admin traffic is denied"
    (Ir.And [ Ir.Path_prefix "/admin"; Ir.Is_anonymous ])

let contract clauses : Contract.t =
  { name = "admin-access"; description = "Admin access contract"; clauses }

let expect label want got =
  let same =
    match (want, got) with
    | Solve.Proved, Solve.Proved -> true
    | Solve.Violated _, Solve.Violated _ -> true
    | _ -> false
  in
  if not same then
    failwith
      (Printf.sprintf "%s: expected %s, got %s" label
         (Solve.string_of_result want) (Solve.string_of_result got))

let check_clause label policy clause want =
  Smt_encode.contract_clause_query policy clause
  |> Solve.check |> expect label want

let () =
  let deny_all : Ir.policy =
    { request_domain = True; rules = []; default = Deny }
  in
  check_clause "deny-all violates functionality" deny_all required_anonymous
    (Solve.Violated
       { path = ""; method_ = ""; is_anon = true; src_ip = 0l; host = "";
         scheme = ""; sni = "";
         headers = [] });

  let open_admin : Ir.policy =
    { request_domain = True; rules = [ route "open" ]; default = Deny }
  in
  check_clause "known open winner proves functionality" open_admin
    required_anonymous Solve.Proved;

  (* The old safety-oriented union sees the open rule and could call this
     allowed. Functionality must consider that the tied auth rule may be Kong's
     real winner, in which case an anonymous request is denied. *)
  let ambiguous : Ir.policy =
    { request_domain = True;
      rules =
        [ route ~guard:Ir.True "open";
          route ~guard:Ir.Requires_auth "auth-required" ];
      default = Deny }
  in
  check_clause "every possible winner must allow" ambiguous required_anonymous
    (Solve.Violated
       { path = ""; method_ = ""; is_anon = true; src_ip = 0l; host = "";
         scheme = ""; sni = "";
         headers = [] });
  let anonymous_admin : Ir.request =
    { principal = Anonymous;
      action = "GET";
      resource = "/admin";
      context = [];
      source = 0l;
      host = "";
      scheme = "http";
      sni = "" }
  in
  if Ir.definitely_allows ambiguous anonymous_admin then
    failwith "ambiguous rejecting winner must prevent definite allowance";

  let known_open_winner : Ir.policy =
    { request_domain = True;
      rules =
        [ route ~rank:2 "open";
          route ~rank:1 ~guard:Ir.Requires_auth "auth-required" ];
      default = Deny }
  in
  check_clause "known priority removes ambiguity" known_open_winner
    required_anonymous Solve.Proved;
  if not (Ir.definitely_allows known_open_winner anonymous_admin) then
    failwith "known open winner must definitely allow the request";

  let incomplete : Ir.policy =
    { request_domain = True;
      rules = [ route ~match_complete:false "header-scoped" ];
      default = Deny }
  in
  check_clause "incomplete match cannot prove functionality" incomplete
    required_anonymous
    (Solve.Violated
       { path = ""; method_ = ""; is_anon = true; src_ip = 0l; host = "";
         scheme = ""; sni = "";
         headers = [] });
  if Ir.definitely_allows incomplete anonymous_admin then
    failwith "incomplete route match must not establish definite allowance";

  let all =
    match Cidr.parse "0.0.0.0/0" with Ok cidr -> cidr | Error e -> failwith e
  in
  let empty = Ir.And [ Ir.Not (Ir.Source_in all); Ir.Is_anonymous ] in
  Smt_encode.condition_query ~name:"empty" ~description:"empty" empty
  |> Solve.check |> expect "empty request class is vacuous" Solve.Proved;

  let safety =
    Contract.must_deny ~name:"deny-anonymous" ~description:"deny anonymous"
      (Ir.And [ Ir.Path_prefix "/admin"; Ir.Is_anonymous ])
  in
  let contradictory : Contract.t =
    { name = "contradictory";
      description = "same request must be denied and allowed";
      clauses = [ safety; required_anonymous ] }
  in
  match Contract.safety_functionality_overlaps contradictory with
  | [ left, right ] ->
    Smt_encode.overlap_query left right |> Solve.check
    |> expect "overlapping clauses are inconsistent"
         (Solve.Violated
            { path = ""; method_ = ""; is_anon = true; src_ip = 0l; host = "";
              scheme = ""; sni = "";
              headers = [] })
  | _ -> failwith "expected exactly one safety/functionality pair"

let () =
  let deny_all : Ir.policy =
    { request_domain = True; rules = []; default = Deny }
  in
  (match Contract_verify.run deny_all (contract [ required_anonymous ]) with
   | Contract_verify.Violated (clause, _) ->
     if Contract.name clause <> Contract.name required_anonymous then
       failwith "contract runner reported the wrong violated clause"
   | _ -> failwith "deny-all must violate the functionality contract");

  let empty =
    let all =
      match Cidr.parse "0.0.0.0/0" with Ok cidr -> cidr | Error e -> failwith e
    in
    Contract.must_allow ~name:"empty" ~description:"empty"
      (Ir.Not (Ir.Source_in all))
  in
  (match Contract_verify.run deny_all (contract [ empty ]) with
   | Contract_verify.Vacuous clause when Contract.name clause = "empty" -> ()
   | _ -> failwith "empty contract clause must be reported vacuous");

  (match
     Contract_verify.run deny_all
       (contract [ safety_anonymous; required_anonymous ])
   with
   | Contract_verify.Inconsistent (safety, functionality)
     when Contract.name safety = Contract.name safety_anonymous
          && Contract.name functionality = Contract.name required_anonymous -> ()
   | _ -> failwith "overlapping safety/functionality clauses must be inconsistent");

  let required_authenticated =
    Contract.must_allow ~name:"authenticated-admin-allowed"
      ~description:"Authenticated admin traffic is allowed"
      (Ir.And [ Ir.Path_prefix "/admin"; Ir.Requires_auth ])
  in
  let guarded : Ir.policy =
    { request_domain = True;
      rules = [ route ~guard:Ir.Requires_auth "admin" ];
      default = Deny }
  in
  (match
     Contract_verify.run guarded
       (contract [ safety_anonymous; required_authenticated ])
   with
   | Contract_verify.Proved -> ()
   | _ -> failwith "guarded admin route must satisfy the paired contract")

let phase_name = function
  | Contract_verify.Inhabitance -> "inhabitance"
  | Contract_verify.Consistency -> "consistency"
  | Contract_verify.Clause -> "clause"

let expect_plan expected plan =
  let actual =
    List.map
      (fun (obligation : Contract_verify.obligation) ->
        (obligation.id, phase_name obligation.phase, obligation.clauses))
      plan
  in
  if actual <> expected then failwith "contract obligation plan changed"

let () =
  let required_authenticated =
    Contract.must_allow ~name:"authenticated-admin-allowed"
      ~description:"Authenticated admin traffic is allowed"
      (Ir.And [ Ir.Path_prefix "/admin"; Ir.Requires_auth ])
  in
  let paired = contract [ safety_anonymous; required_authenticated ] in
  let guarded : Ir.policy =
    { request_domain = True;
      rules = [ route ~guard:Ir.Requires_auth "admin" ];
      default = Deny }
  in
  let expected =
    [ ( "inhabitance-01-anonymous-admin-denied",
        "inhabitance", [ "anonymous-admin-denied" ] );
      ( "inhabitance-02-authenticated-admin-allowed",
        "inhabitance", [ "authenticated-admin-allowed" ] );
      ( "consistency-01-anonymous-admin-denied-authenticated-admin-allowed",
        "consistency",
        [ "anonymous-admin-denied"; "authenticated-admin-allowed" ] );
      ( "clause-01-anonymous-admin-denied",
        "clause", [ "anonymous-admin-denied" ] );
      ( "clause-02-authenticated-admin-allowed",
        "clause", [ "authenticated-admin-allowed" ] ) ]
  in
  let plan = Contract_verify.plan guarded paired in
  expect_plan expected plan;
  if List.exists (fun obligation -> obligation.Contract_verify.smtlib = "") plan
  then failwith "planned obligation omitted its SMT-LIB2";
  let result, trace = Contract_verify.run_with_trace guarded paired in
  (match result with
   | Contract_verify.Proved -> ()
   | _ -> failwith "traced verification changed a proved verdict");
  if
    not
      (List.for_all
         (fun entry ->
           match entry.Contract_verify.execution with
           | Contract_verify.Executed _ -> true
           | Contract_verify.Not_executed -> false)
         trace)
  then failwith "proved contract must execute every planned obligation";

  let all =
    match Cidr.parse "0.0.0.0/0" with Ok cidr -> cidr | Error error -> failwith error
  in
  let empty =
    Contract.must_allow ~name:"empty-scope" ~description:"empty scope"
      (Ir.Not (Ir.Source_in all))
  in
  let result, trace =
    Contract_verify.run_with_trace guarded (contract [ empty; required_authenticated ])
  in
  (match result with
   | Contract_verify.Vacuous clause when Contract.name clause = "empty-scope" -> ()
   | _ -> failwith "trace changed the vacuous short-circuit result");
  (match trace with
   | first :: rest ->
     (match first.execution with
      | Contract_verify.Executed Solve.Proved -> ()
      | _ -> failwith "vacuous inhabitance query was not recorded");
     if
       not
         (List.for_all
            (fun entry -> entry.Contract_verify.execution = Not_executed)
            rest)
     then failwith "obligations after vacuity must be explicitly unexecuted"
   | [] -> failwith "vacuous trace omitted its plan");

  let result, trace =
    Contract_verify.run_with_trace guarded
      (contract [ safety_anonymous; required_anonymous ])
  in
  (match result with
   | Contract_verify.Inconsistent _ -> ()
   | _ -> failwith "trace changed the inconsistency result");
  let executed, skipped =
    List.partition
      (fun entry ->
        match entry.Contract_verify.execution with
        | Executed _ -> true
        | Not_executed -> false)
      trace
  in
  if List.length executed <> 3 || List.length skipped <> 2 then
    failwith "inconsistency trace did not preserve phase short-circuiting"

let () =
  let clause : Report.clause =
    { name = "authenticated-admin-allowed";
      description = "Authenticated admin traffic is allowed";
      kind = Must_allow }
  in
  let report : Report.t =
    { result = Inconsistent "clauses overlap";
      property_name = "admin-access";
      property_description = "Admin access contract";
      assurance = None;
      clause = Some clause;
      frozen_spec = None }
  in
  let expected =
    {|{"result":"inconsistent","schema_version":9,"property":"admin-access","assurance":null,"frozen_spec":null,"clause":{"name":"authenticated-admin-allowed","description":"Authenticated admin traffic is allowed","kind":"must_allow"},"counterexample":null,"reason":"clauses overlap"}|}
  in
  let got = Report.to_json report in
  if got <> expected then
    failwith (Printf.sprintf "unexpected contract JSON\nexpected: %s\ngot:      %s" expected got)
