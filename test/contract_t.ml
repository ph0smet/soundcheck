open Soundcheck_core

let priority key = Ir.{ comparable = true; key = [ key ] }

let route ?(guard = Ir.True) ?(rank = 1) id =
  Ir.{ id;
       match_ = Path_prefix "/admin";
       guard;
       priority = priority rank;
       decision = Allow;
       rate_limited = false;
       targets_admin = false }

let required_anonymous =
  Contract.must_allow ~name:"anonymous-admin-must-work"
    ~description:"Anonymous admin traffic remains functional"
    (Ir.And [ Ir.Path_prefix "/admin"; Ir.Is_anonymous ])

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
  let deny_all : Ir.policy = { rules = []; default = Deny } in
  check_clause "deny-all violates functionality" deny_all required_anonymous
    (Solve.Violated
       { path = ""; method_ = ""; is_anon = true; src_ip = 0l; host = "" });

  let open_admin : Ir.policy =
    { rules = [ route "open" ]; default = Deny }
  in
  check_clause "known open winner proves functionality" open_admin
    required_anonymous Solve.Proved;

  (* The old safety-oriented union sees the open rule and could call this
     allowed. Functionality must consider that the tied auth rule may be Kong's
     real winner, in which case an anonymous request is denied. *)
  let ambiguous : Ir.policy =
    { rules =
        [ route ~guard:Ir.True "open";
          route ~guard:Ir.Requires_auth "auth-required" ];
      default = Deny }
  in
  check_clause "every possible winner must allow" ambiguous required_anonymous
    (Solve.Violated
       { path = ""; method_ = ""; is_anon = true; src_ip = 0l; host = "" });

  let known_open_winner : Ir.policy =
    { rules =
        [ route ~rank:2 "open";
          route ~rank:1 ~guard:Ir.Requires_auth "auth-required" ];
      default = Deny }
  in
  check_clause "known priority removes ambiguity" known_open_winner
    required_anonymous Solve.Proved;

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
            { path = ""; method_ = ""; is_anon = true; src_ip = 0l; host = "" })
  | _ -> failwith "expected exactly one safety/functionality pair"
