open Soundcheck_core

let checks = ref 0
let check label condition =
  incr checks;
  if not condition then failwith label

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

(* An explicitly faulty solver exercises observation decoding separately from
   semantic witness validation. It emits the requested fixture unchanged. *)
let () =
  if Array.length Sys.argv > 1 && Sys.argv.(1) = "-smt2" then begin
    print_endline "sat";
    if contains (read_file Sys.argv.(2)) "(get-value" then
      print_endline (Sys.getenv "SOUNDCHECK_OBJECT_TEST_REPLY");
    exit 0
  end

let coordinates : Ir.object_request =
  { namespace = "frontend"; resource_kind = "configmaps"; name = "settings" }

let request : Ir.request =
  { principal = Authenticated "system:serviceaccount:frontend:frontend-sa";
    action = "get"; resource = ""; context = []; source = 0l; host = "";
    scheme = ""; sni = ""; object_request = Some coordinates }

let principal = "system:serviceaccount:frontend:frontend-sa"
let exact_scope =
  Ir.And [Principal_is principal; Method_is "get";
          Object_is (Object_namespace, "frontend");
          Object_is (Object_kind, "configmaps");
          Object_is (Object_name, "settings")]

let query ?(domain = Ir.True) condition =
  Smt_encode.condition_query ~domain ~name:"object request" ~description:"typed request" condition

let expect_sat label condition =
  match Solve.check (query condition) with
  | Solve.Violated model ->
    check (label ^ ": valid witness")
      (match Witness.validate ~obligation:label (Witness.condition ~domain:Ir.True condition)
               (Solve.Violated model) with Solve.Violated _ -> true | _ -> false);
    model
  | result -> failwith (label ^ ": " ^ Solve.string_of_result result)

let expect_unsat label condition =
  check label (Solve.check (query condition) = Solve.Proved)

let field_conditions () =
  let conditions =
    Ir.[Has_object_request;
        Principal_is principal;
        Principal_is "other";
        Object_is (Object_namespace, "frontend");
        Object_is (Object_namespace, "payments");
        Object_is (Object_kind, "configmaps");
        Object_is (Object_kind, "secrets");
        Object_is (Object_name, "settings");
        Object_is (Object_name, "other");
        Object_matches (Object_namespace, Regex.Lit "frontend");
        Object_matches (Object_kind, Regex.Alt [Regex.Lit "configmaps"; Regex.Lit "secrets"]);
        Object_matches (Object_name, Regex.Concat [Regex.Lit "setting"; Regex.Any]);
        Object_matches (Object_name, Regex.Lit "setting");
        Object_length_at_most (Object_namespace, 8);
        Object_length_at_most (Object_namespace, 7);
        Object_length_at_most (Object_kind, 10);
        Object_length_at_most (Object_name, 8);
        Object_length_at_most (Object_name, 7);
        Object_length_at_most (Object_name, -1)]
  in
  List.iteri (fun index condition ->
      let expected = Ir.matches condition request in
      let opposite = if expected then Ir.Not condition else condition in
      expect_unsat (Printf.sprintf "concrete/SMT field %d" index)
        (Ir.And [exact_scope; opposite])) conditions;
  let absent = {request with object_request = None} in
  let no_object = Ir.And [Principal_is principal; Not Has_object_request] in
  List.iter (fun field ->
      List.iter (fun predicate ->
          check "absent object does not match" (not (Ir.matches predicate absent));
          expect_unsat "absent object cannot satisfy SMT predicate" (Ir.And [no_object; predicate]))
        Ir.[Object_is (field, ""); Object_matches (field, Regex.Star Regex.Any);
            Object_length_at_most (field, max_int)])
    Ir.[Object_namespace; Object_kind; Object_name];
  ignore (expect_sat "absent object negation" (Ir.And [no_object; Not (Object_is (Object_name, ""))]));
  let empty = Ir.{namespace = ""; resource_kind = ""; name = ""} in
  check "empty present object remains distinct from absent"
    (Ir.matches (Object_is (Object_name, "")) {request with object_request = Some empty});
  ignore (expect_sat "empty present object" Ir.(And [Has_object_request; Object_is (Object_name, "")]));
  let utf8 = "\xc3\xa9" in
  let bytes = {request with object_request = Some {coordinates with name = utf8}} in
  check "object length is bytes" (Ir.matches (Object_length_at_most (Object_name, 2)) bytes);
  check "object length is not Unicode scalar count" (not (Ir.matches (Object_length_at_most (Object_name, 1)) bytes));
  expect_unsat "SMT object length is bytes"
    Ir.(And [Object_is (Object_name, utf8); Object_length_at_most (Object_name, 1)])

let faithful_observation () =
  let model = expect_sat "named object" exact_scope in
  check "principal name survives decoding" (model.principal_name = Some principal);
  check "coordinates survive decoding" (model.object_request = Some coordinates);
  let lifted = Witness.request_of_model model in
  check "principal name survives lifting" (lifted.principal = request.principal);
  check "coordinates survive lifting" (lifted.object_request = request.object_request);
  let unnamed = expect_sat "legacy authenticated request" Ir.Requires_auth in
  check "legacy name remains absent" (unnamed.principal_name = None);
  check "legacy object remains absent" (unnamed.object_request = None);
  let lifted = Witness.request_of_model unnamed in
  check "unnamed principal remains authenticated" (Ir.matches Requires_auth lifted);
  check "no fabricated default identity" (not (Ir.matches (Principal_is "subject") lifted));
  check "no fabricated empty identity" (not (Ir.matches (Principal_is "") lifted));
  let anonymous = {model with is_anon = true} |> Witness.request_of_model in
  check "anonymous name cannot satisfy identity predicate" (not (Ir.matches (Principal_is principal) anonymous));
  List.iter (fun value ->
      let m = expect_sat "escaped principal" Ir.(Principal_is value) in
      check "exact case-sensitive escaped name" (m.principal_name = Some value))
    ["Alice"; "alice"; ""; "name\x00suffix"; "quote\"\\u0041\xc3\xa9"];
  let old_query = query Ir.(And [Path_prefix "/admin"; Requires_auth]) in
  check "HTTP query has no principal observation" (not (contains old_query "principal_name"));
  check "HTTP query has no object observation" (not (contains old_query "object_"));
  check "old HTTP observation shape is retained"
    (contains old_query "(get-value (path method is_anon src_ip host scheme sni))")

let rule id match_ : Ir.rule =
  { id; match_; match_complete = true; guard = True; guard_complete = true;
    priority = {comparable = true; key = []}; decision = Allow;
    rate_limited = false; targets_admin = false }

let policy rules : Ir.policy =
  { request_domain = Ir.And [Principal_is principal; Has_object_request]; rules; default = Deny }

let query_integration () =
  let allowance = Ir.Object_is (Object_kind, "configmaps") in
  let overlapping = policy [rule "broad" allowance; rule "narrow" exact_scope] in
  let needed = Contract.must_allow ~name:"needed" ~description:"required grant" exact_scope in
  check "additive grants preserve exact definite allowance"
    (Ir.possibly_allows overlapping request && Ir.definitely_allows overlapping request);
  check "overlapping grants prove functionality"
    (Contract_verify.run overlapping {name = "object"; description = "object"; clauses = [needed]}
     = Contract_verify.Proved);
  let forbidden = Contract.must_deny ~name:"forbidden" ~description:"unwanted grant" exact_scope in
  check "named object contract catches grant"
    (match Contract_verify.run overlapping {name = "object"; description = "object"; clauses = [forbidden]} with
     | Contract_verify.Violated (_, model) -> model.principal_name = Some principal && model.object_request = Some coordinates
     | _ -> false);
  let empty = policy [] in
  let condition = Ir.Object_is (Object_namespace, "frontend") in
  let difference = Smt_encode.decision_equivalence_query ~when_:condition empty overlapping |> Solve.check in
  check "comparison observes object and principal"
    (match Witness.validate ~obligation:"typed comparison"
             (Witness.decision_difference ~when_:condition empty overlapping) difference with
     | Solve.Violated model -> model.principal_name = Some principal && Option.is_some model.object_request
     | _ -> false);
  let observed_only_in_guard = { (rule "guard" Ir.True) with guard = exact_scope } in
  let guarded = {empty with rules = [observed_only_in_guard]; request_domain = True} in
  let property : Property.t =
    {name = "guard"; description = "guard"; forbidden_when = True; reach_via = (fun _ -> true)}
  in
  check "guard observations are included"
    (match Solve.check (Smt_encode.to_smtlib guarded property) with
     | Solve.Violated model -> model.principal_name = Some principal && model.object_request = Some coordinates
     | _ -> false)

let mock_binary =
  if Filename.is_relative Sys.executable_name then Filename.concat (Sys.getcwd ()) Sys.executable_name
  else Sys.executable_name

let with_reply reply action =
  let old = Sys.getenv_opt "SOUNDCHECK_OBJECT_TEST_REPLY" in
  Fun.protect ~finally:(fun () -> Unix.putenv "SOUNDCHECK_OBJECT_TEST_REPLY" (Option.value ~default:"" old))
    (fun () -> Unix.putenv "SOUNDCHECK_OBJECT_TEST_REPLY" reply; action ())

let protocol_checks () =
  let legacy = ["path", "\"\""; "method", "\"get\""; "is_anon", "false";
                "src_ip", "#x00000000"; "host", "\"\""; "scheme", "\"\""; "sni", "\"\""] in
  let objects = ["principal_name", Regex.smt_string principal; "has_object_request", "true";
                 "object_namespace", "\"frontend\""; "object_kind", "\"configmaps\""; "object_name", "\"settings\""] in
  let format bindings =
    "(" ^ String.concat " " (List.map (fun (k,v) -> "(" ^ k ^ " " ^ v ^ ")") bindings) ^ ")"
  in
  let original = legacy @ objects in
  let run bindings = with_reply (format bindings) (fun () -> Solve.check ~z3:mock_binary (query exact_scope)) in
  check "valid typed protocol"
    (match run original with Solve.Violated m -> m.principal_name = Some principal && m.object_request = Some coordinates | _ -> false);
  List.iter (fun field ->
      check ("missing typed observation " ^ field)
        (match run (List.remove_assoc field original) with Solve.Unknown _ -> true | _ -> false);
      check ("wrong typed observation " ^ field)
        (match run ((field, "42") :: List.remove_assoc field original) with Solve.Unknown _ -> true | _ -> false))
    (List.map fst objects);
  check "duplicate typed observation"
    (match run (List.hd objects :: original) with Solve.Unknown _ -> true | _ -> false);
  let validate bindings =
    run bindings |> Witness.validate ~obligation:"typed witness" (Witness.condition ~domain:Ir.True exact_scope)
  in
  List.iter (fun (field,value) ->
      check ("wrong semantic witness " ^ field)
        (match validate ((field,value) :: List.remove_assoc field original) with Solve.Unknown _ -> true | _ -> false))
    ["principal_name", "\"other\""; "has_object_request", "false";
     "object_namespace", "\"payments\""; "object_kind", "\"secrets\""; "object_name", "\"other\"";
     "is_anon", "true"];
  let partial_query =
    "(declare-const path String)\n(declare-const method String)\n(declare-const is_anon Bool)\n"
    ^ "(declare-const src_ip (_ BitVec 32))\n(declare-const host String)\n(declare-const scheme String)\n"
    ^ "(declare-const sni String)\n(declare-const has_object_request Bool)\n"
    ^ "(check-sat)\n(get-value (path method is_anon src_ip host scheme sni has_object_request))\n"
  in
  check "partial object request in query cannot fabricate coordinates"
    (match with_reply (format (legacy @ ["has_object_request", "false"]))
             (fun () -> Solve.check ~z3:mock_binary partial_query) with Solve.Unknown _ -> true | _ -> false)

let () =
  field_conditions ();
  faithful_observation ();
  query_integration ();
  protocol_checks ();
  Printf.printf "%d typed object/identity checks passed\n" !checks
