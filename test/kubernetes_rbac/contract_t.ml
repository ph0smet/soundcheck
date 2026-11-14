open Soundcheck_core
open Soundcheck_kubernetes_rbac

let count = ref 0
let check name value = incr count; if not value then failwith name
let read path =
  let ch = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr ch) (fun () -> really_input_string ch (in_channel_length ch))
let get = function Ok x -> x | Error reason -> failwith reason
let outcome = function
  | Contract_verify.Proved -> "proved" | Violated _ -> "violated" | Unknown _ -> "unknown"
  | Vacuous _ -> "vacuous" | Inconsistent _ -> "inconsistent"
let replace key value = function
  | `O fields -> `O (List.map (fun (k,v) -> k,if k=key then value else v) fields)
  | _ -> assert false

let () =
  let root = Sys.argv.(1) in
  let source = read (root ^ "/contracts/frontend-access.json") in
  let spec = get (Contract_spec.of_string source) in
  let canonical = Contract_spec.canonical spec in
  check "canonical roundtrip" (canonical = Contract_spec.canonical (get (Contract_spec.of_string canonical)));
  let contract = Contract_spec.to_contract spec in
  let cases = match Input.parse (read (root ^ "/cases.json")) with `O values -> values | _ -> assert false in
  let baseline = get (Snapshot.of_string (read (root ^ "/fixtures/01-unsafe.json"))) |> Lower.policy spec in
  List.iter (fun (name,expected) ->
      let fields = Input.obj name ["description";"expected_contract";"expected_preservation";"sha256"] expected in
      let expected_result = Input.string_field name "expected_contract" fields in
      match Snapshot.of_string (read (root ^ "/fixtures/" ^ name ^ ".json")) with
      | Error _ -> check (name ^ " unsupported") (expected_result = "unknown")
      | Ok snapshot ->
        let policy = Lower.policy spec snapshot in
        let result = Contract_verify.run policy contract in
        check (name ^ " verdict") (outcome result = expected_result);
        (match result with
         | Violated (clause,model) ->
           let request = Witness.request_of_model model in
           check (name ^ " witness") (Witness.clause policy clause request);
           if name = "21-named-secret-leak" then
             check "literal witness name" ((Option.get request.object_request).name = "db-password")
         | _ -> ());
        let preservation = Input.field name "expected_preservation" fields in
        (match preservation with
         | `String wanted ->
           let when_ = Ir.Not (Contract_spec.approved_changes spec) in
           let answer = Smt_encode.decision_equivalence_query ~when_ baseline policy
             |> Solve.check |> Witness.validate ~obligation:"preservation"
                  (Witness.decision_difference ~when_ baseline policy) in
           check (name ^ " preservation")
             (match answer,wanted with Solve.Proved,"preserved" | Solve.Violated _,"changed" -> true | _ -> false)
         | `Null -> () | _ -> failwith "bad preservation fixture")) cases;
  let value = Input.parse source in
  List.iter (fun (name,changed) ->
      check name (Result.is_error (Contract_spec.of_string (Input.json changed))))
    ["unknown version",replace "schema_version" (`Number "11") value;
     "v2 requires explicit verbs",replace "schema_version" (`Number "2") value;
     "v3 requires explicit verbs",replace "schema_version" (`Number "3") value;
     "rounded version",replace "schema_version" (`Number "1.0") value;
     "empty clauses",replace "clauses" (`A []) value;
     "missing closure assertion",replace "context" (`O ["schema_version",`Number "1";"snapshot_complete",`Bool false;"identities",`A []]) value;
     "wrong change scope",replace "change_scope" (`String "all") value];
  let clauses = Input.arr "clauses" (Input.field "contract" "clauses" (match value with `O fields -> fields | _ -> assert false)) in
  let required = List.hd clauses in
  check "functionality-only contract rejected"
    (Result.is_error (Contract_spec.of_string (Input.json (replace "clauses" (`A [required]) value))));
  check "safety-only contract rejected"
    (Result.is_error (Contract_spec.of_string (Input.json (replace "clauses" (`A [List.nth clauses 1]) value))));
  let conflicting = required |> replace "name" (`String "conflict") |> replace "kind" (`String "must_not_grant") in
  let conflict = get (Contract_spec.of_string (Input.json (replace "clauses" (`A [required;conflicting]) value))) in
  check "inconsistent paired intent" (outcome (Contract_verify.run baseline (Contract_spec.to_contract conflict)) = "inconsistent");
  let requests = get (Evaluate.requests spec (read (root ^ "/requests.json"))) in
  List.iter (fun row -> check "exact additive may=must"
      (Ir.possibly_allows baseline row.Evaluate.request = Ir.definitely_allows baseline row.request)) requests;
  Printf.printf "RBAC contracts and lowering: %d checks passed\n" !count
