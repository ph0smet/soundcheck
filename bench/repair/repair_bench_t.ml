open Soundcheck_core
open Soundcheck_kong
open Repair_bench

let checks = ref 0
let check name predicate = incr checks; if not predicate then failwith ("repair bench: " ^ name)
let ok = function Ok value -> value | Error _ -> failwith "unexpected failure"
let contains text fragment =
  let rec loop index = index + String.length fragment <= String.length text
    && (String.sub text index (String.length fragment) = fragment || loop (index + 1)) in
  loop 0
let secret = "PRIVATE_REPAIR_SENTINEL_42aa"
let contract = "schema_version: 1\nkind: authenticated-access\nscope: {path_prefix: /" ^ secret ^ "}\n"
let spec = ok (Contract_spec.parse_string contract)
let task ?(id = "task") ?(config = "before.yaml") ?(contract = "contract.yaml") () : Pilot.case =
  { id; config; contract; provenance = Pilot.Synthetic }
let entry ?(task = "task") ?(id = "try-1") ?(config = "candidate.yaml") () =
  Printf.sprintf {|{"task":%S,"id":%S,"config":%S}|} task id config
let submissions values = {|{"format_version":1,"attempts":[|} ^ String.concat "," values ^ "]}"
let parse ?(tasks = [ task () ]) bytes = parse_submissions ~tasks bytes
let report ?(status = Report.Within_profile) ?(codes = []) spec result repair : Compare.repair_report =
  let contract_report : Report.t = {
    result; property_name = Contract_spec.kind_name spec.Contract_spec.kind;
    property_description = secret;
    assurance = Some { profile = Assurance.profile.id; status;
      findings = List.map (fun code -> { Report.code; service = Some secret; route = Some secret;
        detail = secret }) codes };
    clause = Some { name = secret; description = secret; kind = Report.Must_deny };
    frozen_spec = Some (Contract_spec.report_identity spec) } in
  { result = repair; profile = Assurance.profile.id; mode = Compare.Security_decision;
    contract_report; frozen_spec = spec }
let field key = function `O values -> List.assoc key values | _ -> failwith "object expected"
let json bytes = ok (Yaml.of_string bytes)

let () =
  check "valid submissions" (Result.is_ok (parse (submissions [ entry () ])));
  check "empty submissions preserved" (parse (submissions []) = Ok []);
  check "same attempt ID on different tasks" (Result.is_ok
    (parse ~tasks:[ task (); task ~id:"task-2" () ]
      (submissions [ entry (); entry ~task:"task-2" () ])));
  check "literal path with spaces" (Result.is_ok (parse (submissions [ entry ~config:"folder with spaces/a.yaml" () ])));
  List.iteri (fun index bytes -> check (Printf.sprintf "invalid metadata %d" index)
    (Result.is_error (parse bytes)))
    [ ""; "[]"; "{}"; {|{"format_version":2,"attempts":[]}|};
      {|{"format_version":1,"attempts":[],"contract":"override"}|};
      {|{"format_version":1,"format_version":1,"attempts":[]}|};
      submissions [ entry (); entry () ]; submissions [ entry ~task:"absent" () ];
      submissions [ entry ~id:"" () ]; submissions [ entry ~id:"has spaces" () ];
      submissions [ entry ~id:(String.make 65 'a') () ];
      submissions [ entry ~config:"../secret" () ]; submissions [ entry ~config:"/absolute" () ];
      submissions [ entry ~config:"./relative" () ]; submissions [ entry ~config:"nested/../secret" () ];
      submissions [ entry ~config:"folder//file" () ]; submissions [ entry ~config:"folder/" () ];
      submissions [ entry ~config:"" () ];
      {|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"a\u0000b"}]}|};
      {|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"a\\b"}]}|};
      {|{"format_version":1,"attempts":[{"task":"task","task":"task","id":"a","config":"a"}]}|};
      {|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"a","contract":"b"}]}|};
      {|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"a","result":"valid_repair"}]}|};
      {|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"a","mode":"weaker"}]}|};
      {|{"format_version":1,"attempts":[{"task":"task","id":"a","config":null}]}|};
      submissions [ entry () ] ^ "\n---\nattempts: []\n";
      "format_version: !!int 1\nattempts: []\n";
      "format_version: 1\nattempts: [*missing]\n";
      "format_version: 1\nattempts: [{task: task, id: &x a, config: *x}]\n";
      "format_version: 1\nattempts: [{<<: {task: task}, id: a, config: b}]\n" ];
  check "duplicate task identity rejected" (Result.is_error
    (parse ~tasks:[ task (); task () ] (submissions [])));
  check "empty task suite rejected" (Result.is_error (parse ~tasks:[] (submissions [])));

  let tasks = [ task (); task ~id:"second" (); task ~id:"missing" ();
    task ~id:"bad-contract" ~contract:"bad.yaml" ();
    task ~id:"missing-contract" ~contract:"absent.yaml" ();
    task ~id:"missing-baseline" ~config:"absent.yaml" () ] in
  let sources = [ "valid"; "vacuous"; "inconsistent"; "unknown"; "unsupported";
    "missing-candidate"; "parse-error"; "exception"; "spoof"; "valid-again" ] in
  let attempts = ok (parse ~tasks (submissions
    (List.map (fun id -> entry ~id ~config:(id ^ ".yaml") ()) sources @
     List.map (fun task -> entry ~task ~config:"valid.yaml" ())
       [ "second"; "bad-contract"; "missing-contract"; "missing-baseline" ]))) in
  let reads = Hashtbl.create 8 and calls = ref [] and candidate_reads = ref 0 in
  let read_suite path =
    Hashtbl.replace reads path (1 + Option.value ~default:0 (Hashtbl.find_opt reads path));
    if path = "contract.yaml" then Ok contract
    else if path = "before.yaml" then Ok ("baseline-" ^ secret)
    else if path = "bad.yaml" then Ok "schema_version: 22\n"
    else Error () in
  let read_candidate path =
    incr candidate_reads;
    check "all evaluator inputs frozen before candidate reads"
      (List.for_all (Hashtbl.mem reads) [ "contract.yaml"; "before.yaml"; "bad.yaml"; "absent.yaml" ]);
    if path = "missing-candidate.yaml" then Error () else Ok (path ^ secret) in
  let evaluate frozen before after =
    check "frozen property retained" (Contract_spec.canonical_json frozen = Contract_spec.canonical_json spec);
    check "original baseline retained for every attempt" (before = "baseline-" ^ secret);
    calls := after :: !calls;
    if String.starts_with ~prefix:"parse-error" after then Error secret
    else if String.starts_with ~prefix:"exception" after then failwith secret
    else if String.starts_with ~prefix:"vacuous" after then Ok (report frozen Report.Vacuous Compare.Contract_failed)
    else if String.starts_with ~prefix:"inconsistent" after then Ok (report frozen (Report.Inconsistent secret) Compare.Contract_failed)
    else if String.starts_with ~prefix:"unknown" after then Ok (report frozen (Report.Unknown secret) (Compare.Repair_unknown secret))
    else if String.starts_with ~prefix:"unsupported" after then
      Ok (report ~status:Report.Unsupported ~codes:[ "unrecognized-plugin" ] frozen
        (Report.Unknown secret) (Compare.Repair_unknown secret))
    else if String.starts_with ~prefix:"spoof" after then Ok { (report frozen Report.Proved Compare.Valid_repair)
      with profile = secret }
    else Ok (report frozen Report.Proved Compare.Valid_repair) in
  let clock = ref 0. in
  let now () = clock := !clock +. 0.25; !clock in
  let rows = run ~read_suite ~read_candidate ~evaluate ~now ~suite_root:"unused"
      ~submission_root:"unused" tasks attempts in
  check "all task denominators retained" (List.length rows = List.length tasks);
  check "suite ordering retained" (List.map (fun (row : task_row) -> row.id) rows = List.map (fun (task : Pilot.case) -> task.id) tasks);
  check "distinct contracts snapshotted once" (Hashtbl.find reads "contract.yaml" = 1);
  check "distinct baselines snapshotted once" (Hashtbl.find reads "before.yaml" = 1);
  check "preload failure skips candidate IO" (!candidate_reads = 11);
  check "reads once per submitted attempt" (List.length !calls = 10);
  let task_row id = List.find (fun (row : task_row) -> row.id = id) rows in
  let first = task_row "task" in
  let attempt id = List.find (fun (row : attempt_row) -> row.id = id) first.attempts in
  check "attempt ordering retained" (List.map (fun (row : attempt_row) -> row.id) first.attempts = sources);
  check "baseline digest" (first.baseline_sha256 = Some (Sha256.string ("baseline-" ^ secret)));
  check "contract canonical digest" (first.contract_sha256 = Some (Sha256.string (Contract_spec.canonical_json spec)));
  check "candidate exact-byte digest" ((attempt "valid").candidate_sha256 = Some (Sha256.string ("valid.yaml" ^ secret)));
  check "exception retains digest" ((attempt "exception").candidate_sha256 <> None);
  check "timing injection" (List.for_all (fun (row : attempt_row) -> row.elapsed_seconds = 0.25) first.attempts);
  List.iter (fun (id, failure) -> check ("attempt failure " ^ id) ((attempt id).failure = Some failure))
    [ "missing-candidate", Candidate_read_error; "parse-error", Evaluation_error;
      "exception", Unexpected_error; "spoof", Report_mismatch ];
  List.iter (fun (id, failure) -> check ("task failure " ^ id) ((task_row id).failure = Some failure))
    [ "missing", Missing_submission; "bad-contract", Contract_invalid;
      "missing-contract", Contract_read_error; "missing-baseline", Baseline_read_error ];
  let summary = to_json rows in
  check "private values excluded" (not (contains summary secret));
  let data = json summary in
  check "all scheduled tasks in summary" (field "scheduled_tasks" data = `Float 6.);
  check "valid tasks counted once" (field "tasks_with_valid_repair" data = `Float 2.);
  check "errors in task denominator" (field "tasks_with_errors" data = `Float 5.);
  check "all submitted attempts retained" (field "submitted_attempts" data = `Float 14.);
  let counts = field "attempt_counts" data in
  List.iter (fun (name, count) -> check ("attempt count " ^ name) (field name counts = `Float count))
    [ "valid_repair", 3.; "contract_failed", 2.; "out_of_scope_regression", 0.; "unknown", 2.; "errors", 7. ];
  check "errors remain fatal after valid attempt" (exit_code rows = 1);
  check "empty suite never succeeds" (exit_code [] = 1);
  check "all accepted tasks zero" (exit_code [ task_row "second" ] = 0);
  check "complete rejected attempts nonzero" (exit_code [ { first with failure = None;
    attempts = [ attempt "vacuous"; attempt "unknown" ] } ] = 3);

  let forged_changes = [
    (fun r -> { r with Compare.mode = Compare.Route_service });
    (fun r -> { r with Compare.result = Compare.Contract_failed });
    (fun r -> { r with Compare.contract_report = { r.Compare.contract_report with Report.frozen_spec = None } });
    (fun r -> { r with Compare.contract_report = { r.Compare.contract_report with Report.property_name = secret } });
    (fun r -> { r with Compare.contract_report = { r.Compare.contract_report with Report.assurance = None } });
    (fun r -> { r with Compare.contract_report = { r.Compare.contract_report with Report.result = Report.Vacuous } });
    (fun _ -> report ~status:Report.Unsupported spec Report.Proved Compare.Valid_repair);
    (fun _ -> report ~codes:[secret] spec Report.Proved Compare.Valid_repair);
    (fun r -> { r with Compare.frozen_spec = { spec with path_prefix = "/weakened" } });
  ] in
  List.iteri (fun index change ->
    let rows = run ~read_suite ~read_candidate
        ~evaluate:(fun frozen _ _ -> Ok (change (report frozen Report.Proved Compare.Valid_repair)))
        ~suite_root:"unused" ~submission_root:"unused" [ task () ] [ List.hd attempts ] in
    check (Printf.sprintf "spoofed report %d" index)
      ((List.hd (List.hd rows).attempts).failure = Some Report_mismatch)) forged_changes;
  let mutation = ref false in
  let read_suite path = if !mutation then Error () else
    if path = "contract.yaml" then Ok contract else Ok "original baseline" in
  let read_candidate _ = mutation := true; Ok "candidate bytes" in
  let rows = run ~read_suite ~read_candidate
      ~evaluate:(fun frozen before _ ->
        check "files changing later cannot replace snapshots" (before = "original baseline"
          && Contract_spec.canonical_json frozen = Contract_spec.canonical_json spec);
        Ok (report frozen Report.Proved Compare.Valid_repair))
      ~suite_root:"unused" ~submission_root:"unused" [ task (); task ~id:"second" () ]
      [ { task = "task"; id = "one"; config = "a" }; { task = "second"; id = "two"; config = "b" } ] in
  check "all frozen tasks survive source mutation" (exit_code rows = 0);
  Printf.printf "All %d submitted-repair unit checks passed.\n" !checks
