open Soundcheck_core
open Rbac_repair_bench
module K = Soundcheck_kubernetes_rbac
module P = K.Policy_sequence

let checks = ref 0
let check label yes = incr checks; if not yes then failwith ("RBAC retirement evaluator: "^label)
let ok = function Ok value -> value | Error _ -> failwith "unexpected error"
let read path = let channel=open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel)
    (fun () -> really_input_string channel (in_channel_length channel))
let write path bytes = let channel=open_out_bin path in
  Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () -> output_string channel bytes)
let field key = function `O fields -> List.assoc key fields | _ -> failwith "expected object"
let array = function `A values -> values | _ -> failwith "expected array"
let replace key value = function
  | `O fields -> `O (List.map (fun (name,old) -> name,if name=key then value else old) fields)
  | _ -> failwith "expected object"
let remove key = function `O fields -> `O (List.remove_assoc key fields) | _ -> failwith "expected object"
let contains text pattern =
  let rec loop index = index+String.length pattern<=String.length text &&
    (String.sub text index (String.length pattern)=pattern || loop (index+1)) in loop 0
let task ?(id="task") ?(contract="contract.json") ?(config="before.json") () : Pilot.case =
  {id;contract;config;provenance=Pilot.Synthetic}
let entry ?(task="task") id config = Printf.sprintf {|{"task":%S,"id":%S,"config":%S}|} task id config
let submissions entries = {|{"format_version":1,"attempts":[|}^String.concat "," entries^"]}"
let first rows = List.hd (List.hd rows).attempts
let sequence row = Option.get row.sequence
let first_task json = List.hd (array (field "tasks" json))
let first_attempt json = List.hd (array (field "attempts" (first_task json)))
let run_process binary args =
  let output=Filename.temp_file "rbac-retirement-out-" ""
  and errors=Filename.temp_file "rbac-retirement-err-" "" in
  Fun.protect ~finally:(fun () -> Sys.remove output;Sys.remove errors) (fun () ->
    let out_fd=Unix.openfile output [Unix.O_WRONLY;Unix.O_TRUNC] 0o600
    and err_fd=Unix.openfile errors [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let pid=Unix.create_process binary (Array.of_list (binary::args)) Unix.stdin out_fd err_fd in
    Unix.close out_fd;Unix.close err_fd;
    let _,status=Unix.waitpid [] pid in
    let code=match status with Unix.WEXITED code -> code | _ -> failwith "unexpected termination" in
    check "no private stderr diagnostics" (read errors="");
    let bytes=read output in code,K.Input.parse bytes,bytes)
let rec cleanup path = match (Unix.lstat path).Unix.st_kind with
  | Unix.S_DIR -> Array.iter (fun name -> cleanup (Filename.concat path name)) (Sys.readdir path);Unix.rmdir path
  | _ -> Unix.unlink path

type control = {
  id:string; contract:string; baseline:string; candidate:string;
  outcome:string; phase:string; state:int option;
  invariants:string option; checked:int option; preservation:string option;
}
let control ?(contract="contract.json") ?(baseline="before.json")
    ?state ?invariants ?checked ?preservation id candidate outcome phase =
  {id;contract;baseline;candidate;outcome;phase;state;invariants;checked;preservation}

let () =
  if Array.length Sys.argv<>3 then failwith "expected evaluator and retirement workflow";
  let binary=Sys.argv.(1) and root=Sys.argv.(2) in
  let source file=read (Filename.concat root file) in
  let contract=source "contract.json" and before=source "before.json" and repaired=source "repaired.json" in
  let spec=ok (K.Sequence_spec.of_string contract) in
  let controls=[
    control ~state:1 "missing-target" "before.json" "unknown" "preparation";
    control ~state:1 "unauthorized-write" "authorization-failed.json" "authorization_failed" "authorization";
    control ~state:4 "lost-final-access" "contract-failed.json" "contract_failed" "final_verification";
    control ~state:4 "outside-scope" "out-of-scope-regression.json" "out_of_scope_regression" "final_verification";
    control ~invariants:"proved" ~checked:5 ~preservation:"proved" "migration" "repaired.json" "valid_sequence" "complete";
    control ~contract:"gap-contract.json" ~state:1 ~invariants:"violated" ~checked:2
      "guarded-gap" "repaired.json" "invariant_failed" "state_invariants";
    control ~contract:"unguarded-gap-contract.json" ~invariants:"not_required" ~checked:0 ~preservation:"proved"
      "unguarded-gap" "repaired.json" "valid_sequence" "complete";
    control ~baseline:"initial-before.json" ~state:0 ~invariants:"violated" ~checked:1
      "invalid-initial-state" "repaired.json" "invariant_failed" "state_invariants";
    control ~contract:"handoff-contract.json" ~baseline:"handoff-before.json"
      ~state:1 ~invariants:"violated" ~checked:2 "handoff-loss" "handoff-invariant-failed.json" "invariant_failed" "state_invariants";
    control ~contract:"handoff-contract.json" ~baseline:"handoff-before.json"
      ~invariants:"proved" ~checked:3 ~preservation:"proved" "handoff" "handoff-repaired.json" "valid_sequence" "complete"] in
  (* Retain a single real run for every control. Projection tests below may reuse
     those values, but the production evaluator calls the whole gate once per attempt. *)
  let results=List.map (fun control ->
    let selected=ok (K.Sequence_spec.of_string (source control.contract)) in
    control,P.run selected ~before:(source control.baseline) ~after:(source control.candidate)) controls in
  List.iter (fun (control,result) -> check (control.id^" coherent reference run")
    (Result.is_ok (P.validate_evaluation result))) results;
  let valid=snd (List.find (fun (control,_) -> control.id="migration") results) in
  let frozen=ref false and trusted_reads=ref [] in
  let suite=freeze ~suite_root:"unused" ~read_suite:(fun file ->
    check "trusted inputs read only before submissions" (not !frozen);
    trusted_reads:=file::!trusted_reads;Ok (source file))
      (List.map (fun control -> task ~id:control.id ~contract:control.contract ~config:control.baseline ()) controls) in
  frozen:=true;
  let attempts=ok (parse_submissions suite (submissions
    (List.map (fun control -> entry ~task:control.id "attempt" control.candidate) controls))) in
  let calls=ref 0 and candidate_reads=ref 0 in
  let rows=run ~read_candidate:(fun file -> incr candidate_reads;Ok (source file))
    ~evaluate:(fun _ ~before:_ ~after:_ -> failwith "wrong access dispatcher")
    ~evaluate_change:(fun _ ~before:_ ~after:_ -> failwith "wrong change dispatcher")
    ~evaluate_sequence:(fun frozen_spec ~before ~after -> incr calls;
      snd (List.find (fun (control,_) ->
        K.Sequence_spec.canonical frozen_spec=K.Sequence_spec.canonical (ok (K.Sequence_spec.of_string (source control.contract)))
        && before=source control.baseline && after=source control.candidate) results))
    ~now:(fun () -> 0.) ~submission_root:"unused" suite attempts in
  check "each shared trusted path read once" (List.length !trusted_reads=List.length (List.sort_uniq compare !trusted_reads));
  check "one read and one gate call for each candidate" (!calls=List.length controls && !candidate_reads=List.length controls);
  List.iter2 (fun control (row:task_row) ->
    let attempt=List.hd row.attempts and expected_spec=ok (K.Sequence_spec.of_string (source control.contract)) in
    let stages=sequence attempt in
    check (control.id^" projected stage") (attempt.failure=None && attempt.repair_result=Some control.outcome
      && stages.phase=control.phase && stages.step=control.state);
    check (control.id^" invariant accounting") (stages.state_invariants_result=control.invariants
      && stages.state_invariants_checked=control.checked
      && stages.invariant_failure_state=(if control.phase="state_invariants" then control.state else None));
    check (control.id^" preservation stage") (stages.intermediate_preservation_result=control.preservation);
    check (control.id^" frozen profile/version") (row.profile=Some (P.profile_id_for_version 2)
      && row.contract_version=Some 2 && row.contract_kind=Some K.Sequence_spec.kind
      && row.access_profile=Some (K.Assurance.id_for_version 10));
    check (control.id^" frozen exact inputs") (row.baseline_sha256=Some (Sha256.string (source control.baseline))
      && row.contract_sha256=Some (Sha256.string (source control.contract))
      && row.frozen_contract_sha256=Some (Sha256.string (K.Sequence_spec.canonical expected_spec))
      && attempt.candidate_sha256=Some (Sha256.string (source control.candidate)));
    if control.phase="state_invariants" then
      check (control.id^" final proof does not override failed invariants")
        (attempt.contract_result=Some "proved" && stages.final_comparison_result=Some "valid_repair"
         && attempt.authorization_result=Some "allowed" && stages.assurance="within_profile")) controls rows;
  check "completed invariant failures are non-proofs, not tool failures" (exit_code rows=3);
  let json=K.Input.parse (to_json rows) in
  check "version2 contracts select format5" (field "experimental_format_version" json=`Number "5"
    && field "comparison" json=`String "frozen_policy_retirement_and_state_invariants"
    && field "profile" json=`String (P.profile_id_for_version 2));
  List.iter (fun (name,count) -> check ("all controls counted "^name)
    (field name (field "attempt_counts" json)=`Number count))
    ["invariant_failed","3";"valid_sequence","3";"unknown","1";"authorization_failed","1";
     "contract_failed","1";"out_of_scope_regression","1";"errors","0"];
  List.iter (fun private_value -> check "summary contains no selected clause, target, input or diagnostic"
    (not (contains (to_json rows) private_value)))
    ["deployer";"team-a";"configmaps-required";"replacement-reader";"canonical";"counterexample";"smtlib";"reason";"repaired.json"];

  let one=freeze ~suite_root:root [task ()] in
  let attempt=ok (parse_submissions one (submissions [entry "candidate" "repaired.json"])) in
  let evaluate_result result=run ~read_candidate:(fun _ -> Ok repaired)
    ~evaluate_sequence:(fun _ ~before:_ ~after:_ -> result) ~submission_root:"unused" one attempt in
  let substitutions=[
    "invariants removed",replace "invariants" (`A []);
    "different selected clause",replace "invariants" (`A [`String "secrets-not-granted"]);
    "actor",replace "actor" (`String "app");
    "order",(fun json -> replace "steps" (`A (List.rev (array (field "steps" json)))) json);
    "target",(fun json -> let steps=array (field "steps" json) in
      let step=List.hd steps in replace "steps" (`A (replace "target"
        (replace "name" (`String "unapproved-target") (field "target" step)) step::List.tl steps)) json);
    "scope",(fun json -> replace "requirements" (replace "change_scope" (`A []) (field "requirements" json)) json)] in
  List.iter (fun (name,change) ->
    let substituted=ok (K.Sequence_spec.of_string (K.Input.json (change (K.Input.parse contract)))) in
    let row=first (evaluate_result (P.run substituted ~before ~after:repaired)) in
    check ("reject returned run with "^name) (row.failure=Some Report_mismatch && row.repair_result=None)) substitutions;
  List.iter (fun (name,result) -> let row=first (evaluate_result result) in
    check ("reject wrong "^name) (row.failure=Some Report_mismatch && row.repair_result=None))
    ["baseline bytes",P.run spec ~before:(before^" ") ~after:repaired;
     "candidate bytes",P.run spec ~before ~after:(repaired^" ");
     "missing identity",P.invalid_contract "PRIVATE_DIAGNOSTIC" ~before ~after:repaired];
  List.iter (fun override -> check ("reject submitted override "^override)
    (Result.is_error (parse_submissions one
      ({|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"repaired.json",|}^override^"}]}"))))
    ["\"invariants\":[]";"\"state_invariants\":[]";"\"schema_version\":1";"\"actor\":\"admin\"";
     "\"steps\":[]";"\"baseline\":\"replacement\"";"\"contract\":\"replacement\"";"\"profile\":\"other\"";
     "\"result\":\"valid_sequence\"";"\"solver\":\"fake\""];
  List.iter (fun failure -> let json=K.Input.parse (to_json (failed_tasks failure one)) in
    check "invalid submission retains format5 and frozen task version" (field "experimental_format_version" json=`Number "5"
      && field "contract_version" (first_task json)=`Number "2" && field "submitted_attempts" json=`Null))
    [Submissions_invalid;Submissions_read_error];
  let after_success=ok (parse_submissions one (submissions
    [entry "valid" "repaired.json";entry "missing" "missing.json";entry "exception" "exception.json"])) in
  let rows=run ~read_candidate:(fun file -> if file="missing.json" then Error () else if file="exception.json"
      then Ok "private-exception-input" else Ok repaired)
    ~evaluate_sequence:(fun _ ~before:_ ~after -> if after="private-exception-input" then failwith "PRIVATE_DIAGNOSTIC" else valid)
    ~submission_root:"unused" one after_success in
  check "errors after success remain counted and fail aggregate acceptance" (exit_code rows=1
    && List.map (fun (row:attempt_row) -> row.failure) (List.hd rows).attempts=[None;Some Candidate_read_error;Some Evaluation_error]
    && field "first_valid_attempt" (first_task (K.Input.parse (to_json rows)))=`Number "1"
    && not (contains (to_json rows) "PRIVATE_DIAGNOSTIC"));

  let deletion=freeze ~suite_root:root [task ~contract:"delete-contract.json" ~config:"delete-before.json" ()] in
  let deletion_rows=run ~submission_root:root deletion (ok (parse_submissions deletion (submissions
    [entry "still-present" "delete-before.json";entry "deleted" "delete-after.json"]))) in
  let json=K.Input.parse (to_json deletion_rows) in
  check "single deletion uses its versioned gate and format5" (exit_code deletion_rows=0
    && (List.hd deletion_rows).profile=Some (K.Policy_change.profile_id_for_version 2)
    && field "experimental_format_version" json=`Number "5"
    && List.map (fun (row:attempt_row) -> row.repair_result) (List.hd deletion_rows).attempts
      =[Some "unknown";Some "valid_change"]);
  check "single deletion does not claim sequence invariant checks" (List.for_all (fun row -> row.sequence=None)
    (List.hd deletion_rows).attempts && field "state_invariants_result" (first_attempt json)=`Null);
  let unauthorized=freeze ~suite_root:root [task ~contract:"delete-unauthorized-contract.json" ~config:"delete-before.json" ()] in
  let rows=run ~submission_root:root unauthorized (ok (parse_submissions unauthorized (submissions [entry "deleted" "delete-after.json"]))) in
  check "deletion still requires frozen actor authority" ((first rows).repair_result=Some "authorization_failed"
    && (first rows).authorization_result=Some "not_authorized" && (first rows).contract_result=None && exit_code rows=3);

  let safety_contract=K.Input.parse contract |> replace "invariants" (`A [`String "secrets-not-granted"])
    |> K.Input.json in
  let safety=freeze ~suite_root:root ~read_suite:(fun path -> Ok (if path="safety.json" then safety_contract else source path))
    [task ~contract:"safety.json" ()] in
  let rows=run ~submission_root:root safety (ok (parse_submissions safety (submissions [entry "safe-final" "repaired.json"]))) in
  check "selected safety clause can reject initial exposure despite a safe final state"
    ((first rows).failure=None && (first rows).repair_result=Some "invariant_failed"
     && (sequence (first rows)).invariant_failure_state=Some 0
     && (sequence (first rows)).state_invariants_result=Some "violated" && exit_code rows=3);
  let delete_json=K.Input.parse (source "delete-contract.json") in
  let single=K.Input.json (`O ["schema_version",`Number "2";"kind",`String K.Sequence_spec.kind;
    "actor",field "actor" delete_json;"invariants",`A [];
    "steps",`A [`O ["operation",field "operation" delete_json;"target",field "target" delete_json]];
    "requirements",field "requirements" delete_json]) in
  let single_suite=freeze ~suite_root:root ~read_suite:(fun path -> Ok (if path="single.json" then single else source path))
    [task ~contract:"single.json" ~config:"delete-before.json" ()] in
  let rows=run ~submission_root:root single_suite (ok (parse_submissions single_suite (submissions [entry "removed" "delete-after.json"]))) in
  check "one deletion step records both optional stage classes as not required" (exit_code rows=0
    && (sequence (first rows)).state_invariants_result=Some "not_required"
    && (sequence (first rows)).state_invariants_checked=Some 0
    && (sequence (first rows)).intermediate_preservation_result=Some "not_required");

  let legacy_source=K.Input.parse (source "handoff-contract.json") |> replace "schema_version" (`Number "1")
    |> remove "invariants" |> K.Input.json in
  let legacy_spec=ok (K.Sequence_spec.of_string legacy_source) in
  let legacy_before=source "handoff-before.json" and legacy_after=source "handoff-invariant-failed.json" in
  let legacy_result=P.run legacy_spec ~before:legacy_before ~after:legacy_after in
  let mixed=freeze ~suite_root:root ~read_suite:(fun path -> Ok (if path="legacy.json" then legacy_source else source path))
    [task ();task ~id:"legacy" ~contract:"legacy.json" ~config:"handoff-before.json" ();
     task ~id:"deletion" ~contract:"delete-contract.json" ~config:"delete-before.json" ()] in
  let rows=run ~submission_root:root
    ~evaluate_sequence:(fun frozen_spec ~before:_ ~after:_ ->
      if K.Sequence_spec.version frozen_spec=1 then legacy_result else valid)
    mixed (ok (parse_submissions mixed (submissions [entry "new" "repaired.json";
      entry ~task:"legacy" "old" "handoff-invariant-failed.json";entry ~task:"deletion" "deleted" "delete-after.json"]))) in
  let json=K.Input.parse (to_json rows) in
  check "mixed versions preserve legacy final-only semantics" (exit_code rows=0 && field "profile" json=`Null
    && field "experimental_format_version" json=`Number "5"
    && (sequence (List.hd (List.nth rows 1).attempts)).state_invariants_result=None
    && List.map (field "contract_version") (array (field "tasks" json))=[`Number "2";`Number "1";`Number "2"]);
  let legacy=freeze ~suite_root:root ~read_suite:(fun path -> Ok (if path="legacy.json" then legacy_source else source path))
    [task ~contract:"legacy.json" ~config:"handoff-before.json" ()] in
  let rows=run ~submission_root:root ~evaluate_sequence:(fun _ ~before:_ ~after:_ -> legacy_result)
    legacy (ok (parse_submissions legacy (submissions [entry "old" "handoff-invariant-failed.json"]))) in
  let json=K.Input.parse (to_json rows) in
  check "legacy sequence-only summary remains format4 with no added fields" (field "experimental_format_version" json=`Number "4"
    && not (contains (to_json rows) "state_invariants") && not (contains (to_json rows) "contract_version")
    && not (contains (to_json rows) "invariant_failed") && exit_code rows=0);

  let code,json,_=run_process binary [Filename.concat root "suite.yaml";Filename.concat root "submissions.yaml"] in
  check "runnable campaign keeps all eleven attempts across three tasks" (code=0
    && field "experimental_format_version" json=`Number "5" && field "scheduled_tasks" json=`Number "3"
    && field "submitted_attempts" json=`Number "11" && field "tasks_with_valid_repair" json=`Number "3");
  check "campaign preserves first valid ordinals and later invariant failures"
    (List.map (field "first_valid_attempt") (array (field "tasks" json))=[`Number "5";`Number "2";`Number "2"]
     && field "invariant_failed" (field "attempt_counts" json)=`Number "2");

  let temporary=Filename.temp_file "rbac-retirement-evaluator-" "" in Unix.unlink temporary;Unix.mkdir temporary 0o700;
  Fun.protect ~finally:(fun () -> cleanup temporary) (fun () ->
    let local path=Filename.concat temporary path in
    let view=P.evaluation valid in
    let baseline_invariants=List.hd view.state_invariants in
    let clause=List.find (fun (query:Contract_verify.obligation) -> query.phase=Contract_verify.Clause)
      baseline_invariants.queries in
    let check_query=(Solver_protocol.query clause.smtlib).check in
    let comparison=Option.get view.comparison in
    let final_trace=Option.get comparison.trace in
    check "fault is targeted after final verification" (List.for_all (fun (entry:Contract_verify.trace_entry) ->
      (Solver_protocol.query entry.obligation.smtlib).check<>check_query) final_trace.candidate
      && (Solver_protocol.query final_trace.preservation.smtlib).check<>check_query);
    let query_path=local "invariant-check.smt2" and solver_path=local "invariant-unknown-z3" in
    write query_path check_query;
    let actual_z3=List.find_map (fun directory -> let path=Filename.concat directory "z3" in
      if Sys.file_exists path then Some (Unix.realpath path) else None)
        (String.split_on_char ':' (Sys.getenv "PATH")) |> Option.get in
    write solver_path ("#!/bin/sh\nif cmp -s \"$2\" "^Filename.quote query_path
      ^"; then printf 'unknown\\n'; else exec "^Filename.quote actual_z3^" \"$@\"; fi\n");
    Unix.chmod solver_path 0o700;
    let unknown=P.run ~z3:solver_path spec ~before ~after:repaired in
    let rows=evaluate_result unknown in let row=first rows in let stages=sequence row in
    check "invariant solver unknown blocks acceptance while retaining final proof" (exit_code rows=3
      && row.failure=None && row.repair_result=Some "unknown" && row.contract_result=Some "proved"
      && stages.phase="state_invariants" && stages.step=Some 0
      && stages.final_comparison_result=Some "valid_repair" && stages.state_invariants_result=Some "unknown"
      && stages.state_invariants_checked=Some 1 && stages.invariant_failure_state=Some 0
      && stages.intermediate_preservation_result=None && stages.assurance="unsupported_or_inconclusive");
    Array.iter (fun name -> if (Unix.lstat (Filename.concat root name)).Unix.st_kind=Unix.S_REG
      then write (local name) (source name)) (Sys.readdir root);
    let manifest baseline contract=Printf.sprintf
      "format_version: 1\ncases: [{id: task, provenance: synthetic, config: %s, contract: %s}]\n" baseline contract in
    write (local "suite.yaml") (manifest "initial-before.json" "contract.json");
    write (local "submissions.yaml") (submissions [entry "initial" "repaired.json"]);
    let code,json,_=run_process binary [local "suite.yaml";local "submissions.yaml"] in
    check "CLI retains explicit initial state zero" (code=3
      && field "sequence_step" (first_attempt json)=`Number "0"
      && field "invariant_failure_state" (first_attempt json)=`Number "0"
      && field "state_invariants_checked" (first_attempt json)=`Number "1");
    write (local "suite.yaml") (manifest "before.json" "contract.json");
    write (local "submissions.yaml")
      "format_version: 1\nattempts: [{task: task, id: a, config: repaired.json, invariants: []}]\n";
    let code,json,_=run_process binary [local "suite.yaml";local "submissions.yaml"] in
    check "CLI rejects candidate invariant substitution and retains schedule" (code=1
      && field "failure" (first_task json)=`String "submissions_invalid"
      && field "experimental_format_version" json=`Number "5" && field "submitted_attempts" json=`Null));
  Printf.printf "All %d retirement repair evaluator checks passed.\n" !checks
