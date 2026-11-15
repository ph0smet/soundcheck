open Soundcheck_core
open Rbac_repair_bench
module K = Soundcheck_kubernetes_rbac
module P = K.Policy_sequence

let checks = ref 0
let check label yes = incr checks; if not yes then failwith label
let ok = function Ok value -> value | Error _ -> failwith "unexpected error"
let read path = let ch=open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr ch) (fun () -> really_input_string ch (in_channel_length ch))
let write path text = let ch=open_out_bin path in
  Fun.protect ~finally:(fun () -> close_out_noerr ch) (fun () -> output_string ch text)
let field key = function `O fields -> List.assoc key fields | _ -> failwith "expected object"
let array = function `A values -> values | _ -> failwith "expected array"
let replace key value = function
  | `O fields -> `O (List.map (fun (name,old) -> name,if name=key then value else old) fields)
  | _ -> failwith "expected object"
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
  let output=Filename.temp_file "rbac-sequence-eval-out-" ""
  and errors=Filename.temp_file "rbac-sequence-eval-err-" "" in
  Fun.protect ~finally:(fun () -> Sys.remove output;Sys.remove errors) (fun () ->
    let out_fd=Unix.openfile output [Unix.O_WRONLY;Unix.O_TRUNC] 0o600
    and err_fd=Unix.openfile errors [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let pid=Unix.create_process binary (Array.of_list (binary::args)) Unix.stdin out_fd err_fd in
    Unix.close out_fd;Unix.close err_fd;
    let _,status=Unix.waitpid [] pid in
    let code=match status with Unix.WEXITED code -> code | _ -> failwith "unexpected termination" in
    check "no raw stderr diagnostics" (read errors="");
    let bytes=read output in code,K.Input.parse bytes,bytes)
let rec cleanup path = match (Unix.lstat path).Unix.st_kind with
  | Unix.S_DIR -> Array.iter (fun name -> cleanup (Filename.concat path name)) (Sys.readdir path);Unix.rmdir path
  | _ -> Unix.unlink path

let () =
  if Array.length Sys.argv<>4 then failwith "expected evaluator, sequence and change workflows";
  let binary=Sys.argv.(1) and root=Sys.argv.(2) and change_root=Sys.argv.(3) in
  let source file=read (Filename.concat root file) in
  let contract=source "contract.json" and before=source "before.json" and repaired=source "repaired.json" in
  let spec=ok (K.Sequence_spec.of_string contract) in
  let expected=[
    "before.json","unknown",None,None,"preparation",Some 1,None,None;
    "authorization-failed.json","authorization_failed",Some "not_authorized",None,"authorization",Some 1,None,None;
    "contract-failed.json","contract_failed",Some "allowed",Some "violated","final_verification",Some 2,Some "contract_failed",None;
    "out-of-scope-regression.json","out_of_scope_regression",Some "allowed",Some "proved","final_verification",Some 2,Some "out_of_scope_regression",None;
    "intermediate-regression.json","out_of_scope_regression",Some "allowed",Some "proved","intermediate_preservation",Some 1,Some "valid_repair",Some "violated";
    "repaired.json","valid_sequence",Some "allowed",Some "proved","complete",None,Some "valid_repair",Some "proved"] in
  let results=List.map (fun (file,_,_,_,_,_,_,_) -> file,P.run spec ~before ~after:(source file)) expected in
  let valid=List.assoc "repaired.json" results in
  List.iter (fun (_,value) -> check "real retained run is coherent" (Result.is_ok (P.validate_evaluation value))) results;
  let frozen=ref false and trusted_reads=ref 0 in
  let current_contract=ref contract and current_baseline=ref before in
  let suite=freeze ~suite_root:"unused" ~read_suite:(fun path ->
    check "trusted files are read before candidate input" (not !frozen);incr trusted_reads;
    Ok (if path="contract.json" then !current_contract else !current_baseline))
      [task ();task ~id:"second" ()] in
  frozen:=true;current_contract:=source "reverse-contract.json";current_baseline:=repaired;
  let parse text=ok (parse_submissions suite text) in
  let attempts=parse (submissions (List.mapi (fun i (file,_,_,_,_,_,_,_) -> entry ("a"^string_of_int i) file) expected
    @ [entry "later-negative" "authorization-failed.json";entry ~task:"second" "valid" "repaired.json"])) in
  let reads=ref [] and calls=ref [] and clock=ref 0. in
  let evaluate_sequence frozen_spec ~before:baseline ~after =
    check "frozen actor, groups, ordered operations, targets and requirements"
      (K.Sequence_spec.canonical frozen_spec=K.Sequence_spec.canonical spec);
    check "every attempt uses original baseline including after success" (baseline=before);
    calls:=after::!calls;snd (List.find (fun (file,_) -> source file=after) results) in
  let rows=run ~read_candidate:(fun file -> reads:=file::!reads;Ok (source file))
    ~evaluate:(fun _ ~before:_ ~after:_ -> failwith "access dispatch")
    ~evaluate_change:(fun _ ~before:_ ~after:_ -> failwith "single-change dispatch")
    ~evaluate_sequence ~now:(fun () -> clock:= !clock+.0.25;!clock)
    ~submission_root:"unused" suite attempts in
  check "shared trusted inputs read once" (!trusted_reads=2);
  check "one read and one whole gate call per attempt, including later negatives"
    (List.length !reads=8 && List.length !calls=8 && List.length (List.hd rows).attempts=7);
  check "all tasks have accepted sequences despite completed negatives" (exit_code rows=0);
  List.iter (fun (row:task_row) ->
    check "outer and nested profiles" (row.profile=Some P.profile_id && row.contract_kind=Some K.Sequence_spec.kind
      && row.access_profile=Some (K.Assurance.id_for_version 10));
    check "raw/canonical identity and baseline binding" (row.baseline_sha256=Some (Sha256.string before)
      && row.contract_sha256=Some (Sha256.string contract)
      && row.frozen_contract_sha256=Some (Sha256.string (K.Sequence_spec.canonical spec)))) rows;
  List.iteri (fun index (file,outcome,authorization,contract_result,phase,step,final,prefix) ->
    let row=List.nth (List.hd rows).attempts index in let stage=sequence row in
    check (file^" outcome/stages") (row.failure=None && row.repair_result=Some outcome
      && row.authorization_result=authorization && row.contract_result=contract_result
      && stage.phase=phase && stage.step=step && stage.final_comparison_result=final
      && stage.intermediate_preservation_result=prefix);
    check (file^" exact input/timing") (row.candidate_sha256=Some (Sha256.string (source file)) && row.elapsed_seconds=0.25);
    check (file^" skipped nested stages stay absent") (row.contract_assurance=(if final=None then None else Some "within_profile")
      && row.comparison_assurance=(if final=None then None else Some "within_profile"));
    check (file^" sequence assurance independent from single-change") (row.change_assurance=None
      && stage.assurance=(if outcome="unknown" then "unsupported_or_inconclusive" else "within_profile"))) expected;
  let json=K.Input.parse (to_json rows) in
  check "format4 identifies sequence accounting" (field "experimental_format_version" json=`Number "4"
    && field "comparison" json=`String "frozen_ordered_policy_sequence_and_scope_preservation"
    && field "profile" json=`String P.profile_id);
  List.iter (fun (name,count) -> check ("summary count "^name) (field name (field "attempt_counts" json)=`Number count))
    ["valid_sequence","2";"valid_change","0";"valid_repair","0";"authorization_failed","2";
     "contract_failed","1";"out_of_scope_regression","2";"unknown","1";"errors","0"];
  check "first success does not hide later attempt" (field "first_valid_attempt" (first_task json)=`Number "6");
  List.iter (fun private_value -> check "summary minimizes private input/report fields" (not (contains (to_json rows) private_value)))
    ["deployer";"app-reader";"team-a";"canonical";"granting_rule";"counterexample";"smtlib";"reason";"before.json"];
  List.iter (fun override -> check ("reject candidate override "^override)
    (Result.is_error (parse_submissions suite
      ({|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"a",|}^override^"}]}"))))
    ["\"actor\":\"admin\"";"\"steps\":[]";"\"order\":[2,1]";"\"operation\":\"create\"";
     "\"target\":{}";"\"requirements\":{}";"\"context\":{}";"\"groups\":[]";"\"change_scope\":[]";
     "\"baseline\":\"new\"";"\"contract\":\"new\"";"\"z3\":\"fake\"";"\"result\":\"valid_sequence\""];
  let one=freeze ~suite_root:"unused" ~read_suite:(fun path -> Ok (if path="contract.json" then contract else before)) [task ()] in
  let one_attempt=ok (parse_submissions one (submissions [entry "a" "candidate"])) in
  let evaluate_result result=run ~read_candidate:(fun _ -> Ok repaired)
    ~evaluate_sequence:(fun _ ~before:_ ~after:_ -> result) ~submission_root:"unused" one one_attempt in
  let changes=[
    "actor",replace "actor" (`String "app");
    "order",(fun json -> replace "steps" (`A (List.rev (array (field "steps" json)))) json);
    "operation",(fun json -> let steps=array (field "steps" json) in
      replace "steps" (`A (replace "operation" (`String "create") (List.hd steps)::List.tl steps)) json);
    "target",(fun json -> let steps=array (field "steps" json) in let first=List.hd steps in
      replace "steps" (`A (replace "target" (replace "name" (`String "other") (field "target" first)) first::List.tl steps)) json);
    "scope",(fun json -> replace "requirements" (replace "change_scope" (`A []) (field "requirements" json)) json);
    "groups",(fun json -> let req=field "requirements" json in let context=field "context" req in
      let identities=List.map (replace "groups" (`A [`String "operators"])) (array (field "identities" context)) in
      replace "requirements" (replace "context" (replace "identities" (`A identities) context) req) json)] in
  List.iter (fun (label,change) ->
    let wrong=ok (K.Sequence_spec.of_string (K.Input.json (change (K.Input.parse contract)))) in
    let rows=evaluate_result (P.run wrong ~before ~after:repaired) in
    check ("reject substituted "^label) ((first rows).failure=Some Report_mismatch && exit_code rows=1)) changes;
  List.iter (fun (label,result) -> let rows=evaluate_result result in
    check ("bind returned "^label) ((first rows).failure=Some Report_mismatch && exit_code rows=1))
    ["before bytes",P.run spec ~before:(before^" ") ~after:repaired;
     "after bytes",P.run spec ~before ~after:(repaired^" ");
     "missing identity",P.invalid_contract "PRIVATE_DIAGNOSTIC" ~before ~after:repaired];
  let failures=ok (parse_submissions one (submissions [entry "valid" "valid";entry "missing" "missing";entry "throws" "throws"])) in
  let rows=run ~read_candidate:(fun path -> if path="missing" then Error () else if path="throws" then Ok "throws" else Ok repaired)
    ~evaluate_sequence:(fun _ ~before:_ ~after -> if after="throws" then failwith "PRIVATE_DIAGNOSTIC" else valid)
    ~submission_root:"unused" one failures in
  check "input/tool failures after success still block aggregate acceptance" (exit_code rows=1
    && List.map (fun (row:attempt_row) -> row.failure) (List.hd rows).attempts
      =[None;Some Candidate_read_error;Some Evaluation_error]
    && (first rows).repair_result=Some "valid_sequence" && not (contains (to_json rows) "PRIVATE_DIAGNOSTIC"));
  List.iter (fun failure -> let rows=failed_tasks failure one in let json=K.Input.parse (to_json rows) in
    check "invalid submission retains sequence schedule and format" (field "experimental_format_version" json=`Number "4"
      && field "submitted_attempts" json=`Null && field "scheduled_tasks" json=`Number "1"
      && (List.hd rows).frozen_contract_sha256<>None)) [Submissions_invalid;Submissions_read_error];
  let missing=run ~submission_root:"unused" one (ok (parse_submissions one (submissions []))) in
  check "missing task remains in denominator" ((List.hd missing).failure=Some Missing_submission && exit_code missing=1);
  let old file=read (Filename.concat change_root file) in
  let change_bytes=old "contract.json" and change_before=old "before.json" and change_after=old "repaired.json" in
  let change_spec=ok (K.Change_spec.of_string change_bytes) in
  let change_result=K.Policy_change.run change_spec ~before:change_before ~after:change_after in
  let access=K.Sequence_spec.requirements spec in
  let mixed=freeze ~suite_root:"unused" ~read_suite:(fun path -> Ok (match path with
    | "contract.json" -> contract | "access.json" -> K.Contract_spec.canonical access
    | "change.json" -> change_bytes | "change-before.json" -> change_before | _ -> before))
      [task ();task ~id:"access" ~contract:"access.json" ();task ~id:"change" ~contract:"change.json" ~config:"change-before.json" ()] in
  let mixed_rows=run ~read_candidate:(fun file -> Ok (if file="change" then change_after else repaired))
    ~evaluate_sequence:(fun _ ~before:_ ~after:_ -> valid) ~evaluate_change:(fun _ ~before:_ ~after:_ -> change_result)
    ~submission_root:"unused" mixed (ok (parse_submissions mixed (submissions
      [entry "s" "sequence";entry ~task:"access" "a" "access";entry ~task:"change" "c" "change"]))) in
  let json=K.Input.parse (to_json mixed_rows) in
  check "mixed all-three suite keeps gates distinct" (exit_code mixed_rows=0
    && field "experimental_format_version" json=`Number "4" && field "profile" json=`Null
    && List.map (fun key -> field key (field "attempt_counts" json)) ["valid_sequence";"valid_change";"valid_repair"]
      =[`Number "1";`Number "1";`Number "1"]
    && (List.hd (List.nth mixed_rows 1).attempts).sequence=None
    && (List.hd (List.nth mixed_rows 2).attempts).sequence=None);
  let c=K.Input.parse change_bytes in
  let single=K.Input.json (`O ["schema_version",`Number "1";"kind",`String K.Sequence_spec.kind;
    "actor",field "actor" c;"steps",`A [`O ["operation",field "operation" c;"target",field "target" c]];
    "requirements",field "requirements" c]) in
  let single_spec=ok (K.Sequence_spec.of_string single) in
  let single_result=P.run single_spec ~before:change_before ~after:change_after in
  let single_suite=freeze ~suite_root:"unused" ~read_suite:(fun path -> Ok (if path="contract.json" then single else change_before)) [task ()] in
  let single_rows=run ~read_candidate:(fun _ -> Ok change_after) ~evaluate_sequence:(fun _ ~before:_ ~after:_ -> single_result)
    ~submission_root:"unused" single_suite (ok (parse_submissions single_suite (submissions [entry "one" "one"]))) in
  check "one-step sequence records no required intermediate check" (exit_code single_rows=0
    && (sequence (first single_rows)).intermediate_preservation_result=Some "not_required"
    && (sequence (first single_rows)).final_comparison_result=Some "valid_repair");
  let malformed=freeze ~suite_root:"unused" ~read_suite:(fun path -> Ok (if path="bad.json" then
    "{\"kind\":\"kubernetes-rbac-policy-sequence\"}" else if path="contract.json" then contract else before))
      [task ();task ~id:"bad" ~contract:"bad.json" ()] in
  let malformed_rows=run ~read_candidate:(fun _ -> Ok repaired) ~evaluate_sequence:(fun _ ~before:_ ~after:_ -> valid)
    ~submission_root:"unused" malformed (ok (parse_submissions malformed
      (submissions [entry "a" "a";entry ~task:"bad" "bad" "a"]))) in
  check "invalid outer sequence never falls through to access verification"
    ((List.nth malformed_rows 1).failure=Some Contract_invalid && exit_code malformed_rows=1
      && (List.hd (List.nth malformed_rows 1).attempts).candidate_sha256=None);

  let code,json,_=run_process binary [Filename.concat root "suite.yaml";Filename.concat root "submissions.yaml"] in
  check "runnable two-task campaign accepted" (code=0 && field "scheduled_tasks" json=`Number "2"
    && field "submitted_attempts" json=`Number "8" && field "tasks_with_valid_repair" json=`Number "2");
  check "campaign first accepted attempts are retained" (List.map (field "first_valid_attempt") (array (field "tasks" json))
    =[`Number "6";`Number "1"]);
  let temporary=Filename.temp_file "rbac-sequence-evaluator-" "" in Unix.unlink temporary;Unix.mkdir temporary 0o700;
  Fun.protect ~finally:(fun () -> cleanup temporary) (fun () ->
    let local path=Filename.concat temporary path in
    Array.iter (fun name -> if (Unix.lstat (Filename.concat root name)).Unix.st_kind=Unix.S_REG
      then write (local name) (source name)) (Sys.readdir root);
    let manifest config contract=Printf.sprintf "format_version: 1\ncases: [{id: task, provenance: synthetic, config: %s, contract: %s}]\n" config contract in
    write (local "suite.yaml") (manifest "before.json" "contract.json");
    let execute entries=write (local "submissions.yaml") (submissions entries);
      run_process binary [local "suite.yaml";local "submissions.yaml"] in
    List.iter (fun file -> let code,json,_=execute [entry "negative" file] in
      check ("CLI rejected "^file) (code=3 && field "repair_result" (first_attempt json)<>`String "valid_sequence"))
      ["authorization-failed.json";"intermediate-regression.json";"before.json"];
    let code,json,_=execute [entry "valid" "repaired.json";entry "missing" "absent.json"] in
    check "CLI later IO error remains counted" (code=1 && field "errors" (field "attempt_counts" json)=`Number "1"
      && field "valid_sequence" (field "attempt_counts" json)=`Number "1");
    write (local "submissions.yaml") "format_version: 1\nattempts: [{task: task, id: a, config: repaired.json, steps: []}]\n";
    let code,json,_=run_process binary [local "suite.yaml";local "submissions.yaml"] in
    check "CLI candidate cannot rewrite ordered steps" (code=1 && field "failure" (first_task json)=`String "submissions_invalid"
      && field "experimental_format_version" json=`Number "4" && field "submitted_attempts" json=`Null);
    write (local "suite.yaml") (manifest "transient-gain-before.json" "transient-gain-contract.json");
    let code,json,_=execute [entry "temporary-gain" "transient-gain-after.json"] in
    check "temporary out-of-scope gain fails despite final comparison proof" (code=3
      && field "final_comparison_result" (first_attempt json)=`String "valid_repair"
      && field "intermediate_preservation_result" (first_attempt json)=`String "violated"
      && field "sequence_phase" (first_attempt json)=`String "intermediate_preservation");
    write (local "suite.yaml") (manifest "before.json" "contract.json");
    let prefix=List.hd (P.evaluation valid).intermediate_preservation in
    let prefix_check=(Solver_protocol.query prefix.query).check in
    let query_path=local "prefix-check.smt2" and solver_path=local "prefix-unknown-z3" in
    write query_path prefix_check;
    let actual_z3=List.find_map (fun directory -> let path=Filename.concat directory "z3" in
      if Sys.file_exists path then Some (Unix.realpath path) else None)
        (String.split_on_char ':' (Sys.getenv "PATH")) |> Option.get in
    write solver_path ("#!/bin/sh\nif cmp -s \"$2\" "^Filename.quote query_path
      ^"; then printf 'unknown\\n'; else exec "^Filename.quote actual_z3^" \"$@\"; fi\n");
    Unix.chmod solver_path 0o700;
    let prefix_unknown=P.run ~z3:solver_path spec ~before ~after:repaired in
    let unknown_rows=evaluate_result prefix_unknown in
    check "intermediate solver unknown retains final proof but blocks sequence acceptance"
      (exit_code unknown_rows=3 && (first unknown_rows).failure=None
       && (first unknown_rows).repair_result=Some "unknown"
       && (first unknown_rows).contract_result=Some "proved"
       && (sequence (first unknown_rows)).phase="intermediate_preservation"
       && (sequence (first unknown_rows)).step=Some 1
       && (sequence (first unknown_rows)).final_comparison_result=Some "valid_repair"
       && (sequence (first unknown_rows)).intermediate_preservation_result=Some "unknown"
       && (sequence (first unknown_rows)).assurance="unsupported_or_inconclusive");
    let bin=local "bin" in Unix.mkdir bin 0o700;
    let marker=local "solver-called" in
    write (Filename.concat bin "z3") ("#!/bin/sh\nprintf 'PRIVATE_SOLVER_FAILURE\\n'\nprintf called > "^Filename.quote marker^"\n");
    Unix.chmod (Filename.concat bin "z3") 0o700;
    let old_path=Sys.getenv "PATH" in
    Fun.protect ~finally:(fun () -> Unix.putenv "PATH" old_path) (fun () ->
      Unix.putenv "PATH" (bin^":"^old_path);
      let code,_,_=execute [entry "unauthorized" "authorization-failed.json";entry "unsupported" "before.json"] in
      check "preparation/authorization failures never execute solver" (code=3 && not (Sys.file_exists marker));
      let code,json,output=execute [entry "solver-failure" "repaired.json"] in
      let row=first_attempt json in
      check "solver failure after authorization stays unknown" (code=3 && Sys.file_exists marker
        && field "repair_result" row=`String "unknown" && field "sequence_phase" row=`String "final_verification"
        && field "authorization_result" row=`String "allowed" && field "contract_result" row=`String "unknown"
        && field "intermediate_preservation_result" row=`Null && field "failure" row=`Null
        && field "sequence_assurance" row=`String "unsupported_or_inconclusive"
        && not (contains output "PRIVATE_SOLVER_FAILURE"))));
  Printf.printf "All %d ordered-sequence repair evaluator checks passed.\n" !checks
