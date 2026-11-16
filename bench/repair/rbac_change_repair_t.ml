open Soundcheck_core
open Rbac_repair_bench
module K = Soundcheck_kubernetes_rbac
module P = K.Policy_change

let checks = ref 0
let check label predicate = incr checks; if not predicate then failwith ("RBAC change evaluator: " ^ label)
let ok = function Ok value -> value | Error _ -> failwith "unexpected error"
let read path = let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel)
    (fun () -> really_input_string channel (in_channel_length channel))
let write path bytes = let channel = open_out_bin path in
  Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () -> output_string channel bytes)
let field key = function `O fields -> List.assoc key fields | _ -> failwith "object expected"
let array = function `A values -> values | _ -> failwith "array expected"
let replace key value = function
  | `O fields -> `O (List.map (fun (k,v) -> k,if key=k then value else v) fields)
  | _ -> failwith "object expected"
let contains source part =
  let rec loop i = i+String.length part <= String.length source
    && (String.sub source i (String.length part)=part || loop (i+1)) in loop 0
let task ?(id="task") ?(contract="contract.json") () : Pilot.case =
  {id;contract;config="before.json";provenance=Pilot.Synthetic}
let entry ?(task="task") id config =
  Printf.sprintf {|{"task":%S,"id":%S,"config":%S}|} task id config
let submissions entries = {|{"format_version":1,"attempts":[|} ^ String.concat "," entries ^ "]}"
let first rows = List.hd (List.hd rows).attempts
let run_process binary args =
  let output=Filename.temp_file "rbac-change-out-" "" and errors=Filename.temp_file "rbac-change-err-" "" in
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
let first_task json = List.hd (array (field "tasks" json))
let first_attempt json = List.hd (array (field "attempts" (first_task json)))

let () =
  if Array.length Sys.argv<>3 then failwith "expected evaluator and policy-change workflow";
  let binary=Sys.argv.(1) and root=Sys.argv.(2) in
  let source name=read (Filename.concat root name) in
  let contract=source "contract.json" and before=source "before.json" in
  let spec=ok (K.Change_spec.of_string contract) in
  let next_json=replace "schema_version" (`Number "2") (K.Input.parse contract) in
  let next_contract=K.Input.json next_json in
  check "connector supports the next policy version"
    (Result.is_ok (K.Change_spec.of_string next_contract));
  let blocked=freeze ~suite_root:"unused" ~read_suite:(fun file ->
    Ok (if file="contract.json" then next_contract else before)) [task ()] in
  let pending=ok (parse_submissions blocked (submissions [entry "next" "candidate"])) in
  let read_candidate=ref false in
  let blocked_rows=run ~read_candidate:(fun _ -> read_candidate:=true;Ok before)
    ~submission_root:"unused" blocked pending in
  check "unsupported evaluator version fails before candidate evaluation"
    ((first blocked_rows).failure=Some Contract_invalid && exit_code blocked_rows=1
     && not !read_candidate);
  let repaired=source "repaired.json" in
  let expected=[
    "repaired.json","valid_change",Some "allowed",Some "proved";
    "before.json","unknown",None,None;
    "authorization-failed.json","authorization_failed",Some "not_authorized",None;
    "contract-failed.json","contract_failed",Some "allowed",Some "violated";
    "out-of-scope-regression.json","out_of_scope_regression",Some "allowed",Some "proved"] in
  (* Run the real gate once per control. Inject retained results below to probe
     evaluator identity/IO checks without changing the connector or its solver. *)
  let results=List.map (fun (file,_,_,_) -> file,P.run spec ~before ~after:(source file)) expected in
  let valid=List.assoc "repaired.json" results in
  let read_count=ref 0 and frozen=ref false in
  let contract_source=ref contract and baseline_source=ref before in
  let suite=freeze ~suite_root:"unused" ~read_suite:(fun path ->
    check "trusted reads precede candidates" (not !frozen);incr read_count;
    Ok (if path="contract.json" then !contract_source else !baseline_source))
      [task ();task ~id:"second" ()] in
  frozen:=true;
  contract_source:="mutated after freeze";baseline_source:=repaired;
  let reads=ref [] and calls=ref [] in
  let parse bytes=ok (parse_submissions suite bytes) in
  let attempts=parse (submissions (List.mapi (fun i (file,_,_,_) -> entry ("candidate-"^string_of_int i) file) expected
    @ [entry ~task:"second" "a" "repaired.json"])) in
  let evaluate_change frozen_spec ~before:original ~after =
    check "actor, groups, operation, target and requirements remain frozen"
      (K.Change_spec.canonical frozen_spec=K.Change_spec.canonical spec);
    check "all attempts use original baseline, including after success" (original=before);
    calls:=after::!calls;
    snd (List.find (fun (file,_) -> source file=after) results) in
  let clock=ref 0. in
  let rows=run ~read_candidate:(fun file -> reads:=file::!reads;Ok (source file))
    ~evaluate:(fun _ ~before:_ ~after:_ -> failwith "wrong dispatcher") ~evaluate_change
    ~now:(fun () -> clock:= !clock+.0.25;!clock) ~submission_root:"unused" suite attempts in
  check "two shared trusted paths read once" (!read_count=2);
  check "one candidate read and one gate call per attempt, no early success stop"
    (List.length !reads=6 && List.length !calls=6 && List.length (List.hd rows).attempts=5);
  check "all accepted tasks exit zero despite completed negative controls" (exit_code rows=0);
  List.iter (fun (row:task_row) ->
    check "outer and nested profiles stay distinct"
      (row.profile=Some P.profile_id && row.contract_kind=Some K.Change_spec.kind
       && row.access_profile=Some (K.Assurance.id_for_version 10));
    check "raw and canonical hashes bind the whole frozen contract"
      (row.baseline_sha256=Some (Sha256.string before) && row.contract_sha256=Some (Sha256.string contract)
       && row.frozen_contract_sha256=Some (Sha256.string (K.Change_spec.canonical spec)))) rows;
  List.iter2 (fun (file,outcome,authorization,contract_result) (row:attempt_row) ->
    check (file^" stage projection") (row.failure=None && row.repair_result=Some outcome
      && row.authorization_result=authorization && row.contract_result=contract_result);
    check (file^" hashes and timing") (row.candidate_sha256=Some (Sha256.string (source file))
      && row.elapsed_seconds=0.25);
    check (file^" skipped stages stay unavailable")
      (row.contract_assurance=(if contract_result=None then None else Some "within_profile")
       && row.comparison_assurance=(if contract_result=None then None else Some "within_profile"));
    check (file^" outer assurance") (row.change_assurance=Some
      (if outcome="unknown" then "unsupported_or_inconclusive" else "within_profile")))
    expected (List.hd rows).attempts;
  let summary=K.Input.parse (to_json rows) in
  check "policy contracts select experimental format3" (field "experimental_format_version" summary=`Number "3"
    && field "comparison" summary=`String "frozen_policy_change_and_scope_preservation"
    && field "profile" summary=`String P.profile_id);
  check "valid_change count is distinct from access-only valid_repair"
    (field "valid_change" (field "attempt_counts" summary)=`Number "2"
     && field "valid_repair" (field "attempt_counts" summary)=`Number "0"
     && field "authorization_failed" (field "attempt_counts" summary)=`Number "1");
  List.iter (fun private_value -> check "summary excludes contract/report/private fields"
    (not (contains (to_json rows) private_value)))
    ["deployer";"app-reader";"team-a";"canonical";"granting_rule";"counterexample";"smtlib";"reason"];

  List.iter (fun override ->
    check ("candidate metadata cannot override "^override)
      (Result.is_error (parse_submissions suite
        ({|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"a",|}^override^"}]}"))))
    ["\"actor\":\"admin\"";"\"operation\":\"create\"";"\"target\":{}";
     "\"requirements\":{}";"\"context\":{}";"\"groups\":[]";"\"change_scope\":[]";
     "\"baseline\":\"new\"";"\"contract\":\"new\"";"\"z3\":\"fake\"";
     "\"profile\":\"other\"";"\"result\":\"valid_change\"";"\"mode\":\"repair\""];
  let one=freeze ~suite_root:"unused" ~read_suite:(fun path -> Ok (if path="contract.json" then contract else before)) [task ()] in
  let evaluate_result result =
    run ~read_candidate:(fun _ -> Ok repaired) ~evaluate_change:(fun _ ~before:_ ~after:_ -> result)
      ~submission_root:"unused" one (ok (parse_submissions one (submissions [entry "a" "candidate"]))) in
  let changed_contracts=[
    "actor",replace "actor" (`String "app");
    "operation",replace "operation" (`String "create");
    "target",(fun value -> replace "target" (replace "name" (`String "other") (field "target" value)) value);
    "nested scope",(fun value -> replace "requirements"
      (replace "change_scope" (`A []) (field "requirements" value)) value);
    "trusted groups",(fun value ->
      let r=field "requirements" value in let c=field "context" r in
      let identities=List.map (replace "groups" (`A [`String "operators"])) (array (field "identities" c)) in
      replace "requirements" (replace "context" (replace "identities" (`A identities) c) r) value)] in
  List.iter (fun (label,change) ->
    let wrong=ok (K.Change_spec.of_string (K.Input.json (change (K.Input.parse contract)))) in
    let rows=evaluate_result (P.run wrong ~before ~after:repaired) in
    check ("reject substituted "^label) ((first rows).failure=Some Report_mismatch && exit_code rows=1)) changed_contracts;
  List.iter (fun (label,result) ->
    let rows=evaluate_result result in
    check ("bind returned "^label) ((first rows).failure=Some Report_mismatch && exit_code rows=1))
    ["original bytes",P.run spec ~before:(before^" ") ~after:repaired;
     "candidate bytes",P.run spec ~before ~after:(repaired^" ");
     "missing frozen contract",P.invalid_contract "PRIVATE_DIAGNOSTIC" ~before ~after:repaired];
  let errors=ok (parse_submissions one (submissions [entry "valid" "valid";entry "missing" "missing";entry "exception" "exception"])) in
  let rows=run ~read_candidate:(fun path -> if path="missing" then Error () else Ok path)
    ~evaluate_change:(fun _ ~before:_ ~after -> if after="exception" then failwith "PRIVATE_DIAGNOSTIC"
      else P.run spec ~before ~after:repaired) ~submission_root:"unused" one errors in
  (* The deliberately wrong candidate binding above is an error, never success. *)
  check "all errors remain accounted" (List.length (List.hd rows).attempts=3
    && List.map (fun (a:attempt_row) -> a.failure) (List.hd rows).attempts
      =[Some Report_mismatch;Some Candidate_read_error;Some Evaluation_error]
    && exit_code rows=1 && not (contains (to_json rows) "PRIVATE_DIAGNOSTIC"));
  let rows=run ~read_candidate:(fun path -> if path="missing" then Error () else Ok repaired)
    ~evaluate_change:(fun _ ~before:_ ~after:_ -> valid) ~submission_root:"unused" one errors in
  check "later errors prevent acceptance despite an earlier valid attempt"
    (exit_code rows=1 && (first rows).repair_result=Some "valid_change"
     && field "first_valid_attempt" (first_task (K.Input.parse (to_json rows)))=`Number "1");
  let missing=run ~submission_root:"unused" one (ok (parse_submissions one (submissions []))) in
  check "missing task remains in denominator" ((List.hd missing).failure=Some Missing_submission && exit_code missing=1);
  List.iter (fun failure ->
    let rows=failed_tasks failure one in let json=K.Input.parse (to_json rows) in
    check "bad submission retains frozen format3 schedule"
      (field "experimental_format_version" json=`Number "3" && field "submitted_attempts" json=`Null
       && field "scheduled_tasks" json=`Number "1" && (List.hd rows).frozen_contract_sha256<>None))
    [Submissions_invalid;Submissions_read_error];
  let access=K.Change_spec.requirements spec in
  let mixed=freeze ~suite_root:"unused" ~read_suite:(fun path -> Ok
    (if path="contract.json" then contract else if path="access.json" then K.Contract_spec.canonical access else before))
      [task ();task ~id:"access" ~contract:"access.json" ()] in
  let mixed_rows=run ~read_candidate:(fun _ -> Ok repaired) ~evaluate_change:(fun _ ~before:_ ~after:_ -> valid)
    ~submission_root:"unused" mixed (ok (parse_submissions mixed
      (submissions [entry "change" "repaired";entry ~task:"access" "access" "repaired"]))) in
  let json=K.Input.parse (to_json mixed_rows) in
  check "mixed suite preserves access and change meanings" (exit_code mixed_rows=0
    && field "experimental_format_version" json=`Number "3" && field "profile" json=`Null
    && field "valid_change" (field "attempt_counts" json)=`Number "1"
    && field "valid_repair" (field "attempt_counts" json)=`Number "1"
    && (List.nth mixed_rows 1).contract_kind=Some K.Contract_spec.kind
    && (List.hd (List.nth mixed_rows 1).attempts).authorization_result=None);
  let malformed=freeze ~suite_root:"unused" ~read_suite:(fun path -> Ok
    (if path="bad.json" then "{\"kind\":\"kubernetes-rbac-policy-change\"}" else if path="contract.json" then contract else before))
      [task ();task ~id:"bad" ~contract:"bad.json" ()] in
  let rows=run ~read_candidate:(fun _ -> Ok repaired) ~evaluate_change:(fun _ ~before:_ ~after:_ -> valid)
    ~submission_root:"unused" malformed (ok (parse_submissions malformed
      (submissions [entry "a" "a";entry ~task:"bad" "bad" "a"]))) in
  check "invalid outer contract is never treated as an access contract"
    ((List.nth rows 1).failure=Some Contract_invalid && (List.hd (List.nth rows 1).attempts).candidate_sha256=None
     && exit_code rows=1 && field "experimental_format_version" (K.Input.parse (to_json rows))=`Number "3");

  let self_spec=ok (K.Change_spec.of_string (source "self-contract.json")) in
  let self=ok (P.authorize self_spec ~before:(source "self-before.json") ~after:(source "self-escalation.json")) in
  check "self-escalation isolates original-snapshot guard, not missing initial grant"
    (not self.allowed && self.initial.granting_rules<>[]
     && (Option.get self.special).granting_rules=[] && not (Option.get self.coverage).covered);
  let code,json,_=run_process binary [Filename.concat root "suite.yaml";Filename.concat root "submissions.yaml"] in
  check "runnable synthetic campaign accepted" (code=0
    && field "scheduled_tasks" json=`Number "2" && field "submitted_attempts" json=`Number "7"
    && field "tasks_with_valid_repair" json=`Number "2");
  List.iter (fun (key,count) -> check ("campaign count "^key)
    (field key (field "attempt_counts" json)=`Number count))
    ["valid_change","2";"valid_repair","0";"authorization_failed","2";
     "contract_failed","1";"out_of_scope_regression","1";"unknown","1";"errors","0"];
  let rows=array (field "tasks" json) in
  check "campaign first accepted attempts" (List.map (field "first_valid_attempt") rows=[`Number "5";`Number "2"]);
  List.iter (fun row -> check "synthetic provenance stays explicit" (field "provenance" row=`String "synthetic")) rows;
  let temporary=Filename.temp_file "rbac-change-repair-" "" in Unix.unlink temporary;Unix.mkdir temporary 0o700;
  Fun.protect ~finally:(fun () -> cleanup temporary) (fun () ->
    let local path=Filename.concat temporary path in
    Array.iter (fun name -> write (local name) (source name)) (Sys.readdir root);
    write (local "suite.yaml") "format_version: 1\ncases: [{id: task, provenance: synthetic, config: before.json, contract: contract.json}]\n";
    let execute entries = write (local "submissions.yaml") (submissions entries);
      run_process binary [local "suite.yaml";local "submissions.yaml"] in
    List.iter (fun (file,outcome) ->
      let code,json,_=execute [entry "negative" file] in
      check ("CLI unaccepted "^outcome) (code=3
        && field "repair_result" (first_attempt json)=`String outcome))
      ["authorization-failed.json","authorization_failed";"before.json","unknown"];
    let code,json,_=execute [entry "accepted" "repaired.json";entry "missing" "absent.json"] in
    check "CLI later input failure blocks aggregate success" (code=1
      && field "valid_change" (field "attempt_counts" json)=`Number "1"
      && field "errors" (field "attempt_counts" json)=`Number "1");
    write (local "submissions.yaml") "format_version: 1\nattempts: [{task: task, id: a, config: repaired.json, actor: admin}]\n";
    let code,json,_=run_process binary [local "suite.yaml";local "submissions.yaml"] in
    check "CLI override fails with original schedule" (code=1
      && field "failure" (first_task json)=`String "submissions_invalid"
      && field "experimental_format_version" json=`Number "3" && field "submitted_attempts" json=`Null);
    let bin=local "bin" in Unix.mkdir bin 0o700;
    let marker=local "solver-called" in
    write (Filename.concat bin "z3") ("#!/bin/sh\nprintf 'PRIVATE_SOLVER_FAILURE\\n'\nprintf called > "^Filename.quote marker^"\n");
    Unix.chmod (Filename.concat bin "z3") 0o700;
    let old_path=Sys.getenv "PATH" in
    Fun.protect ~finally:(fun () -> Unix.putenv "PATH" old_path) (fun () ->
      Unix.putenv "PATH" (bin^":"^old_path);
      let code,json,_=execute [entry "unauthorized" "authorization-failed.json";entry "unsupported" "before.json"] in
      check "unmet or unsupported authorization never invokes solver" (code=3 && not (Sys.file_exists marker)
        && field "authorization_failed" (field "attempt_counts" json)=`Number "1");
      let code,json,output=execute [entry "solver-error" "repaired.json"] in
      let attempt=first_attempt json in
      check "solver failure after authorization stays unknown, with nested stages"
        (code=3 && Sys.file_exists marker && field "repair_result" attempt=`String "unknown"
         && field "authorization_result" attempt=`String "allowed"
         && field "contract_result" attempt=`String "unknown"
         && field "comparison_assurance" attempt=`String "within_profile"
         && field "change_assurance" attempt=`String "unsupported_or_inconclusive"
         && field "failure" attempt=`Null && not (contains output "PRIVATE_SOLVER_FAILURE"))));
  Printf.printf "All %d policy-change repair evaluator checks passed.\n" !checks
