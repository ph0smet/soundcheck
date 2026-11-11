open Soundcheck_core
module K = Soundcheck_kubernetes_rbac

let checks=ref 0
let check label predicate=incr checks;if not predicate then failwith ("RBAC repair CLI: " ^ label)
let ok=function Ok value->value | Error _->failwith "unexpected error"
let read path=let channel=open_in_bin path in
  Fun.protect ~finally:(fun ()->close_in_noerr channel)
    (fun ()->really_input_string channel (in_channel_length channel))
let write path bytes=let channel=open_out_bin path in
  Fun.protect ~finally:(fun ()->close_out_noerr channel) (fun ()->output_string channel bytes)
let field key=function `O fields->List.assoc key fields | _->failwith "object expected"
let array=function `A values->values | _->failwith "array expected"
let json=K.Input.parse
let contains source fragment=
  let rec loop i=i+String.length fragment<=String.length source
    && (String.sub source i (String.length fragment)=fragment || loop (i+1)) in loop 0
let run binary args=
  let output=Filename.temp_file "rbac-repair-out-" "" and errors=Filename.temp_file "rbac-repair-err-" "" in
  Fun.protect ~finally:(fun ()->Sys.remove output;Sys.remove errors) (fun ()->
    let out_fd=Unix.openfile output [Unix.O_WRONLY;Unix.O_TRUNC] 0o600
    and err_fd=Unix.openfile errors [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let pid=Unix.create_process binary (Array.of_list (binary::args)) Unix.stdin out_fd err_fd in
    Unix.close out_fd;Unix.close err_fd;
    let _,status=Unix.waitpid [] pid in
    let code=match status with Unix.WEXITED code->code | _->failwith "unexpected termination" in
    code,read output,read errors)
let rec cleanup path=
  match (Unix.lstat path).Unix.st_kind with
  | Unix.S_DIR->Array.iter (fun name->cleanup (Filename.concat path name)) (Sys.readdir path);Unix.rmdir path
  | _->Unix.unlink path
let entry ?(task="frontend-access") id config=
  Printf.sprintf "  - task: %s\n    id: %s\n    config: %s\n" task id config
let first_task summary=List.hd (array (field "tasks" summary))
let first_attempt summary=List.hd (array (field "attempts" (first_task summary)))
let summarize (code,stdout,stderr)=check "no raw stderr diagnostics" (stderr="");code,json stdout,stdout

let ()=
  if Array.length Sys.argv<>4 then failwith "expected evaluator, examples, and original RBAC corpus";
  let evaluator=Sys.argv.(1) and examples=Sys.argv.(2) and corpus=Sys.argv.(3) in
  let file name=Filename.concat examples name in
  let expected=[
    "unchanged","01-unsafe.json",Some "violated","contract_failed";
    "delete-workload-grants","02-delete-workload-grants.json",Some "violated","contract_failed";
    "leftover-cluster-grant","04-leftover-cluster-grant.json",Some "violated","contract_failed";
    "group-grant","05-group-grant.json",Some "violated","contract_failed";
    "operator-regression","16-operator-regression.json",Some "proved","out_of_scope_regression";
    "unsupported","17-missing-reference.json",None,"unknown";
    "repaired","03-valid-repair.json",Some "proved","valid_repair"] in
  List.iter (fun (_,name,_,_)->check ("fixture bytes agree with reference corpus: " ^ name)
    (read (file name)=read (Filename.concat (Filename.concat corpus "fixtures") name))) expected;
  check "frozen contract bytes agree with reference corpus"
    (read (file "frontend-access.json")=read (Filename.concat corpus "contracts/frontend-access.json"));
  let exit,summary,stdout=summarize (run evaluator [file "suite.yaml";file "submissions.yaml"]) in
  check "supplied synthetic sequence includes a valid repair" (exit=0);
  check "distinct experimental summary" (field "kind" summary=`String "submitted_rbac_repair_evaluation"
    && field "experimental_format_version" summary=`Number "1");
  check "exact static named-get profile" (field "profile" summary=`String "kubernetes-rbac-v1.34-get-v2");
  check "fixed preservation comparison" (field "comparison" summary=`String "frozen_scope_preservation");
  List.iter (fun (name,value)->check ("summary " ^ name) (field name summary=`Number value))
    ["scheduled_tasks","1";"tasks_with_valid_repair","1";"tasks_with_errors","0";"submitted_attempts","7"];
  List.iter (fun (name,value)->check ("outcome count " ^ name)
    (field name (field "attempt_counts" summary)=`Number value))
    ["valid_repair","1";"contract_failed","4";"out_of_scope_regression","1";"unknown","1";"errors","0"];
  let task=first_task summary in
  check "explicit synthetic provenance" (field "provenance" task=`String "synthetic");
  check "first valid submitted ordinal" (field "first_valid_attempt" task=`Number "7");
  check "baseline exact digest" (field "baseline_sha256" task=`String (Sha256.string (read (file "01-unsafe.json"))));
  let contract=read (file "frontend-access.json") in
  let spec=ok (K.Contract_spec.of_string contract) in
  check "raw contract digest" (field "contract_sha256" task=`String (Sha256.string contract));
  check "canonical contract/context/scope digest" (field "frozen_contract_sha256" task
    =`String (Sha256.string (K.Contract_spec.canonical spec)));
  let attempts=array (field "attempts" task) in
  check "all candidate controls retained" (List.length attempts=List.length expected);
  List.iteri (fun i ((id,path,contract_result,repair_result),attempt)->
    check (id ^ " order") (field "id" attempt=`String id && field "ordinal" attempt=`Number (string_of_int (i+1)));
    check (id ^ " exact candidate bytes") (field "candidate_sha256" attempt=`String (Sha256.string (read (file path))));
    check (id ^ " candidate stage") (field "contract_result" attempt=match contract_result with None->`Null | Some s->`String s);
    check (id ^ " repair stage") (field "repair_result" attempt=`String repair_result);
    check (id ^ " no input/tool error") (field "failure" attempt=`Null);
    check (id ^ " candidate assurance") (field "contract_assurance" attempt
      =if contract_result=None then `Null else `String "within_profile");
    check (id ^ " comparison assurance") (field "comparison_assurance" attempt
      =`String (if contract_result=None then "unsupported" else "within_profile")))
    (List.combine expected attempts);
  List.iter (fun value->check ("private detailed fields absent: " ^ value) (not (contains stdout value)))
    ["counterexample";"granting_rules";"canonical";"system:serviceaccount:";"ops-auditor";"smtlib"];

  let root=Filename.temp_file "soundcheck-rbac-repair-" "" in Unix.unlink root;Unix.mkdir root 0o700;
  Fun.protect ~finally:(fun ()->cleanup root) (fun ()->
    let local name=Filename.concat root name in
    Array.iter (fun name->write (local name) (read (file name))) (Sys.readdir examples);
    let suite=local "suite.yaml" and submissions=local "attempts.yaml" in
    let run_local attempts=
      write submissions ("format_version: 1\nattempts:\n" ^ attempts);
      summarize (run evaluator [suite;submissions]) in
    let code,summary,_=run_local (entry "unchanged" "01-unsafe.json") in
    check "completed but unaccepted task exits 3" (code=3
      && field "tasks_with_valid_repair" summary=`Number "0"
      && field "repair_result" (first_attempt summary)=`String "contract_failed");
    write submissions "format_version: 1\nattempts: []\n";
    let code,summary,_=summarize (run evaluator [suite;submissions]) in
    check "missing task stays in denominator" (code=1 && field "scheduled_tasks" summary=`Number "1"
      && field "failure" (first_task summary)=`String "missing_submission"
      && field "attempts" (first_task summary)=`A []);
    List.iter (fun override->
      write submissions ("format_version: 1\nattempts: [{task: frontend-access, id: a, config: 03-valid-repair.json, " ^ override ^ "}]\n");
      let code,summary,_=summarize (run evaluator [suite;submissions]) in
      check ("submission override rejected: " ^ override) (code=1
        && field "failure" (first_task summary)=`String "submissions_invalid"
        && field "scheduled_tasks" summary=`Number "1"
        && field "submitted_attempts" summary=`Null
        && field "contract_sha256" (first_task summary)=`String (Sha256.string contract)))
      ["contract: weaker.json";"context: {}";"baseline: safer.json";"change_scope: []";"result: valid_repair";"z3: fake"];
    let code,summary,_=run_local (entry ~task:"unscheduled" "a" "03-valid-repair.json") in
    check "unscheduled tasks invalidate metadata" (code=1 && field "failure" (first_task summary)=`String "submissions_invalid");
    let code,summary,_=summarize (run evaluator [suite;local "absent-submissions.yaml"]) in
    check "unreadable submissions keep frozen task identities" (code=1
      && field "failure" (first_task summary)=`String "submissions_read_error"
      && field "baseline_sha256" (first_task summary)<>`Null);
    let secret="PRIVATE_RBAC_ATTEMPT_3ca8" in
    write (local (secret ^ ".json")) ("{\"private-unknown-field\":\"" ^ secret ^ "\"}");
    let before=Sys.readdir root |> Array.to_list |> List.sort String.compare in
    let candidate_before=read (local "03-valid-repair.json") in
    let code,summary,output=run_local (entry "unsupported" (secret ^ ".json")
      ^ entry "unreadable" (secret ^ "-missing.json")) in
    check "input error is explicit alongside unsupported candidate" (code=1
      && field "errors" (field "attempt_counts" summary)=`Number "1"
      && field "unknown" (field "attempt_counts" summary)=`Number "1");
    check "raw input/path/diagnostic not leaked" (not (contains output secret));
    check "no automatic artifact creation" (before=(Sys.readdir root |> Array.to_list |> List.sort String.compare));
    check "candidate never rewritten" (candidate_before=read (local "03-valid-repair.json"));
    Unix.symlink "03-valid-repair.json" (local "linked.json");
    let code,summary,_=run_local (entry "symlink" "linked.json") in
    check "candidate symlink fails read" (code=1 && field "failure" (first_attempt summary)=`String "candidate_read_error");
    Unix.mkdir (local "directory") 0o700;
    let code,summary,_=run_local (entry "directory" "directory") in
    check "directory candidate fails read" (code=1 && field "failure" (first_attempt summary)=`String "candidate_read_error");
    Unix.mkfifo (local "fifo") 0o600;
    let code,summary,_=run_local (entry "fifo" "fifo") in
    check "FIFO candidate rejected without blocking" (code=1 && field "failure" (first_attempt summary)=`String "candidate_read_error");
    Unix.symlink "suite.yaml" (local "linked-suite.yaml");
    let code,summary,_=summarize (run evaluator [local "linked-suite.yaml";submissions]) in
    check "suite symlink cannot define schedule" (code=1 && field "failure" summary=`String "suite_read_error"
      && field "scheduled_tasks" summary=`Null);
    write (local "01-unsafe.json") (read (file "17-missing-reference.json"));
    let code,summary,_=run_local (entry "valid-candidate-unsupported-baseline" "03-valid-repair.json") in
    let attempt=first_attempt summary in
    check "unsupported baseline cannot pretend candidate was checked" (code=3
      && field "contract_result" attempt=`Null && field "contract_assurance" attempt=`Null
      && field "repair_result" attempt=`String "unknown"
      && field "comparison_assurance" attempt=`String "unsupported");
    write (local "01-unsafe.json") (read (file "01-unsafe.json"));
    write (local "frontend-access.json") ("{\"schema_version\":1,\"private\":\"" ^ secret ^ "\"}");
    let code,summary,output=run_local (entry "invalid-contract" "03-valid-repair.json") in
    check "invalid frozen contract rejected before evaluation" (code=1
      && field "failure" (first_task summary)=`String "contract_invalid"
      && field "candidate_sha256" (first_attempt summary)=`Null
      && field "contract_sha256" (first_task summary)<>`Null
      && field "frozen_contract_sha256" (first_task summary)=`Null
      && not (contains output secret));
    write (local "frontend-access.json") contract;
    let fake_bin=local "fake-bin" in Unix.mkdir fake_bin 0o700;
    let fake=Filename.concat fake_bin "z3" in
    write fake ("#!/bin/sh\nprintf 'malformed PRIVATE_RBAC_ATTEMPT_3ca8\\n'\n");Unix.chmod fake 0o700;
    let old_path=Sys.getenv "PATH" in
    Fun.protect ~finally:(fun ()->Unix.putenv "PATH" old_path) (fun ()->
      Unix.putenv "PATH" (fake_bin ^ ":" ^ old_path);
      let code,summary,output=run_local (entry "solver-failure" "03-valid-repair.json") in
      check "solver protocol failure remains a nonaccepted unknown" (code=3
        && field "contract_result" (first_attempt summary)=`String "unknown"
        && field "repair_result" (first_attempt summary)=`String "unknown"
        && field "failure" (first_attempt summary)=`Null
        && field "comparison_assurance" (first_attempt summary)=`String "within_profile"
        && not (contains output secret)));
    write (local "invalid-suite.yaml") "format_version: 1\ncases: []\n";
    let code,summary,_=summarize (run evaluator [local "invalid-suite.yaml";submissions]) in
    check "invalid suite cannot invent denominator" (code=1 && field "scheduled_tasks" summary=`Null
      && field "failure" summary=`String "suite_invalid");
    let code,output,errors=run evaluator ["--unknown";secret;"extra"] in
    check "usage rejects extras without printing submitted text" (code=2 && output="" && not (contains errors secret)));
  Printf.printf "All %d RBAC submitted-repair CLI checks passed.\n" !checks
