open Soundcheck_core
open Rbac_repair_bench
module K = Soundcheck_kubernetes_rbac

let checks = ref 0
let check label predicate = incr checks; if not predicate then failwith ("RBAC repair unit: " ^ label)
let ok = function Ok value -> value | Error _ -> failwith "unexpected error"
let secret = "PRIVATE_RBAC_REPAIR_7fa2"
let contract = Printf.sprintf {| {
  "schema_version":1,"kind":"kubernetes-rbac-access",
  "context":{"schema_version":1,"snapshot_complete":true,
    "identities":[{"username":%S,"groups":["operators"]}]},
  "clauses":[
    {"name":"required","kind":"must_allow","subject":%S,
     "namespace":"frontend","resource":"configmaps","names":null},
    {"name":"forbidden","kind":"must_not_grant","subject":%S,
     "namespace":"payments","resource":"secrets","names":null}],
  "change_scope":[{"subject":%S,"namespace":"payments","resource":"secrets","names":null}]
} |} secret secret secret secret
let spec = ok (K.Contract_spec.of_string contract)
let task ?(id="task") ?(config="before.json") ?(contract="contract.json") () : Pilot.case =
  {id;config;contract;provenance=Pilot.Synthetic}
let entry ?(task="task") ?(config="candidate.json") id =
  Printf.sprintf {|{"task":%S,"id":%S,"config":%S}|} task id config
let submissions values = {|{"format_version":1,"attempts":[|} ^ String.concat "," values ^ "]}"
let freeze_tasks tasks = freeze ~read_suite:(fun path ->
  if path="contract.json" then Ok contract else Ok ("baseline " ^ secret)) ~suite_root:"unused" tasks
let field name = function `O fields -> List.assoc name fields | _ -> failwith "object expected"
let contains source value =
  let rec loop i = i+String.length value<=String.length source
    && (String.sub source i (String.length value)=value || loop (i+1)) in loop 0

let model : Solve.model =
  {path=secret;method_="get";is_anon=false;principal_name=Some secret;
   object_request=Some {namespace=secret;resource_kind="secrets";name=secret};
   src_ip=0l;host=secret;scheme=secret;sni=secret;headers=[secret,secret]}
let witness : Report.counterexample =
  {principal=secret;action="get";path=secret;route=Some secret;service=Some secret;
   shadowed_route=Some secret;shadowed_service=Some secret;host=secret;scheme=secret;
   sni=secret;source_ip=0l;headers=[secret,secret];object_request=model.object_request;
   identity_groups=Some [secret];granting_rules=[secret];note=secret}
let report ?(unsupported=false) ?(property=K.Contract_spec.kind) spec result : Report.t =
  {result;property_name=property;property_description=secret;
   assurance=Some (if unsupported then K.Assurance.assessment ~reason:secret () else K.Assurance.assessment ());
   clause=None;frozen_spec=Some (K.Contract_spec.frozen_spec spec)}
let trace ?(candidate_result=Report.Proved) execution : Evidence.comparison_trace =
  let plan=["inhabitance-1",Contract_verify.Inhabitance,Solve.Violated model;
    "inhabitance-2",Contract_verify.Inhabitance,Solve.Violated model;
    "consistency-1",Contract_verify.Consistency,Solve.Proved;
    "clause-1",Contract_verify.Clause,Solve.Proved;
    "clause-2",Contract_verify.Clause,Solve.Proved] in
  let stop,answer=match candidate_result with
    | Report.Proved->None,Solve.Proved
    | Report.Violated _->Some 4,Solve.Violated model
    | Report.Vacuous->Some 0,Solve.Proved
    | Report.Inconsistent _->Some 2,Solve.Violated model
    | Report.Unknown reason->Some 0,Solve.Unknown reason in
  let candidate=List.mapi (fun i (id,phase,success)->
    let execution=match stop with
      | Some n when i>n->Contract_verify.Not_executed
      | Some n when i=n->Contract_verify.Executed answer
      | _->Contract_verify.Executed success in
    {Contract_verify.obligation={id;phase;clauses=[secret];smtlib=secret};execution}) plan in
  {candidate;
   preservation={id="preservation-outside-change-scope";smtlib=secret;execution}}
let comparison spec mode : K.Verify.comparison =
  let candidate result = report spec result in
  let final result = report ~property:"rbac-repair-preservation" spec result in
  match mode with
  | "unsupported" ->
    {report=report ~unsupported:true spec (Report.Unknown secret);candidate_report=None;trace=None}
  | "valid" ->
    {report=final Report.Proved;candidate_report=Some (candidate Report.Proved);
     trace=Some (trace (Contract_verify.Executed Solve.Proved))}
  | "regression" ->
    {report={(final (Report.Violated witness)) with
       clause=Some {Report.name="preservation-outside-change-scope";description=secret;kind=Report.Must_preserve}};
     candidate_report=Some (candidate Report.Proved);
     trace=Some (trace (Contract_verify.Executed (Solve.Violated model)))}
  | "preservation-unknown" ->
    {report=final (Report.Unknown secret);candidate_report=Some (candidate Report.Proved);
     trace=Some (trace (Contract_verify.Executed (Solve.Unknown secret)))}
  | mode ->
    let result = match mode with
      | "violated" -> Report.Violated witness
      | "vacuous" -> Report.Vacuous
      | "inconsistent" -> Report.Inconsistent secret
      | "candidate-unknown" -> Report.Unknown secret
      | _ -> failwith "unexpected mock outcome" in
    let report = candidate result in
    {report;candidate_report=Some report;trace=Some (trace ~candidate_result:result Contract_verify.Not_executed)}

let () =
  let suite = freeze_tasks [task ();task ~id:"second" ()] in
  let parse bytes = parse_submissions suite bytes in
  check "valid candidate metadata" (Result.is_ok (parse (submissions [entry "one"])));
  check "empty submission accepted for missing-task accounting" (Result.is_ok (parse (submissions [])));
  check "same attempt ID on distinct tasks" (Result.is_ok
    (parse (submissions [entry "same";entry ~task:"second" "same"])));
  List.iteri (fun i bytes -> check (Printf.sprintf "invalid metadata %d" i)
    (Result.is_error (parse bytes))) [
    "";"[]";"{}";{|{"format_version":2,"attempts":[]}|};
    {|{"format_version":1,"attempts":[],"context":{}}|};
    {|{"format_version":1,"format_version":1,"attempts":[]}|};
    submissions [entry "same";entry "same"];submissions [entry ~task:"unknown" "a"];
    submissions [entry ""];submissions [entry "not an id"];
    submissions [entry ~config:"../contract.json" "a"];
    submissions [entry ~config:"/tmp/contract.json" "a"];
    submissions [entry ~config:"nested/./candidate.json" "a"];
    {|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"a","contract":"weaker"}]}|};
    {|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"a","baseline":"weaker"}]}|};
    {|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"a","context":{}}]}|};
    {|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"a","change_scope":[]}]}|};
    {|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"a","result":"proved"}]}|};
    {|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"a","z3":"fake"}]}|};
    {|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"a","mode":"contract-only"}]}|};
    {|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"a","id":"b"}]}|};
    {|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"a\u0000b"}]}|};
    "format_version: 1\nattempts: [*alias]\n";
    "format_version: 1\nattempts: [{task: task, id: &a one, config: *a}]\n";
    "format_version: 1\nattempts: [{<<: {task: task}, id: a, config: b}]\n";
    submissions [] ^ "\n---\nformat_version: 1\nattempts: []\n"];
  List.iter (fun source -> check "invalid suite cannot schedule work" (Result.is_error (Pilot.parse_manifest source)))
    ["format_version: 1\ncases: []\n";
     "format_version: 1\ncases: [{id: a, config: a, contract: b, provenance: synthetic, result: proved}]\n";
     "format_version: 1\ncases: [{id: a, config: a, contract: b, provenance: synthetic}, {id: a, config: a, contract: b, provenance: synthetic}]\n"];

  let reads = Hashtbl.create 8 and frozen_complete = ref false in
  let tasks = [task ();task ~id:"second" ();task ~id:"missing" ();
    task ~id:"bad-contract" ~contract:"invalid.json" ();
    task ~id:"missing-contract" ~contract:"missing.json" ();
    task ~id:"missing-baseline" ~config:"missing.json" ()] in
  let read_suite path =
    check "no trusted-input reload after freeze" (not !frozen_complete);
    Hashtbl.replace reads path (1+Option.value ~default:0 (Hashtbl.find_opt reads path));
    if path="contract.json" then Ok contract
    else if path="before.json" then Ok ("baseline " ^ secret)
    else if path="invalid.json" then Ok ("invalid " ^ secret)
    else Error () in
  let suite = freeze ~read_suite ~suite_root:"unused" tasks in
  frozen_complete := true;
  check "shared sources read once, including cross-role path" (Hashtbl.length reads=4
    && Hashtbl.fold (fun _ count acc -> acc && count=1) reads true);
  let modes = ["valid";"violated";"vacuous";"inconsistent";"candidate-unknown";
    "preservation-unknown";"unsupported";"regression";"missing";"exception";"spoof"] in
  let attempts = ok (parse_submissions suite (submissions (
    List.map (fun mode -> entry ~config:mode mode) modes
    @ List.map (fun task -> entry ~task ~config:"valid" "a")
       ["second";"bad-contract";"missing-contract";"missing-baseline"]))) in
  let candidate_reads = ref [] and evaluations = ref [] in
  let read_candidate path =
    check "candidate IO starts after all evaluator sources frozen" !frozen_complete;
    candidate_reads := path::!candidate_reads;
    if path="missing" then Error () else Ok path in
  let evaluate frozen ~before ~after =
    check "frozen context and changes retained" (K.Contract_spec.canonical frozen=K.Contract_spec.canonical spec);
    check "all attempts use original baseline" (before="baseline " ^ secret);
    evaluations := after::!evaluations;
    if after="exception" then failwith secret
    else if after="spoof" then
      let value=comparison frozen "valid" in {value with report={value.report with frozen_spec=None}}
    else comparison frozen after in
  let clock=ref 0. in let now ()=clock:= !clock+.0.25;!clock in
  let rows=run ~read_candidate ~evaluate ~now ~submission_root:"unused" suite attempts in
  check "every scheduled task retained in order" (List.map (fun (row:task_row)->row.id) rows
    =List.map (fun (task:Pilot.case)->task.id) tasks);
  check "each eligible attempt read exactly once" (List.rev !candidate_reads=modes@["valid"]);
  check "one comparison run per read candidate; no contract rerun" (List.rev !evaluations
    =List.filter ((<>) "missing") modes@["valid"]);
  let row id=List.find (fun (row:task_row)->row.id=id) rows in
  let first=row "task" in
  let attempt id=List.find (fun (row:attempt_row)->row.id=id) first.attempts in
  check "attempt input order retained" (List.map (fun (row:attempt_row)->row.id) first.attempts=modes);
  check "raw contract hash" (first.contract_sha256=Some (Sha256.string contract));
  check "canonical contract hash includes context and changes" (first.frozen_contract_sha256
    =Some (Sha256.string (K.Contract_spec.canonical spec)) && first.contract_sha256<>first.frozen_contract_sha256);
  check "raw baseline hash" (first.baseline_sha256=Some (Sha256.string ("baseline " ^ secret)));
  check "raw candidate hash" ((attempt "valid").candidate_sha256=Some (Sha256.string "valid"));
  check "candidate digest retained on evaluator failure" ((attempt "exception").candidate_sha256<>None);
  check "invalid contract bytes still bound" ((row "bad-contract").contract_sha256
    =Some (Sha256.string ("invalid " ^ secret)) && (row "bad-contract").frozen_contract_sha256=None);
  List.iter (fun (mode,contract_result,repair_result) ->
    check ("stage projection " ^ mode) ((attempt mode).contract_result=contract_result
      && (attempt mode).repair_result=Some repair_result)) [
      "valid",Some "proved","valid_repair";
      "violated",Some "violated","contract_failed";
      "vacuous",Some "vacuous","contract_failed";
      "inconsistent",Some "inconsistent","contract_failed";
      "candidate-unknown",Some "unknown","unknown";
      "preservation-unknown",Some "proved","unknown";
      "unsupported",None,"unknown";
      "regression",Some "proved","out_of_scope_regression"];
  check "unsupported candidate stage honestly unavailable" ((attempt "unsupported").contract_assurance=None
    && (attempt "unsupported").comparison_assurance=Some "unsupported");
  check "solver uncertainty is unknown, never an invented parser/tool classification"
    ((attempt "candidate-unknown").failure=None && (attempt "preservation-unknown").failure=None);
  List.iter (fun (id,failure) -> check ("failure " ^ id) ((attempt id).failure=Some failure))
    ["missing",Candidate_read_error;"exception",Evaluation_error;"spoof",Report_mismatch];
  List.iter (fun (id,failure) -> check ("task failure " ^ id) ((row id).failure=Some failure))
    ["missing",Missing_submission;"bad-contract",Contract_invalid;
     "missing-contract",Contract_read_error;"missing-baseline",Baseline_read_error];
  check "fixed clock controls timing" (List.for_all (fun (row:attempt_row)->row.elapsed_seconds=0.25) first.attempts);
  let summary=to_json rows in
  check "private report, witness, formula, config and exception data excluded" (not (contains summary secret));
  let json=K.Input.parse summary in
  check "separate experimental RBAC kind" (field "kind" json=`String "submitted_rbac_repair_evaluation"
    && field "experimental_format_version" json=`Number "1");
  check "exact supported profile" (field "profile" json=`String "kubernetes-rbac-v1.34-get-v1");
  List.iter (fun (key,value) -> check ("aggregate " ^ key) (field key json=`Number value))
    ["scheduled_tasks","6";"submitted_attempts","15";"tasks_with_valid_repair","2";"tasks_with_errors","5"];
  List.iter (fun (key,value) -> check ("count " ^ key) (field key (field "attempt_counts" json)=`Number value))
    ["valid_repair","2";"contract_failed","3";"out_of_scope_regression","1";"unknown","3";"errors","6"];
  check "errors still fail aggregate after a valid candidate" (exit_code rows=1);
  check "all solved task succeeds" (exit_code [row "second"]=0);
  check "completed but rejected task nonzero" (exit_code [{first with attempts=[attempt "violated";attempt "unsupported"]}]=3);
  check "empty suite never succeeds" (exit_code []=1);
  let failed=failed_tasks Submissions_invalid suite in
  check "invalid submissions retain schedule and frozen digests" (List.length failed=6
    && (List.hd failed).contract_sha256=first.contract_sha256
    && (List.hd failed).baseline_sha256=first.baseline_sha256);
  check "invalid submission count unknown, not zero" (field "submitted_attempts" (K.Input.parse (to_json failed))=`Null);
  let missing=run ~read_candidate:(fun _->failwith "must not read") ~submission_root:"unused"
      (freeze_tasks [task ()]) (ok (parse_submissions (freeze_tasks [task ()]) (submissions []))) in
  check "no attempts explicitly missing" ((List.hd missing).failure=Some Missing_submission && exit_code missing=1);

  let suite=freeze_tasks [task ()] in
  let attempts=ok (parse_submissions suite (submissions [entry "a"])) in
  let forged : (K.Verify.comparison -> K.Verify.comparison) list = [
    (fun r -> {r with K.Verify.report={r.report with frozen_spec=None}});
    (fun r -> {r with K.Verify.report={r.report with assurance=Some {profile="other";status=Report.Within_profile;findings=[]}}});
    (fun r -> {r with K.Verify.report={r.report with property_name=K.Contract_spec.kind}});
    (fun r -> {r with K.Verify.candidate_report=None});
    (fun r -> {r with K.Verify.candidate_report=Some (report spec (Report.Unknown secret))});
    (fun r -> {r with K.Verify.trace=None});
    (fun r -> {r with K.Verify.trace=Some {(Option.get r.trace) with candidate=[]}});
    (fun r -> {r with K.Verify.trace=Some (trace Contract_verify.Not_executed)});
    (fun r -> {r with K.Verify.report={r.report with result=Report.Violated witness}});
    (fun r -> {r with K.Verify.report={r.report with result=Report.Unknown secret}});
    (fun _ -> let r=comparison spec "unsupported" in {r with report={r.report with result=Report.Proved}});
    (fun _ -> let r=comparison spec "preservation-unknown" in {r with report={r.report with result=Report.Unknown "different"}});
    (fun r -> {r with K.Verify.report={r.report with frozen_spec=Some {(K.Contract_spec.frozen_spec spec) with canonical="weakened"}}});
  ] in
  List.iteri (fun i forge ->
    let rows=run ~read_candidate:(fun _->Ok "candidate")
      ~evaluate:(fun spec ~before:_ ~after:_ -> forge (comparison spec "valid"))
      ~submission_root:"unused" suite attempts in
    check (Printf.sprintf "incoherent result %d fails closed" i)
      ((List.hd (List.hd rows).attempts).failure=Some Report_mismatch && exit_code rows=1)) forged;
  let replace_entry index change (trace:Evidence.comparison_trace) =
    {trace with candidate=List.mapi (fun i entry->if i=index then change entry else entry) trace.candidate} in
  let executed result (entry:Contract_verify.trace_entry)={entry with execution=Contract_verify.Executed result} in
  let unexecuted (entry:Contract_verify.trace_entry)={entry with execution=Contract_verify.Not_executed} in
  let trace_forgeries : (string * (Evidence.comparison_trace -> Evidence.comparison_trace)) list = [
    "candidate never executed",(fun trace->{trace with Evidence.candidate=List.map unexecuted trace.candidate});
    "candidate stops before a decisive result",replace_entry 3 unexecuted;
    "candidate unknown cannot be projected as proved",replace_entry 4 (executed (Solve.Unknown secret));
    "candidate violation cannot be projected as proved",replace_entry 4 (executed (Solve.Violated model));
    "vacuous request class cannot be projected as proved",replace_entry 0 (executed Solve.Proved);
    "inconsistent requirements cannot be projected as proved",replace_entry 2 (executed (Solve.Violated model));
    "phases cannot regress",(fun trace->{trace with Evidence.candidate=List.rev trace.candidate});
    "no execution after candidate unknown",replace_entry 0 (executed (Solve.Unknown secret));
  ] in
  List.iter (fun (label,forge)->
    let rows=run ~read_candidate:(fun _->Ok "candidate")
      ~evaluate:(fun spec ~before:_ ~after:_->let value=comparison spec "valid" in
        {value with trace=Some (forge (Option.get value.trace))})
      ~submission_root:"unused" suite attempts in
    check label ((List.hd (List.hd rows).attempts).failure=Some Report_mismatch && exit_code rows=1)) trace_forgeries;
  let rows=run ~read_candidate:(fun _->Ok "candidate")
    ~evaluate:(fun spec ~before:_ ~after:_->let value=comparison spec "candidate-unknown" in
      {value with trace=Some (replace_entry 0 (executed (Solve.Unknown "different")) (Option.get value.trace))})
    ~submission_root:"unused" suite attempts in
  check "candidate unknown reason binds to recorded result"
    ((List.hd (List.hd rows).attempts).failure=Some Report_mismatch);
  Printf.printf "All %d RBAC submitted-repair unit checks passed.\n" !checks
