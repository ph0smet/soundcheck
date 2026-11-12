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
let read_contract = Printf.sprintf {| {
  "schema_version":2,"kind":"kubernetes-rbac-access",
  "context":{"schema_version":1,"snapshot_complete":true,
    "identities":[{"username":%S,"groups":["operators"]}]},
  "clauses":[
    {"name":"required","kind":"must_allow","subject":%S,"verb":"list",
     "namespace":"frontend","resource":"configmaps","names":null},
    {"name":"forbidden","kind":"must_not_grant","subject":%S,"verb":"watch",
     "namespace":null,"resource":"secrets","names":null}],
  "change_scope":[{"subject":%S,"verb":"watch","namespace":null,"resource":"secrets","names":null}]
} |} secret secret secret secret
let write_contract = Printf.sprintf {| {
  "schema_version":3,"kind":"kubernetes-rbac-access",
  "context":{"schema_version":1,"snapshot_complete":true,
    "identities":[{"username":%S,"groups":["operators"]}]},
  "clauses":[
    {"name":"required","kind":"must_allow","subject":%S,"verb":"update",
     "namespace":"frontend","resource":"configmaps","names":["settings"]},
    {"name":"forbidden","kind":"must_not_grant","subject":%S,"verb":"delete",
     "namespace":"payments","resource":"secrets","names":null}],
  "change_scope":[{"subject":%S,"verb":"delete","namespace":"payments","resource":"secrets","names":null}]
} |} secret secret secret secret
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
  let version = K.Contract_spec.version spec in
  {result;property_name=property;property_description=secret;
   assurance=Some (if unsupported then K.Assurance.assessment ~version ~reason:secret ()
                  else K.Assurance.assessment ~version ());
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
  check "exact supported profile" (field "profile" json=`String "kubernetes-rbac-v1.34-get-v3");
  check "schema1 task JSON shape unchanged" (match field "tasks" json with
    | `A (`O fields::_) -> not (List.mem_assoc "profile" fields) | _ -> false);
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

  let freeze_contract source = freeze ~read_suite:(fun path ->
    Ok (if path="contract.json" then source else "baseline"))
      ~suite_root:"unused" [task ()] in
  let read_suite = freeze_contract read_contract in
  let evaluate_suite suite evaluate =
    let attempts=ok (parse_submissions suite (submissions [entry "read"])) in
    run ~read_candidate:(fun _->Ok "candidate") ~evaluate
      ~now:(fun ()->0.) ~submission_root:"unused" suite attempts in
  let read_rows = evaluate_suite read_suite (fun frozen ~before:_ ~after:_ ->
    check "read contract version frozen before dispatch" (K.Contract_spec.version frozen=2);
    comparison frozen "valid") in
  let first_attempt rows = List.hd (List.hd rows).attempts in
  check "v2 read-profile comparison accepted" (exit_code read_rows=0
    && (first_attempt read_rows).repair_result=Some "valid_repair");
  let json=K.Input.parse (to_json read_rows) in
  check "all-v2 summary selects format2 and trusted profile"
    (field "experimental_format_version" json=`Number "2"
      && field "profile" json=`String K.Assurance.read_profile_id
      && (match field "tasks" json with `A [task]->field "profile" task=`String K.Assurance.read_profile_id | _->false));
  let with_profile profile (report:Report.t) =
    {report with assurance=Option.map (fun (assurance:Report.assurance)->
      {assurance with profile}) report.assurance} in
  let map_reports transform (comparison:K.Verify.comparison) =
    {comparison with report=transform comparison.report;
      candidate_report=Option.map transform comparison.candidate_report} in
  let profile_forgeries = [
    "both stages downgraded",map_reports (with_profile K.Assurance.profile_id);
    "candidate profile downgraded",(fun (r:K.Verify.comparison)->
      {r with candidate_report=Option.map (with_profile K.Assurance.profile_id) r.candidate_report});
    "final profile downgraded",(fun (r:K.Verify.comparison)->
      {r with report=with_profile K.Assurance.profile_id r.report});
    "both stages use unrelated profile",map_reports (with_profile "untrusted-profile");
    "frozen contract identity downgraded",map_reports (fun report->
      {report with frozen_spec=Some (K.Contract_spec.frozen_spec spec)});
  ] in
  List.iter (fun (label,forge)->
    let rows=evaluate_suite read_suite (fun frozen ~before:_ ~after:_->
      forge (comparison frozen "valid")) in
    check ("v2 " ^ label ^ " fails closed")
      ((first_attempt rows).failure=Some Report_mismatch
        && (first_attempt rows).repair_result=None && exit_code rows=1
        && (List.hd rows).profile=Some K.Assurance.read_profile_id)) profile_forgeries;
  List.iter (fun mode ->
    let rows=evaluate_suite read_suite (fun frozen ~before:_ ~after:_->comparison frozen mode) in
    check ("v2 uncertainty retained " ^ mode)
      ((first_attempt rows).failure=None && (first_attempt rows).repair_result=Some "unknown"
        && exit_code rows=3)) ["unsupported";"candidate-unknown";"preservation-unknown"];
  let rows=evaluate_suite read_suite (fun frozen ~before:_ ~after:_->
    map_reports (with_profile K.Assurance.profile_id) (comparison frozen "unsupported")) in
  check "unsupported v2 result cannot downgrade profile"
    ((first_attempt rows).failure=Some Report_mismatch && exit_code rows=1);
  let rows=evaluate_suite (freeze_contract contract) (fun frozen ~before:_ ~after:_->
    map_reports (with_profile K.Assurance.read_profile_id) (comparison frozen "valid")) in
  check "schema1 result cannot adopt broader profile"
    ((first_attempt rows).failure=Some Report_mismatch && exit_code rows=1);
  let mixed=freeze ~read_suite:(fun path->Ok (match path with
      | "contract.json"->contract | "read.json"->read_contract | _->"invalid"))
    ~suite_root:"unused" [task ();task ~id:"read" ~contract:"read.json" ();
      task ~id:"invalid" ~contract:"invalid.json" ()] in
  let rows=run ~read_candidate:(fun _->Ok "candidate")
    ~evaluate:(fun frozen ~before:_ ~after:_->comparison frozen "valid")
    ~now:(fun ()->0.) ~submission_root:"unused" mixed
    (ok (parse_submissions mixed (submissions [entry "a";entry ~task:"read" "b";entry ~task:"invalid" "c"]))) in
  let json=K.Input.parse (to_json rows) in
  check "mixed summary has no invented common profile"
    (field "experimental_format_version" json=`Number "2" && field "profile" json=`Null);
  check "mixed task profiles derive only from valid frozen contracts"
    (match field "tasks" json with `A tasks->List.map (field "profile") tasks=
      [`String K.Assurance.profile_id;`String K.Assurance.read_profile_id;`Null] | _->false);
  check "submission failure retains frozen v2 profile"
    (field "profile" (K.Input.parse (to_json (failed_tasks Submissions_invalid read_suite)))
      =`String K.Assurance.read_profile_id);
  check "fatal summaries retain legacy format" (let json=K.Input.parse (fatal_json "suite_invalid") in
    field "experimental_format_version" json=`Number "1" && field "profile" json=`String K.Assurance.profile_id);
  let write_suite = freeze_contract write_contract in
  let write_rows = evaluate_suite write_suite (fun frozen ~before:_ ~after:_ ->
    check "write contract version frozen before dispatch" (K.Contract_spec.version frozen=3);
    comparison frozen "valid") in
  let json=K.Input.parse (to_json write_rows) in
  check "all-v3 summary selects format2 and trusted write profile"
    (exit_code write_rows=0 && field "experimental_format_version" json=`Number "2"
      && field "profile" json=`String K.Assurance.write_profile_id
      && (match field "tasks" json with `A [task]->field "profile" task=`String K.Assurance.write_profile_id | _->false));
  List.iter (fun profile ->
    List.iter (fun (label,forge) ->
      let rows=evaluate_suite write_suite (fun frozen ~before:_ ~after:_->forge (comparison frozen "valid")) in
      check ("v3 rejects " ^ label ^ " " ^ profile)
        ((first_attempt rows).failure=Some Report_mismatch && (first_attempt rows).repair_result=None
          && exit_code rows=1 && (List.hd rows).profile=Some K.Assurance.write_profile_id))
      ["both stage profiles",map_reports (with_profile profile);
       "candidate profile",(fun (r:K.Verify.comparison)->
         {r with candidate_report=Option.map (with_profile profile) r.candidate_report});
       "final profile",(fun (r:K.Verify.comparison)->{r with report=with_profile profile r.report})])
    [K.Assurance.profile_id;K.Assurance.read_profile_id;"untrusted-write-profile"];
  List.iter (fun old_source ->
    let old_spec=ok (K.Contract_spec.of_string old_source) in
    let rows=evaluate_suite write_suite (fun frozen ~before:_ ~after:_->
      map_reports (fun report->{report with frozen_spec=Some (K.Contract_spec.frozen_spec old_spec)})
        (comparison frozen "valid")) in
    check "write result cannot substitute an older frozen contract"
      ((first_attempt rows).failure=Some Report_mismatch && exit_code rows=1)) [contract;read_contract];
  List.iter (fun mode ->
    let rows=evaluate_suite write_suite (fun frozen ~before:_ ~after:_->comparison frozen mode) in
    check ("v3 uncertainty retained " ^ mode)
      ((first_attempt rows).failure=None && (first_attempt rows).repair_result=Some "unknown"
        && exit_code rows=3 && field "profile" (K.Input.parse (to_json rows))=`String K.Assurance.write_profile_id))
    ["unsupported";"candidate-unknown";"preservation-unknown"];
  let downgraded=evaluate_suite write_suite (fun frozen ~before:_ ~after:_->
    map_reports (with_profile K.Assurance.read_profile_id) (comparison frozen "unsupported")) in
  check "unsupported v3 result cannot downgrade its profile"
    ((first_attempt downgraded).failure=Some Report_mismatch && exit_code downgraded=1);
  List.iter (fun old_source ->
    let rows=evaluate_suite (freeze_contract old_source) (fun frozen ~before:_ ~after:_->
      map_reports (with_profile K.Assurance.write_profile_id) (comparison frozen "valid")) in
    check "older contracts cannot adopt the write profile"
      ((first_attempt rows).failure=Some Report_mismatch && exit_code rows=1)) [contract;read_contract];
  let mixed=freeze ~read_suite:(fun path->Ok (match path with
      | "contract.json"->contract | "read.json"->read_contract | "write.json"->write_contract | _->"invalid"))
    ~suite_root:"unused" [task ();task ~id:"read" ~contract:"read.json" ();
      task ~id:"write" ~contract:"write.json" ();task ~id:"invalid" ~contract:"invalid.json" ()] in
  let rows=run ~read_candidate:(fun _->Ok "candidate")
    ~evaluate:(fun frozen ~before:_ ~after:_->comparison frozen "valid") ~now:(fun ()->0.)
    ~submission_root:"unused" mixed (ok (parse_submissions mixed
      (submissions [entry "a";entry ~task:"read" "b";entry ~task:"write" "c";entry ~task:"invalid" "d"]))) in
  let json=K.Input.parse (to_json rows) in
  check "mixed v1/v2/v3 summary retains format2 without a common profile"
    (field "experimental_format_version" json=`Number "2" && field "profile" json=`Null);
  check "mixed tasks retain each frozen profile and invalid null"
    (match field "tasks" json with `A tasks->List.map (field "profile") tasks=
      [`String K.Assurance.profile_id;`String K.Assurance.read_profile_id;`String K.Assurance.write_profile_id;`Null] | _->false);
  let v1_and_v3=[List.hd rows;List.nth rows 2] in
  check "format2 does not depend on a schema2 task being present"
    (let json=K.Input.parse (to_json v1_and_v3) in
     field "experimental_format_version" json=`Number "2" && field "profile" json=`Null);
  check "submission failure retains frozen v3 profile"
    (let json=K.Input.parse (to_json (failed_tasks Submissions_invalid write_suite)) in
     field "experimental_format_version" json=`Number "2" && field "profile" json=`String K.Assurance.write_profile_id);
  let resource_contract = Printf.sprintf {|{
    "schema_version":5,"kind":"kubernetes-rbac-access",
    "context":{"schema_version":1,"snapshot_complete":true,
      "identities":[{"username":%S,"groups":["operators"]}]},
    "clauses":[
      {"name":"required","kind":"must_allow","subject":%S,"verb":"patch",
       "api_group":"apps","resource":"deployments","namespace":"frontend","names":["web"]},
      {"name":"forbidden","kind":"must_not_grant","subject":%S,"verb":"get",
       "api_group":"","resource":"nodes","namespace":null,"names":null}],
    "change_scope":[]}|} secret secret secret in
  let resource_suite=freeze_contract resource_contract in
  let rows=evaluate_suite resource_suite (fun frozen ~before:_ ~after:_->
    check "resource contract frozen before evaluator dispatch" (K.Contract_spec.version frozen=5);
    comparison frozen "valid") in
  let json=K.Input.parse (to_json rows) in
  check "v5 evaluator retains format2 and exact broader profile"
    (exit_code rows=0 && field "experimental_format_version" json=`Number "2"
     && field "profile" json=`String K.Assurance.resource_profile_id);
  List.iter (fun prior_profile ->
    List.iter (fun (label,forge) ->
      let rows=evaluate_suite resource_suite (fun frozen ~before:_ ~after:_->forge (comparison frozen "valid")) in
      check ("v5 evaluator rejects "^label^" downgrade to "^prior_profile)
        ((first_attempt rows).failure=Some Report_mismatch && exit_code rows=1))
      ["both profiles",map_reports (with_profile prior_profile);
       "candidate profile",(fun (r:K.Verify.comparison)->
         {r with candidate_report=Option.map (with_profile prior_profile) r.candidate_report});
       "final profile",(fun (r:K.Verify.comparison)->{r with report=with_profile prior_profile r.report})])
    [K.Assurance.profile_id;K.Assurance.read_profile_id;K.Assurance.write_profile_id;K.Assurance.scoped_profile_id];
  List.iter (fun mode ->
    let rows=evaluate_suite resource_suite (fun frozen ~before:_ ~after:_->comparison frozen mode) in
    check ("v5 evaluator retains uncertainty "^mode)
      ((first_attempt rows).failure=None && (first_attempt rows).repair_result=Some "unknown"
       && exit_code rows=3 && (List.hd rows).profile=Some K.Assurance.resource_profile_id))
    ["unsupported";"candidate-unknown";"preservation-unknown"];
  let collection_contract = Printf.sprintf {|{
    "schema_version":6,"kind":"kubernetes-rbac-access",
    "context":{"schema_version":1,"snapshot_complete":true,
      "identities":[{"username":%S,"groups":["operators"]}]},
    "clauses":[
      {"name":"required","kind":"must_allow","subject":%S,"verb":"create",
       "api_group":"","resource":"pods","namespace":"frontend","names":{"empty":true}},
      {"name":"forbidden","kind":"must_not_grant","subject":%S,"verb":"deletecollection",
       "api_group":"","resource":"nodes","namespace":null,"names":null}],
    "change_scope":[]}|} secret secret secret in
  let collection_suite=freeze_contract collection_contract in
  let rows=evaluate_suite collection_suite (fun frozen ~before:_ ~after:_->
    check "collection-write contract frozen before evaluator dispatch" (K.Contract_spec.version frozen=6);
    comparison frozen "valid") in
  let json=K.Input.parse (to_json rows) in
  check "v6 evaluator retains format2 and exact collection-write profile"
    (exit_code rows=0 && field "experimental_format_version" json=`Number "2"
     && field "profile" json=`String K.Assurance.collection_write_profile_id);
  List.iter (fun prior_profile ->
    List.iter (fun (label,forge) ->
      let rows=evaluate_suite collection_suite (fun frozen ~before:_ ~after:_->forge (comparison frozen "valid")) in
      check ("v6 evaluator rejects "^label^" downgrade to "^prior_profile)
        ((first_attempt rows).failure=Some Report_mismatch && exit_code rows=1))
      ["both profiles",map_reports (with_profile prior_profile);
       "candidate profile",(fun (r:K.Verify.comparison)->
         {r with candidate_report=Option.map (with_profile prior_profile) r.candidate_report});
       "final profile",(fun (r:K.Verify.comparison)->{r with report=with_profile prior_profile r.report})])
    [K.Assurance.profile_id;K.Assurance.read_profile_id;K.Assurance.write_profile_id;
     K.Assurance.scoped_profile_id;K.Assurance.resource_profile_id];
  List.iter (fun mode ->
    let rows=evaluate_suite collection_suite (fun frozen ~before:_ ~after:_->comparison frozen mode) in
    check ("v6 evaluator retains uncertainty "^mode)
      ((first_attempt rows).failure=None && (first_attempt rows).repair_result=Some "unknown"
       && exit_code rows=3 && (List.hd rows).profile=Some K.Assurance.collection_write_profile_id))
    ["unsupported";"candidate-unknown";"preservation-unknown"];
  let upgraded=evaluate_suite resource_suite (fun frozen ~before:_ ~after:_->
    map_reports (with_profile K.Assurance.collection_write_profile_id) (comparison frozen "valid")) in
  check "v5 evaluator cannot silently upgrade to collection-write profile"
    ((first_attempt upgraded).failure=Some Report_mismatch && exit_code upgraded=1);
  let subresource_contract ?(required_subresource="scale") ?(changes=true) () = Printf.sprintf {|{
    "schema_version":7,"kind":"kubernetes-rbac-access",
    "context":{"schema_version":1,"snapshot_complete":true,
      "identities":[{"username":%S,"groups":["operators"]}]},
    "clauses":[
      {"name":"required","kind":"must_allow","subject":%S,"verb":"patch",
       "api_group":"apps","resource":"deployments","subresource":%S,
       "namespace":"frontend","names":["web"]},
      {"name":"forbidden","kind":"must_not_grant","subject":%S,"verb":"create",
       "api_group":"","resource":"pods","subresource":"exec",
       "namespace":"frontend","names":["worker"]}],
    "change_scope":%s}|} secret secret required_subresource secret
    (if changes then Printf.sprintf {|[{"subject":%S,"verb":"create","api_group":"",
      "resource":"pods","subresource":"exec","namespace":"frontend","names":["worker"]}]|} secret
     else "[]") in
  let subresource_profile="kubernetes-rbac-v1.34-subresources-v1" in
  let subresource_source=subresource_contract () in
  let subresource_spec=ok (K.Contract_spec.of_string subresource_source) in
  let subresource_suite=freeze_contract subresource_source in
  let rows=evaluate_suite subresource_suite (fun frozen ~before:_ ~after:_->
    check "subresource contract frozen before evaluator dispatch" (K.Contract_spec.version frozen=7);
    check "all frozen subresource coordinates survive dispatch"
      (K.Contract_spec.canonical frozen=K.Contract_spec.canonical subresource_spec);
    comparison frozen "valid") in
  let json=K.Input.parse (to_json rows) in
  check "v7 evaluator retains format2 and exact subresource profile"
    (exit_code rows=0 && field "experimental_format_version" json=`Number "2"
     && field "profile" json=`String subresource_profile
     && (List.hd rows).frozen_contract_sha256=Some (Sha256.string (K.Contract_spec.canonical subresource_spec)));
  List.iter (fun prior_profile ->
    List.iter (fun (label,forge) ->
      let rows=evaluate_suite subresource_suite (fun frozen ~before:_ ~after:_->forge (comparison frozen "valid")) in
      check ("v7 evaluator rejects "^label^" downgrade to "^prior_profile)
        ((first_attempt rows).failure=Some Report_mismatch && exit_code rows=1))
      ["both profiles",map_reports (with_profile prior_profile);
       "candidate profile",(fun (r:K.Verify.comparison)->
         {r with candidate_report=Option.map (with_profile prior_profile) r.candidate_report});
       "final profile",(fun (r:K.Verify.comparison)->{r with report=with_profile prior_profile r.report})])
    [K.Assurance.profile_id;K.Assurance.read_profile_id;K.Assurance.write_profile_id;
     K.Assurance.scoped_profile_id;K.Assurance.resource_profile_id;K.Assurance.collection_write_profile_id];
  List.iter (fun (label,source) ->
    let forged_spec=ok (K.Contract_spec.of_string source) in
    List.iter (fun (stage,forge) ->
      let rows=evaluate_suite subresource_suite (fun frozen ~before:_ ~after:_->
        forge (fun (report:Report.t) -> {report with frozen_spec=Some (K.Contract_spec.frozen_spec forged_spec)})
          (comparison frozen "valid")) in
      check ("v7 evaluator rejects "^stage^" "^label)
        ((first_attempt rows).failure=Some Report_mismatch && exit_code rows=1))
      ["both stages",map_reports;
       "candidate stage",(fun transform (r:K.Verify.comparison) ->
         {r with candidate_report=Option.map transform r.candidate_report});
       "final stage",(fun transform (r:K.Verify.comparison) -> {r with report=transform r.report})])
    ["schema downgrade",collection_contract;
     "same-schema subresource substitution",subresource_contract ~required_subresource:"status" ();
     "same-schema approved-scope substitution",subresource_contract ~changes:false ()];
  List.iter (fun mode ->
    let rows=evaluate_suite subresource_suite (fun frozen ~before:_ ~after:_->comparison frozen mode) in
    check ("v7 evaluator retains uncertainty "^mode)
      ((first_attempt rows).failure=None && (first_attempt rows).repair_result=Some "unknown"
       && exit_code rows=3 && (List.hd rows).profile=Some subresource_profile))
    ["unsupported";"candidate-unknown";"preservation-unknown"];
  let rows=evaluate_suite subresource_suite (fun frozen ~before:_ ~after:_->
    map_reports (with_profile K.Assurance.collection_write_profile_id) (comparison frozen "unsupported")) in
  check "unsupported subresource results cannot downgrade profile"
    ((first_attempt rows).failure=Some Report_mismatch && exit_code rows=1);
  let rows=evaluate_suite collection_suite (fun frozen ~before:_ ~after:_->
    map_reports (with_profile subresource_profile) (comparison frozen "valid")) in
  check "schema6 evaluator cannot silently acquire the subresource profile"
    ((first_attempt rows).failure=Some Report_mismatch && exit_code rows=1);
  let source=ref subresource_source and read_count=ref 0 in
  let suite=freeze ~read_suite:(fun path -> incr read_count;
      Ok (if path="contract.json" then !source else "original baseline"))
    ~suite_root:"unused" [task ()] in
  source:=subresource_contract ~required_subresource:"status" ~changes:false ();
  let rows=evaluate_suite suite (fun frozen ~before ~after:_ ->
    check "mutated source cannot replace frozen subresource requirement or change scope"
      (before="original baseline" && K.Contract_spec.canonical frozen=K.Contract_spec.canonical subresource_spec);
    comparison frozen "valid") in
  check "schema7 sources read only at freeze and exact result retained" (!read_count=2 && exit_code rows=0);
  List.iter (fun extra ->
    let bytes={|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"candidate.json",|}^extra^"}]}" in
    check "external submissions cannot select subresource or frozen schema"
      (Result.is_error (parse_submissions subresource_suite bytes)))
    ["\"subresource\":\"\"";"\"schema_version\":6";"\"change_scope\":[]"];
  let apply_contract ?(required_operation="apply-missing") ?(changes=true) () = Printf.sprintf {|{
    "schema_version":8,"kind":"kubernetes-rbac-access",
    "context":{"schema_version":1,"snapshot_complete":true,
      "identities":[{"username":%S,"groups":["operators"]}]},
    "clauses":[
      {"name":"required","kind":"must_allow","subject":%S,"operation":%S,
       "api_group":"apps","resource":"deployments","subresource":"",
       "namespace":"frontend","names":["web"]},
      {"name":"forbidden","kind":"must_not_grant","subject":%S,"operation":"apply-missing",
       "api_group":"","resource":"pods","subresource":"",
       "namespace":"frontend","names":["worker"]}],
    "change_scope":%s}|} secret secret required_operation secret
    (if changes then Printf.sprintf {|[{"subject":%S,"operation":"apply-missing","api_group":"",
      "resource":"pods","subresource":"","namespace":"frontend","names":["worker"]}]|} secret
     else "[]") in
  let apply_profile="kubernetes-rbac-v1.34-apply-v1" in
  let apply_source=apply_contract () in
  let apply_spec=ok (K.Contract_spec.of_string apply_source) in
  let apply_suite=freeze_contract apply_source in
  let rows=evaluate_suite apply_suite (fun frozen ~before:_ ~after:_->
    check "apply operations frozen before evaluator dispatch" (K.Contract_spec.version frozen=8);
    check "required apply branch survives dispatch"
      (K.Contract_spec.canonical frozen=K.Contract_spec.canonical apply_spec);
    comparison frozen "valid") in
  let json=K.Input.parse (to_json rows) in
  check "v8 submitted evaluation retains format2 and exact apply profile"
    (exit_code rows=0 && field "experimental_format_version" json=`Number "2"
     && field "profile" json=`String apply_profile
     && (List.hd rows).frozen_contract_sha256=Some (Sha256.string (K.Contract_spec.canonical apply_spec)));
  List.iter (fun prior_profile ->
    List.iter (fun (label,forge) ->
      let rows=evaluate_suite apply_suite (fun frozen ~before:_ ~after:_->forge (comparison frozen "valid")) in
      check ("v8 evaluator rejects "^label^" downgrade to "^prior_profile)
        ((first_attempt rows).failure=Some Report_mismatch && exit_code rows=1))
      ["both profiles",map_reports (with_profile prior_profile);
       "candidate profile",(fun (r:K.Verify.comparison)->
         {r with candidate_report=Option.map (with_profile prior_profile) r.candidate_report});
       "final profile",(fun (r:K.Verify.comparison)->{r with report=with_profile prior_profile r.report})])
    (List.init 7 (fun i -> K.Assurance.id_for_version (i+1)));
  List.iter (fun (label,source) ->
    let forged_spec=ok (K.Contract_spec.of_string source) in
    List.iter (fun (stage,forge) ->
      let rows=evaluate_suite apply_suite (fun frozen ~before:_ ~after:_->
        forge (fun (report:Report.t) -> {report with frozen_spec=Some (K.Contract_spec.frozen_spec forged_spec)})
          (comparison frozen "valid")) in
      check ("v8 evaluator rejects "^stage^" "^label)
        ((first_attempt rows).failure=Some Report_mismatch && exit_code rows=1))
      ["both stages",map_reports;
       "candidate stage",(fun transform (r:K.Verify.comparison) ->
         {r with candidate_report=Option.map transform r.candidate_report});
       "final stage",(fun transform (r:K.Verify.comparison) -> {r with report=transform r.report})])
    ["schema downgrade",subresource_source;
     "hypothetical state substitution",apply_contract ~required_operation:"apply-existing" ();
     "native patch substitution",apply_contract ~required_operation:"patch" ();
     "approved-scope substitution",apply_contract ~changes:false ()];
  List.iter (fun mode ->
    let rows=evaluate_suite apply_suite (fun frozen ~before:_ ~after:_->comparison frozen mode) in
    check ("v8 evaluator retains uncertainty "^mode)
      ((first_attempt rows).failure=None && (first_attempt rows).repair_result=Some "unknown"
       && exit_code rows=3 && (List.hd rows).profile=Some apply_profile))
    ["unsupported";"candidate-unknown";"preservation-unknown"];
  let rows=evaluate_suite apply_suite (fun frozen ~before:_ ~after:_->
    map_reports (with_profile subresource_profile) (comparison frozen "unsupported")) in
  check "unsupported apply result cannot downgrade its profile"
    ((first_attempt rows).failure=Some Report_mismatch && exit_code rows=1);
  let rows=evaluate_suite subresource_suite (fun frozen ~before:_ ~after:_->
    map_reports (with_profile apply_profile) (comparison frozen "valid")) in
  check "schema7 result cannot silently opt into apply"
    ((first_attempt rows).failure=Some Report_mismatch && exit_code rows=1);
  let source=ref apply_source and read_count=ref 0 in
  let suite=freeze ~read_suite:(fun path -> incr read_count;
      Ok (if path="contract.json" then !source else "original baseline"))
    ~suite_root:"unused" [task ()] in
  source:=apply_contract ~required_operation:"patch" ~changes:false ();
  let rows=evaluate_suite suite (fun frozen ~before ~after:_ ->
    check "candidate cannot replace frozen apply branch or approved changes"
      (before="original baseline" && K.Contract_spec.canonical frozen=K.Contract_spec.canonical apply_spec);
    comparison frozen "valid") in
  check "schema8 sources read only at freeze" (!read_count=2 && exit_code rows=0);
  List.iter (fun extra ->
    let bytes={|{"format_version":1,"attempts":[{"task":"task","id":"a","config":"candidate.json",|}^extra^"}]}" in
    check "external submissions cannot select operation, state or frozen version"
      (Result.is_error (parse_submissions apply_suite bytes)))
    ["\"operation\":\"patch\"";"\"object_state\":\"existing\"";
     "\"schema_version\":7";"\"contract_version\":7";"\"change_scope\":[]"];
  Printf.printf "All %d RBAC submitted-repair unit checks passed.\n" !checks
