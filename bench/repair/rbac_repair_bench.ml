open Soundcheck_core
module K = Soundcheck_kubernetes_rbac

type failure =
  | Contract_read_error | Contract_invalid | Baseline_read_error
  | Candidate_read_error | Evaluation_error | Report_mismatch
  | Missing_submission | Submissions_read_error | Submissions_invalid | Unexpected_error
type attempt_row = {
  id : string; ordinal : int; candidate_sha256 : string option;
  contract_result : string option; repair_result : string option;
  contract_assurance : string option; comparison_assurance : string option;
  failure : failure option; elapsed_seconds : float;
}
type task_row = {
  id : string; provenance : Pilot.provenance;
  profile : string option;
  baseline_sha256 : string option; contract_sha256 : string option;
  frozen_contract_sha256 : string option;
  failure : failure option; attempts : attempt_row list;
}
type frozen_task = {
  task : Pilot.case;
  baseline : (string, failure) result;
  contract : (K.Contract_spec.t, failure) result;
  baseline_digest : string option;
  contract_digest : string option;
  frozen_contract_digest : string option;
}
type frozen_suite = frozen_task list
type submissions = Repair_bench.attempt list

let freeze ?read_suite ~suite_root tasks =
  let read = Option.value ~default:(Pilot.read_regular ~root:suite_root) read_suite in
  (* Cache reads across both roles: even one path used as a contract and baseline
     is read only once. Neither submission parsing nor candidate IO occurs here. *)
  let sources = Hashtbl.create (List.length tasks * 2) in
  let source path = match Hashtbl.find_opt sources path with
    | Some value -> value
    | None ->
      let value = try Result.map_error (fun () -> `Read) (read path)
        with _ -> Error `Unexpected in
      Hashtbl.add sources path value; value in
  let contracts = Hashtbl.create (List.length tasks) in
  let contract path = match Hashtbl.find_opt contracts path with
    | Some value -> value
    | None ->
      let value = match source path with
        | Error `Read -> Error Contract_read_error, None, None
        | Error `Unexpected -> Error Unexpected_error, None, None
        | Ok bytes ->
          let digest = Some (Sha256.string bytes) in
          (try match K.Contract_spec.of_string bytes with
           | Error _ -> Error Contract_invalid, digest, None
           | Ok spec -> Ok spec, digest, Some (Sha256.string (K.Contract_spec.canonical spec))
           with _ -> Error Unexpected_error, digest, None) in
      Hashtbl.add contracts path value; value in
  List.map (fun (task : Pilot.case) ->
    let contract, contract_digest, frozen_contract_digest = contract task.contract in
    let baseline, baseline_digest = match source task.config with
      | Ok bytes -> Ok bytes, Some (Sha256.string bytes)
      | Error `Read -> Error Baseline_read_error, None
      | Error `Unexpected -> Error Unexpected_error, None in
    {task;baseline;contract;baseline_digest;contract_digest;frozen_contract_digest}) tasks

let parse_submissions frozen source =
  Repair_bench.parse_submissions ~tasks:(List.map (fun entry -> entry.task) frozen) source

let result_name = function
  | Report.Proved -> "proved" | Report.Violated _ -> "violated"
  | Report.Vacuous -> "vacuous" | Report.Inconsistent _ -> "inconsistent"
  | Report.Unknown _ -> "unknown"

let preservation_id = "preservation-outside-change-scope"
let preservation_property = "rbac-repair-preservation"

(* Check the identity and stage relationship of a trusted connector result.
   The benchmark does not encode policy semantics or interpret raw witnesses. *)
let project spec (comparison : K.Verify.comparison) =
  let identity = K.Contract_spec.frozen_spec spec in
  let expected_profile = K.Assurance.id_for_version (K.Contract_spec.version spec) in
  let assessment (report : Report.t) =
    match report.assurance with
    | Some value when report.frozen_spec = Some identity
        && value.profile = expected_profile ->
      (match value.status, value.findings, report.result with
       | Report.Within_profile, [], _ -> Some "within_profile"
       | Report.Unsupported, [{Report.code="unsupported-rbac-input";_}], Report.Unknown _ ->
         Some "unsupported"
       | _ -> None)
    | _ -> None in
  let final = comparison.report in
  match assessment final, comparison.candidate_report, comparison.trace with
  | Some "unsupported", None, None
      when final.property_name = K.Contract_spec.kind ->
    Ok (None, "unknown", None, "unsupported")
  | Some "within_profile", Some candidate, Some trace
      when assessment candidate = Some "within_profile"
        && candidate.property_name = K.Contract_spec.kind
        && trace.Evidence.preservation.id = preservation_id
        && Result.is_ok (Evidence.comparison_stages final candidate trace) ->
    let repair = match candidate.result, final.result, trace.preservation.execution with
      | Report.Proved, Report.Proved, Contract_verify.Executed Solve.Proved
          when final.property_name = preservation_property && final.clause = None ->
        Some "valid_repair"
      | Report.Proved, Report.Violated _, Contract_verify.Executed (Solve.Violated _)
          when final.property_name = preservation_property
            && (match final.clause with Some clause ->
                clause.name = preservation_id && clause.kind = Report.Must_preserve
              | None -> false) -> Some "out_of_scope_regression"
      | Report.Proved, Report.Unknown reason, Contract_verify.Executed (Solve.Unknown observed)
          when reason = observed && final.property_name = preservation_property && final.clause = None ->
        Some "unknown"
      | (Report.Violated _ | Report.Vacuous | Report.Inconsistent _), _, Contract_verify.Not_executed
          when final = candidate -> Some "contract_failed"
      | Report.Unknown _, _, Contract_verify.Not_executed
          when final = candidate -> Some "unknown"
      | _ -> None in
    (match repair with
     | Some repair -> Ok (Some (result_name candidate.result), repair,
         Some "within_profile", "within_profile")
     | None -> Error Report_mismatch)
  | _ -> Error Report_mismatch

let task_row entry failure attempts =
  {id=entry.task.id;provenance=entry.task.provenance;
   profile=(match entry.contract with Error _ -> None | Ok spec ->
     Some (K.Assurance.id_for_version (K.Contract_spec.version spec)));
   baseline_sha256=entry.baseline_digest;contract_sha256=entry.contract_digest;
   frozen_contract_sha256=entry.frozen_contract_digest;failure;attempts}

let run ?read_candidate ?(evaluate = fun spec ~before ~after -> K.Verify.compare_with_trace spec ~before ~after)
    ?(now = Unix.gettimeofday) ~submission_root frozen attempts =
  let read = Option.value ~default:(Pilot.read_regular ~root:submission_root) read_candidate in
  List.map (fun entry ->
    let selected = List.filter (fun (attempt : Repair_bench.attempt) ->
      attempt.task = entry.task.id) attempts in
    let failure = match entry.contract, entry.baseline with
      | Error error, _ | _, Error error -> Some error
      | _ when selected = [] -> Some Missing_submission
      | _ -> None in
    let rows = List.mapi (fun index (attempt : Repair_bench.attempt) ->
      let started = now () in
      let empty = {id=attempt.id;ordinal=index+1;candidate_sha256=None;
        contract_result=None;repair_result=None;contract_assurance=None;
        comparison_assurance=None;failure;elapsed_seconds=0.} in
      let row = match entry.contract, entry.baseline with
        | Ok spec, Ok before ->
          (try match read attempt.config with
           | Error () -> {empty with failure=Some Candidate_read_error}
           | Ok after ->
             let row = {empty with candidate_sha256=Some (Sha256.string after)} in
             (try match project spec (evaluate spec ~before ~after) with
              | Error error -> {row with failure=Some error}
              | Ok (contract_result, repair_result, contract_assurance, comparison_assurance) ->
                {row with contract_result;repair_result=Some repair_result;
                  contract_assurance;comparison_assurance=Some comparison_assurance}
              with _ -> {row with failure=Some Evaluation_error})
           with _ -> {empty with failure=Some Unexpected_error})
        | _ -> empty in
      let duration = now () -. started in
      {row with elapsed_seconds=if Float.is_finite duration then max 0. duration else 0.}) selected in
    task_row entry failure rows) frozen

let failed_tasks failure frozen = List.map (fun entry -> task_row entry (Some failure) []) frozen
let accepted (row : attempt_row) = row.failure = None && row.repair_result = Some "valid_repair"
let first_valid (task : task_row) = List.find_opt accepted task.attempts
let exit_code tasks =
  if tasks = [] || List.exists (fun (task : task_row) -> task.failure <> None
      || task.attempts = []
      || List.exists (fun (attempt : attempt_row) -> attempt.failure <> None
        || attempt.repair_result = None) task.attempts) tasks then 1
  else if List.for_all (fun task -> Option.is_some (first_valid task)) tasks then 0 else 3

let failure_name = function
  | Contract_read_error -> "contract_read_error" | Contract_invalid -> "contract_invalid"
  | Baseline_read_error -> "baseline_read_error" | Candidate_read_error -> "candidate_read_error"
  | Evaluation_error -> "evaluation_error" | Report_mismatch -> "report_mismatch"
  | Missing_submission -> "missing_submission" | Submissions_read_error -> "submissions_read_error"
  | Submissions_invalid -> "submissions_invalid" | Unexpected_error -> "unexpected_error"
let provenance_name = function
  | Pilot.Synthetic -> "synthetic" | Pilot.Upstream_example -> "upstream-example"
  | Pilot.Authorized_deployment -> "authorized-deployment"

(* Allowlisted summary fields only. Diagnostics and raw reports never cross
   this boundary, including errors from reading/parsing/solving. *)
let string value = `String value
let optional = function Some value -> string value | None -> `Null
let integer value = `Number (string_of_int value)
let attempt_json (row : attempt_row) = `O [
  "id",string row.id; "ordinal",integer row.ordinal;
  "candidate_sha256",optional row.candidate_sha256;
  "contract_result",optional row.contract_result;
  "repair_result",optional row.repair_result;
  "contract_assurance",optional row.contract_assurance;
  "comparison_assurance",optional row.comparison_assurance;
  "failure",optional (Option.map failure_name row.failure);
  "elapsed_seconds",`Number (Printf.sprintf "%.6f" row.elapsed_seconds)]
let task_json ~include_profile (row : task_row) = `O ([
  "id",string row.id; "provenance",string (provenance_name row.provenance);
  "baseline_sha256",optional row.baseline_sha256;
  "contract_sha256",optional row.contract_sha256;
  "frozen_contract_sha256",optional row.frozen_contract_sha256;
  "failure",optional (Option.map failure_name row.failure);
  "first_valid_attempt",(match first_valid row with None -> `Null | Some attempt -> integer attempt.ordinal);
  "attempts",`A (List.map attempt_json row.attempts)]
  @ if include_profile then ["profile",optional row.profile] else [])
let header version profile = ["experimental_format_version",integer version;
  "kind",string "submitted_rbac_repair_evaluation";
  "profile",optional profile;
  "comparison",string "frozen_scope_preservation"]
let to_json tasks =
  let profiles = List.filter_map (fun (task : task_row) -> task.profile) tasks
    |> List.sort_uniq String.compare in
  let version = if List.exists ((<>) K.Assurance.profile_id) profiles then 2 else 1 in
  let profile = if version = 1 then Some K.Assurance.profile_id
    else match profiles with [profile] -> Some profile | _ -> None in
  let attempts = List.concat_map (fun (task : task_row) -> task.attempts) tasks in
  let submissions_known = not (List.exists (fun (task : task_row) ->
    task.failure = Some Submissions_invalid || task.failure = Some Submissions_read_error) tasks) in
  let count predicate values = List.fold_left (fun n value -> if predicate value then n+1 else n) 0 values in
  let counts = List.map (fun result -> result,
    integer (count (fun (row : attempt_row) -> row.repair_result = Some result) attempts))
      ["valid_repair";"contract_failed";"out_of_scope_regression";"unknown"]
    @ ["errors",integer (count (fun (row : attempt_row) -> row.failure <> None
        || row.repair_result = None) attempts)] in
  K.Input.json (`O (header version profile @ [
    "scheduled_tasks",integer (List.length tasks);
    "tasks_with_valid_repair",integer (count (fun task -> Option.is_some (first_valid task)) tasks);
    "tasks_with_errors",integer (count (fun (task : task_row) -> task.failure <> None
      || List.exists (fun (attempt : attempt_row) -> attempt.failure <> None) task.attempts) tasks);
    "submitted_attempts",(if submissions_known then integer (List.length attempts) else `Null);
    "attempt_counts",`O counts;
    "tasks",`A (List.map (task_json ~include_profile:(version = 2)) tasks)]))
let fatal_json failure = K.Input.json (`O (header 1 (Some K.Assurance.profile_id) @
  ["failure",string failure;"scheduled_tasks",`Null;"tasks",`A []]))
