open Soundcheck_core
open Soundcheck_kong

type attempt = { task : string; id : string; config : string }
type failure =
  | Contract_read_error | Contract_invalid | Baseline_read_error
  | Candidate_read_error | Evaluation_error | Report_mismatch
  | Missing_submission | Submissions_read_error | Submissions_invalid | Unexpected_error
type attempt_row = {
  id : string; ordinal : int; candidate_sha256 : string option;
  contract_result : string option; repair_result : string option;
  assurance : string option; finding_codes : string list;
  failure : failure option; elapsed_seconds : float;
}
type task_row = {
  id : string; provenance : Pilot.provenance;
  baseline_sha256 : string option; contract_sha256 : string option;
  failure : failure option; attempts : attempt_row list;
}

let ( let* ) = Result.bind
let invalid () = Error ()
let ascii_id value =
  let alnum = function 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' -> true | _ -> false in
  String.length value > 0 && String.length value <= 64 && alnum value.[0]
  && String.for_all (fun c -> alnum c || c = '-' || c = '_') value

(* Match the pilot manifest's path syntax; actual filesystem checks and reading
   are delegated to Pilot.read_regular rather than a second file reader. *)
let relative_path value =
  value <> "" && Filename.is_relative value
  && String.for_all (fun c -> Char.code c >= 32 && c <> '\127' && c <> '\\') value
  && List.for_all (fun part -> part <> "" && part <> "." && part <> "..")
       (String.split_on_char '/' value)

let fields names = function
  | `O values when List.length values = List.length names
      && List.for_all (fun (key, _) -> List.mem key names) values -> Ok values
  | _ -> invalid ()
let string_field name values =
  match List.assoc_opt name values with Some (`String value) -> Ok value | _ -> invalid ()

let parse_submissions ~tasks source =
  (* Keep metadata's deliberately small language consistent with Pilot. *)
  if String.contains source '\\' || String.contains source '\000' then invalid ()
  else try
    let task_ids = List.map (fun (task : Pilot.case) -> task.id) tasks in
    let* () = if task_ids = []
        || List.length task_ids <> List.length (List.sort_uniq String.compare task_ids)
      then invalid () else Ok () in
    let* value = Result.map_error (fun _ -> ()) (Parse.yaml_value ~where:"submissions" source) in
    let* values = fields [ "format_version"; "attempts" ] value in
    let* () = match List.assoc_opt "format_version" values with
      | Some (`Float 1.) -> Ok () | _ -> invalid () in
    let* attempts = match List.assoc_opt "attempts" values with
      | Some (`A attempts) -> Ok attempts | _ -> invalid () in
    let rec collect seen acc = function
      | [] -> Ok (List.rev acc)
      | value :: tail ->
        let* values = fields [ "task"; "id"; "config" ] value in
        let* task = string_field "task" values in
        let* id = string_field "id" values in
        let* config = string_field "config" values in
        if not (List.mem task task_ids && ascii_id id && relative_path config)
           || List.mem (task, id) seen then invalid ()
        else collect ((task, id) :: seen) ({ task; id; config } :: acc) tail
    in collect [] [] attempts
  with _ -> invalid ()

let failure_name = function
  | Contract_read_error -> "contract_read_error" | Contract_invalid -> "contract_invalid"
  | Baseline_read_error -> "baseline_read_error" | Candidate_read_error -> "candidate_read_error"
  | Evaluation_error -> "evaluation_error" | Report_mismatch -> "report_mismatch"
  | Missing_submission -> "missing_submission" | Submissions_read_error -> "submissions_read_error"
  | Submissions_invalid -> "submissions_invalid" | Unexpected_error -> "unexpected_error"
let provenance_name = function
  | Pilot.Synthetic -> "synthetic" | Pilot.Upstream_example -> "upstream-example"
  | Pilot.Authorized_deployment -> "authorized-deployment"
let result_name = function
  | Report.Proved -> "proved" | Report.Violated _ -> "violated"
  | Report.Vacuous -> "vacuous" | Report.Inconsistent _ -> "inconsistent"
  | Report.Unknown _ -> "unknown"
let repair_name = function
  | Compare.Valid_repair -> "valid_repair" | Compare.Contract_failed -> "contract_failed"
  | Compare.Out_of_scope_regression _ -> "out_of_scope_regression"
  | Compare.Repair_unknown _ -> "unknown"
let assurance_name = function
  | Report.Within_profile -> "within_profile" | Report.Conservative -> "conservative"
  | Report.Unsupported -> "unsupported"

let known_codes =
  let profile = Assurance.profile in
  List.map (fun (feature : Assurance.feature) -> feature.code)
    (profile.modeled @ profile.conservative @ profile.unsupported)

let project_report spec (report : Compare.repair_report) =
  let contract = report.contract_report in
  let expected = Contract_spec.report_identity spec in
  let coherent = match report.result, contract.result with
    | Compare.Valid_repair, Report.Proved
    | Compare.Out_of_scope_regression _, Report.Proved
    | Compare.Contract_failed, (Report.Violated _ | Report.Vacuous | Report.Inconsistent _)
    | Compare.Repair_unknown _, (Report.Unknown _ | Report.Proved) -> true
    | _ -> false in
  match contract.assurance with
  | Some assessment
    when coherent && report.profile = Assurance.profile.id
      && report.mode = Compare.Security_decision
      && Contract_spec.report_identity report.frozen_spec = expected
      && contract.frozen_spec = Some expected
      && contract.property_name = Contract_spec.kind_name spec.Contract_spec.kind
      && assessment.profile = Assurance.profile.id
      && List.for_all (fun (finding : Report.assurance_finding) ->
           List.mem finding.code known_codes) assessment.findings
      && (assessment.status <> Report.Unsupported
          || match contract.result with Report.Unknown _ -> true | _ -> false) ->
    let codes = List.map (fun (finding : Report.assurance_finding) -> finding.code)
        assessment.findings |> List.sort_uniq String.compare in
    Ok (result_name contract.result, repair_name report.result,
        assurance_name assessment.status, codes)
  | _ -> Error Report_mismatch

let run ?read_suite ?read_candidate
    ?(evaluate = fun contract before after -> Compare.run_repair ~contract before after)
    ?(now = Unix.gettimeofday) ~suite_root ~submission_root tasks attempts =
  let read_suite = Option.value ~default:(Pilot.read_regular ~root:suite_root) read_suite in
  let read_candidate = Option.value ~default:(Pilot.read_regular ~root:submission_root) read_candidate in
  (* Snapshot all evaluator inputs first. A candidate cannot choose or reload
     the contract or baseline, even when the original files change later. *)
  let contracts = Hashtbl.create (List.length tasks) in
  let baselines = Hashtbl.create (List.length tasks) in
  List.iter (fun (task : Pilot.case) ->
    if not (Hashtbl.mem contracts task.contract) then begin
      let value = try
        match read_suite task.contract with
        | Error () -> Error Contract_read_error
        | Ok bytes -> (match Contract_spec.parse_string bytes with
          | Error _ -> Error Contract_invalid
          | Ok spec -> Ok (spec, Sha256.string (Contract_spec.canonical_json spec)))
        with _ -> Error Unexpected_error in
      Hashtbl.add contracts task.contract value
    end;
    if not (Hashtbl.mem baselines task.config) then begin
      let value = try
        match read_suite task.config with
        | Error () -> Error Baseline_read_error
        | Ok bytes -> Ok (bytes, Sha256.string bytes)
        with _ -> Error Unexpected_error in
      Hashtbl.add baselines task.config value
    end) tasks;
  List.map (fun (task : Pilot.case) ->
    let selected = List.filter (fun (attempt : attempt) -> attempt.task = task.id) attempts in
    let contract = Hashtbl.find contracts task.contract in
    let baseline = Hashtbl.find baselines task.config in
    let contract_sha256 = match contract with Ok (_, digest) -> Some digest | _ -> None in
    let baseline_sha256 = match baseline with Ok (_, digest) -> Some digest | _ -> None in
    let failure = match contract, baseline with
      | Error failure, _ | _, Error failure -> Some failure
      | _ when selected = [] -> Some Missing_submission
      | _ -> None in
    let attempts = List.mapi (fun index (attempt : attempt) ->
      let started = now () in
      let empty = { id = attempt.id; ordinal = index + 1; candidate_sha256 = None;
        contract_result = None; repair_result = None; assurance = None;
        finding_codes = []; failure; elapsed_seconds = 0. } in
      let row = match contract, baseline with
        | Ok (spec, _), Ok (before, _) ->
          (try match read_candidate attempt.config with
           | Error () -> { empty with failure = Some Candidate_read_error }
           | Ok after ->
             let row = { empty with candidate_sha256 = Some (Sha256.string after) } in
             (try match evaluate spec before after with
              | Error _ -> { row with failure = Some Evaluation_error }
              | Ok report -> (match project_report spec report with
                | Error failure -> { row with failure = Some failure }
                | Ok (contract_result, repair_result, assurance, finding_codes) ->
                  { row with contract_result = Some contract_result;
                    repair_result = Some repair_result; assurance = Some assurance; finding_codes })
              with _ -> { row with failure = Some Unexpected_error })
           with _ -> { empty with failure = Some Unexpected_error })
        | _ -> empty in
      let duration = now () -. started in
      { row with elapsed_seconds = if Float.is_finite duration then max 0. duration else 0. }) selected in
    { id = task.id; provenance = task.provenance; baseline_sha256;
      contract_sha256; failure; attempts }) tasks

let accepted (row : attempt_row) = row.failure = None && row.repair_result = Some "valid_repair"
let first_valid (task : task_row) = List.find_opt accepted task.attempts
let failed_tasks failure tasks =
  List.map (fun (task : Pilot.case) ->
    { id = task.id; provenance = task.provenance; baseline_sha256 = None;
      contract_sha256 = None; failure = Some failure; attempts = [] }) tasks

let exit_code tasks =
  if tasks = [] || List.exists (fun (task : task_row) -> task.failure <> None
      || List.exists (fun (attempt : attempt_row) -> attempt.failure <> None
        || attempt.repair_result = None) task.attempts) tasks then 1
  else if List.for_all (fun task -> Option.is_some (first_valid task)) tasks then 0 else 3

(* Explicit allowlist: raw reports, witnesses, diagnostics, file paths and
   canonical contracts never enter the summary serializer. *)
let quote value =
  let buffer = Buffer.create (String.length value + 2) in
  Buffer.add_char buffer '"';
  String.iter (function
    | '"' -> Buffer.add_string buffer "\\\"" | '\\' -> Buffer.add_string buffer "\\\\"
    | c when Char.code c < 32 -> Buffer.add_string buffer (Printf.sprintf "\\u%04x" (Char.code c))
    | c -> Buffer.add_char buffer c) value;
  Buffer.add_char buffer '"'; Buffer.contents buffer
let optional = function None -> "null" | Some value -> quote value
let array values = "[" ^ String.concat "," values ^ "]"
let object_ values = "{" ^ String.concat ","
    (List.map (fun (key, value) -> quote key ^ ":" ^ value) values) ^ "}"
let attempt_json (row : attempt_row) = object_
  [ "id", quote row.id; "ordinal", string_of_int row.ordinal;
    "candidate_sha256", optional row.candidate_sha256;
    "contract_result", optional row.contract_result; "repair_result", optional row.repair_result;
    "contract_assurance", optional row.assurance;
    "contract_finding_codes", array (List.map quote row.finding_codes);
    "failure", optional (Option.map failure_name row.failure);
    "elapsed_seconds", Printf.sprintf "%.6f" row.elapsed_seconds ]
let task_json (row : task_row) = object_
  [ "id", quote row.id; "provenance", quote (provenance_name row.provenance);
    "baseline_sha256", optional row.baseline_sha256; "contract_sha256", optional row.contract_sha256;
    "failure", optional (Option.map failure_name row.failure);
    "first_valid_attempt", (match first_valid row with None -> "null" | Some attempt -> string_of_int attempt.ordinal);
    "attempts", array (List.map attempt_json row.attempts) ]
let header = [ "experimental_format_version", "1";
  "kind", quote "submitted_repair_evaluation"; "profile", quote Assurance.profile.id;
  "comparison", quote "frozen_scope_preservation" ]
let to_json tasks =
  let attempts = List.concat_map (fun (task : task_row) -> task.attempts) tasks in
  let submissions_known = not (List.exists (fun (task : task_row) ->
    task.failure = Some Submissions_invalid || task.failure = Some Submissions_read_error) tasks) in
  let count predicate values = List.fold_left (fun n value -> if predicate value then n + 1 else n) 0 values in
  let count_result result = count (fun (row : attempt_row) -> row.repair_result = Some result) attempts in
  object_ (header @
    [ "scheduled_tasks", string_of_int (List.length tasks);
      "tasks_with_valid_repair", string_of_int (count (fun task -> Option.is_some (first_valid task)) tasks);
      "tasks_with_errors", string_of_int (count (fun (task : task_row) -> task.failure <> None
        || List.exists (fun (attempt : attempt_row) -> attempt.failure <> None) task.attempts) tasks);
      "submitted_attempts", (if submissions_known then string_of_int (List.length attempts) else "null");
      "attempt_counts", object_ (List.map (fun result -> result, string_of_int (count_result result))
        [ "valid_repair"; "contract_failed"; "out_of_scope_regression"; "unknown" ]
        @ [ "errors", string_of_int (count (fun (row : attempt_row) -> row.failure <> None
               || row.repair_result = None) attempts) ]);
      "tasks", array (List.map task_json tasks) ])
let fatal_json failure = object_ (header @
  [ "failure", quote failure; "scheduled_tasks", "null"; "tasks", "[]" ])
