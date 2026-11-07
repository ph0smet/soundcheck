open Soundcheck_core
module K = Soundcheck_kubernetes_rbac

let usage () =
  prerr_endline
    "usage: soundcheck rbac verify SNAPSHOT.json --contract CONTRACT.json [--format human|json|github] [--evidence-dir NEW_DIRECTORY]\n\
     usage: soundcheck rbac compare BEFORE.json AFTER.json --contract CONTRACT.json [--format human|json|github] [--evidence-dir NEW_DIRECTORY]\n\
     Input is a complete desired RBAC snapshot in one strict JSON Kubernetes v1/List.\n\
     The contract freezes identities, groups, access requirements and approved change scope.\n\
     Use soundcheck profile kubernetes-rbac for the exact model and assumptions.";
  exit 2

let options args =
  let rec parse contract format evidence = function
    | [] -> (match contract with Some path -> path,Option.value ~default:"human" format,evidence | None -> usage ())
    | "--contract" :: path :: rest when contract=None && path<>"" && not (String.starts_with ~prefix:"--" path) ->
      parse (Some path) format evidence rest
    | "--format" :: ("human"|"json"|"github" as value) :: rest when format=None -> parse contract (Some value) evidence rest
    | "--evidence-dir" :: path :: rest when evidence=None && path<>"" && not (String.starts_with ~prefix:"--" path) ->
      parse contract format (Some path) rest
    | _ -> usage () in
  parse None None None args

let read path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
      let size = in_channel_length channel in
      if size > 16 * 1024 * 1024 then raise (Sys_error (path ^ ": input exceeds 16 MiB"));
      really_input_string channel size)

let exit_code = function
  | Report.Proved -> 0 | Violated _ -> 3 | Unknown _ -> 4 | Vacuous -> 5 | Inconsistent _ -> 6

let write_evidence ~on_error directory make_bundle =
  match directory with
  | None -> ()
  | Some directory ->
    let ( let* ) = Result.bind in
    let result =
      let* provenance = Evidence.collect_provenance () in
      let profile : Evidence.profile =
        {id=K.Assurance.profile_id;json=K.Assurance.profile_json ()} in
      let* bundle = make_bundle ~profile ~provenance in
      Evidence.write ~directory bundle in
    match result with
    | Ok () -> ()
    | Error reason -> on_error reason;exit 1

let run args =
  let operation,options_args = match args with
    | "verify" :: file :: rest -> (`Verify file),rest
    | "compare" :: before :: after :: rest -> (`Compare (before,after)),rest
    | _ -> usage () in
  let contract_path,format,evidence_dir = options options_args in
  let file = match operation with `Verify file -> file | `Compare (_,after) -> after in
  let print_error ~title reason =
    if format="github" then
      print_endline (Soundcheck_ci.Github_annotation.error ~file ~title reason)
    else prerr_endline (if title="evidence error" then title ^ ": " ^ reason else reason) in
  let write_evidence = write_evidence ~on_error:(print_error ~title:"evidence error") in
  let report = try
    match K.Contract_spec.of_string (read contract_path) with
    | Error reason -> K.Verify.invalid_contract reason
    | Ok spec -> (match operation with
        | `Verify file ->
          let config = read file in
          let report,trace = K.Verify.run_with_trace spec config in
          write_evidence evidence_dir (Evidence.create ~config ~report ~trace);
          report
        | `Compare (before_path,after_path) ->
          let before = read before_path in
          let after = read after_path in
          let comparison = K.Verify.compare_with_trace spec ~before ~after in
          write_evidence evidence_dir
            (Evidence.create_comparison ~before ~after ~report:comparison.report
               ~candidate_report:comparison.candidate_report ~trace:comparison.trace);
          comparison.report)
    with Sys_error reason ->
      print_error ~title:"I/O error" reason;exit 1 in
  print_endline (match format with
    | "json" -> Report.to_json report
    | "github" -> Soundcheck_ci.Github_annotation.render ~file report
    | _ -> Report.to_human report);
  exit (exit_code report.result)
