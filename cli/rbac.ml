open Soundcheck_core
module K = Soundcheck_kubernetes_rbac

let usage () =
  prerr_endline
    "usage: soundcheck rbac prepare EXPORT.json [--receipt NEW_FILE]\n\
     usage: soundcheck rbac verify SNAPSHOT.json --contract CONTRACT.json [--format human|json|github] [--evidence-dir NEW_DIRECTORY]\n\
     usage: soundcheck rbac compare BEFORE.json AFTER.json --contract CONTRACT.json [--format human|json|github] [--evidence-dir NEW_DIRECTORY]\n\
     Input is a complete desired RBAC snapshot in one strict JSON Kubernetes v1/List.\n\
     The contract freezes identities, groups, access requirements and approved change scope.\n\
     Preparation emits a supported snapshot, not a verification result or completeness proof.\n\
     Use soundcheck profile kubernetes-rbac --contract-version 1|2|3|4 for the exact model and assumptions.";
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

let write_evidence ~on_error ~version directory make_bundle =
  match directory with
  | None -> ()
  | Some directory ->
    let ( let* ) = Result.bind in
    let result =
      let* provenance = Evidence.collect_provenance () in
      let profile : Evidence.profile =
        {id=K.Assurance.id_for_version version;json=K.Assurance.profile_json ~version ()} in
      let* bundle = make_bundle ~profile ~provenance in
      Evidence.write ~directory bundle in
    match result with
    | Ok () -> ()
    | Error reason -> on_error reason;exit 1

let run_verification args =
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
    | Ok spec ->
      let write_evidence = write_evidence ~version:(K.Contract_spec.version spec) in
      (match operation with
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

let run_prepare args =
  let path,receipt_path = match args with
    | [path] when path <> "" && not (String.starts_with ~prefix:"-" path) -> path,None
    | [path;"--receipt";receipt] when path <> "" && receipt <> ""
        && not (String.starts_with ~prefix:"-" path)
        && not (String.starts_with ~prefix:"-" receipt) -> path,Some receipt
    | _ -> usage () in
  try
    match K.Prepare.of_string (read path) with
    | Error reason -> Printf.eprintf "preparation error: %s\n" reason;exit 2
    | Ok prepared ->
      Option.iter (fun path ->
        let descriptor = Unix.openfile path [Unix.O_WRONLY;Unix.O_CREAT;Unix.O_EXCL] 0o600 in
        let channel = Unix.out_channel_of_descr descriptor in
        Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () ->
          output_string channel (K.Prepare.receipt_json prepared);
          output_char channel '\n';
          close_out channel)) receipt_path;
      output_string stdout prepared.snapshot;
      flush stdout;
      Printf.eprintf "Prepared %d RBAC objects; removed %d metadata fields. No verification or completeness claim.\n"
        prepared.object_count (List.length prepared.removed_fields)
  with
  | Sys_error reason -> Printf.eprintf "preparation I/O error: %s\n" reason;exit 1
  | Unix.Unix_error (error,operation,path) ->
    Printf.eprintf "preparation I/O error: %s: %s (%s)\n" operation (Unix.error_message error) path;
    exit 1

let run = function
  | "prepare" :: args -> run_prepare args
  | args -> run_verification args
