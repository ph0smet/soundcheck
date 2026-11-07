open Soundcheck_core
module K = Soundcheck_kubernetes_rbac

let usage () =
  prerr_endline
    "usage: soundcheck rbac verify SNAPSHOT.json --contract CONTRACT.json [--format human|json] [--evidence-dir NEW_DIRECTORY]\n\
     usage: soundcheck rbac compare BEFORE.json AFTER.json --contract CONTRACT.json [--format human|json]\n\
     Input is a complete desired RBAC snapshot in one strict JSON Kubernetes v1/List.\n\
     The contract freezes identities, groups, access requirements and approved change scope.\n\
     Use soundcheck profile kubernetes-rbac for the exact model and assumptions.";
  exit 2

let options args =
  let rec parse contract format evidence = function
    | [] -> (match contract with Some path -> path,Option.value ~default:"human" format,evidence | None -> usage ())
    | "--contract" :: path :: rest when contract=None && path<>"" && not (String.starts_with ~prefix:"--" path) ->
      parse (Some path) format evidence rest
    | "--format" :: ("human"|"json" as value) :: rest when format=None -> parse contract (Some value) evidence rest
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

let write_evidence directory ~config ~report ~trace =
  match directory with
  | None -> ()
  | Some directory ->
    let ( let* ) = Result.bind in
    let result =
      let* provenance = Evidence.collect_provenance () in
      let profile : Evidence.profile =
        {id=K.Assurance.profile_id;json=K.Assurance.profile_json ()} in
      let* bundle = Evidence.create ~config ~profile ~provenance ~report ~trace in
      Evidence.write ~directory bundle in
    match result with
    | Ok () -> ()
    | Error reason -> prerr_endline ("evidence error: " ^ reason);exit 1

let run args =
  let operation,options_args = match args with
    | "verify" :: file :: rest -> (`Verify file),rest
    | "compare" :: before :: after :: rest -> (`Compare (before,after)),rest
    | _ -> usage () in
  let contract_path,format,evidence_dir = options options_args in
  (match operation,evidence_dir with
   | `Compare _,Some _ -> usage ()
   | _ -> ());
  let report = try
    match K.Contract_spec.of_string (read contract_path) with
    | Error reason -> K.Verify.invalid_contract reason
    | Ok spec -> (match operation with
        | `Verify file ->
          let config = read file in
          let report,trace = K.Verify.run_with_trace spec config in
          write_evidence evidence_dir ~config ~report ~trace;
          report
        | `Compare (before,after) -> K.Verify.compare spec ~before:(read before) ~after:(read after))
    with Sys_error reason ->
      prerr_endline reason;exit 1 in
  print_endline (if format="json" then Report.to_json report else Report.to_human report);
  exit (exit_code report.result)
