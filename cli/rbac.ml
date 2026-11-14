open Soundcheck_core
module K = Soundcheck_kubernetes_rbac

let usage () =
  prerr_endline
    "usage: soundcheck rbac prepare EXPORT.json [--receipt NEW_FILE]\n\
     usage: soundcheck rbac prepare MANIFEST --input-format json|yaml [--namespace NAME] [--rbac-only] [--receipt NEW_FILE]\n\
     usage: soundcheck rbac inventory PLAN.json [--receipt NEW_FILE]\n\
     usage: soundcheck rbac bootstrap --kubernetes-version 1.34.0 --pack NAME [--pack NAME...] [--receipt NEW_FILE]\n\
     usage: soundcheck rbac inspect SNAPSHOT.json --contract CONTRACT.json\n\
     usage: soundcheck rbac coverage SNAPSHOT.json --contract CONTRACT.json\n\
     usage: soundcheck rbac catalogue CRDS --input-format json|yaml [--crd-only] [--receipt NEW_FILE]\n\
     usage: soundcheck rbac check-contract CONTRACT.json\n\
     usage: soundcheck rbac verify SNAPSHOT.json --contract CONTRACT.json [--format human|json|github] [--evidence-dir NEW_DIRECTORY]\n\
     usage: soundcheck rbac compare BEFORE.json AFTER.json --contract CONTRACT.json [--format human|json|github] [--evidence-dir NEW_DIRECTORY]\n\
     Verification/comparison input is a complete desired RBAC snapshot in one strict JSON Kubernetes v1/List.\n\
     The contract freezes identities, groups, access requirements and approved change scope.\n\
     Preparation emits a supported snapshot, not a verification result or completeness proof.\n\
     Bootstrap packs: auth-delegator, cluster-admin, extension-apiserver-authentication-reader, view.\n\
     check-contract reviews structure and declared intent only; exit 0 is not a verification gate.\n\
     Use soundcheck profile kubernetes-rbac --contract-version 1|2|3|4|5|6|7|8|9|10 for the exact model and assumptions.";
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

let write_receipt path receipt =
  let descriptor = Unix.openfile path [Unix.O_WRONLY;Unix.O_CREAT;Unix.O_EXCL] 0o600 in
  let channel = Unix.out_channel_of_descr descriptor in
  Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () ->
    output_string channel receipt;
    output_char channel '\n';
    close_out channel)

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
  let argument value = value <> "" && not (String.starts_with ~prefix:"-" value) in
  let path,rest = match args with path::rest when argument path -> path,rest | _ -> usage () in
  let rec options format namespace rbac_only receipt = function
    | [] ->
      if format=None && (namespace<>None || rbac_only) then usage ();
      format,namespace,rbac_only,receipt
    | "--input-format" :: ("json"|"yaml" as value) :: rest when format=None ->
      options (Some (if value="json" then K.Manifest_input.Json else Yaml)) namespace rbac_only receipt rest
    | "--namespace" :: value :: rest when namespace=None && argument value ->
      options format (Some value) rbac_only receipt rest
    | "--rbac-only" :: rest when not rbac_only -> options format namespace true receipt rest
    | "--receipt" :: value :: rest when receipt=None && argument value ->
      options format namespace rbac_only (Some value) rest
    | _ -> usage () in
  let format,namespace,rbac_only,receipt_path = options None None false None rest in
  try
    let source = read path in
    let result = match format with
      | None -> Result.map (fun value -> value,K.Prepare.receipt_json value,0)
          (K.Prepare.of_string source)
      | Some format -> Result.map (fun value -> K.Prepare.manifest_snapshot value,
          K.Prepare.manifest_receipt_json value,K.Prepare.manifest_excluded_count value)
          (K.Prepare.of_manifest ~format ?namespace ~rbac_only source) in
    match result with
    | Error reason -> Printf.eprintf "preparation error: %s\n" reason;exit 2
    | Ok (prepared,receipt,excluded) ->
      Option.iter (fun path -> write_receipt path receipt) receipt_path;
      output_string stdout prepared.snapshot;
      flush stdout;
      Printf.eprintf "Prepared %d RBAC objects; removed %d metadata fields. No verification or completeness claim.\n"
        prepared.object_count (List.length prepared.removed_fields);
      if rbac_only then Printf.eprintf "Explicit RBAC-only selection excluded %d non-RBAC objects.\n" excluded
  with
  | Sys_error reason -> Printf.eprintf "preparation I/O error: %s\n" reason;exit 1
  | Unix.Unix_error (error,operation,path) ->
    Printf.eprintf "preparation I/O error: %s: %s (%s)\n" operation (Unix.error_message error) path;
    exit 1

let run_offline_workflow operation args =
  let argument value = value<>"" && not (String.starts_with ~prefix:"-" value) in
  let regular path =
    if (Unix.lstat path).Unix.st_kind <> Unix.S_REG then raise (Sys_error (path ^ ": expected regular file"));
    read path in
  try
    let result = match operation,args with
      | "inventory",path::rest when argument path ->
        let receipt = match rest with
          | [] -> None
          | ["--receipt";path] when argument path -> Some path
          | _ -> usage () in
        let plan = regular path in
        let directory = Filename.dirname path in
        let load source_path = regular (if Filename.is_relative source_path then Filename.concat directory source_path else source_path) in
        (match K.Inventory.assemble ~load plan with
         | Error reason -> Error reason
         | Ok inventory ->
           Option.iter (fun path -> write_receipt path inventory.receipt) receipt;
           output_string stdout inventory.snapshot;
           flush stdout;
           Printf.eprintf "Assembled %d RBAC objects from explicitly pinned sources. No verification or completeness claim.\n" inventory.object_count;
           Ok ())
      | ("inspect"|"coverage"),[snapshot;"--contract";contract] when argument snapshot && argument contract ->
        let run = if operation="inspect" then K.Inspect.run else K.Coverage.run in
        (match run ~snapshot:(regular snapshot) ~contract:(regular contract) with
         | Error reason -> Error reason
         | Ok report -> print_endline report;Ok ())
      | _ -> usage () in
    (match result with Ok () -> () | Error reason -> Printf.eprintf "%s error: %s\n" operation reason;exit 2)
  with
  | Sys_error reason -> Printf.eprintf "%s I/O error: %s\n" operation reason;exit 1
  | Unix.Unix_error (error,action,path) ->
    Printf.eprintf "%s I/O error: %s: %s (%s)\n" operation action (Unix.error_message error) path;exit 1

let run_check_contract = function
  | [path] when path<>"" && not (String.starts_with ~prefix:"-" path) ->
    (try
       if (Unix.lstat path).Unix.st_kind <> Unix.S_REG then raise (Sys_error (path ^ ": expected regular file"));
       match K.Contract_review.run (read path) with
       | Ok review -> print_string review
       | Error reason -> Printf.eprintf "contract check error: %S\n" reason;exit 2
     with
     | Sys_error reason -> Printf.eprintf "contract check I/O error: %S\n" reason;exit 1
     | Unix.Unix_error (error,action,path) ->
       Printf.eprintf "contract check I/O error: %s: %S (%s)\n" action path (Unix.error_message error);exit 1)
  | _ -> usage ()

let run_catalogue args =
  let argument value = value<>"" && not (String.starts_with ~prefix:"-" value) in
  let path,rest = match args with path::rest when argument path -> path,rest | _ -> usage () in
  let rec options format crd_only receipt = function
    | [] -> (match format with Some format -> format,crd_only,receipt | None -> usage ())
    | "--input-format"::("json"|"yaml" as value)::rest when format=None ->
      options (Some (if value="json" then K.Manifest_input.Json else Yaml)) crd_only receipt rest
    | "--crd-only"::rest when not crd_only -> options format true receipt rest
    | "--receipt"::path::rest when receipt=None && argument path -> options format crd_only (Some path) rest
    | _ -> usage () in
  let format,crd_only,receipt_path = options None false None rest in
  try match K.Catalogue_prepare.run ~crd_only ~format (read path) with
    | Error reason -> Printf.eprintf "catalogue preparation error: %s\n" reason;exit 2
    | Ok prepared ->
      Option.iter (fun path -> write_receipt path prepared.receipt) receipt_path;
      output_string stdout prepared.catalogue;
      flush stdout;
      Printf.eprintf "Prepared metadata from %d CRDs; explicitly excluded %d objects. Review before freezing; no verification or completeness claim.\n"
        prepared.object_count prepared.excluded_count
  with
  | Sys_error reason -> Printf.eprintf "catalogue I/O error: %s\n" reason;exit 1
  | Unix.Unix_error (error,action,path) ->
    Printf.eprintf "catalogue I/O error: %s: %s (%s)\n" action (Unix.error_message error) path;exit 1

let run_bootstrap args =
  let argument value = value<>"" && not (String.starts_with ~prefix:"-" value) in
  let rec options version packs receipt = function
    | [] -> (match version with Some version -> version,List.rev packs,receipt | None -> usage ())
    | "--kubernetes-version" :: value :: rest when version=None && argument value ->
      options (Some value) packs receipt rest
    | "--pack" :: value :: rest when argument value -> options version (value::packs) receipt rest
    | "--receipt" :: path :: rest when receipt=None && argument path -> options version packs (Some path) rest
    | _ -> usage () in
  let kubernetes_version,packs,receipt = options None [] None args in
  try match K.Bootstrap.prepare ~kubernetes_version ~packs with
    | Error reason -> Printf.eprintf "bootstrap selection error: %s\n" reason;exit 2
    | Ok prepared ->
      Option.iter (fun path -> write_receipt path prepared.receipt) receipt;
      output_string stdout prepared.snapshot;flush stdout;
      Printf.eprintf "Selected %d upstream bootstrap RBAC objects. Installed state and completeness were not established.\n"
        prepared.object_count
  with
  | Sys_error reason -> Printf.eprintf "bootstrap I/O error: %s\n" reason;exit 1
  | Unix.Unix_error (error,action,path) ->
    Printf.eprintf "bootstrap I/O error: %s: %s (%s)\n" action (Unix.error_message error) path;exit 1

let run = function
  | "bootstrap" :: args -> run_bootstrap args
  | "catalogue" :: args -> run_catalogue args
  | "prepare" :: args -> run_prepare args
  | "check-contract" :: args -> run_check_contract args
  | ("inventory" | "inspect" | "coverage" as operation) :: args -> run_offline_workflow operation args
  | args -> run_verification args
