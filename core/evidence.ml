type provenance = {
  executable_sha256 : string;
  ocaml_version     : string;
  z3_version        : (string, string) result;
}

type profile = {
  id   : string;
  json : string;
}

type t = (string * string) list

let schema_version = 1

let collect_provenance () =
  let executable =
    if Sys.file_exists Sys.executable_name then Some Sys.executable_name
    else
      Sys.getenv_opt "PATH" |> Option.value ~default:""
      |> String.split_on_char ':'
      |> List.map (fun directory -> Filename.concat directory Sys.executable_name)
      |> List.find_opt Sys.file_exists
  in
  match executable with
  | None -> Error ("cannot locate verifier executable " ^ Sys.executable_name)
  | Some path ->
    match Sha256.file path with
    | Error reason -> Error reason
    | Ok executable_sha256 ->
      Ok { executable_sha256;
           ocaml_version = Sys.ocaml_version;
           z3_version = Solve.version () }

let json_string value =
  let buffer = Buffer.create (String.length value + 2) in
  Buffer.add_char buffer '"';
  String.iter
    (function
      | '"' -> Buffer.add_string buffer "\\\""
      | '\\' -> Buffer.add_string buffer "\\\\"
      | '\n' -> Buffer.add_string buffer "\\n"
      | '\r' -> Buffer.add_string buffer "\\r"
      | '\t' -> Buffer.add_string buffer "\\t"
      | character when Char.code character < 0x20 ->
        Buffer.add_string buffer (Printf.sprintf "\\u%04x" (Char.code character))
      | character -> Buffer.add_char buffer character)
    value;
  Buffer.add_char buffer '"';
  Buffer.contents buffer

let json_option = function None -> "null" | Some value -> json_string value

let artifact_json (path, contents) =
  Printf.sprintf "{\"path\":%s,\"sha256\":%s}"
    (json_string path) (json_string (Sha256.string contents))

let model_json (model : Solve.model) =
  let headers =
    model.headers |> List.sort_uniq compare
    |> List.map (fun (name, value) ->
           Printf.sprintf "{\"name\":%s,\"value\":%s}"
             (json_string name) (json_string value))
    |> String.concat ","
  in
  Printf.sprintf
    "{\"principal\":%s,\"method\":%s,\"path\":%s,\"source_ip\":%s,\"host\":%s,\"scheme\":%s,\"sni\":%s,\"headers\":[%s]}"
    (json_string (if model.is_anon then "anonymous" else "authenticated"))
    (json_string model.method_) (json_string model.path)
    (json_string (Cidr.string_of_ip model.src_ip)) (json_string model.host)
    (json_string model.scheme) (json_string model.sni) headers

let phase_name = function
  | Contract_verify.Inhabitance -> "inhabitance"
  | Contract_verify.Consistency -> "consistency"
  | Contract_verify.Clause -> "clause"

let query_file (entry : Contract_verify.trace_entry) =
  ("queries/" ^ entry.obligation.id ^ ".smt2", entry.obligation.smtlib)

let obligation_json (entry : Contract_verify.trace_entry) =
  let execution, result, model, reason =
    match entry.execution with
    | Contract_verify.Not_executed -> ("not_executed", None, "null", None)
    | Contract_verify.Executed Solve.Proved ->
      ("executed", Some "unsat", "null", None)
    | Contract_verify.Executed (Solve.Violated model) ->
      ("executed", Some "sat", model_json model, None)
    | Contract_verify.Executed (Solve.Unknown reason) ->
      ("executed", Some "unknown", "null", Some reason)
  in
  let clauses =
    entry.obligation.clauses |> List.map json_string |> String.concat ","
  in
  Printf.sprintf
    "{\"id\":%s,\"phase\":%s,\"clauses\":[%s],\"query\":%s,\"execution\":%s,\"solver_result\":%s,\"model\":%s,\"reason\":%s}"
    (json_string entry.obligation.id) (json_string (phase_name entry.obligation.phase))
    clauses (artifact_json (query_file entry)) (json_string execution)
    (json_option result) model (json_option reason)

let outcome_name = function
  | Report.Proved -> "proved"
  | Report.Vacuous -> "vacuous"
  | Report.Inconsistent _ -> "inconsistent"
  | Report.Violated _ -> "violated"
  | Report.Unknown _ -> "unknown"

let safe_id id =
  id <> ""
  && String.for_all
       (function 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '-' | '_' -> true
        | _ -> false)
       id

let create ~config ~(profile : profile) ~(provenance : provenance)
    ~(report : Report.t) ~trace =
  let plan =
    match trace, report.result, report.assurance with
    | Some entries, _, _ -> Ok ("complete", None, entries)
    | None, Report.Unknown reason,
      Some { status = Report.Unsupported; _ } ->
      Ok ("unavailable", Some reason, [])
    | None, _, _ -> Error "evidence requires a complete contract obligation trace"
  in
  match report.frozen_spec, report.assurance, plan with
  | None, _, _ -> Error "evidence requires a frozen contract"
  | _, None, _ -> Error "evidence requires an assurance profile"
  | _, Some assurance, _ when assurance.profile <> profile.id ->
    Error "evidence profile does not match the verification report"
  | _, _, Error reason -> Error reason
  | Some frozen, Some _, Ok (plan_status, plan_reason, entries) ->
    let ids =
      List.map (fun (entry : Contract_verify.trace_entry) -> entry.obligation.id)
        entries
    in
    if not (List.for_all safe_id ids) then
      Error "evidence obligation identities must be filesystem-safe"
    else if List.length (List.sort_uniq compare ids) <> List.length ids then
      Error "evidence obligation identities must be unique"
    else
      let contract = ("contract.json", frozen.canonical ^ "\n") in
      let profile_file = ("assurance-profile.json", profile.json ^ "\n") in
      let report_file = ("report.json", Report.to_json report ^ "\n") in
      let z3_version, version_error =
        match provenance.z3_version with
        | Ok version -> (Some version, None)
        | Error reason -> (None, Some reason)
      in
      let obligations = entries |> List.map obligation_json |> String.concat "," in
      let manifest =
        Printf.sprintf
          "{\"schema_version\":%d,\"config\":{\"sha256\":%s,\"size_bytes\":%d},\"contract\":%s,\"assurance_profile\":{\"id\":%s,\"artifact\":%s},\"soundcheck\":{\"executable_sha256\":%s,\"ocaml_version\":%s,\"report_schema_version\":%d},\"solver\":{\"name\":\"z3\",\"version\":%s,\"version_error\":%s},\"obligation_plan\":{\"status\":%s,\"reason\":%s},\"obligations\":[%s],\"report\":%s,\"result\":%s}\n"
          schema_version (json_string (Sha256.string config)) (String.length config)
          (artifact_json contract) (json_string profile.id) (artifact_json profile_file)
          (json_string provenance.executable_sha256) (json_string provenance.ocaml_version)
          Report.schema_version (json_option z3_version) (json_option version_error)
          (json_string plan_status) (json_option plan_reason) obligations
          (artifact_json report_file) (json_string (outcome_name report.result))
      in
      Ok
        ([ contract; profile_file; report_file ] @ List.map query_file entries
         @ [ ("manifest.json", manifest) ])

let files bundle = bundle

let write ~directory bundle =
  try
    Unix.mkdir directory 0o700;
    Unix.mkdir (Filename.concat directory "queries") 0o700;
    List.iter
      (fun (relative, contents) ->
        let target = Filename.concat directory relative in
        let manifest = relative = "manifest.json" in
        let path = if manifest then target ^ ".tmp" else target in
        let channel =
          open_out_gen [ Open_wronly; Open_creat; Open_excl; Open_binary ] 0o600 path
        in
        Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () ->
            output_string channel contents;
            close_out channel);
        if manifest then begin
          (* Publish only a fully written manifest, without replacing a path
             even if it appeared after we created the private directory. *)
          Unix.link path target;
          Unix.unlink path
        end)
      bundle;
    Ok ()
  with
  | Sys_error reason -> Error reason
  | Unix.Unix_error (Unix.EEXIST, _, _) ->
    Error (Printf.sprintf "evidence destination already exists: %s" directory)
  | Unix.Unix_error (error, operation, argument) ->
    Error
      (Printf.sprintf "%s(%s): %s" operation argument (Unix.error_message error))
