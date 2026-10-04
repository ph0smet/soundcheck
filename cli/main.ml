(* Soundcheck CLI (v0): verify a Kong declarative config against a security
   property. Exit codes: 0 proved, 1 input/output or verification error, 2 usage,
   3 violated, 4 unknown,
   5 vacuous, 6 inconsistent contract. *)

open Soundcheck_core
open Soundcheck_kong

let usage () =
  prerr_endline
    "usage: soundcheck verify <config.yaml> --contract CONTRACT.yaml\n\
    \                                       [--evidence-dir NEW_DIRECTORY]\n\
    \   or: soundcheck verify <config.yaml> [--property P] [--path-prefix PREFIX]\n\
    \                                       [--method METHOD] [--host HOST]\n\
    \                                       [--format human|json|github] [--emit-smt PATH]\n\
    \  --property     no-anonymous-access (default) | rate-limit-on-public\n\
    \                 | no-shadowed-routes | admin-api-not-reachable\n\
    \                 | authenticated-access | network-restricted-access\n\
    \  --path-prefix  prefix for no-anonymous-access (default /admin)\n\
    \  --trusted-cidr trusted IPv4 block; required for network-restricted-access\n\
    \                 (admin-api-not-reachable default 127.0.0.1/32)\n\
    \  --method       optional exact method for paired contracts (default all)\n\
    \  --host         optional exact host for paired contracts (default all)\n\
    \  --contract     frozen, human-confirmed contract artifact; excludes property/scope flags\n\
    \  --format       human (default) | json\n\
    \  --emit-smt     write a single-property SMT-LIB2 query to PATH (not contracts)\n\
    \  --evidence-dir write a complete audit bundle to a new directory; requires --contract\n\
     \n\
     usage: soundcheck compare <before.yaml> <after.yaml>\n\
    \                           [--contract CONTRACT.yaml]\n\
    \                           [--mode decision|route-service|service-target|upstream-uri]\n\
    \                           [--format human|json] [--emit-smt PATH]\n\
    \  Without --contract, compare every modeled Allow/Deny decision.\n\
    \  With --contract, verify the replacement and preserve decisions outside\n\
    \  the frozen contract scope.\n\
     \n\
     usage: soundcheck profile kong [--format human|json]\n\
    \  Print the versioned Kong assurance profile and exit.\n\
     \n\
     usage: soundcheck mcp [--contract CONTRACT.yaml]\n\
    \  With --contract, the MCP verify tool accepts config only and keeps the\n\
    \  human-confirmed specification immutable for the server lifetime.";
  exit 2

type format = Human | Json
type verify_format = Standard of format | Github

let parse_format rest =
  let rec find = function
    | "--format" :: "human" :: _ -> Human
    | "--format" :: "json" :: _ -> Json
    | "--format" :: other :: _ ->
      Printf.eprintf "unknown --format %S (expected human|json)\n" other;
      exit 2
    | _ :: tl -> find tl
    | [] -> Human
  in
  find rest

let parse_verify_format rest =
  let rec find = function
    | "--format" :: "human" :: _ -> Standard Human
    | "--format" :: "json" :: _ -> Standard Json
    | "--format" :: "github" :: _ -> Github
    | "--format" :: other :: _ ->
      Printf.eprintf
        "unknown --format %S (expected human|json|github)\n" other;
      exit 2
    | _ :: tail -> find tail
    | [] -> Standard Human
  in
  find rest

let parse_path_prefix rest =
  let rec find = function
    | "--path-prefix" :: v :: _ -> v
    | _ :: tl -> find tl
    | [] -> "/admin"
  in
  find rest

let parse_optional flag rest =
  let rec find = function
    | name :: value :: _ when name = flag -> Some value
    | _ :: tl -> find tl
    | [] -> None
  in
  find rest

let has_flag flag = List.exists (fun value -> value = flag)

let parse_contract_path rest =
  let rec find = function
    | "--contract" :: path :: _ when not (String.starts_with ~prefix:"--" path) ->
      Some path
    | "--contract" :: _ ->
      prerr_endline "--contract requires a PATH";
      exit 2
    | _ :: tail -> find tail
    | [] -> None
  in
  find rest

let parse_trusted_cidr ?default rest =
  let raw =
    let rec find = function
      | "--trusted-cidr" :: v :: _ -> Some v
      | _ :: tl -> find tl
      | [] -> default
    in
    find rest
  in
  match raw with
  | None ->
    prerr_endline "--trusted-cidr is required for network-restricted-access";
    exit 2
  | Some raw ->
    (match Cidr.parse raw with
     | Ok c -> c
     | Error e ->
       Printf.eprintf "bad --trusted-cidr %S: %s\n" raw e;
       exit 2)

let parse_property rest : Verify.property =
  let rec find = function
    | "--property" :: "no-anonymous-access" :: _ ->
      Verify.No_anonymous_access (parse_path_prefix rest)
    | "--property" :: "rate-limit-on-public" :: _ -> Verify.Rate_limit_on_public
    | "--property" :: "no-shadowed-routes" :: _ -> Verify.No_shadowed_routes
    | "--property" :: "admin-api-not-reachable" :: _ ->
      Verify.Admin_api_not_reachable
        (parse_trusted_cidr ~default:"127.0.0.1/32" rest)
    | "--property" :: "authenticated-access" :: _ ->
      Verify.Authenticated_access
        { path_prefix = parse_path_prefix rest;
          method_ = parse_optional "--method" rest;
          host = parse_optional "--host" rest }
    | "--property" :: "network-restricted-access" :: _ ->
      Verify.Network_restricted_access
        { path_prefix = parse_path_prefix rest;
          method_ = parse_optional "--method" rest;
          host = parse_optional "--host" rest;
          trusted_cidr = parse_trusted_cidr rest }
    | "--property" :: other :: _ ->
      Printf.eprintf
        "unknown --property %S (expected \
         no-anonymous-access|rate-limit-on-public|no-shadowed-routes|\
         admin-api-not-reachable|authenticated-access|network-restricted-access)\n"
        other;
      exit 2
    | _ :: tl -> find tl
    | [] -> Verify.No_anonymous_access (parse_path_prefix rest)
  in
  find rest

let parse_emit_smt rest =
  let rec find = function
    | "--emit-smt" :: v :: _ -> Some v
    | [ "--emit-smt" ] ->
      prerr_endline "--emit-smt requires a PATH";
      exit 2
    | _ :: tl -> find tl
    | [] -> None
  in
  find rest

let parse_evidence_dir rest =
  let rec find found = function
    | "--evidence-dir" :: path :: tail
      when path <> "" && not (String.starts_with ~prefix:"--" path) ->
      if Option.is_some found then begin
        prerr_endline "--evidence-dir may only be specified once";
        exit 2
      end;
      find (Some path) tail
    | "--evidence-dir" :: _ ->
      prerr_endline "--evidence-dir requires a NEW_DIRECTORY";
      exit 2
    | _ :: tail -> find found tail
    | [] -> found
  in
  find None rest

let reject_evidence_dir rest =
  if has_flag "--evidence-dir" rest then begin
    prerr_endline "--evidence-dir is only supported by verify with --contract";
    exit 2
  end

let exit_code : Report.outcome -> int = function
  | Report.Proved -> 0
  | Report.Vacuous -> 5
  | Report.Inconsistent _ -> 6
  | Report.Violated _ -> 3
  | Report.Unknown _ -> 4

let print_verify_error format ~file ~title message =
  match format with
  | Github ->
    print_endline (Soundcheck_ci.Github_annotation.error ~file ~title message)
  | Standard _ -> Printf.eprintf "%s: %s\n" title message

let run_verify file rest =
  let format = parse_verify_format rest in
  let emit_smt = parse_emit_smt rest in
  let evidence_dir = parse_evidence_dir rest in
  if Option.is_some evidence_dir && not (has_flag "--contract" rest) then begin
    prerr_endline "--evidence-dir requires --contract";
    exit 2
  end;
  if Option.is_some evidence_dir && Option.is_some emit_smt then begin
    prerr_endline "--evidence-dir cannot be combined with --emit-smt";
    exit 2
  end;
  let contract_spec, property =
    match parse_contract_path rest with
    | None -> (None, parse_property rest)
    | Some path ->
      let conflicting =
        [ "--property"; "--path-prefix"; "--method"; "--host";
          "--trusted-cidr" ]
        |> List.find_opt (fun flag -> has_flag flag rest)
      in
      (match conflicting with
       | Some flag ->
         Printf.eprintf "%s cannot be combined with --contract\n" flag;
         exit 2
       | None ->
         match Contract_spec.read_file path with
         | Error error ->
           print_verify_error format ~file:path ~title:"contract error" error;
           exit 2
         | Ok spec -> (Some spec, Contract_spec.to_property spec))
  in
  (* Read the config here so a missing/unreadable file is a CLI-level error;
     the verification pipeline itself is the shared {!Verify.run}. *)
  match Parse.read_file file with
  | Error e ->
    (* File failures are CLI-level errors rather than verification outcomes. *)
    print_verify_error format ~file ~title:"parse error" e;
    exit 1
  | Ok config ->
    (match Verify.run_with_trace ?emit_smt ~property config with
     | Error e ->
       print_verify_error format ~file ~title:"verification error" e;
       exit 1
     | Ok (report, trace) ->
       let report =
         match contract_spec with
         | None -> report
         | Some spec -> Contract_spec.bind_report spec report
       in
       (match evidence_dir with
        | None -> ()
        | Some directory ->
          let bundle_result =
            match Evidence.collect_provenance () with
            | Error reason -> Error reason
            | Ok provenance ->
              let profile : Evidence.profile =
                { id = Assurance.profile.id; json = Assurance.profile_json () }
              in
              match Evidence.create ~config ~profile ~provenance ~report ~trace with
              | Error reason -> Error reason
              | Ok bundle -> Evidence.write ~directory bundle
          in
          match bundle_result with
          | Ok () -> ()
          | Error error ->
            print_verify_error format ~file ~title:"evidence error" error;
            exit 1);
       let rendered =
         match format with
         | Standard Human -> Report.to_human report
         | Standard Json -> Report.to_json report
         | Github -> Soundcheck_ci.Github_annotation.render ~file report
       in
       print_endline rendered;
       exit (exit_code report.result))

let run_mcp rest =
  reject_evidence_dir rest;
  match parse_contract_path rest with
  | None -> Soundcheck_mcp.Server.run ()
  | Some path ->
    (match Contract_spec.read_file path with
     | Error error ->
       Printf.eprintf "contract error: %s\n" error;
       exit 2
     | Ok contract -> Soundcheck_mcp.Server.run ~contract ())

let run_compare before_file after_file rest =
  reject_evidence_dir rest;
  let format = parse_format rest in
  let emit_smt = parse_emit_smt rest in
  let mode =
    let rec find = function
      | "--mode" :: "decision" :: _ -> Compare.Security_decision
      | "--mode" :: "route-service" :: _ -> Compare.Route_service
      | "--mode" :: "service-target" :: _ -> Compare.Service_target
      | "--mode" :: "upstream-uri" :: _ -> Compare.Upstream_uri
      | "--mode" :: value :: _ ->
        Printf.eprintf
          "unknown --mode %S (expected decision|route-service|service-target|upstream-uri)\n"
          value;
        exit 2
      | [ "--mode" ] ->
        prerr_endline
          "--mode requires decision, route-service, service-target, or upstream-uri";
        exit 2
      | _ :: tail -> find tail
      | [] -> Compare.Security_decision
    in
    find rest
  in
  let contract =
    match parse_contract_path rest with
    | None -> None
    | Some path ->
      let conflicting =
        [ "--property"; "--path-prefix"; "--method"; "--host";
          "--trusted-cidr" ]
        |> List.find_opt (fun flag -> has_flag flag rest)
      in
      (match conflicting with
       | Some flag ->
         Printf.eprintf "%s cannot be combined with --contract\n" flag;
         exit 2
       | None -> ());
      (match Contract_spec.read_file path with
       | Ok contract -> Some contract
       | Error error ->
         Printf.eprintf "contract error: %s\n" error;
         exit 2)
  in
  match Parse.read_file before_file, Parse.read_file after_file with
  | Error error, _ | _, Error error ->
    Printf.eprintf "parse error: %s\n" error;
    exit 1
  | Ok before_source, Ok after_source ->
    (match contract with
     | Some contract ->
       (match
          Compare.run_repair ?emit_smt ~mode ~contract before_source after_source
        with
        | Error error ->
          Printf.eprintf "comparison error: %s\n" error;
          exit 1
        | Ok report ->
          print_endline
            (match format with
             | Human -> Compare.repair_to_human report
             | Json -> Compare.repair_to_json report);
          exit
            (match report.result with
             | Compare.Valid_repair -> 0
             | Compare.Out_of_scope_regression _ -> 3
             | Compare.Repair_unknown _ -> 4
             | Compare.Contract_failed -> exit_code report.contract_report.result))
     | None ->
    (match Compare.run ?emit_smt ~mode before_source after_source with
     | Error error ->
       Printf.eprintf "comparison error: %s\n" error;
       exit 1
     | Ok report ->
       print_endline
         (match format with Human -> Compare.to_human report | Json -> Compare.to_json report);
       exit
         (match report.result with
          | Compare.Equivalent -> 0
          | Compare.Different _ -> 3
          | Compare.Unknown _ -> 4)))

let run_profile connector rest =
  let format =
    match rest with
    | [] -> Human
    | [ "--format"; "human" ] -> Human
    | [ "--format"; "json" ] -> Json
    | [ "--format"; other ] ->
      Printf.eprintf "unknown --format %S (expected human|json)\n" other;
      exit 2
    | [ "--format" ] ->
      prerr_endline "--format requires human or json";
      exit 2
    | _ -> usage ()
  in
  if connector <> "kong" then begin
    Printf.eprintf "unknown connector %S (expected kong)\n" connector;
    exit 2
  end;
  let rendered =
    match format with
    | Human -> Assurance.profile_human ()
    | Json -> Assurance.profile_json ()
  in
  print_endline rendered

let () =
  match Array.to_list Sys.argv with
  | _ :: "verify" :: file :: rest -> run_verify file rest
  | _ :: "compare" :: before_file :: after_file :: rest ->
    run_compare before_file after_file rest
  | _ :: "profile" :: connector :: rest -> run_profile connector rest
  | _ :: "mcp" :: rest -> run_mcp rest
  | _ -> usage ()
