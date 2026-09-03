(* Soundcheck CLI (v0): verify a Kong declarative config against a security
   property. Exit codes: 0 proved, 1 parse error, 2 usage, 3 violated, 4 unknown,
   5 vacuous, 6 inconsistent contract. *)

open Soundcheck_core
open Soundcheck_kong

let usage () =
  prerr_endline
    "usage: soundcheck verify <config.yaml> [--property P] [--path-prefix PREFIX]\n\
    \                                       [--format human|json] [--emit-smt PATH]\n\
    \  --property     no-anonymous-access (default) | rate-limit-on-public\n\
    \                 | no-shadowed-routes | admin-api-not-reachable\n\
    \  --path-prefix  prefix for no-anonymous-access (default /admin)\n\
    \  --trusted-cidr for admin-api-not-reachable (default 127.0.0.1/32)\n\
    \  --format       human (default) | json\n\
    \  --emit-smt     write the SMT-LIB2 query to PATH and keep it (audit artifact)\n\
     \n\
     usage: soundcheck mcp\n\
    \  Runs the MCP server (JSON-RPC over stdio) exposing the `verify` tool.";
  exit 2

type format = Human | Json

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

let parse_path_prefix rest =
  let rec find = function
    | "--path-prefix" :: v :: _ -> v
    | _ :: tl -> find tl
    | [] -> "/admin"
  in
  find rest

let parse_trusted_cidr rest =
  let raw =
    let rec find = function
      | "--trusted-cidr" :: v :: _ -> v
      | _ :: tl -> find tl
      | [] -> "127.0.0.1/32"
    in
    find rest
  in
  match Cidr.parse raw with
  | Ok c -> c
  | Error e ->
    Printf.eprintf "bad --trusted-cidr %S: %s\n" raw e;
    exit 2

let parse_property rest : Verify.property =
  let rec find = function
    | "--property" :: "no-anonymous-access" :: _ ->
      Verify.No_anonymous_access (parse_path_prefix rest)
    | "--property" :: "rate-limit-on-public" :: _ -> Verify.Rate_limit_on_public
    | "--property" :: "no-shadowed-routes" :: _ -> Verify.No_shadowed_routes
    | "--property" :: "admin-api-not-reachable" :: _ ->
      Verify.Admin_api_not_reachable (parse_trusted_cidr rest)
    | "--property" :: other :: _ ->
      Printf.eprintf
        "unknown --property %S (expected \
         no-anonymous-access|rate-limit-on-public|no-shadowed-routes)\n"
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

let exit_code : Report.outcome -> int = function
  | Report.Proved -> 0
  | Report.Vacuous -> 5
  | Report.Inconsistent _ -> 6
  | Report.Violated _ -> 3
  | Report.Unknown _ -> 4

let run_verify file rest =
  let property = parse_property rest in
  let format = parse_format rest in
  let emit_smt = parse_emit_smt rest in
  (* Read the config here so a missing/unreadable file is a CLI-level error;
     the verification pipeline itself is the shared {!Verify.run}. *)
  match Parse.read_file file with
  | Error e ->
    (* File/parse failures are a CLI-level error (not a verification outcome), so
       they stay on stderr with exit 1 regardless of --format. *)
    Printf.eprintf "parse error: %s\n" e;
    exit 1
  | Ok config ->
    (match Verify.run ?emit_smt ~property config with
     | Error e ->
       Printf.eprintf "parse error: %s\n" e;
       exit 1
     | Ok report ->
       let rendered =
         match format with
         | Human -> Report.to_human report
         | Json -> Report.to_json report
       in
       print_endline rendered;
       exit (exit_code report.result))

let () =
  match Array.to_list Sys.argv with
  | _ :: "verify" :: file :: rest -> run_verify file rest
  | _ :: "mcp" :: _ -> Soundcheck_mcp.Server.run ()
  | _ -> usage ()
