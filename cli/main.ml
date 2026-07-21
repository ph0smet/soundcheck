(* Soundcheck CLI (v0): verify a Kong declarative config against a security
   property. Exit codes: 0 proved, 1 parse error, 3 violated, 2 usage, 4 unknown. *)

open Soundcheck_core
open Soundcheck_kong

let usage () =
  prerr_endline
    "usage: soundcheck verify <config.yaml> [--path-prefix PREFIX] [--format human|json]\n\
    \  Verifies that no anonymous request is allowed under PREFIX (default /admin).\n\
    \  --format selects the output rendering (default human).\n\
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

let exit_code : Report.outcome -> int = function
  | Report.Proved -> 0
  | Report.Violated _ -> 3
  | Report.Unknown _ -> 4

let run_verify file rest =
  let path_prefix = parse_path_prefix rest in
  let format = parse_format rest in
  (* Read the config here so a missing/unreadable file is a CLI-level error;
     the verification pipeline itself is the shared {!Verify.run}. *)
  match Parse.read_file file with
  | Error e ->
    (* File/parse failures are a CLI-level error (not a verification outcome), so
       they stay on stderr with exit 1 regardless of --format. *)
    Printf.eprintf "parse error: %s\n" e;
    exit 1
  | Ok config ->
    (match Verify.run ~config ~path_prefix with
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
