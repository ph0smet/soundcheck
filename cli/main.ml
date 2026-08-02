(* Soundcheck CLI (v0): verify a Kong declarative config against a security
   property. Exit codes: 0 proved, 1 parse error, 3 violated, 2 usage, 4 unknown. *)

open Soundcheck_core
open Soundcheck_kong

let usage () =
  prerr_endline
    "usage: soundcheck verify <config.yaml> [--path-prefix PREFIX] [--format human|json]\n\
    \  Verifies that no anonymous request is allowed under PREFIX (default /admin).\n\
    \  --format selects the output rendering (default human).";
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

(* Map the solver outcome into the connector-lifted presentation value. *)
let to_report cfg (prop : Property.t) (result : Solve.result) : Report.t =
  let result : Report.outcome =
    match result with
    | Solve.Proved -> Report.Proved
    | Solve.Violated m -> Report.Violated (Lift.counterexample cfg m)
    | Solve.Unknown s -> Report.Unknown s
  in
  { Report.result;
    property_name = prop.name;
    property_description = prop.description }

let exit_code : Report.outcome -> int = function
  | Report.Proved -> 0
  | Report.Violated _ -> 3
  | Report.Unknown _ -> 4

let run_verify file rest =
  let path_prefix = parse_path_prefix rest in
  let format = parse_format rest in
  match Parse.parse_file file with
  | Error e ->
    (* Parse failures are a CLI-level error (not a verification outcome), so they
       stay on stderr with exit 1 regardless of --format. *)
    Printf.eprintf "parse error: %s\n" e;
    exit 1
  | Ok cfg ->
    let policy = Lower.to_policy cfg in
    let prop : Property.t = Property.no_anonymous_access ~path_prefix in
    let smt = Smt_encode.to_smtlib policy prop in
    let report = to_report cfg prop (Solve.check smt) in
    let rendered =
      match format with
      | Human -> Report.to_human report
      | Json -> Report.to_json report
    in
    print_endline rendered;
    exit (exit_code report.result)

let () =
  match Array.to_list Sys.argv with
  | _ :: "verify" :: file :: rest -> run_verify file rest
  | _ -> usage ()
