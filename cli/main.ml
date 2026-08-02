(* Soundcheck CLI (v0): verify a Kong declarative config against a security
   property. Exit codes: 0 proved, 1 parse error, 3 violated, 2 usage, 4 unknown. *)

open Soundcheck_core
open Soundcheck_kong

let usage () =
  prerr_endline
    "usage: soundcheck verify <config.yaml> [--path-prefix PREFIX]\n\
    \  Verifies that no anonymous request is allowed under PREFIX (default /admin).";
  exit 2

let run_verify file rest =
  let path_prefix =
    let rec find = function
      | "--path-prefix" :: v :: _ -> v
      | _ :: tl -> find tl
      | [] -> "/admin"
    in
    find rest
  in
  match Parse.parse_file file with
  | Error e ->
    Printf.eprintf "parse error: %s\n" e;
    exit 1
  | Ok cfg ->
    let policy = Lower.to_policy cfg in
    let prop : Property.t = Property.no_anonymous_access ~path_prefix in
    let smt = Smt_encode.to_smtlib policy prop in
    (match Solve.check smt with
     | Solve.Proved ->
       Printf.printf "PROVED   %s\n         %s\n" prop.name prop.description;
       exit 0
     | Solve.Violated m ->
       Printf.printf "VIOLATED %s\n         %s\n" prop.name (Lift.lift cfg m);
       exit 3
     | Solve.Unknown s ->
       Printf.printf "UNKNOWN  %s\n" s;
       exit 4)

let () =
  match Array.to_list Sys.argv with
  | _ :: "verify" :: file :: rest -> run_verify file rest
  | _ -> usage ()
