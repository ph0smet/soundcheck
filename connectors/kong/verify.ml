(* Shared Kong verification pipeline: config text -> {!Soundcheck_core.Report.t}.

   Both adapters (CLI, MCP) drive this one function, so the
   parse -> lower -> encode -> solve -> lift sequence lives in exactly one place.
   Adapters own only their own I/O and exit/error conventions.

   This is Kong-specific glue (it names {!Parse}/{!Lower}/{!Lift}), so it lives in
   the connector, never in core — core stays connector-free. *)

open Soundcheck_core

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

(* Verify a decK config (as text) against the no-anonymous-access property.
   [Error] is a parse failure (malformed config — a caller-level error), while
   [Ok report] is a verification outcome (proved / violated / unknown). *)
let run ~config ~path_prefix : (Report.t, string) result =
  match Parse.parse_string config with
  | Error e -> Error e
  | Ok cfg ->
    let policy = Lower.to_policy cfg in
    let prop = Property.no_anonymous_access ~path_prefix in
    let smt = Smt_encode.to_smtlib policy prop in
    Ok (to_report cfg prop (Solve.check smt))
