(* Shared Kong verification pipeline: config text -> {!Soundcheck_core.Report.t}.

   Both adapters (CLI, MCP) drive this one function, so the
   parse -> lower -> encode -> solve -> lift sequence lives in exactly one place.
   Adapters own only their own I/O and exit/error conventions.

   This is Kong-specific glue (it names {!Parse}/{!Lower}/{!Lift}), so it lives in
   the connector, never in core — core stays connector-free. *)

open Soundcheck_core

(* Which invariant to verify. Adapters (CLI, MCP) validate the user-facing name
   into this variant, rejecting unknown names at their own boundary. *)
type property =
  | No_anonymous_access of string  (** path prefix that must require auth *)
  | Rate_limit_on_public

(* The core property template plus the connector lift that explains its
   counterexample in Kong's own vocabulary. The lift's [culprit] mirrors the
   property's reach_via so the named route is exactly the one the solver
   exploited. *)
let resolve (cfg : Ast.config) :
    property -> Property.t * (Solve.model -> Report.counterexample) = function
  | No_anonymous_access path_prefix ->
    ( Property.no_anonymous_access ~path_prefix,
      fun m -> Lift.counterexample cfg m )
  | Rate_limit_on_public ->
    ( Property.rate_limit_on_public,
      fun m ->
        Lift.counterexample
          ~culprit:(fun s r ->
            not (Lower.requires_auth s r) && not (Lower.rate_limited s r))
          ~missing:"no rate-limiting plugin is attached to the route or its service."
          cfg m )

(* Verify a decK config (as text) against [property]. [Error] is a parse failure
   (malformed config — a caller-level error), while [Ok report] is a verification
   outcome (proved / violated / unknown). *)
let run ~config ~(property : property) : (Report.t, string) result =
  match Parse.parse_string config with
  | Error e -> Error e
  | Ok cfg ->
    let policy = Lower.to_policy cfg in
    let prop, lift = resolve cfg property in
    let smt = Smt_encode.to_smtlib policy prop in
    let result : Report.outcome =
      match Solve.check smt with
      | Solve.Proved -> Report.Proved
      | Solve.Violated m -> Report.Violated (lift m)
      | Solve.Unknown s -> Report.Unknown s
    in
    Ok { Report.result;
         property_name = prop.name;
         property_description = prop.description }
