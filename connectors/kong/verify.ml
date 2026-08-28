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
  | No_shadowed_routes
  | Admin_api_not_reachable of Cidr.t  (** trusted source block *)

(* The core property template plus the connector lift that explains its
   counterexample in Kong's own vocabulary. The lift's [culprit] mirrors the
   property's reach_via so the named route is exactly the one the solver
   exploited.

   [None] for no-shadowed-routes: it is not a single query over requests and so
   has no {!Property.t}. Returning an option rather than raising keeps the
   distinction visible to the type checker instead of deferring it to runtime. *)
let resolve (cfg : Ast.config) :
    property -> (Property.t * (Solve.model -> Report.counterexample)) option =
  function
  | No_anonymous_access path_prefix ->
    Some
      ( Property.no_anonymous_access ~path_prefix,
        fun m -> Lift.counterexample cfg m )
  | Rate_limit_on_public ->
    Some
      ( Property.rate_limit_on_public,
        fun m ->
          Lift.counterexample
            ~culprit:(fun s r ->
              not (Lower.requires_auth s r) && not (Lower.rate_limited s r))
            ~missing:
              "no rate-limiting plugin is attached to the route or its service."
            cfg m )
  | Admin_api_not_reachable trusted ->
    Some
      ( Property.admin_api_not_reachable ~trusted,
        fun m ->
          Lift.counterexample
            ~culprit:(fun s _ -> Lower.targets_admin_api s)
            ~show_source:true
            ~missing:
              "its service proxies the Kong Admin API, with neither an auth \
               plugin nor an ip-restriction confining it."
            cfg m )
  | No_shadowed_routes -> None

(* Verify a decK config (as text) against [property]. [Error] is a parse failure
   (malformed config — a caller-level error), while [Ok report] is a verification
   outcome (proved / violated / unknown). [emit_smt] keeps the SMT-LIB2 query at
   that path as an audit artifact.

   [config] is positional and last so [emit_smt] stays erasable: callers that do
   not want the artifact (MCP, the corpus runner) need not mention it. *)
(* Shadowing asks one query PER CANDIDATE PAIR rather than one per config, so it
   cannot ride the {!Property.t} path. Pairs are checked in turn and the FIRST
   satisfiable one is reported: a single, fully explained finding beats a list,
   and the fix for one shadowed route often changes the rest. No candidate pairs
   (or none satisfiable) means proved.

   An [Unknown] from any pair aborts immediately rather than continuing: once one
   query is inconclusive we can no longer claim the remaining ones establish a
   proof. *)
let run_shadowing ?emit_smt (cfg : Ast.config) (policy : Ir.policy) :
    Report.outcome =
  let rec go = function
    | [] -> Report.Proved
    | (pair : Shadowing.pair) :: rest -> (
      let smt = Smt_encode.shadowing_query policy pair in
      match Solve.check ?emit_smt smt with
      | Solve.Violated m ->
        Report.Violated (Lift.shadowing_counterexample cfg pair m)
      | Solve.Unknown s -> Report.Unknown s
      | Solve.Proved -> go rest)
  in
  go (Shadowing.candidates policy)

let run ?emit_smt ~(property : property) (config : string) :
    (Report.t, string) result =
  match Parse.parse_string config with
  | Error e -> Error e
  | Ok cfg ->
    let name, description =
      match resolve cfg property with
      | Some (prop, _) -> (prop.name, prop.description)
      | None -> (Shadowing.name, Shadowing.description)
    in
    let outcome : Report.outcome =
      (* Check the decidability boundary BEFORE encoding: a config outside the
         supported fragment must report [unknown], never a quiet pass. *)
      match Fragment.check cfg with
      | Error reason -> Report.Unknown reason
      | Ok () -> (
        let policy = Lower.to_policy cfg in
        match resolve cfg property with
        | None -> run_shadowing ?emit_smt cfg policy
        | Some (prop, lift) -> (
          let smt = Smt_encode.to_smtlib policy prop in
          match Solve.check ?emit_smt smt with
          | Solve.Proved -> Report.Proved
          | Solve.Violated m -> Report.Violated (lift m)
          | Solve.Unknown s -> Report.Unknown s))
    in
    Ok { Report.result = outcome;
         property_name = name;
         property_description = description }
