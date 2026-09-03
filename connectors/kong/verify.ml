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
  | Authenticated_access of {
      path_prefix : string;
      method_     : string option;
      host        : string option;
    }
      (** paired contract: anonymous denied and authenticated allowed *)

let authenticated_access_contract ~path_prefix ~method_ ~host : Contract.t =
  let scope =
    Ir.And
      ([ Ir.Path_prefix path_prefix ]
       @ Option.to_list (Option.map (fun method_ -> Ir.Method_is method_) method_)
       @ Option.to_list
           (Option.map
              (fun host ->
                Ir.Host_matches (Regex.Lit (String.lowercase_ascii host)))
              host))
  in
  let scope_description =
    String.concat ", "
      ([ "path prefix " ^ path_prefix ]
       @ Option.to_list (Option.map (fun method_ -> "method " ^ method_) method_)
       @ Option.to_list (Option.map (fun host -> "host " ^ host) host))
  in
  { Contract.name = "authenticated-access";
    description =
      "Anonymous requests must be denied and authenticated requests allowed for "
      ^ scope_description;
    clauses =
      [ Contract.must_deny ~name:"anonymous-access-denied"
          ~description:("Anonymous requests are denied for " ^ scope_description)
          (Ir.And [ scope; Ir.Is_anonymous ]);
        Contract.must_allow ~name:"authenticated-access-allowed"
          ~description:
            ("Authenticated requests are allowed for " ^ scope_description)
          (Ir.And [ scope; Ir.Requires_auth ]) ] }

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
  | Authenticated_access _ -> None
  | No_shadowed_routes -> None

let report_clause (clause : Contract.clause) : Report.clause =
  { name = Contract.name clause;
    description = Contract.description clause;
    kind =
      (match clause with
       | Contract.Must_deny _ -> Report.Must_deny
       | Contract.Must_allow _ -> Report.Must_allow) }

let run_contract cfg policy contract : Report.outcome * Report.clause option =
  match Contract_verify.run policy contract with
  | Contract_verify.Proved -> (Report.Proved, None)
  | Contract_verify.Vacuous clause ->
    (Report.Vacuous, Some (report_clause clause))
  | Contract_verify.Inconsistent (safety, functionality) ->
    let reason =
      Printf.sprintf
        "clauses %S and %S overlap: the same request is required to be both denied and allowed"
        (Contract.name safety) (Contract.name functionality)
    in
    (Report.Inconsistent reason, Some (report_clause functionality))
  | Contract_verify.Violated (clause, model) ->
    let counterexample =
      match clause with
      | Contract.Must_deny _ -> Lift.counterexample cfg model
      | Contract.Must_allow _ ->
        Lift.functionality_counterexample cfg policy model
    in
    (Report.Violated counterexample, Some (report_clause clause))
  | Contract_verify.Unknown reason -> (Report.Unknown reason, None)

(* Verify a decK config (as text) against [property]. [Error] is a caller-level
   failure (malformed config or an unsupported output option), while [Ok report]
   is a verification outcome. [emit_smt] keeps a single-property SMT-LIB2 query
   at that path as an audit artifact; multi-query contracts reject it explicitly.

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
    let contract =
      match property with
      | Authenticated_access { path_prefix; method_; host } ->
        Some (authenticated_access_contract ~path_prefix ~method_ ~host)
      | _ -> None
    in
    if Option.is_some contract && Option.is_some emit_smt then
      Error "--emit-smt is not yet supported for multi-query contracts"
    else
      let name, description =
      match contract with
      | Some contract -> (contract.Contract.name, contract.description)
      | None ->
        (match resolve cfg property with
         | Some (prop, _) -> (prop.name, prop.description)
         | None -> (Shadowing.name, Shadowing.description))
      in
      let (outcome, clause) : Report.outcome * Report.clause option =
      (* Check the decidability boundary BEFORE encoding: a config outside the
         supported fragment must report [unknown], never a quiet pass. *)
      match Fragment.check cfg with
      | Error reason -> (Report.Unknown reason, None)
      | Ok () -> (
        let policy = Lower.to_policy cfg in
        match contract with
        | Some contract -> run_contract cfg policy contract
        | None ->
          (match resolve cfg property with
        | None -> (run_shadowing ?emit_smt cfg policy, None)
        | Some (prop, lift) ->
          let preflight =
            Smt_encode.condition_query ~name:prop.name
              ~description:prop.description prop.forbidden_when
          in
          match Solve.check ?emit_smt preflight with
          | Solve.Proved -> (Report.Vacuous, None)
          | Solve.Unknown s -> (Report.Unknown s, None)
          | Solve.Violated _ -> (
            let smt = Smt_encode.to_smtlib policy prop in
            match Solve.check ?emit_smt smt with
            | Solve.Proved -> (Report.Proved, None)
            | Solve.Violated m -> (Report.Violated (lift m), None)
            | Solve.Unknown s -> (Report.Unknown s, None))))
      in
      Ok { Report.result = outcome;
           property_name = name;
           property_description = description;
           clause;
           frozen_spec = None }
