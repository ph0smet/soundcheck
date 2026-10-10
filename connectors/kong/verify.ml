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
  | Network_restricted_access of {
      path_prefix  : string;
      method_      : string option;
      host         : string option;
      trusted_cidr : Cidr.t;
    }
      (** paired contract: untrusted sources denied and authenticated trusted
          sources allowed *)

let request_scope ~path_prefix ~method_ ~host =
  Ir.And
    ([ Ir.Path_prefix path_prefix ]
     @ Option.to_list (Option.map (fun method_ -> Ir.Method_is method_) method_)
     @ Option.to_list
         (Option.map
            (fun host ->
              Ir.Host_matches (Regex.Lit (String.lowercase_ascii host)))
            host))

let scope_description ~path_prefix ~method_ ~host =
  String.concat ", "
    ([ "path prefix " ^ path_prefix ]
     @ Option.to_list (Option.map (fun method_ -> "method " ^ method_) method_)
     @ Option.to_list (Option.map (fun host -> "host " ^ host) host))

let authenticated_access_contract ~path_prefix ~method_ ~host : Contract.t =
  let scope = request_scope ~path_prefix ~method_ ~host in
  let scope_description = scope_description ~path_prefix ~method_ ~host in
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

let network_restricted_access_contract ~path_prefix ~method_ ~host
    ~trusted_cidr : Contract.t =
  let scope = request_scope ~path_prefix ~method_ ~host in
  let scope_description = scope_description ~path_prefix ~method_ ~host in
  let trusted = Cidr.to_string trusted_cidr in
  { Contract.name = "network-restricted-access";
    description =
      Printf.sprintf
        "Requests outside %s are denied and authenticated requests inside it are allowed for %s"
        trusted scope_description;
    clauses =
      [ Contract.must_deny ~name:"untrusted-network-access-denied"
          ~description:
            (Printf.sprintf "Requests outside %s are denied for %s" trusted
               scope_description)
          (Ir.And [ scope; Ir.Not (Ir.Source_in trusted_cidr) ]);
        Contract.must_allow ~name:"trusted-authenticated-access-allowed"
          ~description:
            (Printf.sprintf
               "Authenticated requests inside %s are allowed for %s" trusted
               scope_description)
          (Ir.And [ scope; Ir.Source_in trusted_cidr; Ir.Requires_auth ]) ] }

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
              not (Lower.requires_auth cfg s r)
              && not (Lower.rate_limited cfg s r))
            ~missing:
              "no recognized general request-rate limit is attached at route, service, or global scope."
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
  | Network_restricted_access _ -> None
  | No_shadowed_routes -> None

let report_clause (clause : Contract.clause) : Report.clause =
  { name = Contract.name clause;
    description = Contract.description clause;
    kind =
      (match clause with
       | Contract.Must_deny _ -> Report.Must_deny
       | Contract.Must_allow _ -> Report.Must_allow) }

let report_assurance (assessment : Assurance.assessment) : Report.assurance =
  let status =
    match assessment.status with
    | Assurance.Within_profile -> Report.Within_profile
    | Assurance.Conservative -> Report.Conservative
    | Assurance.Unsupported -> Report.Unsupported
  in
  let findings =
    List.map
      (fun (finding : Assurance.finding) : Report.assurance_finding ->
        { code = finding.code;
          service = finding.service;
          route = finding.route;
          detail = finding.detail })
      assessment.findings
  in
  { profile = Assurance.profile.id; status; findings }

let contract_outcome ?(show_source = false) ~lift_denied cfg policy :
    Contract_verify.result -> Report.outcome * Report.clause option = function
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
      | Contract.Must_deny _ -> lift_denied model
      | Contract.Must_allow _ ->
        Lift.functionality_counterexample ~show_source cfg policy model
    in
    (Report.Violated counterexample, Some (report_clause clause))
  | Contract_verify.Unknown reason -> (Report.Unknown reason, None)

let run_contract_with_trace ?(show_source = false) ~lift_denied cfg policy contract =
  let result, trace = Contract_verify.run_with_trace policy contract in
  (contract_outcome ~show_source ~lift_denied cfg policy result, trace)

let run_contract ?(show_source = false) ~lift_denied cfg policy contract =
  fst (run_contract_with_trace ~show_source ~lift_denied cfg policy contract)

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
  (* Display names currently double as IR route identities. Inspect entities
     before path/SNI expansion: one multi-path route is fine, two distinct
     routes with the same name (including unnamed routes) are ambiguous.
     Never let [candidates]' same-entity pruning turn that ambiguity into proof.
     Referenced top-level routes are already inserted into service.routes. *)
  let route_names =
    List.concat_map
      (fun (service : Ast.service) ->
        List.map (fun (route : Ast.route) -> route.name) service.routes)
      cfg.services
    @ List.filter_map
        (fun (top : Ast.top_level_route) ->
          if top.service = None && not top.unsupported_reference then
            Some top.route.name
          else None)
        cfg.top_level_routes
  in
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
  if List.length route_names <> List.length (List.sort_uniq String.compare route_names)
  then
    Report.Unknown
      "shadowing requires distinct route names: multiple entities share a name or are unnamed"
  else go (Shadowing.candidates policy)

(* The trace is absent for legacy properties and configs rejected before
   lowering. In particular, unsupported configs never acquire invented queries
   just to populate an evidence bundle. *)
let run_with_trace ?emit_smt ~(property : property) (config : string) :
    (Report.t * Contract_verify.trace_entry list option, string) result =
  let property_scope =
    match property with
    | No_anonymous_access path_prefix
    | Authenticated_access { path_prefix; _ }
    | Network_restricted_access { path_prefix; _ } -> Some path_prefix
    | Rate_limit_on_public | No_shadowed_routes | Admin_api_not_reachable _ -> None
  in
  match property_scope with
  | Some path_prefix
    when not (Path_normalization.is_normalized_literal path_prefix) ->
    Error
      (Printf.sprintf "property path_prefix %S is not normalized; use %S"
         path_prefix (Path_normalization.normalize_literal path_prefix))
  | _ ->
  match Parse.parse_string config with
  | Error e -> Error e
  | Ok cfg ->
    (match Validate.check cfg with
     | Error _ as error -> error
     | Ok () ->
    let assurance = report_assurance (Assurance.assess cfg) in
    let contract, show_source, lift_denied =
      match property with
      | Authenticated_access { path_prefix; method_; host } ->
        ( Some (authenticated_access_contract ~path_prefix ~method_ ~host),
          false,
          Lift.counterexample cfg )
      | Network_restricted_access
          { path_prefix; method_; host; trusted_cidr } ->
        ( Some
            (network_restricted_access_contract ~path_prefix ~method_ ~host
               ~trusted_cidr),
          true,
          Lift.counterexample ~culprit:(fun _ _ -> true) ~show_source:true
            ~missing:
              "the selected route does not enforce the frozen trusted-network boundary."
            cfg )
      | _ -> (None, false, Lift.counterexample cfg)
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
      let (outcome, clause), trace =
      (* Check the decidability boundary BEFORE encoding: a config outside the
         supported fragment must report [unknown], never a quiet pass. *)
      match Fragment.check cfg with
      | Error reason -> ((Report.Unknown reason, None), None)
      | Ok () ->
        let policy = Lower.to_policy cfg in
        match contract with
        | Some contract ->
          let outcome, trace =
            run_contract_with_trace ~show_source ~lift_denied cfg policy contract
          in
          (outcome, Some trace)
        | None ->
          let outcome =
            match resolve cfg property with
            | None -> (run_shadowing ?emit_smt cfg policy, None)
            | Some (prop, lift) ->
              let preflight =
                Smt_encode.condition_query ~domain:policy.request_domain
                  ~name:prop.name ~description:prop.description prop.forbidden_when
              in
              match Solve.check ?emit_smt preflight with
              | Solve.Proved -> (Report.Vacuous, None)
              | Solve.Unknown s -> (Report.Unknown s, None)
              | Solve.Violated _ -> (
                let smt = Smt_encode.to_smtlib policy prop in
                match Solve.check ?emit_smt smt with
                | Solve.Proved -> (Report.Proved, None)
                | Solve.Violated m -> (Report.Violated (lift m), None)
                | Solve.Unknown s -> (Report.Unknown s, None))
          in
          (outcome, None)
      in
      Ok ({ Report.result = outcome;
           property_name = name;
           property_description = description;
           assurance = Some assurance;
           clause;
           frozen_spec = None }, trace))

let run ?emit_smt ~property config =
  match run_with_trace ?emit_smt ~property config with
  | Ok (report, _) -> Ok report
  | Error reason -> Error reason
