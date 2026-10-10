(* Lift an abstract SMT counterexample back into Kong's own vocabulary, so the
   finding is actionable in the user's config terms rather than solver terms. *)

open Soundcheck_core

(* A candidate must satisfy the actual modeled routing/guard relation, including
   method, host, headers, SNI, strict precedence and the property's structural
   filter. A path-only AST search can name a route that cannot serve the witness. *)
let offending_rule ~reach_via (cfg : Ast.config) (model : Solve.model) =
  let policy = Lower.to_policy cfg in
  let request = Witness.request_of_model model in
  if not (Ir.matches policy.request_domain request) then None
  else
    List.find_opt
      (fun (rule : Ir.rule) ->
        rule.decision = Ir.Allow && reach_via rule
        && Ir.selected policy request rule && Ir.matches rule.guard request)
      policy.rules

(* Display names are not entity identities. If several entities share a name,
   do not invent a service owner by choosing the first AST occurrence. *)
let service_of_route (cfg : Ast.config) route_name =
  let owners =
    List.concat_map
      (fun (service : Ast.service) ->
        List.filter_map
          (fun (route : Ast.route) ->
            if route.name = route_name then Some (Some service.name) else None)
          service.routes)
      cfg.services
    @ List.filter_map
        (fun (top : Ast.top_level_route) ->
          if top.service = None && not top.unsupported_reference
             && top.route.name = route_name then Some None else None)
        cfg.top_level_routes
  in
  match owners with [owner] -> owner | _ -> None

let modeled_allowance =
  "the modeled guard permits this forbidden request."

let headers_note headers =
  match headers with
  | [] -> ""
  | entries ->
    entries
    |> List.map (fun (name, value) -> Printf.sprintf "%s: %s" name value)
    |> String.concat ", " |> Printf.sprintf " with header(s) %s"

let transport_note (model : Solve.model) =
  match model.scheme, model.sni with
  | "", "" -> ""
  | scheme, "" -> Printf.sprintf " over %s" scheme
  | scheme, sni -> Printf.sprintf " over %s with SNI %s" scheme sni

(* Structured lift: the abstract SMT model rendered into a core
   [Report.counterexample], carrying Kong's route/service vocabulary so the JSON
   contract (and every adapter over it) is actionable in the user's own terms.
   [reach_via] selects the eligible rule and [missing] explains the property, so
   the same lift serves different properties (auth vs rate-limiting). *)
let counterexample ?(reach_via = fun _ -> true) ?(missing = modeled_allowance)
    ?(show_source = false) (cfg : Ast.config) (m : Solve.model) :
    Report.counterexample =
  let principal = if m.is_anon then "anonymous" else "authenticated" in
  (* [show_source] adds the address to the human note only, for properties whose
     whole point is WHERE the request came from. It must not touch [principal]:
     that is a structured field with its own vocabulary. Naming an address the
     property never constrained would be noise, since the solver picked it
     freely. *)
  let origin =
    if show_source then Printf.sprintf "from %s, " (Cidr.string_of_ip m.src_ip)
    else ""
  in
  let meth = if m.method_ = "" then "<any-method>" else m.method_ in
  let headers = headers_note m.headers in
  let transport = transport_note m in
  let candidate = offending_rule ~reach_via cfg m in
  let route = Option.map (fun (rule : Ir.rule) -> rule.id) candidate in
  let service = Option.bind route (service_of_route cfg) in
  let via =
    match route, service with
    | Some route, Some service -> Printf.sprintf "route %S (service %S)" route service
    | Some route, None ->
      Printf.sprintf "route %S (service ownership is absent or ambiguous)" route
    | None, _ -> "the modeled policy (no eligible route identified for lifting)"
  in
  { Report.principal;
    action = m.method_;
    path = m.path;
    route;
    service;
    shadowed_route = None;
    shadowed_service = None;
    host = m.host;
    scheme = m.scheme;
    sni = m.sni;
    source_ip = m.src_ip;
    headers = m.headers;
    note =
      Printf.sprintf
        "Conservative model-level candidate, not a guaranteed target replay: \
         %s%s request %s %s%s%s may be ALLOWED via %s — %s"
        origin principal meth m.path transport headers via missing }

(* Human one-liner, kept as the [note] of the structured lift (no duplication). *)
let lift (cfg : Ast.config) (m : Solve.model) : string =
  (counterexample cfg m).note

(* A functionality counterexample is a required request that is not guaranteed
   to work. A possible winner with an incomplete match/guard does not establish
   definite allowance, even if its upper-bound guard admits the request. Do not
   conflate that uncertainty with absence of a route. *)
let functionality_counterexample ?(show_source = false) (cfg : Ast.config)
    (policy : Ir.policy) (m : Solve.model) : Report.counterexample =
  let request = Witness.request_of_model m in
  let rejecting =
    List.find_opt
      (fun (rule : Ir.rule) ->
        Ir.selected policy request rule
        && (not rule.match_complete || not rule.guard_complete
            || rule.decision = Deny || not (Ir.matches rule.guard request)))
      policy.rules
  in
  let route = Option.map (fun (rule : Ir.rule) -> rule.id) rejecting in
  let service = Option.bind route (service_of_route cfg) in
  let principal = if m.is_anon then "anonymous" else "authenticated" in
  let origin =
    if show_source then Printf.sprintf " from %s" (Cidr.string_of_ip m.src_ip)
    else ""
  in
  let meth = if m.method_ = "" then "<any-method>" else m.method_ in
  let headers = headers_note m.headers in
  let transport = transport_note m in
  let reason =
    match rejecting with
    | Some rule when not rule.match_complete ->
      Printf.sprintf
        "route %S has an incomplete modeled match, so its selection and allowance are not guaranteed"
        rule.id
    | Some rule when not rule.guard_complete ->
      Printf.sprintf
        "route %S has an incomplete modeled guard, so allowance is not guaranteed"
        rule.id
    | Some rule ->
      Printf.sprintf "route %S may serve it and reject it in the model" rule.id
    | None -> "no modeled route serves it, so the denying default applies"
  in
  { Report.principal;
    action = m.method_;
    path = m.path;
    route;
    service;
    shadowed_route = None;
    shadowed_service = None;
    host = m.host;
    scheme = m.scheme;
    sni = m.sni;
    source_ip = m.src_ip;
    headers = m.headers;
    note =
      Printf.sprintf
        "Conservative model-level candidate, not a guaranteed target replay: \
         %s request%s %s %s%s%s is NOT DEFINITELY ALLOWED — %s."
        principal origin meth m.path transport headers reason }

(* Shadowing names two modeled routes: a possible permissive winner and the
   more restrictive route written to handle the same request. Neither possible
   selection nor incomplete guard coverage is a guaranteed target execution. *)
let shadowing_counterexample (cfg : Ast.config) (pair : Shadowing.pair)
    (m : Solve.model) : Report.counterexample =
  let serving = pair.shadowing.Ir.id and written = pair.shadowed.Ir.id in
  let meth = if m.method_ = "" then "<any-method>" else m.method_ in
  (* Equal and incomparable priority keys both leave the order unresolved.
     OCaml's structural record ordering is not the modeled outranks relation. *)
  let relation =
    if Ir.outranks pair.shadowing.Ir.priority pair.shadowed.Ir.priority then
      Printf.sprintf "outranks route %S written to handle it" written
    else
      Printf.sprintf
        "has unresolved order with route %S written to handle it (either may serve in the model)"
        written
  in
  { Report.principal = (if m.is_anon then "anonymous" else "authenticated");
    action = m.method_;
    path = m.path;
    route = Some serving;
    service = service_of_route cfg serving;
    shadowed_route = Some written;
    shadowed_service = service_of_route cfg written;
    host = m.host;
    scheme = m.scheme;
    sni = m.sni;
    source_ip = m.src_ip;
    headers = m.headers;
    note =
      Printf.sprintf
        "Conservative model-level candidate, not a guaranteed target replay: \
         %s %s may be served by route %S, which is more permissive and %s — the \
         modeled guard on %S does not establish protection for this request."
        meth m.path serving relation written;
  }
