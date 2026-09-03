(* Lift an abstract SMT counterexample back into Kong's own vocabulary, so the
   finding is actionable in the user's config terms rather than solver terms. *)

open Soundcheck_core

(* The route (and its service) serving [path] that is the culprit for the finding
   — i.e. the one the solver's model exploited. [culprit] captures what makes a
   path-matching route the offender: for no-anonymous-access it is "not requiring
   auth"; for rate-limit-on-public it is "anonymous-reachable and unthrottled". *)
let offending_route ~culprit (cfg : Ast.config) (path : string)
  : (Ast.service * Ast.route) option =
  List.fold_left
    (fun acc (service : Ast.service) ->
      match acc with
      | Some _ -> acc
      | None ->
        List.fold_left
          (fun acc (route : Ast.route) ->
            match acc with
            | Some _ -> acc
            | None ->
              (* Via {!Lower.path_matches}, so regex routes are recognised here
                 exactly as the encoder models them. *)
              let path_matches =
                route.paths = []
                || List.exists (fun p -> Lower.path_matches p path) route.paths
              in
              if path_matches && culprit service route then Some (service, route)
              else None)
          None service.routes)
    None cfg.services

(* The default culprit / explanation: a path-matching route that does not require
   authentication (the no-anonymous-access story). *)
let no_auth_culprit (service : Ast.service) (route : Ast.route) =
  not (Lower.requires_auth service route)

let no_auth_missing =
  "no authentication plugin is attached to the route or its service."

(* Structured lift: the abstract SMT model rendered into a core
   [Report.counterexample], carrying Kong's route/service vocabulary so the JSON
   contract (and every adapter over it) is actionable in the user's own terms.
   [culprit] selects the offending route and [missing] names what it lacks, so
   the same lift serves different properties (auth vs rate-limiting). *)
let counterexample ?(culprit = no_auth_culprit) ?(missing = no_auth_missing)
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
  match offending_route ~culprit cfg m.path with
  | Some (service, route) ->
    { Report.principal;
      action  = m.method_;
      path    = m.path;
      route   = Some route.name;
      service = Some service.name;
      shadowed_route = None;
      shadowed_service = None;
      host = m.host;
      source_ip = m.src_ip;
      note =
        Printf.sprintf
          "%s%s request %s %s is ALLOWED via route %S (service %S) — %s"
          origin principal meth m.path route.name service.name missing;
    }
  | None ->
    { Report.principal;
      action  = m.method_;
      path    = m.path;
      route   = None;
      service = None;
      shadowed_route = None;
      shadowed_service = None;
      host = m.host;
      source_ip = m.src_ip;
      note =
        Printf.sprintf
          "%s request %s %s is ALLOWED (no matching Kong route identified for \
           lifting)."
          principal meth m.path;
    }

(* Human one-liner, kept as the [note] of the structured lift (no duplication). *)
let lift (cfg : Ast.config) (m : Solve.model) : string =
  (counterexample cfg m).note

(* IR rule ids are Kong route names (a route split across paths keeps its name),
   so this recovers the owning service for the report. *)
let service_of_route (cfg : Ast.config) (route_name : string) : string option =
  List.find_map
    (fun (service : Ast.service) ->
      if List.exists (fun (r : Ast.route) -> r.name = route_name) service.routes
      then Some service.name
      else None)
    cfg.services

(* A functionality counterexample is a required request that is not guaranteed
   to work. Name one possible winner that rejects it when available; otherwise
   the request falls through to the policy's denying default. *)
let functionality_counterexample (cfg : Ast.config) (policy : Ir.policy)
    (m : Solve.model) : Report.counterexample =
  let request : Ir.request =
    { principal = (if m.is_anon then Anonymous else Authenticated "user");
      action = m.method_;
      resource = m.path;
      context = [];
      source = m.src_ip;
      host = m.host }
  in
  let rejecting =
    List.find_opt
      (fun (rule : Ir.rule) ->
        Ir.selected policy request rule
        && (rule.decision = Deny || not (Ir.matches rule.guard request)))
      policy.rules
  in
  let route = Option.map (fun (rule : Ir.rule) -> rule.id) rejecting in
  let service = Option.bind route (service_of_route cfg) in
  let principal = if m.is_anon then "anonymous" else "authenticated" in
  let meth = if m.method_ = "" then "<any-method>" else m.method_ in
  let reason =
    match route with
    | Some name ->
      Printf.sprintf "route %S may serve it and reject it" name
    | None -> "no route serves it, so the denying default applies"
  in
  { Report.principal;
    action = m.method_;
    path = m.path;
    route;
    service;
    shadowed_route = None;
    shadowed_service = None;
    host = m.host;
    source_ip = m.src_ip;
    note =
      Printf.sprintf "%s request %s %s is NOT DEFINITELY ALLOWED — %s."
        principal meth m.path reason }

(* Shadowing names TWO routes: the one that actually serves the request and the
   one written to handle it. Saying only "this request got through" would lose
   the point of the finding, which is that a guard you wrote is not covering what
   it appears to cover. *)
let shadowing_counterexample (cfg : Ast.config) (pair : Shadowing.pair)
    (m : Solve.model) : Report.counterexample =
  let serving = pair.shadowing.Ir.id and written = pair.shadowed.Ir.id in
  let meth = if m.method_ = "" then "<any-method>" else m.method_ in
  (* A tie is a weaker claim than an outranking: the config does not say which
     route wins, so we must not assert that the permissive one does. *)
  let relation =
    if pair.shadowing.Ir.priority > pair.shadowed.Ir.priority then
      Printf.sprintf "outranks route %S written to handle it" written
    else
      Printf.sprintf
        "ties with route %S written to handle it (the config does not determine \
         which wins, so either may serve)"
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
    source_ip = m.src_ip;
    note =
      Printf.sprintf
        "%s %s can be served by route %S, which is more permissive and %s — the \
         guard on %S does not apply to this request."
        meth m.path serving relation written;
  }
