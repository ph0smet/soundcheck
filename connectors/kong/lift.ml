(* Lift an abstract SMT counterexample back into Kong's own vocabulary, so the
   finding is actionable in the user's config terms rather than solver terms. *)

open Soundcheck_core

let starts_with ~prefix s =
  let lp = String.length prefix in
  String.length s >= lp && String.sub s 0 lp = prefix

(* The route (and its service) that would serve [path] without requiring auth —
   i.e. the one enabling the anonymous access the solver found. *)
let offending_route (cfg : Ast.config) (path : string)
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
              let path_matches =
                route.paths = []
                || List.exists (fun pre -> starts_with ~prefix:pre path) route.paths
              in
              if path_matches && not (Lower.requires_auth service route) then
                Some (service, route)
              else None)
          None service.routes)
    None cfg.services

(* Structured lift: the abstract SMT model rendered into a core
   [Report.counterexample], carrying Kong's route/service vocabulary so the JSON
   contract (and every adapter over it) is actionable in the user's own terms. *)
let counterexample (cfg : Ast.config) (m : Solve.model) : Report.counterexample =
  let principal = if m.is_anon then "anonymous" else "authenticated" in
  let meth = if m.method_ = "" then "<any-method>" else m.method_ in
  match offending_route cfg m.path with
  | Some (service, route) ->
    { Report.principal;
      action  = m.method_;
      path    = m.path;
      route   = Some route.name;
      service = Some service.name;
      note =
        Printf.sprintf
          "%s request %s %s is ALLOWED via route %S (service %S) — no \
           authentication plugin is attached to the route or its service."
          principal meth m.path route.name service.name;
    }
  | None ->
    { Report.principal;
      action  = m.method_;
      path    = m.path;
      route   = None;
      service = None;
      note =
        Printf.sprintf
          "%s request %s %s is ALLOWED (no matching Kong route identified for \
           lifting)."
          principal meth m.path;
    }

(* Human one-liner, kept as the [note] of the structured lift (no duplication). *)
let lift (cfg : Ast.config) (m : Solve.model) : string =
  (counterexample cfg m).note
