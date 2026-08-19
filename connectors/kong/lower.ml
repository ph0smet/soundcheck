(* Lower a Kong config into the shared decision IR.

   Semantics (v0): each route becomes an Allow rule guarded by its path(s),
   method(s), and — if an authentication plugin is attached to the route or its
   service — a [Requires_auth] condition. Unmatched requests fall through to the
   default [Deny]. This models "a request can reach a route iff it matches and
   satisfies that route's auth requirement". *)

open Soundcheck_core

(* Kong authentication plugins: presence means the route is not anonymous. *)
let auth_plugins =
  [ "key-auth"; "key-auth-enc"; "jwt"; "basic-auth"; "oauth2"; "hmac-auth";
    "ldap-auth"; "ldap-auth-advanced"; "openid-connect"; "mtls-auth" ]

let is_auth_plugin (name : string) = List.mem name auth_plugins

let requires_auth (service : Ast.service) (route : Ast.route) : bool =
  let has ps =
    List.exists (fun (p : Ast.plugin) -> p.enabled && is_auth_plugin p.name) ps
  in
  has route.plugins || has service.plugins

(* Kong rate-limiting / throttling plugins. *)
let rate_limit_plugins =
  [ "rate-limiting"; "rate-limiting-advanced"; "response-ratelimiting";
    "graphql-rate-limiting-advanced" ]

let is_rate_limit_plugin (name : string) = List.mem name rate_limit_plugins

let rate_limited (service : Ast.service) (route : Ast.route) : bool =
  let has ps =
    List.exists (fun (p : Ast.plugin) -> p.enabled && is_rate_limit_plugin p.name) ps
  in
  has route.plugins || has service.plugins

(* Routing criteria only: which requests this route is a candidate to serve.
   Policy (auth) is deliberately NOT folded in — see {!Ir.rule}. *)
let match_condition (path : string option) (route : Ast.route) : Ir.condition =
  let path_c = match path with None -> Ir.True | Some p -> Ir.Path_prefix p in
  let method_c =
    match route.methods with
    | [] -> Ir.True
    | ms -> Ir.Or (List.map (fun m -> Ir.Method_is m) ms)
  in
  Ir.And [ path_c; method_c ]

let guard_condition (service : Ast.service) (route : Ast.route) : Ir.condition =
  if requires_auth service route then Ir.Requires_auth else Ir.True

(* Kong's traditional router prefers the LONGER prefix, so path length is a
   priority we can justify. Its other ranking inputs (number of match criteria,
   and regex_priority for regex routes, which we reject outright) are NOT modelled
   here: guessing an order we do not know would be unsound, whereas leaving rules
   tied is always safe because ties degrade to a union. A route with no paths
   matches everything and is therefore the weakest possible candidate. *)
let priority_of_path = function None -> 0 | Some p -> String.length p

(* One IR rule per (route, path) rather than per route. A Kong route may carry
   several paths of different lengths, which would leave a single rule with no
   well-defined priority. Splitting keeps priority exact, and is behaviour-
   preserving under the current flat-OR encoder since (or (or p1 p2)) = (or p1 p2).
   Both rules keep the route's name as [id], so counterexample lifting is
   unaffected. *)
let rules_of_route (service : Ast.service) (route : Ast.route) : Ir.rule list =
  let paths =
    match route.paths with [] -> [ None ] | ps -> List.map (fun p -> Some p) ps
  in
  let guard = guard_condition service route in
  let rate_limited = rate_limited service route in
  List.map
    (fun path : Ir.rule ->
      { id = route.name;
        match_ = match_condition path route;
        guard;
        priority = priority_of_path path;
        decision = Ir.Allow;
        rate_limited })
    paths

let to_policy (cfg : Ast.config) : Ir.policy =
  let rules =
    List.concat_map
      (fun (service : Ast.service) ->
        List.concat_map (rules_of_route service) service.routes)
      cfg.services
  in
  { rules; default = Ir.Deny }
