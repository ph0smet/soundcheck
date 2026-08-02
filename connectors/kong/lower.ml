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

let route_condition (service : Ast.service) (route : Ast.route) : Ir.condition =
  let path_c =
    match route.paths with
    | [] -> Ir.True
    | ps -> Ir.Or (List.map (fun p -> Ir.Path_prefix p) ps)
  in
  let method_c =
    match route.methods with
    | [] -> Ir.True
    | ms -> Ir.Or (List.map (fun m -> Ir.Method_is m) ms)
  in
  let auth_c = if requires_auth service route then Ir.Requires_auth else Ir.True in
  Ir.And [ path_c; method_c; auth_c ]

let to_policy (cfg : Ast.config) : Ir.policy =
  let rules =
    List.concat_map
      (fun (service : Ast.service) ->
        List.map
          (fun (route : Ast.route) : Ir.rule ->
            { id = route.name;
              when_ = route_condition service route;
              decision = Ir.Allow;
              rate_limited = rate_limited service route })
          service.routes)
      cfg.services
  in
  { rules; default = Ir.Deny }
