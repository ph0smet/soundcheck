(* Shared recognition boundary, independent of lowering and assurance output. *)
let auth =
  [ "key-auth"; "key-auth-enc"; "jwt"; "basic-auth"; "oauth2"; "hmac-auth";
    "ldap-auth"; "ldap-auth-advanced"; "openid-connect"; "mtls-auth" ]

let general_rate_limit = [ "rate-limiting"; "rate-limiting-advanced" ]
let specialized_rate_limit = [ "response-ratelimiting"; "graphql-rate-limiting-advanced" ]

let known name =
  List.mem name (auth @ general_rate_limit @ specialized_rate_limit)
  || name = "ip-restriction" || name = "request-termination"

let active_http (plugin : Ast.plugin) =
  plugin.enabled
  && List.exists (fun protocol -> List.mem protocol [ "http"; "https"; "grpc"; "grpcs" ])
       plugin.protocols

let nested (cfg : Ast.config) =
  List.concat_map
    (fun (service : Ast.service) ->
      service.plugins @ List.concat_map (fun (route : Ast.route) -> route.plugins) service.routes)
    cfg.services
  @ List.concat_map (fun (top : Ast.top_level_route) -> top.route.plugins) cfg.top_level_routes

let all cfg =
  cfg.Ast.global_plugins
  @ List.map (fun (scoped : Ast.scoped_plugin) -> scoped.plugin) cfg.scoped_plugins
  @ nested cfg
