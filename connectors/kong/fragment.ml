(* The decidability boundary for the Kong connector.

   A Kong route path is either a literal prefix or a regex. Both are now modelled
   — see {!Lower.path_condition}. {!Regex_boundary.parse} restricts the generic
   parser to a bounded language justified across both supported router flavors.
   Regularity alone does not establish faithful PCRE/Unicode-Regex semantics.

   Rejection remains WHOLE-CONFIG rather than per-route, and deliberately so: the
   route we cannot model may be exactly the one that decides the property, so
   verifying the rest and calling the result a proof would be unsound. *)

type finding = {
  service : string;
  route   : string;
  path    : string;
  why     : string;
}

(* Modern Kong uses only '~'. Parse.config_of has already performed the
   version-specific 1.1/2.1 migration. Guessing regex syntax from punctuation in
   modern literal paths is unsound (e.g. literal /a+b does not match /ab). *)
let is_regex_path (p : string) : bool =
  String.length p > 0 && p.[0] = '~'

(* Strip Kong 3.x's explicit marker before handing the pattern to the parser. *)
let pattern_of (p : string) : string =
  if String.length p > 0 && p.[0] = '~' then String.sub p 1 (String.length p - 1)
  else p

let findings (cfg : Ast.config) : finding list =
  let route_findings service (route : Ast.route) =
    List.filter_map
      (fun path ->
        if not (is_regex_path path) then None
        else
          match Regex_boundary.parse (pattern_of path) with
          | Ok _ -> None
          | Error why ->
            Some { service; route = route.name; path; why })
      route.paths
  in
  List.concat_map
    (fun (s : Ast.service) ->
      List.concat_map (route_findings s.name) s.routes)
    cfg.services
  @ (cfg.top_level_routes
    |> List.filter (fun (top : Ast.top_level_route) ->
           top.service = None && not top.unsupported_reference)
    |> List.concat_map (fun (top : Ast.top_level_route) ->
           route_findings "<no-service>" top.route))

let describe (f : finding) =
  Printf.sprintf "route %S (service %S) path %S — %s" f.route f.service f.path
    f.why

(* Name every offender: the point of [unknown] is that the user can act on it, and
   a config stays unverifiable until each one is rewritten. *)
let reason (fs : finding list) : string =
  Printf.sprintf
    "unsupported fragment: %d route path(s) use regex constructs outside the \
     supported subset, so no verdict can be given for this config. %s. Rewriting \
     the path within the bounded shared subset (ASCII literals, positive ASCII \
     classes, grouping, grouped alternation and bounded quantifiers) permits \
     conservative verification; inspect `soundcheck profile kong` for limits."
    (List.length fs)
    (String.concat "; " (List.map describe fs))

let check (cfg : Ast.config) : (unit, string) result =
  match List.find_opt
      (fun (plugin : Ast.plugin) ->
        Plugin_support.active_http plugin && not (Plugin_support.known plugin.name))
      (Plugin_support.all cfg) with
  | Some plugin ->
    Error (Printf.sprintf
      "unsupported fragment: plugin %S has unmodeled behavior; it may alter routing, guards, or upstream targets"
      plugin.name)
  | None ->
  match List.find_opt
      (fun (plugin : Ast.plugin) -> plugin.has_relationships)
      (Plugin_support.nested cfg) with
  | Some plugin ->
    Error (Printf.sprintf
      "unsupported fragment: nested plugin %S has explicit relationships that are not resolved"
      plugin.name)
  | None ->
  match
    List.find_opt
      (fun (top : Ast.top_level_route) -> top.unsupported_reference)
      cfg.top_level_routes
  with
  | Some top ->
    Error
      (Printf.sprintf
         "unsupported fragment: top-level route %S uses a non-string service reference"
         top.route.name)
  | None ->
    (match
      List.find_opt
        (fun (scoped : Ast.scoped_plugin) ->
          scoped.consumer_scoped || scoped.unsupported_reference)
        cfg.scoped_plugins
    with
    | Some scoped ->
      Error
        (Printf.sprintf
           "unsupported fragment: root-level plugin %S uses a consumer scope or non-string route/service reference"
           scoped.plugin.name)
     | None ->
       (match findings cfg with [] -> Ok () | fs -> Error (reason fs)))
