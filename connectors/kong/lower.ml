(* Lower a Kong config into the shared decision IR.

   Semantics (v0): each route becomes an Allow rule guarded by its path(s),
   method(s), and — if an authentication plugin is attached to the route or its
   service — a [Requires_auth] condition. Unmatched requests fall through to the
   default [Deny]. This models "a request can reach a route iff it matches and
   satisfies that route's auth requirement". *)

open Soundcheck_core

(* Kong authentication plugins: presence means the route is not anonymous. *)
let auth_plugins = Plugin_support.auth

let is_auth_plugin (name : string) = List.mem name auth_plugins

let http_plugin = Plugin_support.active_http

(* Kong executes at most one configuration for a given plugin name. The most
   specific enabled entity wins: route, then service, then global. A disabled
   entity is not loaded and therefore does not hide a less-specific enabled
   configuration. *)
let effective_plugin (config : Ast.config) name (service : Ast.service)
    (route : Ast.route) =
  let find plugins =
    List.find_opt
      (fun (plugin : Ast.plugin) -> http_plugin plugin && plugin.name = name)
      plugins
  in
  let find_scoped service_ref route_ref =
    List.find_map
      (fun (scoped : Ast.scoped_plugin) ->
        if
          scoped.service = service_ref && scoped.route = route_ref
          && not scoped.consumer_scoped
          && not scoped.unsupported_reference
          && http_plugin scoped.plugin && scoped.plugin.name = name
        then Some scoped.plugin
        else None)
      config.scoped_plugins
  in
  match find_scoped (Some service.name) (Some route.name) with
  | Some plugin -> Some plugin
  | None ->
    (match find route.plugins with
     | Some plugin -> Some plugin
     | None ->
       (match find_scoped None (Some route.name) with
        | Some plugin -> Some plugin
        | None ->
          (match find service.plugins with
           | Some plugin -> Some plugin
           | None ->
             (match find_scoped (Some service.name) None with
              | Some plugin -> Some plugin
              | None -> find config.global_plugins))))

let supports_preflight_bypass = function
  | "key-auth" | "jwt" -> true
  | _ -> false

let requires_auth config (service : Ast.service) (route : Ast.route) =
  List.exists
    (fun name ->
      match effective_plugin config name service route with
      | Some plugin ->
        not plugin.anonymous_fallback
        && (plugin.run_on_preflight || not (supports_preflight_bypass name))
      | None -> false)
    auth_plugins

let auth_condition config (service : Ast.service) (route : Ast.route) =
  let conditions =
    List.filter_map
      (fun name ->
        match effective_plugin config name service route with
        | None -> None
        | Some plugin when plugin.anonymous_fallback -> None
        | Some plugin
          when supports_preflight_bypass name && not plugin.run_on_preflight ->
          Some (Ir.Or [ Ir.Requires_auth; Ir.Method_is "OPTIONS" ])
        | Some _ -> Some Ir.Requires_auth)
      auth_plugins
  in
  match conditions with [] -> Ir.True | [ condition ] -> condition | _ -> Ir.And conditions

(* General request-rate plugins cover every request that reaches the route.
   Response and GraphQL rate limiting are deliberately separate: the former
   depends on upstream usage headers, while the latter covers GraphQL query
   cost rather than arbitrary HTTP traffic. *)
let general_rate_limit_plugins = Plugin_support.general_rate_limit

let specialized_rate_limit_plugins = Plugin_support.specialized_rate_limit

let is_general_rate_limit_plugin name =
  List.mem name general_rate_limit_plugins

let is_specialized_rate_limit_plugin name =
  List.mem name specialized_rate_limit_plugins

let is_rate_limit_plugin name =
  is_general_rate_limit_plugin name || is_specialized_rate_limit_plugin name

let is_known_plugin = Plugin_support.known

let effective_plugins config service route =
  config.Ast.global_plugins @ service.Ast.plugins @ route.Ast.plugins
  @ List.map (fun (scoped : Ast.scoped_plugin) -> scoped.plugin) config.scoped_plugins
  |> List.map (fun (plugin : Ast.plugin) -> plugin.name)
  |> List.sort_uniq String.compare
  |> List.filter_map (fun name -> effective_plugin config name service route)

let guard_complete config service route =
  effective_plugins config service route
  |> List.for_all (fun (plugin : Ast.plugin) ->
       is_known_plugin plugin.name
       && not (is_rate_limit_plugin plugin.name)
       && not plugin.anonymous_fallback
       && (plugin.name <> "request-termination" || plugin.trigger = None)
       && (plugin.name <> "ip-restriction"
           || List.for_all (fun value -> Result.is_ok (Cidr.parse value))
                (plugin.allow @ plugin.deny)))

let rate_limited config (service : Ast.service) (route : Ast.route) : bool =
  List.exists
    (fun name -> Option.is_some (effective_plugin config name service route))
    general_rate_limit_plugins

let request_termination config (service : Ast.service) (route : Ast.route) =
  effective_plugin config "request-termination" service route

(* One route path as an IR condition.

   ANCHORING (established from Kong's router source, and the reason this is not a
   guess): a regex path is anchored at the START but not at the end. The
   traditional router matches with ngx.re's "a" flag (PCRE_ANCHORED), and the
   traditional_compatible translation prepends "^" with a comment saying it does
   so "to match the anchored behavior of the traditional router". So the pattern
   must match a PREFIX of the request path — hence [Star Any] appended, unless the
   author wrote a trailing [$], which pins the end.

   A literal path stays [Path_prefix]: it is provably the same language as the
   equivalent regex (z3: [str.prefixof p path] = [str.in_re path (re.++ p re.all)])
   but [str.prefixof] is the cheaper encoding, and literal paths are the common
   case by a wide margin. *)
let path_condition (p : string) : Ir.condition =
  if not (Fragment.is_regex_path p) then Ir.Path_prefix p
  else
    match Regex_boundary.parse (Fragment.pattern_of p) with
    | Error _ ->
      (* {!Fragment.check} runs before lowering and rejects these, so this is
         unreachable; fall back to the sound reading rather than raise. *)
      Ir.True
    | Ok { re; anchored_end } ->
      Ir.Path_regex (if anchored_end then re else Regex.Concat [ re; Regex.Star Regex.Any ])

(* Does a Kong path match a concrete request path? Defined via {!path_condition}
   so counterexample lifting cannot drift from the encoding: a lifter comparing
   prefixes by hand would silently fail to recognise regex routes and report a
   finding with no route attached. *)
let path_matches (kong_path : string) (concrete : string) : bool =
  Ir.matches (path_condition kong_path)
    { Ir.principal = Ir.Anonymous; action = ""; resource = concrete;
      context = []; source = 0l; host = ""; scheme = "http"; sni = "" }

(* Kong compiles a host pattern to a regex at load time and matches it against the
   request Host. Transcribed from kong/router/traditional.lua:

     wildcard_host_regex = host:gsub("%.", "\\."):gsub("%*", ".+") .. "$"
     -- and, when the pattern carries no port:
     wildcard_host_regex = wildcard_host_regex:gsub("%$$", "(?::\\d+)?$")
     re_find(host_with_port, wildcard_host_regex, "ajo")

   Four things that follow, none of them guessable from the docs:

   - traditional uses [.+], but matches a host with a synthesized default port;
     compatible uses prefix/suffix string matching with a possibly empty wildcard.
     The shared upper bound therefore uses [.*] and is never a complete match.
   - dots are literal, not "any character".
   - the "a" flag anchors the match at the START, and the pattern ends in [$], so
     a wildcard host is anchored at BOTH ends. (Contrast a regex PATH, where only
     the start is anchored.)
   - a pattern without a port still matches a Host that carries one, via the
     appended optional [(?::\d+)?].

   A PLAIN host is an exact table lookup against both the raw Host and the Host
   with its port stripped. Unlike wildcard matching, this final lookup does not
   use the synthesized host_with_port. Compatible routing can instead match an
   explicit route port against the effective destination port. Portless plain
   patterns share the literal-plus-optional-port language; port-bearing patterns
   remain incomplete below. *)
let host_condition (hosts : string list) : Ir.condition option =
  let port_suffix =
    (* (?::\d+)? — an optional ":" followed by one or more digits *)
    Regex.Opt (Regex.Concat [ Regex.Lit ":"; Regex.Plus (Regex.Class (false, [ ('0', '9') ])) ])
  in
  let of_host (h : string) : Ir.condition =
    let has_port = String.contains h ':' in
    (* Request.host does not encode Kong compatible's effective Host port. An
       omitted raw port can match an explicit route :80/:443; raw equality would
       underapproximate. Keep the whole host unconstrained until modeled. *)
    if has_port then Ir.True else
    (* Split on '*': literals stay literal; the wildcard may be empty. *)
    let parts = String.split_on_char '*' h in
    let rec interleave = function
      | [] -> []
      | [ last ] -> [ Regex.Lit last ]
      | p :: rest -> Regex.Lit p :: Regex.Star Regex.Any :: interleave rest
    in
    let body = Regex.Concat (interleave parts) in
    let re = Regex.Concat [ body; port_suffix ] in
    Ir.Host_matches re
  in
  match hosts with [] -> None | hs -> Some (Ir.Or (List.map of_host hs))

(* Traditional recognizes regex only for singleton header-value lists; the
   compatible transformer recognizes each ~* value, including mixed lists.
   The shared model must not treat such a list as exact literal equality. *)
let is_header_regex values =
  List.exists (String.starts_with ~prefix:"~*") values

let routable_headers (route : Ast.route) =
  List.filter
    (fun (name, _) -> String.lowercase_ascii name <> "host")
    route.headers

let header_condition (route : Ast.route) : Ir.condition option =
  let exact =
    routable_headers route
    |> List.filter (fun (_, values) -> not (is_header_regex values))
    |> List.map (fun (name, values) ->
           let name = String.lowercase_ascii name in
           Ir.Or
             (List.map
                (fun value -> Ir.Header_has (name, String.lowercase_ascii value))
                values))
  in
  match exact with [] -> None | conditions -> Some (Ir.And conditions)

let normalized_sni value =
  let length = String.length value in
  if length > 1 && value.[length - 1] = '.' then
    String.sub value 0 (length - 1)
  else value

let has_wildcard_sni (route : Ast.route) =
  List.exists (fun sni -> String.contains sni '*') route.snis

type sni_variant = Unscoped | Http_ignores_sni | Https_sni

let sni_condition (variant : sni_variant) (route : Ast.route) : Ir.condition option =
  match variant with
  | Unscoped -> None
  | Http_ignores_sni -> Some (Ir.Scheme_is "http")
  | Https_sni when has_wildcard_sni route -> Some (Ir.Scheme_is "https")
  | Https_sni ->
    Some
      (Ir.And
         [ Ir.Scheme_is "https";
           Ir.Or
             (List.map (fun sni -> Ir.Sni_is (normalized_sni sni)) route.snis) ])

(* Routing criteria only: which requests this route is a candidate to serve.
   Policy (auth) is deliberately NOT folded in — see {!Ir.rule}. *)
let match_condition (variant : sni_variant) (path : string option)
    (route : Ast.route) : Ir.condition =
  let path_c = match path with None -> Ir.True | Some p -> path_condition p in
  let method_c =
    match route.methods with
    | [] -> Ir.True
    | ms -> Ir.Or (List.map (fun m -> Ir.Method_is m) ms)
  in
  let host_c = host_condition route.hosts in
  let header_c = header_condition route in
  let sni_c = sni_condition variant route in
  Ir.And
    (List.filter_map Fun.id
       [ Some path_c; Some method_c; host_c; header_c; sni_c ])

(* Kong's Admin API listens on 8001 (http) and 8444 (https) by default. A service
   whose upstream is that port is proxying the Admin API through the public proxy
   — the classic Kong footgun this property exists to catch.

   Port-based recognition is a known-name lookup in the same spirit as the plugin
   lists, and errs the same way: an unusual admin port is NOT recognised, so such
   a route is treated as ordinary and the property stays quiet about it. That is
   the false-negative direction for THIS property, which is why the port list is
   documented rather than buried. *)
let admin_ports = [ "8001"; "8444" ]

let targets_admin_api (service : Ast.service) : bool =
  match service.url with
  | None ->
    (* The entity schema defaults an omitted explicit port to 80. URL shorthand
       is handled separately because Kong's non-deprecated shorthand overrides
       explicit fields (schema/init.lua process_auto_fields). *)
    Option.fold ~none:false
      ~some:(fun port -> List.mem (string_of_int port) admin_ports) service.port
  | Some url ->
  (* Kong's services.lua shorthand uses socket.url.parse and tonumber on the
     parsed port. Handle scheme-relative authorities and fragments, and compare
     the numeric port: leading zeros do not change the upstream endpoint.
     This remains the documented default-Admin-port heuristic, not a general
     URL/schema validator or a claim about custom Admin API listeners. *)
  let after_scheme =
    if String.starts_with ~prefix:"//" url then
      String.sub url 2 (String.length url - 2)
    else match String.index_opt url ':' with
    | Some i when i + 3 <= String.length url && String.sub url i 3 = "://" ->
      String.sub url (i + 3) (String.length url - i - 3)
    | _ -> ""
  in
  let authority =
    let rec finish i =
      if i = String.length after_scheme then i
      else
        match after_scheme.[i] with
        (* LuaSocket 3.0-rc1 extracts authority before query, so a query without
           a preceding slash is part of the port and fails Kong's schema. *)
        | '/' | '#' -> i
        | _ -> finish (i + 1)
    in
    String.sub after_scheme 0 (finish 0)
  in
  match String.rindex_opt authority ':' with
  | None -> false
  | Some i ->
    let port = String.sub authority (i + 1) (String.length authority - i - 1) in
    (match float_of_string_opt (String.trim port) with
     | Some value -> value = 8001. || value = 8444.
     | None -> false)

(* ip-restriction as a policy guard: it runs after routing, so it constrains who
   may be served, not which route serves.

   Kong checks DENY FIRST (a listed address is refused outright), then treats
   ALLOW as a whitelist (when non-empty, anything unlisted is refused). An address
   that fails to parse — IPv6, or malformed — is dropped from the condition, which
   WEAKENS the guard and therefore over-reports rather than proving too much. *)
let cidrs_of (entries : string list) : Ir.condition list =
  List.filter_map
    (fun e -> match Cidr.parse e with Ok c -> Some (Ir.Source_in c) | Error _ -> None)
    entries

let ip_restriction_condition config (service : Ast.service) (route : Ast.route) :
    Ir.condition =
  let plugins =
    Option.to_list (effective_plugin config "ip-restriction" service route)
  in
  let conds =
    List.concat_map
      (fun (p : Ast.plugin) ->
        let denied = cidrs_of p.deny in
        let allowed = cidrs_of p.allow in
        (if denied = [] then [] else [ Ir.Not (Ir.Or denied) ])
        @ if allowed = [] || List.length allowed <> List.length p.allow then []
          else [ Ir.Or allowed ])
      plugins
  in
  match conds with [] -> Ir.True | cs -> Ir.And cs

let guard_condition config (service : Ast.service) (route : Ast.route) : Ir.condition =
  if List.exists (fun (plugin : Ast.plugin) -> not (is_known_plugin plugin.name))
       (effective_plugins config service route)
  then Ir.True
  else
  let auth = auth_condition config service route in
  let protocol =
    if List.mem "https" route.protocols && not (List.mem "http" route.protocols)
    then Ir.Scheme_is "https"
    else Ir.True
  in
  let termination =
    match request_termination config service route with
    | Some { trigger = None; _ } -> Ir.Or []
    | Some { trigger = Some _; _ } | None -> Ir.True
  in
  match
    List.filter (fun c -> c <> Ir.True)
      [ protocol; auth; ip_restriction_condition config service route; termination ]
  with
  | [] -> Ir.True
  | [ c ] -> c
  | cs -> Ir.And cs

(* A shared partial order, not a transcription of only traditional's sort.
   Both flavors first compare criterion counts. At equal counts their category,
   host/header, and regex tiebreaks differ; traditional also reduces candidates
   using a request-dependent global URI/header hit before its full category scan.
   Detailed path order is used only with globally identical non-path predicates.
   Unresolved cases stay tied; SNI variants and regex runtime matches stay
   incomparable. Pinned basis: traditional.lua sort_categories/reduce/exec and
   transform.lua get_priority/split_routes_and_services, Kong 3.9.3. *)

let active_routes (config : Ast.config) =
  let http (route : Ast.route) =
    List.exists (fun p -> p = "http" || p = "https") route.protocols
  in
  (List.concat_map
     (fun (service : Ast.service) -> if service.enabled then service.routes else [])
     config.services
   @ List.filter_map
       (fun (top : Ast.top_level_route) ->
         if top.service = None && not top.unsupported_reference then Some top.route else None)
       config.top_level_routes)
  |> List.filter http

let detailed_path_order config =
  let signature (route : Ast.route) =
    (route.methods, route.hosts_present, route.hosts, route.headers, route.snis,
     route.protocols, route.has_sources_or_destinations)
  in
  match active_routes config with
  | [] -> true
  | first :: rest -> List.for_all (fun route -> signature route = signature first) rest

let unmodelled_match (variant : sni_variant) (route : Ast.route) : bool =
  route.has_sources_or_destinations
  || (variant = Https_sni && has_wildcard_sni route)
  || List.exists (fun (_, values) -> is_header_regex values) (routable_headers route)
  || List.exists (fun h -> String.lowercase_ascii h <> h) route.hosts
  || List.exists (fun h -> String.contains h ':' || String.contains h '*') route.hosts

let priority_of ?(detailed = false) ~(regex_priority : int) ~(include_sni : bool)
    (route : Ast.route) (path : string option) : Ir.priority =
  let match_weight =
    List.length (List.filter Fun.id
      [ path <> None; route.methods <> []; route.hosts <> [];
        routable_headers route <> []; include_sni ])
  in
  let is_regex = Option.fold ~none:false ~some:Fragment.is_regex_path path in
  let uri_length =
    match path with Some p when not is_regex -> String.length p | _ -> 0
  in
  (* Compatible packs regex_priority into 32 bits and literal length into 19.
     Values outside this justified domain must not contaminate count ordering. *)
  let comparable =
    regex_priority >= 0 && Int64.of_int regex_priority <= 0xffffffffL
    && uri_length <= 0x7ffff && route.snis = []
  in
  { Ir.comparable;
    key = if detailed then
      [ match_weight; (if is_regex then 1 else 0);
        (if is_regex then regex_priority else 0); uri_length ]
    else [ match_weight; 0; 0; 0 ] }

(* One IR rule per (route, path) rather than per route. A Kong route may carry
   several paths of different lengths, which would leave a single rule with no
   well-defined priority. Both pinned routers split paths before ordering;
   compatible groups regex paths / same-length prefixes. Only the justified
   common partial order above is retained. Variants keep one entity identity. *)
let rules_of_route ?(decision = Ir.Allow) config (service : Ast.service)
    (route : Ast.route) : Ir.rule list =
  if
    not
      (List.exists
         (fun protocol -> protocol = "http" || protocol = "https")
         route.protocols)
  then []
  else
  let paths =
    match route.paths with [] -> [ None ] | ps -> List.map (fun p -> Some p) ps
  in
  let guard = guard_condition config service route in
  let guard_complete = guard_complete config service route in
  let rate_limited = rate_limited config service route in
  let targets_admin = targets_admin_api service in
  let variants =
    if route.snis = [] then [ Unscoped ]
    else [ Http_ignores_sni; Https_sni ]
  in
  List.concat_map
    (fun path ->
      List.map
        (fun variant : Ir.rule ->
          (* PCRE match-limit failures cause Kong to continue to other routes.
             Language membership is therefore only a may-match bound for regex
             routes, even for syntax shared by both flavors. Such a match must
             never suppress another candidate or prove definite functionality. *)
          let regex = Option.fold ~none:false ~some:Fragment.is_regex_path path in
          let match_complete = not regex && not (unmodelled_match variant route) in
          let priority =
            priority_of ~detailed:(detailed_path_order config)
              ~regex_priority:route.regex_priority
              ~include_sni:(variant = Https_sni) route path
          in
          { id = route.name;
            match_ = match_condition variant path route;
            match_complete;
            guard;
            guard_complete;
            priority = { priority with comparable = priority.comparable && match_complete };
            decision;
            rate_limited;
            targets_admin })
        variants)
    paths

let to_policy (cfg : Ast.config) : Ir.policy =
  let service_rules =
    List.concat_map
      (fun (service : Ast.service) ->
        if not service.enabled then []
        else List.concat_map (rules_of_route cfg service) service.routes)
      cfg.services
  in
  let no_service : Ast.service =
    { name = "<no-service>";
      enabled = true;
      url = None;
      protocol = None;
      host = None;
      port = None;
      path = None;
      routes = [];
      plugins = [] }
  in
  let service_less_rules =
    cfg.top_level_routes
    |> List.filter (fun (top : Ast.top_level_route) ->
           top.service = None && not top.unsupported_reference)
    |> List.concat_map (fun (top : Ast.top_level_route) ->
           rules_of_route ~decision:Ir.Deny cfg no_service top.route)
  in
  let rules = service_rules @ service_less_rules in
  { request_domain =
      Ir.And
        [ Path_normalization.request_domain;
          Ir.Or [ Ir.Scheme_is "http"; Ir.Scheme_is "https" ] ];
    rules;
    default = Ir.Deny }
