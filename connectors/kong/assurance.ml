type feature = {
  code        : string;
  description : string;
}

type profile = {
  id           : string;
  connector    : string;
  version      : int;
  target       : string;
  modeled      : feature list;
  conservative : feature list;
  unsupported  : feature list;
}

type status = Within_profile | Conservative | Unsupported

type finding = {
  code    : string;
  service : string option;
  route   : string option;
  detail  : string;
}

type assessment = {
  status   : status;
  findings : finding list;
}

let feature code description = { code; description }

let profile =
  { id = "kong-traditional-http-v11";
    connector = "kong";
    version = 11;
    target = "Kong OSS 3.9.3 traditional/traditional_compatible HTTP routing";
    modeled =
      [ feature "literal-path-prefix" "literal HTTP path-prefix matching";
        feature "normalized-request-path" "Kong-normalized request-path domain and literal route validation";
        feature "regular-path-regex" "bounded shared ASCII-atom regex language; matching remains an upper bound";
        feature "http-method" "HTTP method matching";
        feature "lowercase-host" "lowercase exact Host matching without an explicit route port";
        feature "exact-header-match" "case-insensitive exact HTTP header matching, including repeated values";
        feature "http-https-protocol" "HTTP subsystem selection and HTTPS-only rejection";
        feature "exact-sni" "exact SNI matching for HTTPS and Kong's HTTP bypass";
        feature "shared-route-priority" "common criterion-count order; detailed path order only with identical non-path predicates";
        feature "known-auth-plugins" "authentication requirement from Soundcheck's known plugin list";
        feature "auth-preflight-bypass" "Key Auth and JWT OPTIONS bypass when run_on_preflight is false";
        feature "general-request-rate-limit" "request-rate coverage from rate-limiting and rate-limiting-advanced";
        feature "ipv4-ip-restriction" "IPv4 ip-restriction allow and deny guards over Kong's derived client IP";
        feature "request-termination" "unconditional request-termination denial with Kong plugin precedence";
        feature "global-plugin-scope" "global plugins with route-over-service-over-global precedence";
        feature "plugin-subsystem" "plugin protocols activate the HTTP subsystem, not an individual request scheme";
        feature "disabled-service" "disabled services and their routes are excluded from routing";
        feature "root-route-service-plugin-scope" "root plugins scoped by string route/service references";
        feature "top-level-route" "top-level routes with string service references or denying no-service behavior";
        feature "default-admin-ports" "Admin API recognition on default ports 8001 and 8444";
        feature "default-deny" "denying fallthrough when no route matches; a failing guard denies without rerouting" ];
    conservative =
      [ feature "route-created-at-tie" "created_at is absent from decK and unresolved route order remains tied";
        feature "shared-route-order" "overlapping possible winners are not ordered unless both router flavors justify suppression";
        feature "regex-match-runtime" "regex engine match-limit failures may remove a match; regex candidates never suppress or establish definite allowance";
        feature "rate-limit-runtime" "quota and rate-limit runtime state cannot establish definite allowance";
        feature "route-header-regex" "regex header values are over-approximated and the route is left incomparable";
        feature "wildcard-sni" "wildcard SNI depends on router flavor and is over-approximated";
        feature "route-stream-match" "source/destination criteria are over-approximated and the route is left incomparable";
        feature "uppercase-host" "uppercase route hosts are left incomparable because request hosts are lowercased";
        feature "wildcard-host" "wildcard Host semantics differ; a possibly empty wildcard is only an upper bound";
        feature "host-port" "effective Host ports are not modeled; port-bearing route hosts are unconstrained and incomplete";
        feature "invalid-ip-cidr" "unmodeled restrictions use may/must bounds; mixed unknown allow entries do not narrow possible allowance";
        feature "conditional-request-termination" "triggered request-termination depends on unmodeled query parameters";
        feature "auth-anonymous-fallback" "authentication anonymous fallback is over-approximated without resolving Consumers";
        feature "response-rate-limit-dependency" "response rate limiting depends on upstream usage headers outside the config";
        feature "graphql-rate-limit-scope" "GraphQL query-cost limiting does not establish general HTTP request-rate coverage" ];
    unsupported =
      [ feature "unsupported-path-regex" "non-regular or untranslated regex constructs make the whole result unknown";
        feature "unrecognized-plugin" "unmodeled plugins can alter routing, guards or upstream targets; whole-config verification fails closed";
        feature "nested-plugin-reference" "explicit nested plugin relationships are not resolved";
        feature "consumer-scoped-plugin" "consumer-scoped plugins require a richer principal identity model";
        feature "non-string-plugin-reference" "non-string root plugin references are not resolved";
        feature "non-string-route-service-reference" "non-string top-level route service references are not resolved" ] }

let string_of_status = function
  | Within_profile -> "within_profile"
  | Conservative -> "conservative"
  | Unsupported -> "unsupported"

let finding ?service ?route code detail = { code; service; route; detail }

let plugin_findings ?service ?route plugins =
  List.concat_map
    (fun (plugin : Ast.plugin) ->
      if not (Plugin_support.active_http plugin) then []
      else
      let known =
        Plugin_support.known plugin.name
      in
      let unknown =
        if known then []
        else
          [ finding ?service ?route "unrecognized-plugin"
              (Printf.sprintf "plugin %S has no modeled security semantics" plugin.name) ]
      in
      let invalid_cidrs =
        if plugin.name <> "ip-restriction" then []
        else
          List.filter_map
            (fun entry ->
              match Soundcheck_core.Cidr.parse entry with
              | Ok _ -> None
              | Error _ ->
                Some
                  (finding ?service ?route "invalid-ip-cidr"
                     (Printf.sprintf "ip-restriction entry %S is not modeled as IPv4" entry)))
            (plugin.allow @ plugin.deny)
      in
      let conditional_termination =
        match (plugin.name, plugin.trigger) with
        | "request-termination", Some trigger ->
          [ finding ?service ?route "conditional-request-termination"
              (Printf.sprintf
                 "request-termination trigger %S depends on header or query presence"
                 trigger) ]
        | _ -> []
      in
      let anonymous_fallback =
        if Lower.is_auth_plugin plugin.name && plugin.anonymous_fallback then
          [ finding ?service ?route "auth-anonymous-fallback"
              (Printf.sprintf
                 "plugin %S forwards failed authentication as its configured anonymous Consumer"
                 plugin.name) ]
        else []
      in
      let specialized_rate_limit =
        match plugin.name with
        | "response-ratelimiting" ->
          [ finding ?service ?route "response-rate-limit-dependency"
              "response-ratelimiting consumes quota only from upstream usage headers" ]
        | "graphql-rate-limiting-advanced" ->
          [ finding ?service ?route "graphql-rate-limit-scope"
              "graphql-rate-limiting-advanced covers GraphQL query cost, not general HTTP request rate" ]
        | _ -> []
      in
      let rate_limit_runtime =
        if Lower.is_general_rate_limit_plugin plugin.name then
          [ finding ?service ?route "rate-limit-runtime"
              "quota and runtime state are not modeled, so this plugin cannot establish definite allowance" ]
        else []
      in
      unknown @ invalid_cidrs @ conditional_termination @ anonymous_fallback
      @ specialized_rate_limit @ rate_limit_runtime)
    plugins

let route_findings ?service (route : Ast.route) =
  let location code detail = finding ?service ~route:route.name code detail in
  let routing =
    (if
       List.exists
         (fun (_, values) -> Lower.is_header_regex values)
         (Lower.routable_headers route)
     then
       [ location "route-header-regex"
           "route has a regex header value that is conservatively approximated" ]
     else [])
    @ (if Lower.has_wildcard_sni route then
         [ location "wildcard-sni"
             "route has wildcard SNI behavior that depends on router flavor" ]
       else [])
    @ (if route.has_sources_or_destinations then
         [ location "route-stream-match" "route has source or destination matching criteria" ]
       else [])
    @ List.filter_map
        (fun host ->
          if String.lowercase_ascii host = host then None
          else Some (location "uppercase-host" (Printf.sprintf "route host %S contains uppercase" host)))
        route.hosts
    @ (if List.exists (fun host -> String.contains host '*') route.hosts then
         [ location "wildcard-host"
             "wildcard hosts are possible matches only; shared empty-wildcard and effective-port behavior cannot establish definite selection" ]
       else [])
    @ (if List.exists (fun host -> String.contains host ':') route.hosts then
         [ location "host-port"
             "explicit route host ports may match an implicit request port; the host constraint is conservatively omitted" ]
       else [])
  in
  let regex =
    List.filter_map
      (fun path ->
        if not (Fragment.is_regex_path path) then None
        else
          match Regex_boundary.parse (Fragment.pattern_of path) with
          | Ok _ ->
            Some (location "regex-match-runtime"
              (Printf.sprintf
                 "path %S is only a possible match: regex runtime failures cannot justify route suppression or definite allowance"
                 path))
          | Error why ->
            Some
              (location "unsupported-path-regex"
                 (Printf.sprintf "path %S is unsupported: %s" path why)))
      route.paths
  in
  routing @ regex
  @ plugin_findings ?service ~route:route.name route.plugins

let assess (config : Ast.config) =
  (* A cheap over-approximation only for assurance labels; actual overlap is
     queried separately by comparison/shadowing. Disjoint literal prefixes or
     disjoint method sets cannot compete. Other uncertain pairs stay visible. *)
  let rec path_prefix = function
    | Soundcheck_core.Ir.Path_prefix value -> Some value
    | Soundcheck_core.Ir.And terms -> List.find_map path_prefix terms
    | _ -> None
  in
  let rec methods = function
    | Soundcheck_core.Ir.Method_is value -> Some [ value ]
    | Soundcheck_core.Ir.Or terms
      when List.for_all (function Soundcheck_core.Ir.Method_is _ -> true | _ -> false) terms ->
      Some (List.filter_map (function Soundcheck_core.Ir.Method_is value -> Some value | _ -> None) terms)
    | Soundcheck_core.Ir.And terms -> List.find_map methods terms
    | _ -> None
  in
  let policy = Lower.to_policy config in
  let uncertain_order =
    Result.is_ok (Fragment.check config)
    && List.exists (fun (a : Soundcheck_core.Ir.rule) ->
      List.exists (fun (b : Soundcheck_core.Ir.rule) ->
        a.id <> b.id
        && not (Soundcheck_core.Ir.outranks a.priority b.priority)
        && not (Soundcheck_core.Ir.outranks b.priority a.priority)
        && (match path_prefix a.match_, path_prefix b.match_ with
            | Some a, Some b -> String.starts_with ~prefix:a b || String.starts_with ~prefix:b a
            | _ -> true)
        && (match methods a.match_, methods b.match_ with
            | Some a, Some b -> List.exists (fun method_ -> List.mem method_ b) a
            | _ -> true)) policy.rules) policy.rules
  in
  let findings =
    (Plugin_support.nested config
     |> List.filter_map (fun (plugin : Ast.plugin) ->
          if plugin.has_relationships then
            Some (finding "nested-plugin-reference"
              (Printf.sprintf "nested plugin %S has unresolved explicit relationships" plugin.name))
          else None))
    @ plugin_findings config.global_plugins
    @ List.concat_map
        (fun (scoped : Ast.scoped_plugin) ->
          let plugin_semantics =
            plugin_findings ?service:scoped.service ?route:scoped.route
              [ scoped.plugin ]
          in
          let unsupported =
            (if scoped.consumer_scoped then
               [ finding ?service:scoped.service ?route:scoped.route
                   "consumer-scoped-plugin"
                   (Printf.sprintf
                      "root-level plugin %S has a consumer or consumer-group scope"
                      scoped.plugin.name) ]
             else [])
            @ if scoped.unsupported_reference then
                [ finding "non-string-plugin-reference"
                    (Printf.sprintf
                       "root-level plugin %S has a non-string route or service reference"
                       scoped.plugin.name) ]
              else []
          in
          plugin_semantics @ unsupported)
        config.scoped_plugins
    @ List.filter_map
        (fun (top : Ast.top_level_route) ->
          if top.unsupported_reference then
            Some
              (finding ~route:top.route.name
                 "non-string-route-service-reference"
                 "top-level route has a non-string service reference")
          else None)
        config.top_level_routes
    @ (config.top_level_routes
      |> List.filter (fun (top : Ast.top_level_route) ->
             top.service = None && not top.unsupported_reference)
      |> List.concat_map (fun (top : Ast.top_level_route) ->
             route_findings top.route))
    @ List.concat_map
      (fun (service : Ast.service) ->
        plugin_findings ~service:service.name service.plugins
        @ List.concat_map (route_findings ~service:service.name) service.routes)
      config.services
    @ (if uncertain_order then
         [ finding "shared-route-order"
             "overlapping candidate route order is not established for both router flavors; all possible winners are retained" ]
       else [])
  in
  let status =
    if
      List.exists
        (fun finding ->
          List.mem finding.code
            [ "unsupported-path-regex"; "consumer-scoped-plugin";
              "unrecognized-plugin"; "nested-plugin-reference";
              "non-string-plugin-reference";
              "non-string-route-service-reference" ])
        findings
    then Unsupported
    else if findings = [] then Within_profile
    else Conservative
  in
  { status; findings }

let escape_json value =
  let buffer = Buffer.create (String.length value) in
  String.iter
    (function
      | '"' -> Buffer.add_string buffer "\\\""
      | '\\' -> Buffer.add_string buffer "\\\\"
      | '\n' -> Buffer.add_string buffer "\\n"
      | '\r' -> Buffer.add_string buffer "\\r"
      | '\t' -> Buffer.add_string buffer "\\t"
      | character -> Buffer.add_char buffer character)
    value;
  Buffer.contents buffer

let json_string value = "\"" ^ escape_json value ^ "\""

let features_json features =
  features
  |> List.map (fun (feature : feature) ->
         Printf.sprintf "{\"code\":%s,\"description\":%s}"
           (json_string feature.code) (json_string feature.description))
  |> String.concat ","
  |> Printf.sprintf "[%s]"

let profile_json () =
  Printf.sprintf
    "{\"schema_version\":1,\"id\":%s,\"connector\":%s,\"version\":%d,\"target\":%s,\"modeled\":%s,\"conservative\":%s,\"unsupported\":%s}"
    (json_string profile.id) (json_string profile.connector) profile.version
    (json_string profile.target) (features_json profile.modeled)
    (features_json profile.conservative) (features_json profile.unsupported)

let human_features title features =
  let rows =
    features
    |> List.map (fun (feature : feature) ->
           Printf.sprintf "  - %s: %s" feature.code feature.description)
    |> String.concat "\n"
  in
  Printf.sprintf "%s:\n%s" title rows

let profile_human () =
  String.concat "\n"
    [ Printf.sprintf "KONG ASSURANCE PROFILE  %s" profile.id;
      Printf.sprintf "Connector: %s" profile.connector;
      Printf.sprintf "Profile version: %d" profile.version;
      Printf.sprintf "Target: %s" profile.target;
      "";
      human_features "Modeled" profile.modeled;
      "";
      human_features "Conservative" profile.conservative;
      "";
      human_features "Unsupported" profile.unsupported ]
