open Soundcheck_core

type mode = Security_decision | Route_service | Service_target | Upstream_uri

type service_target = {
  protocol : string;
  host     : string;
  port     : int;
  path     : string option;
}

type observation = {
  decision : Ir.decision;
  route    : string option;
  service  : string option;
  service_target : service_target option;
  upstream_uri : string option;
}

type witness = {
  request : Solve.model;
  before  : observation;
  after   : observation;
}

type outcome = Equivalent | Different of witness | Unknown of string

type report = {
  result  : outcome;
  profile : string;
  mode    : mode;
}

let parse label source =
  match Parse.parse_string source with
  | Error error -> Error (Printf.sprintf "%s config: %s" label error)
  | Ok config ->
    (match Validate.check config with
     | Error error -> Error (Printf.sprintf "%s config: %s" label error)
     | Ok () -> Ok config)

let assessment_reason label (assessment : Assurance.assessment) =
  match assessment.findings with
  | [] -> Printf.sprintf "%s config is not within the assurance profile" label
  | finding :: _ ->
    Printf.sprintf "%s config is %s: %s — %s" label
      (Assurance.string_of_status assessment.status) finding.code finding.detail

let can_check_exactness (assessment : Assurance.assessment) =
  match assessment.status with
  | Assurance.Within_profile -> true
  | Assurance.Unsupported -> false
  | Assurance.Conservative ->
    (* Ordering alone need not change the requested observation. exact_policy
       below still requires complete predicates and proves different effects or
       identities cannot overlap. All other approximation findings fail closed. *)
    List.for_all
      (fun (finding : Assurance.finding) -> finding.code = "shared-route-order")
      assessment.findings

let unresolved_pairs ~label mode (policy : Ir.policy) =
  let rec pairs = function
    | [] -> []
    | rule :: rest -> List.map (fun other -> (rule, other)) rest @ pairs rest
  in
  pairs policy.rules
  |> List.filter (fun ((left : Ir.rule), (right : Ir.rule)) ->
         not (Ir.outranks left.priority right.priority)
         && not (Ir.outranks right.priority left.priority)
         && (left.decision <> right.decision || left.guard <> right.guard
            || (mode <> Security_decision && label left <> label right)))

let exact_policy ?(z3 = "z3") ~rule_label mode label (policy : Ir.policy) =
  if List.exists (fun (rule : Ir.rule) -> not rule.match_complete || not rule.guard_complete) policy.rules
  then Error (label ^ " config contains an incomplete route match or policy guard")
  else
    let rec check = function
      | [] -> Ok ()
      | ((left : Ir.rule), (right : Ir.rule)) :: rest ->
        let query =
          Smt_encode.condition_query ~domain:policy.request_domain
            ~name:"route-order-determinism"
            ~description:
              "unresolved routes with different decisions, guards, or observed identities overlap"
            (Ir.And [ left.match_; right.match_ ])
        in
        (match Solve.check ~z3 query
               |> Witness.validate ~obligation:(label ^ " route-order determinism")
                    (Witness.condition ~domain:policy.request_domain
                       (Ir.And [left.match_; right.match_])) with
         | Solve.Proved -> check rest
         | Solve.Violated _ ->
           Error
             (Printf.sprintf
                "%s config has overlapping routes %S and %S whose winner is not determined by the declarative config"
                label left.id right.id)
         | Solve.Unknown reason ->
           Error
             (Printf.sprintf "%s config route-order check was inconclusive: %s"
                label reason))
    in
    check (unresolved_pairs ~label:rule_label mode policy)

let route_locations (config : Ast.config) =
  let service_routes =
    List.concat_map
      (fun (service : Ast.service) ->
        List.map
          (fun (route : Ast.route) -> (route.name, Some service.name))
          service.routes)
      config.services
  in
  let service_less =
    config.top_level_routes
    |> List.filter (fun (top : Ast.top_level_route) ->
           top.service = None && not top.unsupported_reference)
    |> List.map (fun (top : Ast.top_level_route) -> (top.route.name, None))
  in
  service_routes @ service_less

let routing_identity label config =
  let locations = route_locations config in
  let service_names =
    config.Ast.services
    |> List.filter (fun (service : Ast.service) -> service.routes <> [])
    |> List.map (fun (service : Ast.service) -> service.name)
  in
  match List.find_opt (( = ) "<unnamed-service>") service_names with
  | Some _ ->
    Error (label ^ " config contains a routed service without an explicit name")
  | None ->
  match
    List.find_opt
      (fun name -> List.length (List.filter (( = ) name) service_names) > 1)
      (List.sort_uniq String.compare service_names)
  with
  | Some name ->
    Error (Printf.sprintf "%s config contains duplicate service name %S" label name)
  | None ->
  match List.find_opt (fun (route, _) -> route = "<unnamed-route>") locations with
  | Some _ -> Error (label ^ " config contains a route without an explicit name")
  | None ->
    let names = List.map fst locations in
    (match
       List.find_opt
         (fun name -> List.length (List.filter (( = ) name) names) > 1)
         names
     with
     | Some name ->
       Error
         (Printf.sprintf "%s config contains duplicate route name %S" label name)
     | None -> Ok locations)

let location_label locations (rule : Ir.rule) =
  let service = List.assoc rule.id locations in
  rule.id ^ "\x1f" ^ Option.value ~default:"<no-service>" service

let default_port = function "https" -> 443 | _ -> 80

let target ~protocol ~host ~port ~path =
  let protocol = String.lowercase_ascii protocol in
  { protocol;
    host = String.lowercase_ascii host;
    port;
    path }

let parse_port value =
  match int_of_string_opt value with
  | Some port when port >= 1 && port <= 65535 -> Ok port
  | _ -> Error (Printf.sprintf "invalid upstream port %S" value)

let parse_authority authority =
  if authority = "" then Error "upstream URL has no host"
  else if String.contains authority '@' then
    Error "upstream URL userinfo is not supported"
  else if authority.[0] = '[' then
    match String.index_opt authority ']' with
    | None -> Error "upstream URL has an unterminated IPv6 host"
    | Some closing ->
      let host = String.sub authority 1 (closing - 1) in
      let suffix =
        String.sub authority (closing + 1)
          (String.length authority - closing - 1)
      in
      if suffix = "" then Ok (host, None)
      else if suffix.[0] = ':' then
        Result.map (fun port -> (host, Some port))
          (parse_port (String.sub suffix 1 (String.length suffix - 1)))
      else Error "upstream URL has invalid text after its IPv6 host"
  else
    match String.rindex_opt authority ':' with
    | None -> Ok (authority, None)
    | Some colon ->
      let host = String.sub authority 0 colon in
      let raw_port =
        String.sub authority (colon + 1) (String.length authority - colon - 1)
      in
      if String.contains host ':' then
        Error "upstream URL IPv6 hosts must use brackets"
      else
        Result.map (fun port -> (host, Some port)) (parse_port raw_port)

let target_of_url url =
  if String.contains url '?' || String.contains url '#' then
    Error "upstream URL query strings and fragments are not supported"
  else
    match String.index_opt url ':' with
    | None -> Error "upstream URL has no protocol"
    | Some colon
      when colon + 2 >= String.length url
           || String.sub url colon 3 <> "://" ->
      Error "upstream URL must contain ://"
    | Some colon ->
      let protocol = String.sub url 0 colon in
      let remainder =
        String.sub url (colon + 3) (String.length url - colon - 3)
      in
      let authority, path =
        match String.index_opt remainder '/' with
        | None -> (remainder, None)
        | Some slash ->
          ( String.sub remainder 0 slash,
            Some
              (String.sub remainder slash (String.length remainder - slash)) )
      in
      Result.map
        (fun (host, port) ->
          let normalized_protocol = String.lowercase_ascii protocol in
          target ~protocol ~host
            ~port:(Option.value ~default:(default_port normalized_protocol) port)
            ~path)
        (parse_authority authority)

let service_target (service : Ast.service) =
  match service.url with
  | Some url ->
    if
      List.exists Option.is_some
        [ service.protocol; service.host; Option.map string_of_int service.port;
          service.path ]
    then Error "combines url shorthand with explicit target fields"
    else target_of_url url
  | None ->
    (match service.host with
     | None -> Error "has no upstream host"
     | Some host ->
       Ok
         (target
            ~protocol:(Option.value ~default:"http" service.protocol)
            ~host ~port:(Option.value ~default:80 service.port)
            ~path:service.path))

let target_key target =
  Printf.sprintf "%s\x1f%s\x1f%d\x1f%s" target.protocol target.host target.port
    (Option.value ~default:"<no-path>" target.path)

let target_endpoint_key target =
  Printf.sprintf "%s\x1f%s\x1f%d" target.protocol target.host target.port

let service_targets label (config : Ast.config) =
  let routed =
    List.filter (fun (service : Ast.service) -> service.routes <> []) config.services
  in
  let rec collect = function
    | [] -> Ok []
    | (service : Ast.service) :: rest ->
      (match service_target service with
       | Error reason ->
         Error
           (Printf.sprintf "%s service %S %s" label service.name reason)
       | Ok target ->
         Result.map (fun targets -> (service.name, target) :: targets)
           (collect rest))
  in
  collect routed

let observed_label mode locations targets rule =
  let location = location_label locations rule in
  match mode, List.assoc_opt rule.Ir.id locations with
  | Service_target, Some (Some service) ->
    location ^ "\x1f" ^ target_key (List.assoc service targets)
  | Upstream_uri, Some (Some service) ->
    location ^ "\x1f" ^ target_endpoint_key (List.assoc service targets)
  | _ -> location

let rec literal_path = function
  | Ir.Path_prefix path -> Ok (Some path)
  | Ir.Path_regex _ -> Error "contains a regex route path"
  | Ir.And conditions | Ir.Or conditions ->
    let rec find = function
      | [] -> Ok None
      | condition :: rest ->
        (match literal_path condition with
         | Error _ as error -> error
         | Ok (Some _ as path) -> Ok path
         | Ok None -> find rest)
    in
    find conditions
  | Ir.Not condition -> literal_path condition
  | _ -> Ok None

let route_by_name config name =
  List.find_map
    (fun (service : Ast.service) ->
      Option.map (fun route -> (service, route))
        (List.find_opt (fun (route : Ast.route) -> route.name = name)
           service.routes))
    config.Ast.services

let drop count = Smt_encode.Drop_prefix count
let lit value = Smt_encode.Literal value
let concat terms = Smt_encode.Concat terms

let sanitized_postfix offset =
  let raw = drop offset in
  let without_parent =
    Smt_encode.If
      ( Smt_encode.Starts_with (raw, "../"),
        drop (offset + 3), raw )
  in
  let without_current =
    Smt_encode.If
      ( Smt_encode.Starts_with (raw, "./"),
        drop (offset + 2), without_parent )
  in
  Smt_encode.If
    ( Smt_encode.Equal (raw, lit "."), lit "",
      Smt_encode.If
        (Smt_encode.Equal (raw, lit ".."), lit "", without_current) )

let upstream_path_term (route : Ast.route) target matched_path =
  let base = Option.value ~default:"/" target.path in
  let postfix =
    match matched_path with
    | None -> drop 1
    | Some prefix -> sanitized_postfix (String.length prefix)
  in
  let base_ends_slash = String.ends_with ~suffix:"/" base in
  if route.path_handling = "v1" then
    if route.strip_path then
      if base_ends_slash then
        Smt_encode.If
          ( Smt_encode.Starts_with (postfix, "/"),
            concat [ lit (String.sub base 0 (String.length base - 1)); postfix ],
            concat [ lit base; postfix ] )
      else concat [ lit base; postfix ]
    else concat [ lit base; drop 1 ]
  else if base_ends_slash then
    if route.strip_path then
      Smt_encode.If
        ( Smt_encode.Equal (postfix, lit ""),
          (if base = "/" then lit "/"
           else
             Smt_encode.If
               ( Smt_encode.Ends_with (Smt_encode.Request_path, "/"),
                 lit base,
                 lit (String.sub base 0 (String.length base - 1)) )),
          Smt_encode.If
            ( Smt_encode.Starts_with (postfix, "/"),
              concat [ lit (String.sub base 0 (String.length base - 1)); postfix ],
              concat [ lit base; postfix ] ) )
    else concat [ lit base; drop 1 ]
  else if route.strip_path then
    Smt_encode.If
      ( Smt_encode.Equal (postfix, lit ""),
        Smt_encode.If
          ( Smt_encode.Length_greater_than (Smt_encode.Request_path, 1),
            Smt_encode.If
              ( Smt_encode.Ends_with (Smt_encode.Request_path, "/"),
                concat [ lit base; lit "/" ], lit base ),
            lit base ),
        Smt_encode.If
          ( Smt_encode.Starts_with (postfix, "/"),
            concat [ lit base; postfix ],
            concat [ lit base; lit "/"; postfix ] ) )
  else
    Smt_encode.If
      ( Smt_encode.Equal (Smt_encode.Request_path, lit "/"),
        lit base,
        concat [ lit base; Smt_encode.Request_path ] )

let upstream_terms label config targets policy =
  let rec build acc = function
    | [] -> Ok acc
    | (rule : Ir.rule) :: rest ->
      (match route_by_name config rule.id with
       | None -> build ((rule, lit "") :: acc) rest
       | Some (service, route) ->
         match literal_path rule.match_ with
         | Error reason ->
           Error (Printf.sprintf "%s config route %S %s" label route.name reason)
         | Ok matched_path ->
           let target = List.assoc service.name targets in
           build ((rule, upstream_path_term route target matched_path) :: acc) rest)
  in
  Result.map
    (fun terms rule -> List.assq rule terms)
    (build [] policy.Ir.rules)

let authority target =
  let host = if String.contains target.host ':' then "[" ^ target.host ^ "]" else target.host in
  Printf.sprintf "%s://%s:%d" target.protocol host target.port

let observe config targets value (policy : Ir.policy) model =
  let request = Witness.request_of_model model in
  let selected_rules =
    if Ir.matches policy.request_domain request then
      List.filter (Ir.selected policy request) policy.rules
    else []
  in
  let routes =
    selected_rules
    |> List.map (fun (rule : Ir.rule) -> rule.id)
    |> List.sort_uniq String.compare
  in
  let route = match routes with [ route ] -> Some route | _ -> None in
  let service = Option.bind route (Lift.service_of_route config) in
  { decision = Ir.evaluate policy request;
    route;
    service;
    service_target = Option.bind service (fun name -> List.assoc_opt name targets);
    upstream_uri =
      (match selected_rules, service with
       | [ rule ], Some service ->
         Option.map
           (fun value ->
             authority (List.assoc service targets)
             ^ Smt_encode.eval_string_term ~path:model.path (value rule))
           value
       | _ -> None) }

let run_comparison ?(z3 = "z3") ?emit_smt ?(when_ = Ir.True)
    ?(mode = Security_decision) before_source after_source =
  match parse "before" before_source, parse "after" after_source with
  | Error error, _ | _, Error error -> Error error
  | Ok before_config, Ok after_config ->
    let profile = Assurance.profile.id in
    let before_assessment = Assurance.assess before_config in
    let after_assessment = Assurance.assess after_config in
    let identities =
      match mode with
      | Security_decision -> Ok (([], []), ([], []))
      | Route_service | Service_target | Upstream_uri ->
        (match routing_identity "before" before_config with
         | Error _ as error -> error
         | Ok before ->
           match routing_identity "after" after_config with
           | Error _ as error -> error
           | Ok after ->
             if mode = Route_service then Ok ((before, []), (after, []))
             else
               match service_targets "before config" before_config with
               | Error _ as error -> error
               | Ok before_targets ->
                 (match service_targets "after config" after_config with
                  | Error _ as error -> error
                  | Ok after_targets ->
                    Ok ((before, before_targets), (after, after_targets))))
    in
    if not (can_check_exactness before_assessment) then
      Ok
        { result = Unknown (assessment_reason "before" before_assessment);
          profile;
          mode }
    else if not (can_check_exactness after_assessment) then
      Ok
        { result = Unknown (assessment_reason "after" after_assessment);
          profile;
          mode }
    else
      match identities with
      | Error reason -> Ok { result = Unknown reason; profile; mode }
      | Ok ((before_locations, before_targets), (after_locations, after_targets)) ->
      let before_policy = Lower.to_policy before_config in
      let after_policy = Lower.to_policy after_config in
      let before_label = observed_label mode before_locations before_targets in
      let after_label = observed_label mode after_locations after_targets in
      let values =
        if mode <> Upstream_uri then Ok (None, None)
        else
          match
            upstream_terms "before" before_config before_targets before_policy
          with
          | Error _ as error -> error
          | Ok before_value ->
            Result.map
              (fun after_value -> (Some before_value, Some after_value))
              (upstream_terms "after" after_config after_targets after_policy)
      in
      (match values with
       | Error reason -> Ok { result = Unknown reason; profile; mode }
       | Ok (before_value, after_value) ->
      match exact_policy ~z3 ~rule_label:before_label mode "before" before_policy with
       | Error reason -> Ok { result = Unknown reason; profile; mode }
       | Ok () ->
         match exact_policy ~z3 ~rule_label:after_label mode "after" after_policy with
         | Error reason -> Ok { result = Unknown reason; profile; mode }
         | Ok () ->
         let query =
           match mode with
           | Security_decision ->
             Smt_encode.decision_equivalence_query ~when_ before_policy after_policy
           | Route_service | Service_target | Upstream_uri ->
             Smt_encode.route_equivalence_query ~when_ ?left_value:before_value
               ?right_value:after_value
               ~left_label:before_label ~right_label:after_label before_policy
               after_policy
         in
         let satisfies =
           match mode with
           | Security_decision ->
             Witness.decision_difference ~when_ before_policy after_policy
           | Route_service | Service_target | Upstream_uri ->
             Witness.route_difference ~when_ ?left_value:before_value
               ?right_value:after_value ~left_label:before_label
               ~right_label:after_label before_policy after_policy
         in
         match Solve.check ~z3 ?emit_smt query
               |> Witness.validate ~obligation:"configuration comparison" satisfies with
         | Solve.Proved -> Ok { result = Equivalent; profile; mode }
         | Solve.Unknown reason -> Ok { result = Unknown reason; profile; mode }
         | Solve.Violated request ->
           Ok
             { result =
                 Different
                   { request;
                     before =
                       observe before_config before_targets before_value before_policy
                         request;
                     after =
                       observe after_config after_targets after_value after_policy
                         request };
               profile;
               mode })

let run ?z3 ?emit_smt ?mode before_source after_source =
  run_comparison ?z3 ?emit_smt ?mode before_source after_source

let escape value =
  let buffer = Buffer.create (String.length value) in
  String.iter
    (function
      | '"' -> Buffer.add_string buffer "\\\""
      | '\\' -> Buffer.add_string buffer "\\\\"
      | '\n' -> Buffer.add_string buffer "\\n"
      | '\r' -> Buffer.add_string buffer "\\r"
      | '\t' -> Buffer.add_string buffer "\\t"
      | character when Char.code character < 0x20 ->
        Buffer.add_string buffer
          (Printf.sprintf "\\u%04x" (Char.code character))
      | character -> Buffer.add_char buffer character)
    value;
  Buffer.contents buffer

let jstring value = "\"" ^ escape value ^ "\""
let jopt = function None -> "null" | Some value -> jstring value

let target_json = function
  | None -> "null"
  | Some target ->
    Printf.sprintf
      "{\"protocol\":%s,\"host\":%s,\"port\":%d,\"path\":%s}"
      (jstring target.protocol) (jstring target.host) target.port
      (jopt target.path)

let observation_json observation =
  Printf.sprintf
    "{\"decision\":%s,\"route\":%s,\"service\":%s,\"service_target\":%s,\"upstream_uri\":%s}"
    (jstring (Ir.string_of_decision observation.decision |> String.lowercase_ascii))
    (jopt observation.route) (jopt observation.service)
    (target_json observation.service_target) (jopt observation.upstream_uri)

let witness_json witness =
  let request = witness.request in
  let headers =
    request.headers
    |> List.map (fun (name, value) ->
           Printf.sprintf "{\"name\":%s,\"value\":%s}" (jstring name) (jstring value))
    |> String.concat ","
  in
  Printf.sprintf
    "{\"request\":{\"principal\":%s,\"action\":%s,\"path\":%s,\"host\":%s,\"scheme\":%s,\"sni\":%s,\"headers\":[%s],\"source_ip\":%s},\"before\":%s,\"after\":%s}"
    (jstring (if request.is_anon then "anonymous" else "authenticated"))
    (jstring request.method_) (jstring request.path) (jstring request.host)
    (jstring request.scheme) (jstring request.sni) headers
    (jstring (Cidr.string_of_ip request.src_ip))
    (observation_json witness.before) (observation_json witness.after)

let to_json report =
  let comparison =
    match report.mode with
    | Security_decision -> "security_decision"
    | Route_service -> "route_service"
    | Service_target -> "service_target"
    | Upstream_uri -> "upstream_uri"
  in
  let head =
    Printf.sprintf "\"schema_version\":1,\"comparison\":%s,\"assurance_profile\":%s"
      (jstring comparison) (jstring report.profile)
  in
  match report.result with
  | Equivalent ->
    Printf.sprintf "{\"result\":\"equivalent\",%s,\"witness\":null}" head
  | Different witness ->
    Printf.sprintf "{\"result\":\"different\",%s,\"witness\":%s}" head
      (witness_json witness)
  | Unknown reason ->
    Printf.sprintf
      "{\"result\":\"unknown\",%s,\"witness\":null,\"reason\":%s}"
      head (jstring reason)

let observation_human label observation =
  Printf.sprintf "%s: %s%s%s%s%s" label (Ir.string_of_decision observation.decision)
    (match observation.route with None -> "" | Some route -> ", route " ^ route)
    (match observation.service with None -> "" | Some service -> ", service " ^ service)
    (match observation.service_target with
     | None -> ""
     | Some target ->
       Printf.sprintf ", target %s://%s:%d%s" target.protocol target.host
         target.port (Option.value ~default:"" target.path))
    (match observation.upstream_uri with
     | None -> ""
     | Some uri -> ", upstream URI " ^ uri)

let to_human report =
  match report.result with
  | Equivalent ->
    Printf.sprintf "EQUIVALENT  %s agree for every modeled request\n            Assurance: %s"
      (match report.mode with
       | Security_decision -> "security decisions"
       | Route_service -> "security decisions and selected route/service"
       | Service_target ->
         "security decisions, selected route/service, and service target"
       | Upstream_uri ->
         "security decisions, selected route/service, and upstream URI")
      report.profile
  | Unknown reason -> Printf.sprintf "UNKNOWN  %s" reason
  | Different witness ->
    let request = witness.request in
    Printf.sprintf
      "DIFFERENT  model-level witness: %s request %s %s makes the configs disagree\n           %s\n           %s\n           Not a guaranteed target replay. Assurance: %s"
      (if request.is_anon then "anonymous" else "authenticated")
      (if request.method_ = "" then "<any-method>" else request.method_)
      request.path (observation_human "before" witness.before)
      (observation_human "after" witness.after) report.profile

type repair_outcome =
  | Valid_repair
  | Contract_failed
  | Out_of_scope_regression of witness
  | Repair_unknown of string

type repair_report = {
  result          : repair_outcome;
  profile         : string;
  contract_report : Report.t;
  frozen_spec     : Contract_spec.t;
  mode            : mode;
}

let run_repair ?z3 ?emit_smt ?(mode = Security_decision) ~contract before_source
    after_source =
  match parse "before" before_source, parse "after" after_source with
  | Error error, _ | _, Error error -> Error error
  | Ok _, Ok _ ->
  match Verify.run ?z3 ~property:(Contract_spec.to_property contract) after_source with
  | Error error -> Error error
  | Ok raw_contract_report ->
    let contract_report = Contract_spec.bind_report contract raw_contract_report in
    let profile = Assurance.profile.id in
    (match contract_report.result with
     | Report.Proved ->
       let outside = Ir.Not (Contract_spec.scope_condition contract) in
       (match
          run_comparison ?z3 ?emit_smt ~when_:outside ~mode before_source after_source
        with
        | Error error -> Error error
        | Ok comparison ->
          let result =
            match comparison.result with
            | Equivalent -> Valid_repair
            | Different witness -> Out_of_scope_regression witness
            | Unknown reason -> Repair_unknown reason
          in
          Ok { result; profile; contract_report; frozen_spec = contract; mode })
     | Report.Unknown reason ->
       Ok
         { result = Repair_unknown reason;
           profile;
           contract_report;
           frozen_spec = contract;
           mode }
     | Report.Vacuous | Report.Inconsistent _ | Report.Violated _ ->
       Ok
         { result = Contract_failed;
           profile;
           contract_report;
           frozen_spec = contract;
           mode })

let repair_to_json report =
  let comparison =
    match report.mode with
    | Security_decision -> "frozen_scope_preservation"
    | Route_service -> "frozen_route_service_preservation"
    | Service_target -> "frozen_service_target_preservation"
    | Upstream_uri -> "frozen_upstream_uri_preservation"
  in
  let head result =
    Printf.sprintf
      "\"result\":%s,\"schema_version\":1,\"comparison\":%s,\"assurance_profile\":%s,\"frozen_spec\":%s,\"contract_result\":%s"
      (jstring result) (jstring comparison) (jstring report.profile)
      (Contract_spec.canonical_json report.frozen_spec)
      (Report.to_json report.contract_report)
  in
  match report.result with
  | Valid_repair ->
    Printf.sprintf "{%s,\"witness\":null}" (head "valid_repair")
  | Contract_failed ->
    Printf.sprintf "{%s,\"witness\":null}" (head "contract_failed")
  | Out_of_scope_regression witness ->
    Printf.sprintf "{%s,\"witness\":%s}" (head "out_of_scope_regression")
      (witness_json witness)
  | Repair_unknown reason ->
    Printf.sprintf "{%s,\"witness\":null,\"reason\":%s}" (head "unknown")
      (jstring reason)

let repair_to_human report =
  match report.result with
  | Valid_repair ->
    Printf.sprintf
      "VALID REPAIR  replacement satisfies %s and preserves %s outside its frozen scope\n              Assurance: %s\n              Frozen spec: %s"
      report.contract_report.property_name
      (match report.mode with
       | Security_decision -> "every security decision"
       | Route_service -> "every security decision and selected route/service"
       | Service_target ->
         "every security decision, selected route/service, and service target"
       | Upstream_uri ->
         "every security decision, selected route/service, and upstream URI")
      report.profile
      (Contract_spec.canonical_json report.frozen_spec)
  | Contract_failed ->
    "INVALID REPAIR  replacement does not satisfy the frozen contract\n"
    ^ Report.to_human report.contract_report
  | Repair_unknown reason -> Printf.sprintf "UNKNOWN  %s" reason
  | Out_of_scope_regression witness ->
    let request = witness.request in
    Printf.sprintf
      "OUT-OF-SCOPE REGRESSION  model-level witness: %s request %s %s changed outside the frozen repair scope\n                         %s\n                         %s\n                         Not a guaranteed target replay. Frozen spec: %s"
      (if request.is_anon then "anonymous" else "authenticated")
      (if request.method_ = "" then "<any-method>" else request.method_)
      request.path (observation_human "before" witness.before)
      (observation_human "after" witness.after)
      (Contract_spec.canonical_json report.frozen_spec)
