open Soundcheck_core

let replace replacements value =
  let buffer = Buffer.create (String.length value) in
  String.iter
    (fun character ->
      match List.assoc_opt character replacements with
      | Some escaped -> Buffer.add_string buffer escaped
      | None -> Buffer.add_char buffer character)
    value;
  Buffer.contents buffer

let escape_data = replace [ ('%', "%25"); ('\r', "%0D"); ('\n', "%0A") ]

let escape_property =
  replace
    [ ('%', "%25"); ('\r', "%0D"); ('\n', "%0A"); (':', "%3A");
      (',', "%2C") ]

let command ~level ~file ~title message =
  Printf.sprintf "::%s file=%s,title=%s::%s" level (escape_property file)
    (escape_property title) (escape_data message)

let assurance = function
  | None -> []
  | Some (value : Report.assurance) ->
    let status =
      match value.status with
      | Report.Within_profile -> "within_profile"
      | Report.Conservative -> "conservative"
      | Report.Unsupported -> "unsupported"
    in
    let findings =
      value.findings
      |> List.map (fun (finding : Report.assurance_finding) ->
             finding.code ^ ": " ^ finding.detail)
    in
    ("assurance " ^ value.profile ^ " (" ^ status ^ ")") :: findings

let frozen = function
  | None -> []
  | Some (spec : Report.frozen_spec) -> [ "frozen spec " ^ spec.canonical ]

let clause = function
  | None -> []
  | Some (value : Report.clause) ->
    let kind =
      match value.kind with
      | Report.Must_deny -> "must_deny" | Report.Must_allow -> "must_allow"
      | Report.Must_not_grant -> "must_not_grant" | Report.Must_preserve -> "must_preserve"
    in
    [ Printf.sprintf "clause %s (%s)" value.name kind ]

let counterexample (value : Report.counterexample) =
  let request, location = match value.object_request with
    | Some object_request ->
      let strings values =
        "[" ^ String.concat ", " (List.map (Printf.sprintf "%S") values) ^ "]" in
      let request =
        if value.action = "list" || value.action = "watch" then
          let scope = if object_request.namespace = "" then "in all namespaces"
            else "in namespace " ^ object_request.namespace in
          let names = if object_request.name = "" then "with no exact-name restriction"
            else "with effective name " ^ object_request.name in
          Printf.sprintf "%s %s %s %s %s" value.principal value.action
            object_request.resource_kind scope names
        else Printf.sprintf "%s %s %s/%s in namespace %s" value.principal
            value.action object_request.resource_kind object_request.name
            object_request.namespace in
      (request,
       (Option.to_list (Option.map (fun groups -> "identity groups " ^ strings groups)
                          value.identity_groups)) @
       ["granting rules " ^ strings value.granting_rules])
    | None ->
      (Printf.sprintf "%s %s %s" value.principal
         (if value.action = "" then "<any-method>" else value.action)
         value.path,
       [ Option.map (fun route -> "route " ^ route) value.route;
         Option.map (fun service -> "service " ^ service) value.service;
         Option.map (fun route -> "shadowed route " ^ route) value.shadowed_route;
         Option.map (fun service -> "shadowed service " ^ service) value.shadowed_service ]
       |> List.filter_map Fun.id)
  in
  String.concat "; " (request :: location @ [ value.note ])

let render ~file (report : Report.t) =
  let level, summary =
    match report.result with
    | Report.Proved -> ("notice", report.property_name ^ " proved")
    | Report.Violated value ->
      ("error", report.property_name ^ " violated; " ^ counterexample value)
    | Report.Vacuous ->
      ("error", report.property_name ^ " is vacuous; no configuration was verified")
    | Report.Inconsistent reason ->
      ("error", report.property_name ^ " is inconsistent; " ^ reason)
    | Report.Unknown reason ->
      ("error", report.property_name ^ " is unknown; " ^ reason)
  in
  let details = clause report.clause @ assurance report.assurance @ frozen report.frozen_spec in
  let message = String.concat "; " (summary :: details) in
  command ~level ~file ~title:("Soundcheck: " ^ report.property_name) message

let error ~file ~title message =
  command ~level:"error" ~file ~title:("Soundcheck: " ^ title) message
