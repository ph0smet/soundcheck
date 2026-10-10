let request_of_model (model : Solve.model) : Ir.request =
  { principal = if model.is_anon then Anonymous else Authenticated "subject";
    action = model.method_;
    resource = model.path;
    context = model.headers;
    source = model.src_ip;
    host = model.host;
    scheme = model.scheme;
    sni = model.sni }

let validate ~obligation satisfies = function
  | Solve.Violated model ->
    let prefix =
      "solver witness validation failed for " ^ Solver_process.diagnostic obligation
    in
    (try
       if satisfies (request_of_model model) then Solve.Violated model
       else Solve.Unknown (prefix ^ ": decoded request does not satisfy the obligation")
     with exception_ ->
       Solve.Unknown
         (prefix ^ ": could not evaluate decoded request: "
          ^ Solver_process.diagnostic (Printexc.to_string exception_)))
  | result -> result

let condition ~domain condition request =
  Ir.matches domain request && Ir.matches condition request

let property policy (property : Property.t) request =
  condition ~domain:policy.Ir.request_domain property.forbidden_when request
  && Ir.possibly_allows ~reach_via:property.reach_via policy request

let clause policy clause request =
  condition ~domain:policy.Ir.request_domain (Contract.request_class clause) request
  && match clause with
     | Contract.Must_deny clause ->
       Ir.possibly_allows ~reach_via:clause.reach_via policy request
     | Contract.Must_allow _ -> not (Ir.definitely_allows policy request)

let shadowing policy (pair : Shadowing.pair) request =
  Ir.matches policy.Ir.request_domain request
  && Ir.selected policy request pair.shadowing
  && Ir.matches pair.shadowed.match_ request
  && Ir.matches pair.shadowing.guard request
  && not (Ir.matches (Ir.must_guard pair.shadowed) request)

let comparison_scope when_ left right request =
  Ir.matches when_ request
  && (Ir.matches left.Ir.request_domain request
      || Ir.matches right.Ir.request_domain request)

let decision_difference ?(when_ = Ir.True) left right request =
  comparison_scope when_ left right request
  && (Ir.possibly_allows left request <> Ir.possibly_allows right request)

let route_difference ?(when_ = Ir.True) ?left_value ?right_value
    ~left_label ~right_label left right request =
  let selected policy =
    if Ir.matches policy.Ir.request_domain request then
      List.filter (Ir.selected policy request) policy.rules
    else []
  in
  let selected_left = selected left and selected_right = selected right in
  let labels label rules = List.map label rules |> List.sort_uniq String.compare in
  let value_difference () =
    match left_value, right_value with
    | None, None -> false
    | Some left_value, Some right_value ->
      List.exists
        (fun left_rule ->
          List.exists
            (fun right_rule ->
              Smt_encode.eval_string_term ~path:request.Ir.resource (left_value left_rule)
              <> Smt_encode.eval_string_term ~path:request.resource (right_value right_rule))
            selected_right)
        selected_left
    | _ -> invalid_arg "route_difference requires both value callbacks"
  in
  comparison_scope when_ left right request
  && (Ir.possibly_allows left request <> Ir.possibly_allows right request
      || labels left_label selected_left <> labels right_label selected_right
      || value_difference ())
