open Soundcheck_core

let report_clause clause : Report.clause =
  {name=Contract.name clause;description=Contract.description clause;
   kind=(match clause with Contract.Must_allow _ -> Report.Must_allow
       | Contract.Must_deny _ -> Report.Must_not_grant)}

let description =
  "The frozen access requirements hold for named get requests within the static RBAC profile; absence of a grant is NoOpinion, not final API-server denial."

let report ?clause ?unsupported spec result : Report.t =
  {result;property_name=Contract_spec.kind;
   property_description=(match Contract_spec.version spec with
     | 1 -> description
     | 2 -> "The frozen get/list/watch requirements hold within the static RBAC read profile; absence of a grant is NoOpinion, not final API-server denial."
     | 6 -> "The frozen read, named-write and collection-write requirements hold within the static RBAC profile; grants describe initial authorization, not object contents, deletion targets or successful mutation, and NoOpinion is not final API-server denial."
     | 7 -> "The frozen requirements hold within the explicit base-resource and subresource operation catalogue; grants describe initial RBAC authorization, not successful execution, token issuance, response contents, admission or additional authorization, and NoOpinion is not final API-server denial."
     | 8 -> "The frozen initial RBAC and conditional server-side apply requirements hold within the explicit operation catalogue. Apply requires every modeled prerequisite at the same target; the object-state branch is hypothetical, not observed. NoOpinion means at least one prerequisite lacks an RBAC grant, not final API-server denial; Allow does not establish API success."
     | 9 -> "The frozen resource, custom-resource and non-resource URL requirements hold within the static coverage profile, including modeled conditional SSA/PUT prerequisites. NoOpinion is not final API-server denial; catalogue completeness, metadata and identities are trusted inputs, and Allow does not establish successful execution."
     | _ -> "The frozen read and named-write requirements hold within the static RBAC profile; write grants describe authorization, not successful mutation, and NoOpinion is not final API-server denial.");
   assurance=Some (Assurance.assessment ~version:(Contract_spec.version spec) ?reason:unsupported ());clause;
   frozen_spec=Some (Contract_spec.frozen_spec spec)}

let invalid_contract reason : Report.t =
  {result=Report.Unknown ("invalid RBAC contract: " ^ reason);
   property_name=Contract_spec.kind;property_description=description;
   assurance=Some (Assurance.assessment ~reason ());clause=None;frozen_spec=None}

let counterexample spec policy ~note model : Report.counterexample =
  let request = Witness.request_of_model model in
  let username = match request.principal with
    | Ir.Authenticated name -> name
    | _ -> invalid_arg "RBAC witness lacks a named identity" in
  let identity = List.find (fun (identity : Identity.identity) -> identity.username=username)
      (Contract_spec.identities spec) in
  {principal=username;action=model.method_;path=(if model.object_request=None then model.path else "");
   route=None;service=None;shadowed_route=None;shadowed_service=None;
   host="";scheme="";sni="";source_ip=0l;headers=[];note;
   object_request=model.object_request;identity_groups=Some identity.groups;
   granting_rules=Lower.granting_rules policy request}

let request_description spec model =
  match model.Solve.object_request with
  | None -> Printf.sprintf "%S %s non-resource URL %S"
      (Option.get model.principal_name) model.method_ model.path
  | Some coordinates ->
  let entry = Resource_domain.of_kind_in (Contract_spec.resources spec) coordinates.resource_kind in
  let resource = match entry with Some entry -> Resource_domain.description entry
    | None -> coordinates.resource_kind in
  let location =
    if Option.fold ~none:false ~some:Resource_domain.is_namespace entry && coordinates.namespace<>""
    then Printf.sprintf "with authorization namespace %S equal to its target name" coordinates.namespace
    else if Option.fold ~none:false ~some:(fun entry -> not entry.Resource_domain.namespaced) entry then "at cluster scope"
    else if coordinates.namespace = "" then "at the all-namespace endpoint"
    else Printf.sprintf "in namespace %S" coordinates.namespace in
  if Option.fold ~none:false ~some:(fun entry -> entry.Resource_domain.subresource<>"") entry then
    Printf.sprintf "%S %s %s on parent %S %s"
      (Option.get model.principal_name) model.method_ resource coordinates.name location
  else if Option.is_some (Resource_domain.object_state ~operation:model.method_) then
    Printf.sprintf "%S %s %s %S %s (conditional %s-object storage branch)"
      (Option.get model.principal_name) model.method_ resource coordinates.name location
      (Option.get (Resource_domain.object_state ~operation:model.method_))
  else if List.mem model.method_ ["get";"update";"patch";"delete"] then
    Printf.sprintf "%S %s %s %S %s"
      (Option.get model.principal_name) model.method_ resource coordinates.name location
  else Printf.sprintf "%S %s %s %s (%s)"
    (Option.get model.principal_name) model.method_ resource location
    (if model.method_ = "create" || model.method_ = "deletecollection" then
       "empty authorization name; object contents and deletion targets are not constrained"
     else if coordinates.name = "" then "no effective exact-name restriction"
     else Printf.sprintf "effective authorization name %S" coordinates.name)

let prerequisite_description policy request =
  Lower.authorization_checks policy request |> List.map (fun (verb,grants) ->
    verb ^ "=" ^ if grants=[] then "NoOpinion (missing grant)" else "Allow")
  |> String.concat ", "

let apply_note policy model =
  match Resource_domain.object_state ~operation:model.Solve.method_ with
  | None -> ""
  | Some _ -> "; prerequisite evaluation (not an execution trace): "
      ^ prerequisite_description policy (Witness.request_of_model model)

let contract_report_of_result spec policy = function
  | Contract_verify.Proved -> report spec Report.Proved
  | Vacuous clause -> report ~clause:(report_clause clause) spec Report.Vacuous
  | Inconsistent (left,right) ->
    report ~clause:(report_clause right) spec
      (Report.Inconsistent (Printf.sprintf "clauses %S and %S require both a grant and no grant for the same request"
        (Contract.name left) (Contract.name right)))
  | Unknown reason -> report spec (Report.Unknown reason)
  | Violated (clause,model) ->
    let compound = Option.is_some (Resource_domain.object_state ~operation:model.method_) in
    let decision = match clause with
      | Contract.Must_allow _ when compound -> "NoOpinion (a required RBAC prerequisite is absent)"
      | Contract.Must_deny _ when compound -> "Allow (every forbidden operation prerequisite grants)"
      | Contract.Must_allow _ -> "NoOpinion (required RBAC grant is absent)"
      | Contract.Must_deny _ -> "Allow (forbidden RBAC grant exists)" in
    let note = request_description spec model ^ " => " ^ decision ^ apply_note policy model in
    report ~clause:(report_clause clause) spec
      (Report.Violated (counterexample spec policy ~note model))

let contract_report_with_trace ?z3 spec policy =
  let result,trace = Contract_verify.run_with_trace ?z3 policy (Contract_spec.to_contract spec) in
  contract_report_of_result spec policy result,trace

let run_with_trace ?z3 spec source =
  match Snapshot.of_string source with
  | Error reason -> report ~unsupported:reason spec (Report.Unknown reason),None
  | Ok snapshot ->
    let report,trace = contract_report_with_trace ?z3 spec (Lower.policy spec snapshot) in
    report,Some trace

let run ?z3 spec source = fst (run_with_trace ?z3 spec source)

type selected_plan = {
  selected_spec : Contract_spec.t;
  selected_policy : Ir.policy;
  selected_contract : Contract.t;
  selected_identity : Report.frozen_spec;
  selected_queries : Contract_verify.obligation list;
}
type selected = { report : Report.t; trace : Contract_verify.trace_entry list }

let plan_selected spec ~clauses ~frozen_spec source =
  let contract = Contract_spec.to_contract spec in
  let known = List.map Contract.name contract.clauses in
  if clauses=[] || List.length (List.sort_uniq String.compare clauses)<>List.length clauses ||
     not (List.for_all (fun name -> List.mem name known) clauses) then
    Error "selected invariant clauses must be nonempty, unique names in the frozen access contract"
  else match Snapshot.of_string source with
    | Error reason -> Error reason
    | Ok snapshot ->
      let policy = Lower.policy spec snapshot in
      let contract = {contract with clauses=List.filter (fun c -> List.mem (Contract.name c) clauses) contract.clauses} in
      Ok {selected_spec=spec;selected_policy=policy;selected_contract=contract;
        selected_identity=frozen_spec;selected_queries=Contract_verify.plan policy contract}

let selected_queries plan = plan.selected_queries
let execute_selected ?z3 plan =
  let result,trace=Contract_verify.run_with_trace ?z3 plan.selected_policy plan.selected_contract in
  let report=contract_report_of_result plan.selected_spec plan.selected_policy result in
  {report={report with property_name="rbac-sequence-invariants";
    property_description="The selected frozen access clauses hold at this sequence state; unselected final-only clauses are not asserted by this report.";
    frozen_spec=Some plan.selected_identity};trace}

type comparison = {
  report : Report.t;
  candidate_report : Report.t option;
  trace : Evidence.comparison_trace option;
}

let compare_with_trace ?z3 spec ~before ~after =
  let ( let* ) = Result.bind in
  let prepared =
    let* before = Snapshot.of_string before |> Result.map_error (fun e -> "baseline: " ^ e) in
    let* after = Snapshot.of_string after |> Result.map_error (fun e -> "candidate: " ^ e) in
    Ok (Lower.policy spec before,Lower.policy spec after) in
  match prepared with
  | Error reason ->
    {report=report ~unsupported:reason spec (Report.Unknown reason);
     candidate_report=None;trace=None}
  | Ok (before,after) ->
    let when_ = Ir.Not (Contract_spec.approved_changes spec) in
    let id = "preservation-outside-change-scope" in
    let query = Smt_encode.decision_equivalence_query ~when_ before after in
    let candidate,candidate_trace = contract_report_with_trace ?z3 spec after in
    let final_report,execution = match candidate.result with
      | Report.Proved ->
        let answer = Solve.check ?z3 query
          |> Witness.validate ~obligation:id
               (Witness.decision_difference ~when_ before after) in
        let result,clause = match answer with
          | Solve.Proved -> Report.Proved,None
          | Solve.Unknown reason -> Report.Unknown reason,None
          | Solve.Violated model ->
            let request = Witness.request_of_model model in
            let decision policy = if Ir.possibly_allows policy request then "Allow" else "NoOpinion" in
            let note = Printf.sprintf "%s changed from %s to %s outside the approved change scope"
              (request_description spec model) (decision before) (decision after)
              ^ (match Resource_domain.object_state ~operation:request.action with
                 | None -> ""
                 | Some _ -> Printf.sprintf "; prerequisite evaluations (not execution traces): baseline [%s]; candidate [%s]"
                     (prerequisite_description before request) (prerequisite_description after request)) in
            Report.Violated (counterexample spec after ~note model),
            Some {Report.name=id;description=note;kind=Report.Must_preserve} in
        {candidate with result;clause;property_name="rbac-repair-preservation";
         property_description=(match Contract_spec.version spec with
           | 1 -> "The candidate satisfies the frozen access requirements and preserves every RBAC decision outside the approved change scope, within the fixed identity and named-get domain."
           | 2 -> "The candidate satisfies the frozen access requirements and preserves every RBAC decision outside the approved change scope, within the fixed identity and get/list/watch domain."
           | 6 -> "The candidate satisfies the frozen access requirements and preserves every RBAC decision outside the approved change scope, across all eight verbs and all eight resources for every frozen identity. This concerns initial authorization, not successful mutation, object contents or deletion targets."
           | 7 -> "The candidate satisfies the frozen access requirements and preserves every initial RBAC decision outside the approved change scope, over all supported base-resource and subresource operations for every frozen identity. This does not assert successful execution, token issuance, response contents or final authorization."
           | 8 -> "The candidate satisfies the frozen requirements and preserves every aggregate initial or conditional-apply operation decision outside the exact approved scope for every frozen identity. Equivalent patch/apply-existing predicates remain distinct operation classes. This does not preserve every intermediate grant or assert live object state, successful API execution or final authorization."
           | 9 -> "The candidate satisfies the frozen requirements and preserves every aggregate operation decision outside the exact approved scope, across the entire fixed/custom resource catalogue and supported non-resource URL domain for every frozen identity. Catalogue, identities and scope cannot change during repair. Conditional SSA/PUT prerequisites do not establish API success or preserve every intermediate grant."
           | 10 -> "The candidate satisfies the frozen requirements and preserves every aggregate operation decision outside the exact approved scope, across the fixed/custom resource catalogue, controller/review APIs and supported non-resource URLs for every frozen identity. Conditional SSA/PUT prerequisites and initial review authorization do not establish API success, review results or preservation of every intermediate grant."
           | _ -> "The candidate satisfies the frozen access requirements and preserves every RBAC decision outside the approved change scope, within the fixed identity and read/named-write domain. This does not assert successful mutation or preservation of object contents.")},
        Contract_verify.Executed answer
      | _ -> candidate,Contract_verify.Not_executed in
    {report=final_report;candidate_report=Some candidate;
     trace=Some {Evidence.candidate=candidate_trace;
                 preservation={id;smtlib=query;execution}}}

let compare ?z3 spec ~before ~after = (compare_with_trace ?z3 spec ~before ~after).report

type preservation_plan = {
  spec : Contract_spec.t;
  original : Ir.policy;
  proposed : Ir.policy;
  when_ : Ir.condition;
  query : string;
}
type preservation = { report : Report.t; trace : Evidence.preservation_trace }

let plan_preservation spec ~before ~after =
  let ( let* ) = Result.bind in
  let* before = Snapshot.of_string before |> Result.map_error (fun e -> "baseline: " ^ e) in
  let* after = Snapshot.of_string after |> Result.map_error (fun e -> "intermediate: " ^ e) in
  let original = Lower.policy spec before and proposed = Lower.policy spec after in
  let when_ = Ir.Not (Contract_spec.approved_changes spec) in
  Ok {spec;original;proposed;when_;query=Smt_encode.decision_equivalence_query ~when_ original proposed}

let preservation_query p = p.query
let execute_preservation ?z3 p =
  let id = "preservation-outside-change-scope" in
  let answer = Solve.check ?z3 p.query
    |> Witness.validate ~obligation:id
         (Witness.decision_difference ~when_:p.when_ p.original p.proposed) in
  let result,clause = match answer with
    | Solve.Proved -> Report.Proved,None
    | Solve.Unknown reason -> Report.Unknown reason,None
    | Solve.Violated model ->
      let request = Witness.request_of_model model in
      let decision policy = if Ir.possibly_allows policy request then "Allow" else "NoOpinion" in
      let note = Printf.sprintf "%s changed from %s to %s outside the approved change scope at this intermediate state"
        (request_description p.spec model) (decision p.original) (decision p.proposed) in
      Report.Violated (counterexample p.spec p.proposed ~note model),
      Some {Report.name=id;description=note;kind=Report.Must_preserve} in
  let report = { (report ?clause p.spec result) with
    property_name="rbac-sequence-preservation";
    property_description="Preserve original modeled decisions outside the frozen approved change scope at this intermediate state. This obligation does not check the final access clauses." } in
  {report;trace={id;smtlib=p.query;execution=Contract_verify.Executed answer}}
