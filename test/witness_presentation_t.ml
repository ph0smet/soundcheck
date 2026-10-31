open Soundcheck_core
open Soundcheck_kong

let ok = function Ok value -> value | Error message -> failwith message
let checks = ref 0
let check name value = incr checks; if not value then failwith name
let contains text fragment =
  let rec at offset =
    offset + String.length fragment <= String.length text
    && (String.sub text offset (String.length fragment) = fragment || at (offset + 1))
  in at 0

let model : Solve.model =
  { method_ = ""; path = "/admin"; is_anon = true; src_ip = 0l;
    host = "example.test"; scheme = "http"; sni = ""; headers = [] }

(* The same method-category scenario as the regression corpus: GET requires
   authentication while other modeled methods reach the open fallback. *)
let method_config = ok (Parse.parse_string
  {|services: [{name: api, routes: [
    {name: get-guarded, paths: [/admin], methods: [GET], plugins: [{name: key-auth}]},
    {name: any-open, paths: [/admin]}]}]|})
let method_policy = Lower.to_policy method_config

let report counterexample : Report.t =
  { result = Report.Violated counterexample;
    property_name = "no-anonymous-access"; property_description = "presentation regression";
    assurance = None; clause = None; frozen_spec = None }

let check_method label method_ human json =
  let expected = if method_ = "" then "(empty method)" else method_ in
  check (label ^ " preserves the concrete human method") (contains human expected);
  check (label ^ " does not invent universal method coverage") (not (contains human "<any-method>"));
  check (label ^ " preserves the JSON method value")
    (contains json ("\"action\":\"" ^ method_ ^ "\""));
  check (label ^ " keeps human placeholders out of JSON") (not (contains json "(empty method)"))

let () =
  let request = Witness.request_of_model model in
  check "empty-method request is a real modeled violation"
    (Ir.possibly_allows method_policy request);
  check "GET is denied, so this witness does not establish all methods"
    (not (Ir.possibly_allows method_policy { request with action = "GET" }));

  let open_source = "services: [{name: api, routes: [{name: admin, paths: [/admin]}]}]" in
  let guarded_source = "services: [{name: api, routes: [{name: admin, paths: [/admin], plugins: [{name: key-auth}]}]}]" in
  let open_cfg = ok (Parse.parse_string open_source) in
  let guarded_cfg = ok (Parse.parse_string guarded_source) in
  let guarded_policy = Lower.to_policy guarded_cfg in
  let spec = ok (Contract_spec.parse_string
    "schema_version: 1\nkind: authenticated-access\nscope: {path_prefix: /admin, method: GET}\n") in
  let contract_report = ok (Verify.run ~property:(Contract_spec.to_property spec) guarded_source)
    |> Contract_spec.bind_report spec in
  check "repair fixture satisfies its scoped contract" (contract_report.result = Report.Proved);
  let shadow_cfg = ok (Parse.parse_string
    {|services: [{name: api, routes: [
      {name: protected, paths: [/admin], plugins: [{name: key-auth}]},
      {name: public-health, paths: [/admin/health]}]}]|}) in
  let shadow_policy = Lower.to_policy shadow_cfg in
  let rule name = List.find (fun (rule : Ir.rule) -> rule.id = name) shadow_policy.rules in
  let pair : Shadowing.pair = { shadowing = rule "public-health"; shadowed = rule "protected" } in
  List.iter (fun method_ ->
    let model = { model with method_ } in
    let request = Witness.request_of_model model in
    let allowed = Lift.counterexample method_config model in
    let denied = Lift.functionality_counterexample guarded_cfg guarded_policy model in
    check "functionality fixture actually denies the concrete request"
      (not (Ir.definitely_allows guarded_policy request));
    let shadow_model = { model with path = "/admin/health" } in
    check "shadowing fixture actually has a permissive selected route"
      (Ir.possibly_allows shadow_policy (Witness.request_of_model shadow_model));
    let shadow = Lift.shadowing_counterexample shadow_cfg pair shadow_model in
    List.iter (fun (label, counterexample) ->
      let rendered = report counterexample in
      check_method label method_ (Report.to_human rendered) (Report.to_json rendered))
      [ "safety", allowed; "functionality", denied; "shadowing", shadow ];
    let observation decision : Compare.observation =
      { decision; route = Some "admin"; service = Some "api";
        service_target = None; upstream_uri = None } in
    check "comparison witness is allowed before"
      (Ir.possibly_allows (Lower.to_policy open_cfg) request);
    check "comparison witness is denied after"
      (not (Ir.possibly_allows guarded_policy request));
    check "repair witness is outside the frozen GET scope"
      (not (Ir.matches (Contract_spec.scope_condition spec) request));
    let witness : Compare.witness =
      { request = model; before = observation Ir.Allow; after = observation Ir.Deny } in
    let comparison : Compare.report =
      { result = Compare.Different witness; profile = Assurance.profile.id; mode = Compare.Security_decision } in
    check_method "comparison" method_ (Compare.to_human comparison) (Compare.to_json comparison);
    let repair : Compare.repair_report =
      { result = Compare.Out_of_scope_regression witness; profile = Assurance.profile.id;
        contract_report; frozen_spec = spec; mode = Compare.Security_decision } in
    check_method "repair" method_ (Compare.repair_to_human repair) (Compare.repair_to_json repair))
    [ ""; "POST" ];
  Printf.printf "Witness presentation: %d checks passed\n" !checks
