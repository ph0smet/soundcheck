open Soundcheck_core

let report result =
  { Report.result = result;
    property_name = "admin: access";
    property_description = "admin access policy";
    assurance = None;
    clause = None;
    frozen_spec = None }

let expect name expected actual =
  if expected <> actual then
    failwith
      (Printf.sprintf "%s annotation mismatch\nexpected: %s\nactual:   %s" name
         expected actual)

let () =
  let file = "kong,prod.yaml" in
  expect "proved"
    "::notice file=kong%2Cprod.yaml,title=Soundcheck%3A admin%3A access::admin: access proved"
    (Soundcheck_ci.Github_annotation.render ~file (report Report.Proved));
  expect "vacuous"
    "::error file=kong%2Cprod.yaml,title=Soundcheck%3A admin%3A access::admin: access is vacuous; no configuration was verified"
    (Soundcheck_ci.Github_annotation.render ~file (report Report.Vacuous));
  expect "inconsistent"
    "::error file=kong%2Cprod.yaml,title=Soundcheck%3A admin%3A access::admin: access is inconsistent; deny/allow overlap"
    (Soundcheck_ci.Github_annotation.render ~file
       (report (Report.Inconsistent "deny/allow overlap")));
  expect "unknown"
    "::error file=kong%2Cprod.yaml,title=Soundcheck%3A admin%3A access::admin: access is unknown; unsupported route"
    (Soundcheck_ci.Github_annotation.render ~file
       (report (Report.Unknown "unsupported route")));
  let counterexample : Report.counterexample =
    { principal = "anonymous";
      action = "GET";
      path = "/admin";
      route = Some "admin";
      service = Some "api";
      shadowed_route = None;
      shadowed_service = None;
      host = "";
      scheme = "http";
      sni = "";
      source_ip = 0l;
      headers = [];
      object_request = None; identity_groups = None; granting_rules = [];
      note = "public% access\nexposed" }
  in
  let detailed =
    { (report (Report.Violated counterexample)) with
      clause =
        Some
          { Report.name = "deny-anonymous";
            description = "deny anonymous traffic";
            kind = Report.Must_deny };
      assurance =
        Some
          { Report.profile = "kong-http-v1";
            status = Report.Conservative;
            findings =
              [ { Report.code = "route-header";
                  service = Some "api";
                  route = Some "admin";
                  detail = "header, uncertain" } ] };
      frozen_spec =
        Some
          { Report.schema_version = 1;
            kind = "authenticated-access";
            canonical = {|{"kind":"access%"}|} } }
  in
  expect "violated"
    {|::error file=kong%2Cprod.yaml,title=Soundcheck%3A admin%3A access::admin: access violated; anonymous GET /admin; route admin; service api; public%25 access%0Aexposed; clause deny-anonymous (must_deny); assurance kong-http-v1 (conservative); route-header: header, uncertain; frozen spec {"kind":"access%25"}|}
    (Soundcheck_ci.Github_annotation.render ~file detailed);
  let object_witness =
    { counterexample with
      principal = "alice"; action = "get"; path = "";
      route = None; service = None;
      object_request = Some { Ir.namespace="payments"; resource_kind="secrets"; name="signing-key" };
      identity_groups = Some ["system:authenticated"; "operators"];
      granting_rules = ["RoleBinding payments/read -> ClusterRole secrets rule 0"];
      note = "RBAC decision: Allow" } in
  let object_report witness kind =
    { (report (Report.Violated witness)) with
      property_name="rbac-access";
      clause=Some { Report.name="secrets-boundary";description="frozen access";kind } } in
  expect "typed object grant"
    {|::error file=rbac.json,title=Soundcheck%3A rbac-access::rbac-access violated; alice get secrets/signing-key in namespace payments; identity groups ["system:authenticated", "operators"]; granting rules ["RoleBinding payments/read -> ClusterRole secrets rule 0"]; RBAC decision: Allow; clause secrets-boundary (must_not_grant)|}
    (Soundcheck_ci.Github_annotation.render ~file:"rbac.json"
       (object_report object_witness Report.Must_not_grant));
  expect "typed absent grant is NoOpinion"
    {|::error file=rbac.json,title=Soundcheck%3A rbac-access::rbac-access violated; alice get secrets/signing-key in namespace payments; identity groups ["system:authenticated", "operators"]; granting rules []; NoOpinion (required RBAC grant is absent); clause secrets-boundary (must_allow)|}
    (Soundcheck_ci.Github_annotation.render ~file:"rbac.json"
       (object_report {object_witness with granting_rules=[];
           note="NoOpinion (required RBAC grant is absent)"} Report.Must_allow));
  expect "typed preservation annotation"
    {|::error file=rbac.json,title=Soundcheck%3A rbac-access::rbac-access violated; alice get secrets/signing-key in namespace payments; identity groups ["system:authenticated", "operators"]; granting rules []; changed from Allow to NoOpinion outside the approved change scope; clause secrets-boundary (must_preserve)|}
    (Soundcheck_ci.Github_annotation.render ~file:"rbac.json"
       (object_report {object_witness with granting_rules=[];
           note="changed from Allow to NoOpinion outside the approved change scope"} Report.Must_preserve));
  expect "typed fields cannot inject workflow commands"
    {|::error file=rbac%2Cprod%0A.json,title=Soundcheck%3A rbac-access::rbac-access violated; alice%25%0D%0A::notice::injected get secrets/signing-key in namespace payments; identity groups ["group%25\n::error::injected"]; granting rules ["rule%25\r\n::notice::injected"]; note%25%0A::warning::injected; clause secrets-boundary (must_not_grant)|}
    (Soundcheck_ci.Github_annotation.render ~file:"rbac,prod\n.json"
       (object_report {object_witness with principal="alice%\r\n::notice::injected";
           identity_groups=Some ["group%\n::error::injected"];
           granting_rules=["rule%\r\n::notice::injected"];
           note="note%\n::warning::injected"} Report.Must_not_grant));
  print_endline "GitHub annotation checks passed (HTTP and typed objects)"
