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
    (Soundcheck_ci.Github_annotation.render ~file detailed)
