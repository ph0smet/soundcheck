open Soundcheck_core
open Soundcheck_kong

let parse source =
  match Parse.parse_string source with
  | Ok config -> config
  | Error error -> failwith error

let config ?(root = "[]") ?(service = "[]") ?(route = "[]") () =
  Printf.sprintf
    {|plugins: %s
services:
  - name: api
    plugins: %s
    routes:
      - name: admin
        paths: [/admin]
        plugins: %s
|}
    root service route

let expect_result expected property source =
  match Verify.run ~property source with
  | Ok report when report.Report.result = expected -> ()
  | Ok _ -> failwith "unexpected global-plugin verification result"
  | Error error -> failwith error

let request : Ir.request =
  { object_request = None; principal = Anonymous;
    action = "GET";
    resource = "/admin";
    context = [];
    source = 0l;
    host = "";
    scheme = "http";
    sni = "" }

let () =
  let global_auth = config ~root:"[{name: key-auth}]" () in
  let parsed = parse global_auth in
  if List.length parsed.global_plugins <> 1 || parsed.scoped_plugins <> [] then
    failwith "relationship-free root plugin was not classified as global";
  expect_result Report.Proved (Verify.No_anonymous_access "/admin") global_auth;

  let disabled_service =
    config ~root:"[{name: key-auth}]"
      ~service:"[{name: key-auth, enabled: false}]" ()
  in
  expect_result Report.Proved (Verify.No_anonymous_access "/admin")
    disabled_service;

  let global_rate_limit = config ~root:"[{name: rate-limiting}]" () in
  expect_result Report.Proved Verify.Rate_limit_on_public global_rate_limit;

  let root_service_auth =
    config ~root:"[{name: key-auth, service: api}]" ()
  in
  expect_result Report.Proved (Verify.No_anonymous_access "/admin")
    root_service_auth;
  let root_route_auth = config ~root:"[{name: key-auth, route: admin}]" () in
  expect_result Report.Proved (Verify.No_anonymous_access "/admin")
    root_route_auth;

  let overridden_termination =
    config ~root:"[{name: request-termination}]"
      ~service:
        "[{name: request-termination, config: {trigger: x-maintenance}}]"
      ()
  in
  let policy = Lower.to_policy (parse overridden_termination) in
  if Ir.evaluate policy request <> Allow then
    failwith "service plugin must override the global plugin of the same name";

  let combined_precedence =
    config
      ~root:
        "[{name: request-termination}, {name: request-termination, service: api}, {name: request-termination, route: admin}, {name: request-termination, service: api, route: admin, config: {trigger: x-debug}}]"
      ()
  in
  if Ir.evaluate (Lower.to_policy (parse combined_precedence)) request <> Allow then
    failwith "combined route/service scope must be the most specific plugin";

  let consumer_scoped =
    config ~root:"[{name: key-auth, consumer: alice}]" ()
  in
  let scoped = parse consumer_scoped in
  if List.length scoped.scoped_plugins <> 1 || scoped.global_plugins <> [] then
    failwith "associated root plugin was incorrectly classified as global";
  (match
     Verify.run ~property:(Verify.No_anonymous_access "/admin") consumer_scoped
   with
   | Ok
       { result = Report.Unknown reason;
         assurance = Some { status = Report.Unsupported; _ };
         _ }
     when String.starts_with ~prefix:"unsupported fragment: root-level plugin"
            reason -> ()
   | Ok _ -> failwith "consumer-scoped plugin must produce unknown/unsupported"
   | Error error -> failwith error);

  (match
     Verify.run ~property:(Verify.No_anonymous_access "/admin")
       (config ~root:"[{name: key-auth, service: missing}]" ())
   with
   | Error error
     when String.starts_with
            ~prefix:
              "invalid Kong config: root plugin \"key-auth\" references unknown service"
            error -> ()
   | Error error -> failwith ("unexpected reference validation error: " ^ error)
   | Ok _ -> failwith "unknown root-plugin service reference was accepted");

  let mismatched_scope =
    {|plugins: [{name: key-auth, service: other, route: admin}]
services:
  - name: api
    routes: [{name: admin, paths: [/admin]}]
  - name: other
    routes: [{name: other-route, paths: [/other]}]
|}
  in
  (match
     Verify.run ~property:(Verify.No_anonymous_access "/admin") mismatched_scope
   with
   | Error error
     when String.starts_with
            ~prefix:
              "invalid Kong config: root plugin \"key-auth\" references route \"admin\" outside service \"other\""
            error -> ()
   | Error error -> failwith ("unexpected ownership validation error: " ^ error)
   | Ok _ -> failwith "mismatched root-plugin route/service scope was accepted");

  let non_string_reference =
    config ~root:"[{name: key-auth, route: {id: route-id}}]" ()
  in
  (match
     Verify.run ~property:(Verify.No_anonymous_access "/admin")
       non_string_reference
   with
   | Ok
       { result = Report.Unknown reason;
         assurance = Some { status = Report.Unsupported; _ };
         _ }
     when String.starts_with ~prefix:"unsupported fragment: root-level plugin"
            reason -> ()
   | Ok _ -> failwith "non-string plugin reference must be unsupported"
   | Error error -> failwith error);

  let top_level_route =
    "routes: [{name: root-route, service: {id: service-id}, paths: [/admin]}]\nservices: []"
  in
  (match Verify.run ~property:(Verify.No_anonymous_access "/admin") top_level_route with
   | Ok
       { result = Report.Unknown reason;
         assurance = Some { status = Report.Unsupported; _ };
         _ }
     when String.starts_with ~prefix:"unsupported fragment: top-level route"
            reason -> ()
   | Ok _ -> failwith "non-string top-level route reference must be unsupported"
   | Error error -> failwith error)
