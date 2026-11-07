open Soundcheck_core
open Soundcheck_kong

let parse source =
  match Parse.parse_string source with
  | Ok config -> config
  | Error error -> failwith error

let request ?(source = 0l) () : Ir.request =
  { object_request = None; principal = Anonymous;
    action = "GET";
    resource = "/maintenance";
    context = [];
    source;
    host = "";
    scheme = "http";
    sni = "" }

let config ?(service_plugin = "") route_plugin =
  Printf.sprintf
    {|services:
  - name: api
    plugins: %s
    routes:
    - name: maintenance
      paths: [/maintenance]
      plugins: %s
|}
    service_plugin route_plugin

let decision ?source config =
  Lower.to_policy (parse config)
  |> fun policy -> Ir.evaluate policy (request ?source ())

let ip address =
  match Cidr.parse address with Ok cidr -> cidr.base | Error error -> failwith error

let () =
  let unconditional = "[{name: request-termination}]" in
  let conditional =
    "[{name: request-termination, config: {trigger: x-debug}}]"
  in
  if decision (config unconditional) <> Deny then
    failwith "unconditional route request-termination must deny upstream access";
  if decision (config ~service_plugin:unconditional "[]") <> Deny then
    failwith "service request-termination must apply to its routes";
  if decision (config ~service_plugin:unconditional conditional) <> Allow then
    failwith "a route-scoped plugin must override the service configuration";
  if
    decision
      (config ~service_plugin:unconditional
         "[{name: request-termination, enabled: false}]")
    <> Deny
  then failwith "a disabled route plugin must not hide the enabled service plugin";

  let restriction_precedence =
    config
      ~service_plugin:
        "[{name: ip-restriction, config: {allow: [10.0.0.0/8]}}]"
      "[{name: ip-restriction, config: {allow: [192.168.0.0/16]}}]"
  in
  if decision ~source:(ip "192.168.1.1") restriction_precedence <> Allow then
    failwith "route ip-restriction must override its service configuration";
  if decision ~source:(ip "10.1.1.1") restriction_precedence <> Deny then
    failwith "overridden service ip-restriction must not remain active";

  (match
     Verify.run ~property:(Verify.No_anonymous_access "/maintenance")
       (config unconditional)
   with
   | Ok { result = Report.Proved; _ } -> ()
   | Ok _ -> failwith "request-termination must close anonymous reachability"
   | Error error -> failwith error);

  (match
     Verify.run
       ~property:
         (Verify.Authenticated_access
            { path_prefix = "/maintenance"; method_ = None; host = None })
       (config unconditional)
   with
   | Ok
       { result = Report.Violated _;
         clause = Some { kind = Report.Must_allow; _ };
         _ } -> ()
   | Ok _ -> failwith "request-termination must fail required functionality"
   | Error error -> failwith error);

  (match Assurance.assess (parse (config conditional)) with
   | { status = Assurance.Conservative;
       findings = [ { code = "conditional-request-termination"; _ } ] } -> ()
   | _ -> failwith "triggered request-termination must remain conservative")
