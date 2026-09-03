open Soundcheck_core
open Soundcheck_kong

let contract ?method_ ?host () =
  Verify.Authenticated_access
    { path_prefix = "/admin"; method_; host }

let verify ?method_ ?host config =
  match Verify.run ~property:(contract ?method_ ?host ()) config with
  | Ok report -> report
  | Error error -> failwith error

let expect_clause report kind name =
  match report.Report.clause with
  | Some clause when clause.kind = kind && clause.name = name -> ()
  | _ -> failwith ("unexpected or missing clause metadata for " ^ name)

let secure =
  {|services:
  - name: admin-api
    routes:
    - name: admin-route
      paths: [/admin]
      plugins: [{name: key-auth}]
|}

let open_route =
  {|services:
  - name: admin-api
    routes:
    - name: admin-route
      paths: [/admin]
|}

let deny_all = "services: []\n"

let method_scoped =
  {|services:
  - name: admin-api
    routes:
    - name: admin-get
      paths: [/admin]
      methods: [GET]
      plugins: [{name: key-auth}]
|}

let host_scoped =
  {|services:
  - name: admin-api
    routes:
    - name: admin-host
      paths: [/admin]
      hosts: [admin.example]
      plugins: [{name: key-auth}]
|}

let () =
  (match (verify secure).Report.result with
   | Proved -> ()
   | _ -> failwith "secure authenticated access contract must prove");

  let denied = verify deny_all in
  (match denied.result with
   | Violated ce ->
     expect_clause denied Must_allow "authenticated-access-allowed";
     let request : Ir.request =
       { principal = Authenticated "user";
         action = ce.action;
         resource = ce.path;
         context = [];
         source = ce.source_ip;
         host = ce.host }
     in
     let policy : Ir.policy = { rules = []; default = Deny } in
     if Ir.definitely_allows policy request then
       failwith "deny-all counterexample was not actually blocked"
   | _ -> failwith "deny-all must violate the functionality clause");

  let unsafe = verify open_route in
  (match unsafe.result with
   | Violated _ -> expect_clause unsafe Must_deny "anonymous-access-denied"
   | _ -> failwith "open route must violate the safety clause");

  (match (verify ~method_:"GET" method_scoped).result with
   | Proved -> ()
   | _ -> failwith "explicit GET scope must prove");
  (match (verify method_scoped).result with
   | Violated _ -> ()
   | _ -> failwith "all-method scope must expose the blocked method");

  (match (verify ~host:"ADMIN.EXAMPLE" host_scoped).result with
   | Proved -> ()
   | _ -> failwith "explicit host scope must prove case-insensitively");
  (match (verify host_scoped).result with
   | Violated _ -> ()
   | _ -> failwith "all-host scope must expose the blocked host");

  (match
     Verify.run ~emit_smt:"unused-contract-audit.smt2"
       ~property:(contract ~method_:"GET" ()) secure
   with
   | Error _ -> ()
   | Ok _ -> failwith "contract audit emission must not be silently ignored")
