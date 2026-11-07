open Soundcheck_core

let contains text fragment =
  let rec loop i =
    i + String.length fragment <= String.length text
    && (String.sub text i (String.length fragment) = fragment || loop (i + 1))
  in loop 0

let expect label text fragment =
  if not (contains text fragment) then failwith (label ^ ": missing " ^ fragment)

let witness : Report.counterexample =
  {principal="system:serviceaccount:frontend:frontend-sa";action="get";
   path="";host="";scheme="";sni="";headers=[];source_ip=0l;
   route=None;service=None;shadowed_route=None;shadowed_service=None;
   object_request=Some {namespace="payments";resource_kind="secrets";name="db-password"};
   identity_groups=Some ["system:authenticated";"quoted\"group\n"];
   granting_rules=["RoleBinding/payments/extra -> ClusterRole/secret-reader/rules/0"];
   note="RBAC grants the forbidden request"}

let report clause : Report.t =
  {result=Violated witness;property_name="rbac-access";property_description="access";
   assurance=None;frozen_spec=None;clause}

let () =
  let json = Report.to_json (report None) in
  expect "version" json {|"schema_version":10|};
  expect "exact identity" json {|"principal":"system:serviceaccount:frontend:frontend-sa"|};
  expect "object coordinates" json {|"object_request":{"namespace":"payments","resource_kind":"secrets","name":"db-password"}|};
  expect "frozen groups escaped" json {|"identity_groups":["system:authenticated","quoted\"group\n"]|};
  expect "opaque rule identifiers" json {|"granting_rules":["RoleBinding/payments/extra -> ClusterRole/secret-reader/rules/0"]|};
  let http = {witness with principal="authenticated";object_request=None;
    identity_groups=None;granting_rules=[]} in
  expect "absent HTTP dimensions" (Report.to_json {(report None) with result=Violated http})
    {|"object_request":null,"identity_groups":null,"granting_rules":[]|};
  List.iter (fun (kind,expected) ->
    let clause : Report.clause = {name="requirement";description="fixed requirement";kind} in
    expect "clause kind" (Report.to_json (report (Some clause)))
      (Printf.sprintf "\"kind\":\"%s\"" expected))
    [Report.Must_deny,"must_deny";Report.Must_allow,"must_allow";
     Report.Must_not_grant,"must_not_grant";Report.Must_preserve,"must_preserve"];
  print_endline "Report schema 10: typed witnesses and clause kinds passed"
