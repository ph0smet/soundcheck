open Soundcheck_core

let profile_id = "kubernetes-rbac-v1.34-get-v1"
let assumptions = [
  "The input is the complete static desired RBAC snapshot, including every applicable binding and referenced role.";
  "The contract's fixed usernames and groups are trusted request attributes; authentication is not verified.";
  "Only named get requests for core ConfigMaps and Secrets, with no subresource, are quantified.";
  "NoOpinion means RBAC supplied no grant; it is not a final API-server denial.";
  "Admission, object existence, aggregation controllers, list/watch and privilege-escalation paths are outside this profile.";
  "Applying a partial manifest does not remove omitted live bindings; deployment reconciliation must establish the assumed snapshot." ]

let assessment ?reason () : Report.assurance =
  {profile=profile_id;
   status=(if Option.is_some reason then Report.Unsupported else Report.Within_profile);
   findings=(match reason with None -> [] | Some detail ->
     [{Report.code="unsupported-rbac-input";service=None;route=None;detail}])}

let profile_json () =
  Input.json (`O ["schema_version",`Number "1";"id",`String profile_id;
    "connector",`String "kubernetes-rbac";"reference_version",`String "v1.34.0";
    "input_format",`String "strict-json-kubernetes-list";
    "decision",`String "Allow|NoOpinion";
    "verb",`String "get";"api_group",`String "";"subresource",`String "";
    "resources",`A [`String "configmaps";`String "secrets"];
    "assumptions",`A (List.map (fun s -> `String s) assumptions)])

let profile_human () =
  "Kubernetes RBAC assurance profile: " ^ profile_id ^ "\n"
  ^ "Input: one strict JSON v1/List of static RBAC objects. Reference: Kubernetes v1.34.0.\n"
  ^ String.concat "\n" (List.map (fun s -> "- " ^ s) assumptions)
