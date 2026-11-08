open Soundcheck_core

let profile_id = "kubernetes-rbac-v1.34-get-v1"
let read_profile_id = "kubernetes-rbac-v1.34-read-v1"
let id_for_version = function
  | 1 -> profile_id | 2 -> read_profile_id
  | _ -> invalid_arg "unsupported RBAC contract version"
let assumptions = [
  "The input is the complete static desired RBAC snapshot, including every applicable binding and referenced role.";
  "The contract's fixed usernames and groups are trusted request attributes; authentication is not verified.";
  "Only named get requests for core ConfigMaps and Secrets, with no subresource, are quantified.";
  "NoOpinion means RBAC supplied no grant; it is not a final API-server denial.";
  "Admission, object existence, aggregation controllers, list/watch and privilege-escalation paths are outside this profile.";
  "Applying a partial manifest does not remove omitted live bindings; deployment reconciliation must establish the assumed snapshot." ]

let read_assumptions = [
  "The input is the complete static desired RBAC snapshot, including every applicable binding and referenced role.";
  "The contract's fixed usernames and groups are trusted request attributes; authentication is not verified.";
  "Only get/list/watch authorization of core ConfigMaps and Secrets, with no subresource, is quantified.";
  "Get requires a valid namespace and object name. List/watch also permit an empty namespace (all-namespace endpoint) and empty effective authorization name.";
  "Nonempty effective authorization names are DNS1123 object names. For list/watch they may come from an exact metadata.name selector or a legacy named watch path after Kubernetes request interpretation; they are not the names of returned objects.";
  "An empty effective name means no usable exact-name restriction; it does not assert that the HTTP request has no selectors.";
  "NoOpinion means RBAC supplied no grant; it is not a final API-server denial.";
  "Raw HTTP/selector parsing, API execution, response contents, watch events, admission, object existence, aggregation controllers, mutation and indirect privilege-escalation paths are outside this profile.";
  "Applying a partial manifest does not remove omitted live bindings; deployment reconciliation must establish the assumed snapshot." ]

let assessment ?(version=1) ?reason () : Report.assurance =
  {profile=id_for_version version;
   status=(if Option.is_some reason then Report.Unsupported else Report.Within_profile);
   findings=(match reason with None -> [] | Some detail ->
     [{Report.code="unsupported-rbac-input";service=None;route=None;detail}])}

let profile_json ?(version=1) () =
  let id = id_for_version version in
  if version = 2 then
    Input.json (`O ["schema_version",`Number "2";"id",`String id;
      "connector",`String "kubernetes-rbac";"reference_version",`String "v1.34.0";
      "contract_schema_version",`Number "2";
      "input_format",`String "strict-json-kubernetes-list";
      "decision",`String "Allow|NoOpinion";
      "verbs",`A [`String "get";`String "list";`String "watch"];
      "api_group",`String "";"subresource",`String "";
      "resources",`A [`String "configmaps";`String "secrets"];
      "assumptions",`A (List.map (fun s -> `String s) read_assumptions)])
  else Input.json (`O ["schema_version",`Number "1";"id",`String profile_id;
    "connector",`String "kubernetes-rbac";"reference_version",`String "v1.34.0";
    "input_format",`String "strict-json-kubernetes-list";
    "decision",`String "Allow|NoOpinion";
    "verb",`String "get";"api_group",`String "";"subresource",`String "";
    "resources",`A [`String "configmaps";`String "secrets"];
    "assumptions",`A (List.map (fun s -> `String s) assumptions)])

let profile_human ?(version=1) () =
  "Kubernetes RBAC assurance profile: " ^ id_for_version version ^ "\n"
  ^ "Input: one strict JSON v1/List of static RBAC objects. Reference: Kubernetes v1.34.0.\n"
  ^ String.concat "\n" (List.map (fun s -> "- " ^ s)
      (if version = 1 then assumptions else read_assumptions))
