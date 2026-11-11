open Soundcheck_core

let profile_id = "kubernetes-rbac-v1.34-get-v3"
let read_profile_id = "kubernetes-rbac-v1.34-read-v3"
let write_profile_id = "kubernetes-rbac-v1.34-read-write-v3"
let scoped_profile_id = "kubernetes-rbac-v1.34-scoped-read-write-v3"
let id_for_version = function
  | 1 -> profile_id | 2 -> read_profile_id | 3 -> write_profile_id | 4 -> scoped_profile_id
  | _ -> invalid_arg "unsupported RBAC contract version"
let assumptions = [
  "The input is the complete static desired RBAC snapshot, including every applicable binding and the complete ClusterRole inventory with labels, even unbound aggregation contributors.";
  "Aggregated ClusterRoles must have acyclic dependencies (self-matches ignored) and stored full rule sets equal to recursively selected rules. Completeness is assumed; no controller reconciliation, rollout or future label/object changes are verified.";
  "The contract's fixed usernames and groups are trusted request attributes; authentication is not verified.";
  "Only named get requests for core ConfigMaps and Secrets, with no subresource, are quantified.";
  "Validated ClusterRole non-resource URL rules are retained but cannot grant resource requests. Non-resource URL authorization and preservation are outside this profile.";
  "NoOpinion means RBAC supplied no grant; it is not a final API-server denial.";
  "Admission, object existence, live aggregation controllers, list/watch and privilege-escalation paths are outside this profile.";
  "Applying a partial manifest does not remove omitted live bindings; deployment reconciliation must establish the assumed snapshot." ]

let read_assumptions = [
  "The input is the complete static desired RBAC snapshot, including every applicable binding and the complete ClusterRole inventory with labels, even unbound aggregation contributors.";
  "Aggregated ClusterRoles must have acyclic dependencies (self-matches ignored) and stored full rule sets equal to recursively selected rules. Completeness is assumed; no controller reconciliation, rollout or future label/object changes are verified.";
  "The contract's fixed usernames and groups are trusted request attributes; authentication is not verified.";
  "Only get/list/watch authorization of core ConfigMaps and Secrets, with no subresource, is quantified.";
  "Validated ClusterRole non-resource URL rules are retained but cannot grant resource requests. Non-resource URL authorization and preservation are outside this profile.";
  "Get requires a valid namespace and object name. List/watch also permit an empty namespace (all-namespace endpoint) and empty effective authorization name.";
  "Nonempty effective authorization names are DNS1123 object names. For list/watch they may come from an exact metadata.name selector or a legacy named watch path after Kubernetes request interpretation; they are not the names of returned objects.";
  "An empty effective name means no usable exact-name restriction; it does not assert that the HTTP request has no selectors.";
  "NoOpinion means RBAC supplied no grant; it is not a final API-server denial.";
  "Raw HTTP/selector parsing, API execution, response contents, watch events, admission, object existence, live aggregation controllers, mutation and indirect privilege-escalation paths are outside this profile.";
  "Applying a partial manifest does not remove omitted live bindings; deployment reconciliation must establish the assumed snapshot." ]

let write_assumptions = [
  "The input is the complete static desired RBAC snapshot, including every applicable binding and the complete ClusterRole inventory with labels, even unbound aggregation contributors.";
  "Aggregated ClusterRoles must have acyclic dependencies (self-matches ignored) and stored full rule sets equal to recursively selected rules. Completeness is assumed; no controller reconciliation, rollout or future label/object changes are verified.";
  "The contract's fixed usernames and groups are trusted request attributes; authentication is not verified.";
  "Only get/list/watch and named update/patch/delete authorization of core ConfigMaps and Secrets, with no subresource, is quantified.";
  "Validated ClusterRole non-resource URL rules are retained but cannot grant resource requests. Non-resource URL authorization and preservation are outside this profile.";
  "Get/update/patch/delete require a valid namespace and object name. List/watch also permit an empty namespace (all-namespace endpoint) and empty effective authorization name.";
  "Nonempty effective authorization names are DNS1123 object names. For list/watch they may come from an exact metadata.name selector or a legacy named watch path after Kubernetes request interpretation; they are not the names of returned objects.";
  "An empty effective name means no usable exact-name restriction; it does not assert that the HTTP request has no selectors.";
  "NoOpinion means RBAC supplied no grant; it is not a final API-server denial.";
  "Named write grants describe initial request authorization only, not request bodies, changed fields, additional operation-specific authorization, successful mutation, object existence, or admission decisions. Create and deletecollection are outside the profile.";
  "Raw HTTP/selector parsing, API execution, response contents, watch events, other authorizers, live aggregation controllers and indirect privilege-escalation paths are outside this profile.";
  "Applying a partial manifest does not remove omitted live bindings; deployment reconciliation must establish the assumed snapshot." ]

let assessment ?(version=1) ?reason () : Report.assurance =
  {profile=id_for_version version;
   status=(if Option.is_some reason then Report.Unsupported else Report.Within_profile);
   findings=(match reason with None -> [] | Some detail ->
     [{Report.code="unsupported-rbac-input";service=None;route=None;detail}])}

let scoped_assumptions = write_assumptions @ [
  "Namespace include/exclude selectors range over valid nonempty namespaces, including those absent from the inventory. The all-namespace list/watch endpoint remains a separate null scope.";
  "Name complements explicitly select whether empty effective authorization names are included. Empty-only scopes are restricted to list/watch.";
  "The same selectors define required access and the approved changes excluded from preservation; only frozen identities are quantified." ]

let profile_json ?(version=1) () =
  let id = id_for_version version in
  if version >= 2 then
    Input.json (`O ["schema_version",`Number "2";"id",`String id;
      "connector",`String "kubernetes-rbac";"reference_version",`String "v1.34.0";
      "contract_schema_version",`Number (string_of_int version);
      "input_format",`String "strict-json-kubernetes-list";
      "decision",`String "Allow|NoOpinion";
      "verbs",`A (List.map (fun s -> `String s)
        (if version >= 3 then ["get";"list";"watch";"update";"patch";"delete"] else ["get";"list";"watch"]));
      "api_group",`String "";"subresource",`String "";
      "resources",`A [`String "configmaps";`String "secrets"];
      "assumptions",`A (List.map (fun s -> `String s)
        (match version with 4 -> scoped_assumptions | 3 -> write_assumptions | _ -> read_assumptions))])
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
      (match version with 1 -> assumptions | 2 -> read_assumptions | 3 -> write_assumptions | _ -> scoped_assumptions))
