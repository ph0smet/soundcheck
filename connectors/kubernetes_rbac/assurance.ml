open Soundcheck_core

let profile_id = "kubernetes-rbac-v1.34-get-v3"
let read_profile_id = "kubernetes-rbac-v1.34-read-v3"
let write_profile_id = "kubernetes-rbac-v1.34-read-write-v3"
let scoped_profile_id = "kubernetes-rbac-v1.34-scoped-read-write-v3"
let resource_profile_id = "kubernetes-rbac-v1.34-resource-read-write-v1"
let collection_write_profile_id = "kubernetes-rbac-v1.34-collection-write-v1"
let subresource_profile_id = "kubernetes-rbac-v1.34-subresources-v1"
let id_for_version = function
  | 1 -> profile_id | 2 -> read_profile_id | 3 -> write_profile_id | 4 -> scoped_profile_id
  | 5 -> resource_profile_id
  | 6 -> collection_write_profile_id
  | 7 -> subresource_profile_id
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

let resource_assumptions = [
  "The input is the complete static desired RBAC snapshot, including every applicable binding and the complete ClusterRole inventory with labels, even unbound aggregation contributors.";
  "Aggregated ClusterRoles must have acyclic dependencies (self-matches ignored) and stored full rule sets equal to recursively selected rules. Completeness is assumed; no controller reconciliation, rollout or future label/object changes are verified.";
  "The contract's fixed usernames and groups are trusted request attributes; authentication is not verified.";
  "Only get/list/watch and named update/patch/delete initial RBAC authorization is quantified, with an empty subresource, over the fixed resource_domains catalogue.";
  "For namespaced resources, get/update/patch/delete require a nonempty DNS1123 namespace label of at most 63 characters. List/watch also permit the empty authorization namespace for the all-namespace endpoint.";
  "Nodes always have an empty authorization namespace. Only cluster-wide bindings contribute to these requests. Namespace objects are outside this profile because their request attributes differ from Nodes.";
  "Nonempty effective authorization names are restricted to DNS1123 subdomains of at most 253 characters. This is a bounded request domain, not object-body name validation or a claim of complete HTTP request coverage. Get/update/patch/delete require nonempty names; list/watch also permit empty names.";
  "List/watch names are effective authorization attributes after Kubernetes request interpretation, not names of returned objects. An empty effective name means no usable exact-name restriction, not necessarily absence of selectors.";
  "Namespace include/exclude selectors range over nonempty namespaces, including those absent from the inventory. Node scopes require null. Name complements explicitly select whether empty list/watch names are included.";
  "Required access and approved changes match exact API-group/resource pairs. Preservation quantifies all eight catalogue entries for every frozen identity, including resources absent from clauses. Existing contract versions keep their own smaller domains.";
  "Counterexample resource_kind uses a fixed injective catalogue: raw core plural, deployments.apps, or endpointslices.discovery.k8s.io. Contracts and evaluation requests use separate raw group/resource fields.";
  "Validated ClusterRole non-resource URL rules are retained but cannot grant resource requests. Non-resource URL authorization and preservation are outside this profile.";
  "NoOpinion means RBAC supplied no grant; it is not a final API-server denial.";
  "Grants describe initial request authorization only, not object existence, API route availability, request bodies, changed fields, successful execution, additional operation-specific authorization, admission, response contents, watch events, or indirect privilege escalation.";
  "Create, deletecollection, subresources, Namespaces, custom resources and resources outside the catalogue are outside this profile. No controller or workload effects are modeled.";
  "Applying a partial manifest does not remove omitted live bindings; deployment reconciliation must establish the assumed snapshot." ]

let collection_write_assumptions = [
  "The input is the complete static desired RBAC snapshot, including every applicable binding and the complete ClusterRole inventory with labels, even unbound aggregation contributors.";
  "Aggregated ClusterRoles must have acyclic dependencies (self-matches ignored) and stored full rule sets equal to recursively selected rules. Completeness is assumed; no controller reconciliation, rollout or future label/object changes are verified.";
  "The contract's fixed usernames and groups are trusted request attributes; authentication is not verified.";
  "Only get/list/watch, named update/patch/delete, and empty-name create/deletecollection initial RBAC authorization is quantified, with an empty subresource, over the fixed eight-entry resource_domains catalogue.";
  "For namespaced resources, get/update/patch/delete/create/deletecollection require a nonempty DNS1123 namespace label of at most 63 characters. Only list/watch also permit the empty authorization namespace for the all-namespace endpoint.";
  "Nodes always have an empty authorization namespace. Only cluster-wide bindings contribute to these requests. Namespace objects are outside this profile because their request attributes differ from Nodes.";
  "Nonempty effective authorization names are restricted to DNS1123 subdomains of at most 253 characters. Get/update/patch/delete require nonempty names; list/watch also permit empty names. These are request-domain bounds, not object-body validation or complete HTTP request coverage.";
  "Create/deletecollection require an empty effective authorization name. A create body name or generateName, and a deletecollection field/label selector, never constrain that name. Named POST and all-namespace writes on namespaced resources are outside this domain.";
  "For create/deletecollection, names:null and empty:true both select the empty authorization name. Name lists/complements are rejected; they cannot express restrictions on created/deleted object names or contents.";
  "Policy resourceNames use exact matching: omitted or empty lists are unrestricted; a list containing the empty string matches empty-name requests, while a nonempty literal name or literal star alone does not. A grant still requires matching rule dimensions and a binding to the caller.";
  "List/watch names are effective authorization attributes after Kubernetes request interpretation, not names of returned objects. An empty effective name does not imply absence of selectors.";
  "Namespace include/exclude selectors range over nonempty namespaces, including those absent from the inventory. Node scopes require null. Name complements retain their existing meaning for reads and named writes.";
  "Required access and approved changes match exact API-group/resource pairs. Preservation quantifies all eight verbs and all eight catalogue entries for every frozen identity, including dimensions absent from clauses. Schemas 1-5 retain their original domains and canonical identities.";
  "Counterexample resource_kind uses a fixed injective catalogue: raw core plural, deployments.apps, or endpointslices.discovery.k8s.io. Contracts and evaluation requests use separate raw group/resource fields.";
  "Validated ClusterRole non-resource URL rules are retained but cannot grant resource requests. Non-resource URL authorization and preservation are outside this profile.";
  "NoOpinion means RBAC supplied no grant; it is not a final API-server denial.";
  "Grants describe initial request authorization only, not object existence, API route availability, request bodies, changed fields, selected/deleted objects, successful execution, additional operation-specific authorization, admission, response contents, watch events, or indirect privilege escalation.";
  "Raw HTTP/body/selector parsing, subresources, Namespaces, custom resources and resources outside the catalogue are outside the verifier. No controller or workload effects are modeled.";
  "Applying a partial manifest does not remove omitted live bindings; deployment reconciliation must establish the assumed snapshot." ]

let subresource_assumptions = [
  "The input is the complete static desired RBAC snapshot, including every applicable binding and the complete ClusterRole inventory with labels, even unbound aggregation contributors.";
  "Aggregated ClusterRoles must have acyclic dependencies (self-matches ignored) and stored full rule sets equal to recursively selected rules. Completeness is assumed; no controller reconciliation, rollout or future label/object changes are verified.";
  "The contract's fixed usernames and groups are trusted request attributes; authentication is not verified.";
  "Only the listed API-group/resource/subresource operations are quantified. The operations in each resource_domains entry define its verb, authorization-name and namespace domains; the union of verbs must not be treated as a Cartesian product with resources.";
  "The eight schema-6 base resources retain their get/list/watch, named update/patch/delete and empty-name create/deletecollection domains. Only base list/watch permit empty namespaced authorization namespaces or empty-or-named effective names.";
  "Every supported subresource operation requires the nonempty parent object name from the URL. In particular, create on pods/exec and serviceaccounts/token is named, unlike base collection create. Body metadata, query selectors and log follow=true do not replace the named parent authorization attributes.";
  "Namespaced subresources require a nonempty namespace; nodes/status is cluster-scoped with an empty namespace. Only cluster-wide bindings can grant Node or Node/status requests.";
  "Nonempty effective names are restricted to DNS1123 subdomains of at most 253 characters, and nonempty namespaces to DNS1123 labels of at most 63 characters. These are bounded authorization attributes, not full HTTP or object-body validation.";
  "Schema 7 requires separate exact api_group, resource and subresource fields, with an empty subresource for base resources. Namespace selectors retain their nonempty domain; Node scopes require null. Named subresources permit name sets/complements without empty names. Base collection-write names:null or empty:true select only the empty name.";
  "Policy matching uses exact combined resource/subresource, whole *, or */ followed by an exact subresource. A base-resource rule does not grant subresources; parent/* and */* are not general subresource globs. API group and verb matching remain separate.";
  "Policy resourceNames match literal authorization names: omitted or empty arrays are unrestricted; a literal star is not a wildcard, and an empty-string entry cannot grant a named subresource operation.";
  "Deployment scale requests use API group apps, and ServiceAccount token requests use the core group. Response object API groups do not alter these authorization groups.";
  "Required access and approved changes match exact operation coordinates. Preservation quantifies all supported base and subresource operations for every frozen identity, including dimensions absent from clauses. Schemas 1-6 retain their original domains and canonical identities.";
  "Counterexample resource_kind uses an injective fixed catalogue: core resource[/subresource], or resource[/subresource].group for noncore entries. Decode through the catalogue; contracts and evaluation requests use separate raw fields.";
  "Validated non-resource URL rules are retained but cannot grant resource requests. Non-resource URL authorization and preservation remain outside this profile.";
  "The reference is Kubernetes v1.34.0 initial RBAC Allow|NoOpinion only. NoOpinion is absence of an RBAC grant, not final API-server denial; Allow does not establish API route availability, object existence or operation success.";
  "Exec get/create are distinct initial verbs, not the admission operation CONNECT. Newer Kubernetes versions can additionally require create for WebSocket GET exec. Token issuance can involve additional NodeRestriction audience authorization. These extra checks and other authorizers are not modeled.";
  "Response contents (including full objects returned by status GET), token issuance and resulting privileges, execution, request-body validity, changed fields, selected/deleted objects, admission, controller/workload effects and indirect privilege escalation are outside this profile.";
  "Raw HTTP/body/selector parsing, unlisted subresources or operations, base ServiceAccounts, Namespaces and custom resources are outside this catalogue. Unsupported request classes are rejected, not modeled as denied.";
  "Applying a partial manifest does not remove omitted live bindings; deployment reconciliation must establish the assumed snapshot." ]

let profile_json ?(version=1) () =
  let id = id_for_version version in
  if version=7 then
    Input.json (`O ["schema_version",`Number "4";"id",`String id;
      "connector",`String "kubernetes-rbac";"reference_version",`String "v1.34.0";
      "contract_schema_version",`Number "7";
      "input_format",`String "strict-json-kubernetes-list";"decision",`String "Allow|NoOpinion";
      "resource_domains",`A (List.map (fun (entry : Resource_domain.t) -> `O [
        "api_group",`String entry.api_group;"resource",`String entry.resource;
        "subresource",`String entry.subresource;
        "scope",`String (if entry.namespaced then "namespaced" else "cluster");
        "resource_kind",`String (Resource_domain.kind entry);
        "operations",`A (List.map (fun verb -> `O ["verb",`String verb;
          "name_domain",`String (Resource_domain.name_domain entry ~verb);
          "namespace_domain",`String (Resource_domain.namespace_domain entry ~verb)])
          (Resource_domain.verbs ~version entry))]) (Resource_domain.for_version version));
      "assumptions",`A (List.map (fun s -> `String s) subresource_assumptions)])
  else if version >= 5 then
    Input.json (`O ["schema_version",`Number "3";"id",`String id;
      "connector",`String "kubernetes-rbac";"reference_version",`String "v1.34.0";
      "contract_schema_version",`Number (string_of_int version);
      "input_format",`String "strict-json-kubernetes-list";
      "decision",`String "Allow|NoOpinion";
      "verbs",`A (List.map (fun s -> `String s)
        (["get";"list";"watch";"update";"patch";"delete"]
         @ if version=6 then ["create";"deletecollection"] else []));
      "subresource",`String "";
      "resource_domains",`A (List.map (fun (entry : Resource_domain.t) -> `O [
        "api_group",`String entry.api_group;"resource",`String entry.resource;
        "scope",`String (if entry.namespaced then "namespaced" else "cluster");
        "resource_kind",`String (Resource_domain.kind entry)]) (Resource_domain.for_version version));
      "assumptions",`A (List.map (fun s -> `String s)
        (if version=6 then collection_write_assumptions else resource_assumptions))])
  else if version >= 2 then
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
  ^ (if version>=5 then "Fixed resource catalogue:\n" ^ String.concat "\n"
       (List.map (fun (entry : Resource_domain.t) -> Printf.sprintf "- %s (%s; resource_kind %S)"
         (Resource_domain.description entry) (if entry.namespaced then "namespaced" else "cluster-scoped")
         (Resource_domain.kind entry)
         ^ (if version=7 then "; operations: " ^ String.concat ", "
             (List.map (fun verb -> Printf.sprintf "%s [name=%s; namespace=%s]" verb
               (Resource_domain.name_domain entry ~verb) (Resource_domain.namespace_domain entry ~verb))
               (Resource_domain.verbs ~version entry)) else "")) (Resource_domain.for_version version)) ^ "\n"
     else "")
  ^ String.concat "\n" (List.map (fun s -> "- " ^ s)
      (match version with 1 -> assumptions | 2 -> read_assumptions | 3 -> write_assumptions
       | 4 -> scoped_assumptions | 6 -> collection_write_assumptions | 7 -> subresource_assumptions | _ -> resource_assumptions))
