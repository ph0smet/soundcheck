open Input
open Soundcheck_core

type namespace_selector =
  | Exact_namespace of string
  | Namespace_set of string list
  | Outside_namespaces of string list
type name_selector =
  | All_names
  | Names of string list
  | Empty_name
  | Other_names of { excluded : string list; include_empty : bool }
type target = Resource_target of Resource_domain.t | Url_target of Url_domain.selector
type scope = {
  subject : string;
  verb : string;
  namespace : namespace_selector;
  resource : string;
  names : name_selector;
  api_group : string;
  subresource : string;
  target : target;
}
type kind = Must_allow | Must_not_grant
type clause = { name : string; kind : kind; scope : scope }
type t = {
  version : int;
  identities : Identity.identity list;
  clauses : clause list;
  change_scope : scope list;
  custom_resources : Catalogue.t;
  resources : Resource_domain.t list;
}

let kind = "kubernetes-rbac-access"
let scope_fields version =
  ["subject";"namespace";"resource";"names"]
  @ (if version >= 8 then ["operation"] else if version >= 2 then ["verb"] else [])
  @ (if version >= 5 then ["api_group"] else [])
  @ (if version >= 7 then ["subresource"] else [])
  @ (if version >= 9 then ["request_kind"] else [])

let collection_read_verb verb = verb = "list" || verb = "watch"
let collection_write_verb verb = verb = "create" || verb = "deletecollection"

let selector_values ~allow_empty ~valid ~expected path value =
  let values = strings path value in
  if not allow_empty && values = [] then reject path "selector list must not be empty";
  let seen = Hashtbl.create (List.length values) in
  List.iteri (fun index value ->
    let path = Printf.sprintf "%s[%d]" path index in
    if not (valid value) then reject path (Printf.sprintf "%S is not %s" value expected);
    if Hashtbl.mem seen value then reject path (Printf.sprintf "duplicate selector value %S" value);
    Hashtbl.add seen value ()) values;
  List.sort String.compare values

let parse_namespace version verb path = function
  | `Null when version >= 2 && collection_read_verb verb -> Exact_namespace ""
  | `Null when version >= 6 && collection_write_verb verb ->
    reject path "create/deletecollection of namespaced resources require a nonempty namespace; there is no all-namespace write scope. Use an independently reviewed namespace or include/exclude selector"
  | `Null -> reject path "null denotes only the all-namespace list/watch endpoint (schema 2+), not every named namespace; choose the independently intended scope"
  | `String "*" -> reject path "\"*\" is not a namespace wildcard; schema 4 supports reviewed include/exclude selectors over nonempty namespaces"
  | `String ns -> Exact_namespace (namespace path ns)
  | `O _ as value when version >= 4 ->
    let fields = obj path ["include";"exclude"] value in
    let values key ~allow_empty value = selector_values ~allow_empty
        ~valid:(fun value -> Result.is_ok (protect (fun () -> namespace path value)))
        ~expected:"a DNS1123 namespace label; selector members are literals, not wildcards"
        (path ^ "." ^ key) value in
    (match fields with
     | ["include",value] -> Namespace_set (values "include" ~allow_empty:false value)
     | ["exclude",value] -> Outside_namespaces (values "exclude" ~allow_empty:true value)
     | _ -> reject path "use exactly one namespace include or exclude selector")
  | `O _ -> reject path "namespace include/exclude selectors require contract schema 4; a contract upgrade needs separate requirement review"
  | _ -> reject path "namespace must be a DNS label; only list/watch permit null for the all-namespace endpoint"

let parse_names version ~subresource verb path value =
  if version >= 6 && subresource="" && collection_write_verb verb then
    (* Collection writes have no object name at initial authorization. Do not
       let a name selector appear to constrain the created/deleted objects. *)
    match value with
    | `Null -> All_names
    | `O _ ->
      let fields = obj path ["empty";"exclude";"include_empty"] value in
      (match fields with
       | ["empty",`Bool true] -> Empty_name
       | _ -> reject path "create/deletecollection require names:null or {\"empty\":true}; their effective authorization name is empty, not a request-body or deletion-target name")
    | _ -> reject path "create/deletecollection require names:null or {\"empty\":true}; object-name lists or complements cannot restrict their initial RBAC authorization"
  else match value with
  | `Null -> All_names
  | `O _ as value when version >= 4 ->
    let fields = obj path ["empty";"exclude";"include_empty"] value in
    (match fields with
     | ["empty",`Bool true] when collection_read_verb verb -> Empty_name
     | ["empty",_] -> reject (path ^ ".empty") "empty:true cannot select named requests, including named subresource operations; it selects empty list/watch or base collection-write authorization names only"
     | _ when List.length fields = 2 && List.mem_assoc "exclude" fields && List.mem_assoc "include_empty" fields ->
       let excluded = selector_values ~allow_empty:true ~valid:dns_subdomain
           ~expected:"a DNS1123 object name; exclusions are literal names, not wildcards"
           (path ^ ".exclude") (field path "exclude" fields) in
       let include_empty = match field path "include_empty" fields with
         | `Bool value when not value || collection_read_verb verb -> value
         | _ -> reject (path ^ ".include_empty") "must be boolean; only list/watch permit true for empty effective authorization names" in
       Other_names {excluded;include_empty}
     | _ -> reject path "use empty:true for list/watch, or exclude with an explicit include_empty boolean")
  | `O _ -> reject path "name selectors require contract schema 4; a contract upgrade needs separate requirement review"
  | `A [] -> reject path "an empty list selects no names and is not accepted; names:null means all supported names, while schema-4 empty:true selects only empty list/watch authorization names; choose the intended scope"
  | value ->
    Names (selector_values ~allow_empty:false ~valid:dns_subdomain
      ~expected:"a DNS1123 object name; \"*\" is not a wildcard and \"\" is not a named request (use explicit reviewed name/collection selectors)" path value)

let parse_scope version identities resources path fields =
  let subject = string_field path "subject" fields in
  if not (List.exists (fun (i : Identity.identity) -> i.username = subject) identities) then
    reject (path ^ ".subject") (Printf.sprintf "%S must exactly match a frozen context.identities[].username; review the caller identity independently, without inferring it or its groups from grants" subject);
  let operation_field = if version>=8 then "operation" else "verb" in
  let verb = if version = 1 then "get" else string_field path operation_field fields in
  let request_kind = if version>=9 then string_field path "request_kind" fields else "resource" in
  if request_kind="non_resource" then begin
    ignore (obj path ["subject";"operation";"request_kind";"paths"] (`O fields));
    if not (List.mem verb Url_domain.methods) then reject (path ^ ".operation")
      "expected a supported lowercase non-resource HTTP method; head and get are distinct";
    let selector = Url_domain.parse (path ^ ".paths") (field path "paths" fields) in
    {subject;verb;namespace=Exact_namespace "";resource="";names=All_names;
     api_group="";subresource="";target=Url_target selector}
  end else begin
  if request_kind<>"resource" then reject (path ^ ".request_kind") "expected resource or non_resource";
  ignore (obj path (scope_fields version) (`O fields));
  let verbs = if version >= 6 then ["get";"list";"watch";"update";"patch";"delete";"create";"deletecollection"]
    else if version >= 3 then ["get";"list";"watch";"update";"patch";"delete"]
    else ["get";"list";"watch"] in
  let verbs = verbs @ if version>=8 then ["apply-existing";"apply-missing"] else [] in
  let verbs = verbs @ if version>=9 then ["update-existing";"update-missing"] else [] in
  if not (List.mem verb verbs) then
    reject (path ^ "." ^ operation_field) (Printf.sprintf "%S is outside contract schema %d; supported %s: %s. Do not substitute a different operation to make the contract pass" verb version (if version>=8 then "operations" else "verbs") (String.concat ", " verbs));
  let resource = string_field path "resource" fields in
  let api_group = if version>=5 then string_field path "api_group" fields else "" in
  let subresource = if version>=7 then string_field path "subresource" fields else "" in
  let entry = match Resource_domain.find_in resources ~api_group ~resource ~subresource with
    | Some entry -> entry
    | None when version < 5 -> reject (path ^ ".resource")
        (Printf.sprintf "%S is outside the modeled resource domain; use core configmaps or secrets only, with no API-group prefix or subresource" resource)
    | None when version>=7 -> reject (path ^ ".subresource")
        (Printf.sprintf "API group %S, resource %S and subresource %S are outside contract schema %d's fixed catalogue; use separate exact fields, with subresource:\"\" for base resources. Policy wildcard syntax is not a contract selector" api_group resource subresource version)
    | None -> reject (path ^ ".resource")
        (Printf.sprintf "API group %S and resource %S are outside contract schema %d's fixed resource catalogue; use separate exact api_group/resource fields in schema %d, with no wildcard, qualified alias or subresource. A contract upgrade needs separate requirement review" api_group resource version version) in
  if not (List.mem verb (Resource_domain.operations ~version entry)) then
    reject (path ^ "." ^ operation_field)
      (Printf.sprintf "%S is outside the supported operations for %s; supported %s: %s. Other operations are not modeled as denied"
        verb (Resource_domain.description entry) (if version>=8 then "operations" else "verbs")
        (String.concat ", " (Resource_domain.operations ~version entry)));
  let ns_value = field path "namespace" fields in
  let ns = if entry.namespaced || Resource_domain.namespace_domain entry ~verb="same-as-name"
    then parse_namespace version verb (path ^ ".namespace") ns_value
    else match ns_value with
      | `Null -> Exact_namespace ""
      | _ -> reject (path ^ ".namespace") (if version<9 then "Nodes require namespace:null for cluster-scoped requests; namespace strings and selectors are not applicable"
        else "this cluster-scoped or Namespace collection request requires namespace:null; named Namespace requests instead use authorization namespace equal to target name") in
  let names = parse_names version ~subresource verb (path ^ ".names") (field path "names" fields) in
  {subject; verb; namespace=ns; resource; names; api_group; subresource;target=Resource_target entry}
  end

let compare_scope version left right =
  if version >= 4 then compare left right else
  (* Preserve the original record's string/option ordering, including null
     namespace/name scopes. A new selector constructor must not reorder old
     canonical contracts or change their frozen identities. *)
  let legacy scope =
    let namespace = match scope.namespace with Exact_namespace value -> value | _ -> assert false in
    let names = match scope.names with All_names -> None | Names values -> Some values | _ -> assert false in
    scope.subject,scope.verb,namespace,scope.resource,names in
  compare (legacy left) (legacy right)

let parse_value value =
  let path = "contract" in
  let fields = obj path ["schema_version";"kind";"context";"clauses";"change_scope";"custom_resources"] value in
  let version = match field path "schema_version" fields with
   | `Number "1" -> 1 | `Number "2" -> 2 | `Number "3" -> 3 | `Number "4" -> 4 | `Number "5" -> 5 | `Number "6" -> 6 | `Number "7" -> 7 | `Number "8" -> 8 | `Number "9" -> 9
   | _ -> reject path "schema_version must be integer 1, 2, 3, 4, 5, 6, 7, 8 or 9" in
  if version<9 && List.mem_assoc "custom_resources" fields then reject path "unsupported field custom_resources";
  let custom_resources = Catalogue.parse (path ^ ".custom_resources")
    (if version>=9 then field path "custom_resources" fields else `A []) in
  let resources = Resource_domain.for_version version @ Catalogue.resources custom_resources in
  require_equal (path ^ ".kind") (string_field path "kind" fields) kind;
  let identities = Identity.parse_context (field path "context" fields)
    |> List.sort (fun (a : Identity.identity) b -> String.compare a.username b.username) in
  let seen = Hashtbl.create 8 in
  let clauses = arr (path ^ ".clauses") (field path "clauses" fields)
    |> List.mapi (fun index value ->
        let path = Printf.sprintf "contract.clauses[%d]" index in
        let fields = obj path ("name"::"kind"::(scope_fields version @ if version>=9 then ["paths"] else [])) value in
        let name = string_field path "name" fields in
        if name = "" || String.length name > 128
           || not (String.for_all (function 'a'..'z'|'A'..'Z'|'0'..'9'|'-'|'_' -> true | _ -> false) name)
        then reject path "clause name must contain 1..128 ASCII letters, digits, hyphens or underscores";
        if Hashtbl.mem seen name then reject path "duplicate clause name";
        Hashtbl.add seen name ();
        let kind = match string_field path "kind" fields with
          | "must_allow" -> Must_allow | "must_not_grant" -> Must_not_grant
          | _ -> reject path "kind must be must_allow or must_not_grant" in
        {name;kind;scope=parse_scope version identities resources path
          (List.filter (fun (key,_) -> key<>"name" && key<>"kind") fields)}) in
  if clauses = [] then reject path "clauses must be nonempty";
  if not (List.exists (fun clause -> clause.kind = Must_allow) clauses
          && List.exists (fun clause -> clause.kind = Must_not_grant) clauses) then
    reject path "this paired-access contract requires both must_allow and must_not_grant clauses";
  let change_scope = arr (path ^ ".change_scope") (field path "change_scope" fields)
    |> List.mapi (fun index value ->
        let path = Printf.sprintf "contract.change_scope[%d]" index in
        parse_scope version identities resources path
          (obj path (scope_fields version @ if version>=9 then ["paths"] else []) value))
    |> List.sort_uniq (compare_scope version) in
  {version;identities;clauses;change_scope;custom_resources;resources}

let of_string source = protect (fun () -> parse_value (parse source))
let version spec = spec.version
let identities spec = spec.identities
let clauses spec = spec.clauses
let changes spec = spec.change_scope
let resources spec = spec.resources
let custom_resources spec = spec.custom_resources

let member coordinate values =
  Ir.Or (List.map (fun value -> Ir.Object_is (coordinate,value)) values)

let namespace_condition = function
  | Exact_namespace value -> Ir.Object_is (Ir.Object_namespace,value)
  | Namespace_set values -> member Ir.Object_namespace values
  | Outside_namespaces values ->
    (* Complement over namespaced requests, never the all-namespace endpoint.
       Validity/length restrictions come from the unchanged request domain. *)
    Ir.Not (member Ir.Object_namespace ("" :: values))

let names_condition = function
  | All_names -> Ir.True
  | Names values -> member Ir.Object_name values
  | Empty_name -> Ir.Object_is (Ir.Object_name,"")
  | Other_names {excluded;include_empty} ->
    Ir.Not (member Ir.Object_name (if include_empty then excluded else "" :: excluded))

let scope_condition scope =
  match scope.target with
  | Url_target selector -> Ir.And [Ir.Principal_is scope.subject;Ir.Method_is scope.verb;
      Ir.Not Ir.Has_object_request;Url_domain.selector_condition selector]
  | Resource_target entry ->
  Ir.And [Ir.Principal_is scope.subject;Ir.Method_is scope.verb;
          namespace_condition scope.namespace;
          Ir.Object_is (Ir.Object_kind,Resource_domain.kind entry);
          names_condition scope.names]

let approved_changes spec = Ir.Or (List.map scope_condition spec.change_scope)

let quoted values = String.concat ", " (List.map (Printf.sprintf "%S") values)

let describe_scope scope =
  match scope.target with
  | Url_target selector -> Printf.sprintf "%s for %S on non-resource %s"
      scope.verb scope.subject (Url_domain.describe selector)
  | Resource_target resource ->
  let entry = Some resource in
  Printf.sprintf "%s for %S on %s %s (%s)"
    scope.verb scope.subject
    (match entry with Some entry -> Resource_domain.description entry | None -> "unsupported resource")
    (match scope.namespace with
     | Exact_namespace "" when Option.fold ~none:false ~some:(fun entry -> not entry.Resource_domain.namespaced) entry -> "at cluster scope"
     | Exact_namespace "" -> "at the all-namespace endpoint"
     | Exact_namespace value -> Printf.sprintf "in namespace %S" value
     | Namespace_set values -> "in namespaces " ^ quoted values
     | Outside_namespaces [] -> "in every valid nonempty namespace"
     | Outside_namespaces values -> "in every valid nonempty namespace except " ^ quoted values)
    (match scope.names with
     | All_names when scope.subresource="" && collection_write_verb scope.verb -> "empty effective authorization name only; object contents and deletion targets are not constrained"
     | All_names when scope.subresource<>"" -> "all valid nonempty parent authorization names"
     | All_names when collection_read_verb scope.verb -> "empty or any valid effective authorization name"
     | All_names -> "all valid names"
     | Names names -> (if scope.subresource<>"" then "parent authorization name: " else if collection_read_verb scope.verb then "effective authorization name: " else "") ^ quoted names
     | Empty_name when collection_write_verb scope.verb -> "empty effective authorization name only; object contents and deletion targets are not constrained"
     | Empty_name -> "empty effective authorization name only"
     | Other_names {excluded;include_empty} ->
       (if include_empty then "empty or any valid effective authorization name" else "any valid nonempty name")
       ^ (if excluded=[] then "" else " except " ^ quoted excluded))
  ^ (match Resource_domain.object_state ~operation:scope.verb with
     | None -> ""
     | Some state -> Printf.sprintf "; conditional %s-object storage branch, requiring RBAC %s at the same named target"
         state (String.concat " AND " (Resource_domain.checks ~operation:scope.verb)))

let description clause =
  "RBAC " ^ (match clause.kind with Must_allow -> "must grant " | Must_not_grant -> "must not grant ")
  ^ describe_scope clause.scope

let to_contract spec : Contract.t =
  {name=kind;description=(match spec.version with
     | 1 -> "Frozen named-get RBAC access requirements"
     | 2 -> "Frozen get/list/watch RBAC access requirements"
     | 3 -> "Frozen read and named-write RBAC access requirements"
     | 4 -> "Frozen read and named-write RBAC requirements with explicit scope selectors"
     | 6 -> "Frozen read, named-write and collection-write RBAC requirements over the explicit resource catalogue"
     | 7 -> "Frozen RBAC requirements over the explicit base-resource and subresource operation catalogue"
     | 8 -> "Frozen initial RBAC and conditional server-side apply prerequisite requirements"
     | 9 -> "Frozen static RBAC resource, custom-resource and URL requirements with conditional SSA/PUT prerequisites"
     | _ -> "Frozen read and named-write RBAC requirements over the explicit resource catalogue");
   clauses=List.map (fun clause ->
       let make = match clause.kind with
         | Must_allow -> Contract.must_allow
         | Must_not_grant -> (fun ~name ~description condition -> Contract.must_deny ~name ~description condition) in
       make ~name:clause.name ~description:(description clause) (scope_condition clause.scope)) spec.clauses}

let scope_json version scope =
  match scope.target with
  | Url_target selector -> ["subject",`String scope.subject;"operation",`String scope.verb;
      "request_kind",`String "non_resource";"paths",Url_domain.json selector]
  | Resource_target _ ->
  let values xs = `A (List.map (fun value -> `String value) xs) in
  ["subject",`String scope.subject;
   "namespace",(match scope.namespace with
     | Exact_namespace "" when version >= 2 -> `Null
     | Exact_namespace value -> `String value
     | Namespace_set xs -> `O ["include",values xs]
     | Outside_namespaces xs -> `O ["exclude",values xs]);
   "resource",`String scope.resource;
   "names",(match scope.names with
     | All_names -> `Null | Names xs -> values xs
     | Empty_name -> `O ["empty",`Bool true]
     | Other_names {excluded;include_empty} -> `O ["exclude",values excluded;"include_empty",`Bool include_empty])]
  @ (if version >= 8 then ["operation",`String scope.verb]
     else if version >= 2 then ["verb",`String scope.verb] else [])
  @ (if version >= 5 then ["api_group",`String scope.api_group] else [])
  @ (if version >= 7 then ["subresource",`String scope.subresource] else [])
  @ (if version >= 9 then ["request_kind",`String "resource"] else [])

let canonical spec =
  json (`O (["schema_version",`Number (string_of_int spec.version);"kind",`String kind;
    "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
      "identities",`A (List.map (fun (identity : Identity.identity) ->
        `O ["username",`String identity.username;"groups",`A (List.map (fun s -> `String s) identity.groups)]) spec.identities)]]
    @ (if spec.version>=9 then ["custom_resources",Catalogue.json spec.custom_resources] else [])
    @ [
    "clauses",`A (List.map (fun clause -> `O
      (["name",`String clause.name;"kind",`String (match clause.kind with Must_allow -> "must_allow" | Must_not_grant -> "must_not_grant")]
       @ scope_json spec.version clause.scope)) spec.clauses);
    "change_scope",`A (List.map (fun scope -> `O (scope_json spec.version scope)) spec.change_scope)]))

let frozen_spec spec : Report.frozen_spec =
  {schema_version=spec.version;kind;canonical=canonical spec}
