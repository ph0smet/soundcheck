open Input
open Soundcheck_core

type scope = {
  subject : string;
  verb : string;
  namespace : string;
  resource : string;
  names : string list option;
}
type kind = Must_allow | Must_not_grant
type clause = { name : string; kind : kind; scope : scope }
type t = {
  version : int;
  identities : Identity.identity list;
  clauses : clause list;
  change_scope : scope list;
}

let kind = "kubernetes-rbac-access"
let scope_fields version =
  ["subject";"namespace";"resource";"names"] @ if version = 2 then ["verb"] else []

let parse_scope version identities path fields =
  let subject = string_field path "subject" fields in
  if not (List.exists (fun (i : Identity.identity) -> i.username = subject) identities) then
    reject path "subject must name one of the frozen context identities";
  let verb = if version = 1 then "get" else string_field path "verb" fields in
  if not (List.mem verb ["get";"list";"watch"]) then
    reject path "verb must be get, list or watch";
  let ns = match field path "namespace" fields with
    | `Null when version = 2 && verb <> "get" -> ""
    | `String ns -> namespace (path ^ ".namespace") ns
    | _ -> reject path "namespace must be a DNS label; only list/watch permit null for the all-namespace endpoint" in
  let resource = string_field path "resource" fields in
  if resource <> "configmaps" && resource <> "secrets" then
    reject path "resource must be configmaps or secrets";
  let names = match field path "names" fields with
    | `Null -> None
    | value ->
      let values = strings (path ^ ".names") value in
      if values = [] || List.exists (fun name -> not (dns_subdomain name)) values then
        reject path "names must be null (all valid names) or a nonempty list of DNS1123 subdomains";
      if List.length values <> List.length (List.sort_uniq String.compare values) then
        reject path "duplicate resource name";
      Some (List.sort String.compare values)
  in
  {subject; verb; namespace=ns; resource; names}

let parse_value value =
  let path = "contract" in
  let fields = obj path ["schema_version";"kind";"context";"clauses";"change_scope"] value in
  let version = match field path "schema_version" fields with
   | `Number "1" -> 1 | `Number "2" -> 2
   | _ -> reject path "schema_version must be integer 1 or 2" in
  require_equal (path ^ ".kind") (string_field path "kind" fields) kind;
  let identities = Identity.parse_context (field path "context" fields)
    |> List.sort (fun (a : Identity.identity) b -> String.compare a.username b.username) in
  let seen = Hashtbl.create 8 in
  let clauses = arr (path ^ ".clauses") (field path "clauses" fields)
    |> List.mapi (fun index value ->
        let path = Printf.sprintf "contract.clauses[%d]" index in
        let fields = obj path ("name"::"kind"::scope_fields version) value in
        let name = string_field path "name" fields in
        if name = "" || String.length name > 128
           || not (String.for_all (function 'a'..'z'|'A'..'Z'|'0'..'9'|'-'|'_' -> true | _ -> false) name)
        then reject path "clause name must contain 1..128 ASCII letters, digits, hyphens or underscores";
        if Hashtbl.mem seen name then reject path "duplicate clause name";
        Hashtbl.add seen name ();
        let kind = match string_field path "kind" fields with
          | "must_allow" -> Must_allow | "must_not_grant" -> Must_not_grant
          | _ -> reject path "kind must be must_allow or must_not_grant" in
        {name;kind;scope=parse_scope version identities path fields}) in
  if clauses = [] then reject path "clauses must be nonempty";
  if not (List.exists (fun clause -> clause.kind = Must_allow) clauses
          && List.exists (fun clause -> clause.kind = Must_not_grant) clauses) then
    reject path "this paired-access contract requires both must_allow and must_not_grant clauses";
  let change_scope = arr (path ^ ".change_scope") (field path "change_scope" fields)
    |> List.mapi (fun index value ->
        let path = Printf.sprintf "contract.change_scope[%d]" index in
        parse_scope version identities path (obj path (scope_fields version) value))
    |> List.sort_uniq compare in
  {version;identities;clauses;change_scope}

let of_string source = protect (fun () -> parse_value (parse source))
let version spec = spec.version
let identities spec = spec.identities
let clauses spec = spec.clauses
let changes spec = spec.change_scope

let scope_condition scope =
  Ir.And [Ir.Principal_is scope.subject;Ir.Method_is scope.verb;
          Ir.Object_is (Ir.Object_namespace,scope.namespace);
          Ir.Object_is (Ir.Object_kind,scope.resource);
          (match scope.names with None -> Ir.True
           | Some names -> Ir.Or (List.map (fun name -> Ir.Object_is (Ir.Object_name,name)) names))]

let approved_changes spec = Ir.Or (List.map scope_condition spec.change_scope)

let description clause =
  Printf.sprintf "RBAC %s %s for %S on core %s %s (%s)"
    (match clause.kind with Must_allow -> "must grant" | Must_not_grant -> "must not grant")
    clause.scope.verb clause.scope.subject clause.scope.resource
    (if clause.scope.namespace = "" then "at the all-namespace endpoint"
     else Printf.sprintf "in namespace %S" clause.scope.namespace)
    (match clause.scope.names with
     | None when clause.scope.verb <> "get" -> "empty or any valid effective authorization name"
     | None -> "all valid names"
     | Some names -> (if clause.scope.verb = "get" then "" else "effective authorization name: ")
       ^ String.concat ", " (List.map (Printf.sprintf "%S") names))

let to_contract spec : Contract.t =
  {name=kind;description=(if spec.version = 1 then "Frozen named-get RBAC access requirements"
                        else "Frozen get/list/watch RBAC access requirements");
   clauses=List.map (fun clause ->
       let make = match clause.kind with
         | Must_allow -> Contract.must_allow
         | Must_not_grant -> (fun ~name ~description condition -> Contract.must_deny ~name ~description condition) in
       make ~name:clause.name ~description:(description clause) (scope_condition clause.scope)) spec.clauses}

let scope_json version scope =
  ["subject",`String scope.subject;
   "namespace",(if version = 2 && scope.namespace = "" then `Null else `String scope.namespace);
   "resource",`String scope.resource;
   "names",(match scope.names with None -> `Null | Some xs -> `A (List.map (fun s -> `String s) xs))]
  @ if version = 2 then ["verb",`String scope.verb] else []

let canonical spec =
  json (`O ["schema_version",`Number (string_of_int spec.version);"kind",`String kind;
    "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
      "identities",`A (List.map (fun (identity : Identity.identity) ->
        `O ["username",`String identity.username;"groups",`A (List.map (fun s -> `String s) identity.groups)]) spec.identities)];
    "clauses",`A (List.map (fun clause -> `O
      (["name",`String clause.name;"kind",`String (match clause.kind with Must_allow -> "must_allow" | Must_not_grant -> "must_not_grant")]
       @ scope_json spec.version clause.scope)) spec.clauses);
    "change_scope",`A (List.map (fun scope -> `O (scope_json spec.version scope)) spec.change_scope)])

let frozen_spec spec : Report.frozen_spec =
  {schema_version=spec.version;kind;canonical=canonical spec}
