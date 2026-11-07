open Input
open Soundcheck_core

type scope = {
  subject : string;
  namespace : string;
  resource : string;
  names : string list option;
}
type kind = Must_allow | Must_not_grant
type clause = { name : string; kind : kind; scope : scope }
type t = {
  identities : Identity.identity list;
  clauses : clause list;
  change_scope : scope list;
}

let kind = "kubernetes-rbac-access"
let scope_fields = ["subject";"namespace";"resource";"names"]

let parse_scope identities path fields =
  let subject = string_field path "subject" fields in
  if not (List.exists (fun (i : Identity.identity) -> i.username = subject) identities) then
    reject path "subject must name one of the frozen context identities";
  let ns = string_field path "namespace" fields |> namespace (path ^ ".namespace") in
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
  {subject; namespace=ns; resource; names}

let parse_value value =
  let path = "contract" in
  let fields = obj path ["schema_version";"kind";"context";"clauses";"change_scope"] value in
  (match field path "schema_version" fields with
   | `Number "1" -> () | _ -> reject path "schema_version must be integer 1");
  require_equal (path ^ ".kind") (string_field path "kind" fields) kind;
  let identities = Identity.parse_context (field path "context" fields)
    |> List.sort (fun (a : Identity.identity) b -> String.compare a.username b.username) in
  let seen = Hashtbl.create 8 in
  let clauses = arr (path ^ ".clauses") (field path "clauses" fields)
    |> List.mapi (fun index value ->
        let path = Printf.sprintf "contract.clauses[%d]" index in
        let fields = obj path ("name"::"kind"::scope_fields) value in
        let name = string_field path "name" fields in
        if name = "" || String.length name > 128
           || not (String.for_all (function 'a'..'z'|'A'..'Z'|'0'..'9'|'-'|'_' -> true | _ -> false) name)
        then reject path "clause name must contain 1..128 ASCII letters, digits, hyphens or underscores";
        if Hashtbl.mem seen name then reject path "duplicate clause name";
        Hashtbl.add seen name ();
        let kind = match string_field path "kind" fields with
          | "must_allow" -> Must_allow | "must_not_grant" -> Must_not_grant
          | _ -> reject path "kind must be must_allow or must_not_grant" in
        {name;kind;scope=parse_scope identities path fields}) in
  if clauses = [] then reject path "clauses must be nonempty";
  let change_scope = arr (path ^ ".change_scope") (field path "change_scope" fields)
    |> List.mapi (fun index value ->
        let path = Printf.sprintf "contract.change_scope[%d]" index in
        parse_scope identities path (obj path scope_fields value))
    |> List.sort_uniq compare in
  {identities;clauses;change_scope}

let of_string source = protect (fun () -> parse_value (parse source))
let identities spec = spec.identities
let clauses spec = spec.clauses
let changes spec = spec.change_scope

let scope_condition scope =
  Ir.And [Ir.Principal_is scope.subject;
          Ir.Object_is (Ir.Object_namespace,scope.namespace);
          Ir.Object_is (Ir.Object_kind,scope.resource);
          (match scope.names with None -> Ir.True
           | Some names -> Ir.Or (List.map (fun name -> Ir.Object_is (Ir.Object_name,name)) names))]

let approved_changes spec = Ir.Or (List.map scope_condition spec.change_scope)

let description clause =
  Printf.sprintf "RBAC %s get for %S on core %s in namespace %S (%s)"
    (match clause.kind with Must_allow -> "must grant" | Must_not_grant -> "must not grant")
    clause.scope.subject clause.scope.resource clause.scope.namespace
    (match clause.scope.names with None -> "all valid names"
     | Some names -> String.concat ", " (List.map (Printf.sprintf "%S") names))

let to_contract spec : Contract.t =
  {name=kind;description="Frozen named-get RBAC access requirements";
   clauses=List.map (fun clause ->
       let make = match clause.kind with
         | Must_allow -> Contract.must_allow
         | Must_not_grant -> (fun ~name ~description condition -> Contract.must_deny ~name ~description condition) in
       make ~name:clause.name ~description:(description clause) (scope_condition clause.scope)) spec.clauses}

let scope_json scope =
  ["subject",`String scope.subject;"namespace",`String scope.namespace;
   "resource",`String scope.resource;
   "names",(match scope.names with None -> `Null | Some xs -> `A (List.map (fun s -> `String s) xs))]

let canonical spec =
  json (`O ["schema_version",`Number "1";"kind",`String kind;
    "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
      "identities",`A (List.map (fun (identity : Identity.identity) ->
        `O ["username",`String identity.username;"groups",`A (List.map (fun s -> `String s) identity.groups)]) spec.identities)];
    "clauses",`A (List.map (fun clause -> `O
      (["name",`String clause.name;"kind",`String (match clause.kind with Must_allow -> "must_allow" | Must_not_grant -> "must_not_grant")]
       @ scope_json clause.scope)) spec.clauses);
    "change_scope",`A (List.map (fun scope -> `O (scope_json scope)) spec.change_scope)])

let frozen_spec spec : Report.frozen_spec =
  {schema_version=1;kind;canonical=canonical spec}
