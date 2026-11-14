open Input

type operation = Create | Update_existing
type target = { kind : string; namespace : string; name : string }
type t = { actor : Identity.identity; operation : operation; target : target;
           requirements : Contract_spec.t }
let kind = "kubernetes-rbac-policy-change"
let has_kind source = match protect (fun () -> parse source) with
  | Ok (`O fields) -> List.assoc_opt "kind" fields=Some (`String kind)
  | _ -> false
let actor t = t.actor
let operation t = t.operation
let target t = t.target
let requirements t = t.requirements
let operation_name = function Create -> "create" | Update_existing -> "update-existing"
let resource target = match target.kind with
  | "Role" -> "roles" | "ClusterRole" -> "clusterroles"
  | "RoleBinding" -> "rolebindings" | "ClusterRoleBinding" -> "clusterrolebindings"
  | _ -> invalid_arg "unsupported RBAC change target"

let of_string source = protect (fun () ->
  let p = "change_contract" in
  let fields = obj p ["schema_version";"kind";"actor";"operation";"target";"requirements"] (parse source) in
  if field p "schema_version" fields <> `Number "1" then reject p "schema_version must be integer 1";
  require_equal (p ^ ".kind") (string_field p "kind" fields) kind;
  let requirements = match Contract_spec.of_string (json (field p "requirements" fields)) with
    | Ok value -> value | Error reason -> reject (p ^ ".requirements") reason in
  let username = string_field p "actor" fields in
  let actor = match List.find_opt (fun (i : Identity.identity) -> i.username=username)
      (Contract_spec.identities requirements) with
    | Some identity -> identity
    | None -> reject (p ^ ".actor") "must exactly match a trusted requirements.context.identities username" in
  if List.mem "system:masters" actor.groups then
    reject (p ^ ".actor") "system:masters bypass actors are outside the policy-change profile";
  let operation = match string_field p "operation" fields with
    | "create" -> Create | "update-existing" -> Update_existing
    | _ -> reject (p ^ ".operation") "expected create or update-existing; patch, apply, delete and create-on-update are unsupported" in
  let p = p ^ ".target" in
  let fields = obj p ["kind";"namespace";"name"] (field "change_contract" "target" fields) in
  let target_kind = string_field p "kind" fields in
  if not (List.mem target_kind ["Role";"ClusterRole";"RoleBinding";"ClusterRoleBinding"]) then
    reject (p ^ ".kind") "expected Role, ClusterRole, RoleBinding or ClusterRoleBinding";
  let name = string_field p "name" fields |> rbac_name (p ^ ".name") in
  let namespaced = target_kind="Role" || target_kind="RoleBinding" in
  let ns = match field p "namespace" fields with
    | `String value when namespaced -> namespace (p ^ ".namespace") value
    | `Null when not namespaced -> ""
    | _ -> reject (p ^ ".namespace") "use a namespace string for Role/RoleBinding and null for cluster-scoped kinds" in
  {actor;operation;target={kind=target_kind;namespace=ns;name};requirements})

let canonical t = json (`O ["schema_version",`Number "1";"kind",`String kind;
  "actor",`String t.actor.username;"operation",`String (operation_name t.operation);
  "target",`O ["kind",`String t.target.kind;
    "namespace",(if t.target.namespace="" then `Null else `String t.target.namespace);
    "name",`String t.target.name];
  "requirements",parse (Contract_spec.canonical t.requirements)])

let review t =
  Printf.sprintf "Frozen RBAC policy change (schema 1)\nActor: %S; trusted groups: [%s]\nOperation: %s\nTarget: %s namespace=%S name=%S\nOnly this target may change. Authorization uses the original snapshot.\nInitial and bind/escalate/coverage checks do not establish successful mutation.\nNested access contract: schema %d; preservation domain follows that schema.\n"
    t.actor.username (String.concat ", " (List.map (Printf.sprintf "%S") t.actor.groups))
    (operation_name t.operation) t.target.kind t.target.namespace t.target.name
    (Contract_spec.version t.requirements)
