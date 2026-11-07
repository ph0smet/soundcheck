open Input
open Identity

type rule = {
  verbs : string list;
  api_groups : string list;
  resources : string list;
  resource_names : string list;
}

type subject = User of string | Group of string | Service_account of string * string
type role_ref = Local_role of string | Cluster_role of string
type role = { role_kind : string; role_namespace : string; role_name : string; rules : rule list }
type binding = {
  binding_kind : string;
  binding_namespace : string;
  binding_name : string;
  subjects : subject list;
  role_ref : role_ref;
}
type bound_grant = { binding : binding; bound_rules : rule list }
type t = bound_grant list
type resource_object = Role of role | Binding of binding

let metadata path namespaced value =
  let o = obj path [ "name"; "namespace"; "labels"; "annotations" ] value in
  let name = string_field path "name" o |> rbac_name (path ^ ".name") in
  let ns = optional_string path "namespace" o in
  if namespaced then ignore (namespace (path ^ ".namespace") ns)
  else if ns <> "" then reject path "cluster-scoped object has a namespace";
  List.iter
    (fun key ->
      match List.assoc_opt key o with
      | None -> ()
      | Some `Null -> ()
      | Some value -> metadata_map (path ^ "." ^ key) ~annotations:(key = "annotations") value)
    [ "labels"; "annotations" ];
  (name, ns)

let parse_rule path value =
  let o = obj path [ "verbs"; "apiGroups"; "resources"; "resourceNames"; "nonResourceURLs" ] value in
  if List.mem_assoc "nonResourceURLs" o then
    reject path "nonResourceURLs is outside this resource-request profile";
  let required key =
    let values = strings (path ^ "." ^ key) (field path key o) in
    if values = [] then reject path (key ^ " must not be empty");
    values
  in
  { verbs = required "verbs";
    api_groups = required "apiGroups";
    resources = required "resources";
    resource_names = optional_strings path "resourceNames" o }

let parse_subject path binding_namespace value =
  let o = obj path [ "kind"; "apiGroup"; "name"; "namespace" ] value in
  let name = string_field path "name" o |> nonempty (path ^ ".name") in
  let kind = string_field path "kind" o in
  let api_group = optional_string path "apiGroup" o in
  let ns = optional_string path "namespace" o in
  match kind with
  | "User" ->
      require_equal (path ^ ".apiGroup") api_group group;
      User name
  | "Group" ->
      require_equal (path ^ ".apiGroup") api_group group;
      Group name
  | "ServiceAccount" ->
      require_equal (path ^ ".apiGroup") api_group "";
      if not (dns_subdomain name) then reject path "invalid service-account name";
      let effective_ns = if ns = "" then binding_namespace else ns in
      ignore (namespace (path ^ ".namespace") effective_ns);
      Service_account (effective_ns, name)
  | _ -> reject path "unsupported subject kind"

let parse_role_ref path binding_kind value =
  let o = obj path [ "apiGroup"; "kind"; "name" ] value in
  require_equal (path ^ ".apiGroup") (string_field path "apiGroup" o) group;
  let name = string_field path "name" o |> rbac_name (path ^ ".name") in
  match string_field path "kind" o with
  | "Role" when binding_kind = "RoleBinding" -> Local_role name
  | "ClusterRole" -> Cluster_role name
  | _ -> reject path "invalid roleRef kind for binding"

let parse_resource_object path value =
  (* Validate all fields even for unbound roles and unrelated subjects. *)
  let raw = match value with `O o -> o | _ -> reject path "expected object" in
  let kind = string_field path "kind" raw in
  let allowed =
    match kind with
    | "Role" | "ClusterRole" -> [ "apiVersion"; "kind"; "metadata"; "rules" ]
    | "RoleBinding" | "ClusterRoleBinding" ->
        [ "apiVersion"; "kind"; "metadata"; "subjects"; "roleRef" ]
    | _ -> reject path "only RBAC Roles and Bindings are supported"
  in
  let o = obj path allowed value in
  require_equal (path ^ ".apiVersion") (string_field path "apiVersion" o) api_version;
  let namespaced = kind = "Role" || kind = "RoleBinding" in
  let name, ns = metadata (path ^ ".metadata") namespaced (field path "metadata" o) in
  match kind with
  | "Role" | "ClusterRole" ->
      let rules = optional_list path "rules" o
        |> List.mapi (fun i -> parse_rule (Printf.sprintf "%s.rules[%d]" path i)) in
      Role { role_kind = kind; role_namespace = ns; role_name = name; rules }
  | _ ->
      let subjects = optional_list path "subjects" o
        |> List.mapi (fun i -> parse_subject (Printf.sprintf "%s.subjects[%d]" path i) ns) in
      let role_ref = parse_role_ref (path ^ ".roleRef") kind (field path "roleRef" o) in
      Binding { binding_kind = kind; binding_namespace = ns; binding_name = name; subjects; role_ref }

let parse_manifest value =
  let p = "manifest" in
  let o = obj p [ "apiVersion"; "kind"; "items"; "metadata" ] value in
  require_equal (p ^ ".apiVersion") (string_field p "apiVersion" o) "v1";
  require_equal (p ^ ".kind") (string_field p "kind" o) "List";
  (match List.assoc_opt "metadata" o with
   | None -> ()
   | Some value -> ignore (obj "manifest.metadata" [] value));
  let objects = arr "manifest.items" (field p "items" o)
    |> List.mapi (fun i -> parse_resource_object (Printf.sprintf "manifest.items[%d]" i)) in
  let seen = Hashtbl.create (List.length objects) in
  let roles = Hashtbl.create (List.length objects) in
  List.iter
    (fun resource_object ->
      let key =
        match resource_object with
        | Role r -> (r.role_kind, r.role_namespace, r.role_name)
        | Binding b -> (b.binding_kind, b.binding_namespace, b.binding_name)
      in
      if Hashtbl.mem seen key then reject p "duplicate RBAC object identity";
      Hashtbl.add seen key ();
      match resource_object with
      | Role r -> Hashtbl.add roles key r.rules
      | Binding _ -> ())
    objects;
  List.filter_map
    (function
      | Role _ -> None
      | Binding b ->
          let key = match b.role_ref with
            | Local_role name -> ("Role", b.binding_namespace, name)
            | Cluster_role name -> ("ClusterRole", "", name)
          in
          let bound_rules = match Hashtbl.find_opt roles key with
            | Some rules -> rules
            | None -> reject p ("unresolved roleRef from " ^ b.binding_name)
          in
          Some { binding = b; bound_rules })
    objects

let binding_label b =
  if b.binding_kind = "RoleBinding" then
    "RoleBinding/" ^ b.binding_namespace ^ "/" ^ b.binding_name
  else "ClusterRoleBinding/" ^ b.binding_name

let subject_matches identity = function
  | User name -> identity.username = name
  | Group name -> List.mem name identity.groups
  | Service_account (ns, name) ->
      identity.username = "system:serviceaccount:" ^ ns ^ ":" ^ name

let role_label b = match b.role_ref with
  | Local_role name -> "Role/" ^ b.binding_namespace ^ "/" ^ name
  | Cluster_role name -> "ClusterRole/" ^ name

let grants snapshot = snapshot


let of_string source = protect (fun () -> parse_manifest (parse source))
