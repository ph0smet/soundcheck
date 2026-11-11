open Input
open Identity

type resource_rule = {
  verbs : string list;
  api_groups : string list;
  resources : string list;
  resource_names : string list;
}
type nonresource_rule = { verbs : string list; urls : string list }
type rule = Resource of resource_rule | Non_resource of nonresource_rule

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
type missing_reference = { binding_index : int; binding_label : string; role_label : string }

let binding_label b =
  if b.binding_kind = "RoleBinding" then
    "RoleBinding/" ^ b.binding_namespace ^ "/" ^ b.binding_name
  else "ClusterRoleBinding/" ^ b.binding_name

let role_key b = match b.role_ref with
  | Local_role name -> ("Role", b.binding_namespace, name)
  | Cluster_role name -> ("ClusterRole", "", name)

let role_label b = match b.role_ref with
  | Local_role name -> "Role/" ^ b.binding_namespace ^ "/" ^ name
  | Cluster_role name -> "ClusterRole/" ^ name

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

let parse_rule ~namespaced path value =
  let o = obj path [ "verbs"; "apiGroups"; "resources"; "resourceNames"; "nonResourceURLs" ] value in
  let required key =
    let values = strings (path ^ "." ^ key) (field path key o) in
    if values = [] then reject path (key ^ " must not be empty");
    values
  in
  let verbs = required "verbs" in
  (* Kubernetes ValidatePolicyRule classifies by nonempty URL contents, not
     field presence. All fields are still type-checked, even if unbound. *)
  let urls = optional_strings path "nonResourceURLs" o in
  if urls=[] then Resource {verbs;api_groups=required "apiGroups";
    resources=required "resources";resource_names=optional_strings path "resourceNames" o}
  else begin
    let api_groups = optional_strings path "apiGroups" o
    and resources = optional_strings path "resources" o
    and resource_names = optional_strings path "resourceNames" o in
    if namespaced then reject path "namespaced Role rules cannot apply to non-resource URLs";
    if api_groups<>[] || resources<>[] || resource_names<>[] then
      reject path "a rule cannot apply to both resources and non-resource URLs";
    (* The pinned API validates no URL syntax. Preserve literal strings without
       interpreting their paths, wildcard placement or request reachability. *)
    Non_resource {verbs;urls}
  end

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
        |> List.mapi (fun i -> parse_rule ~namespaced (Printf.sprintf "%s.rules[%d]" path i)) in
      Role { role_kind = kind; role_namespace = ns; role_name = name; rules }
  | _ ->
      let subjects = optional_list path "subjects" o
        |> List.mapi (fun i -> parse_subject (Printf.sprintf "%s.subjects[%d]" path i) ns) in
      let role_ref = parse_role_ref (path ^ ".roleRef") kind (field path "roleRef" o) in
      Binding { binding_kind = kind; binding_namespace = ns; binding_name = name; subjects; role_ref }

let parse_objects value =
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
  objects,roles

let unresolved (objects,roles) =
  List.mapi (fun binding_index -> function
    | Role _ -> None
    | Binding b when Hashtbl.mem roles (role_key b) -> None
    | Binding b -> Some {binding_index;binding_label=binding_label b;role_label=role_label b}) objects
  |> List.filter_map Fun.id

let unresolved_references source = protect (fun () -> unresolved (parse_objects (parse source)))

let parse_manifest value =
  let objects,roles = parse_objects value in
  let missing = unresolved (objects,roles) in
  if missing <> [] then reject "manifest" ("unresolved roleRef: " ^ String.concat "; "
    (List.map (fun r -> Printf.sprintf "items[%d] %s -> %s" r.binding_index r.binding_label r.role_label) missing));
  List.filter_map
    (function
      | Role _ -> None
      | Binding b ->
          let bound_rules = Hashtbl.find roles (role_key b) in
          Some { binding = b; bound_rules })
    objects

let subject_matches identity = function
  | User name -> identity.username = name
  | Group name -> List.mem name identity.groups
  | Service_account (ns, name) ->
      identity.username = "system:serviceaccount:" ^ ns ^ ":" ^ name

let grants snapshot = snapshot


let of_string source = protect (fun () -> parse_manifest (parse source))
