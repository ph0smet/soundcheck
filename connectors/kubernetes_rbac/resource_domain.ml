type t = { api_group : string; resource : string; namespaced : bool; subresource : string }

let core resource = {api_group="";resource;namespaced=true;subresource=""}
let legacy = [core "configmaps";core "secrets"]
let expanded = legacy @ [
  core "pods";core "services";core "endpoints";
  {api_group="apps";resource="deployments";namespaced=true;subresource=""};
  {api_group="discovery.k8s.io";resource="endpointslices";namespaced=true;subresource=""};
  {api_group="";resource="nodes";namespaced=false;subresource=""} ]

let subresources = [
  { (core "pods") with subresource="log" };
  { (core "pods") with subresource="exec" };
  { (core "serviceaccounts") with subresource="token" };
  { (core "pods") with subresource="status" };
  { (core "services") with subresource="status" };
  { (core "nodes") with subresource="status";namespaced=false };
  {api_group="apps";resource="deployments";namespaced=true;subresource="status"};
  {api_group="apps";resource="deployments";namespaced=true;subresource="scale"} ]

let for_version = function
  | 1 | 2 | 3 | 4 -> legacy
  | 5 | 6 -> expanded
  | 7 | 8 -> expanded @ subresources
  | _ -> invalid_arg "unsupported RBAC contract version"

let find_subresource ~version ~api_group ~resource ~subresource =
  List.find_opt (fun entry -> entry.api_group=api_group && entry.resource=resource && entry.subresource=subresource)
    (for_version version)

let find ~version ~api_group ~resource = find_subresource ~version ~api_group ~resource ~subresource:""

let combined_resource entry =
  entry.resource ^ (if entry.subresource="" then "" else "/" ^ entry.subresource)

let kind entry =
  let resource = combined_resource entry in
  if entry.api_group="" then resource else resource ^ "." ^ entry.api_group

let of_kind ~version value =
  List.find_opt (fun entry -> kind entry=value) (for_version version)

let description entry =
  let resource = combined_resource entry in
  if entry.api_group="" then "core " ^ resource
  else resource ^ " in API group " ^ Printf.sprintf "%S" entry.api_group

let verbs ~version entry =
  if entry.subresource<>"" then match entry.subresource with
    | "log" -> ["get"]
    | "exec" -> ["get";"create"]
    | "token" -> ["create"]
    | "status" | "scale" -> ["get";"update";"patch"]
    | _ -> invalid_arg "unregistered RBAC subresource"
  else if version=1 then ["get"]
  else ["get";"list";"watch"]
       @ (if version>=3 then ["update";"patch";"delete"] else [])
       @ (if version>=6 then ["create";"deletecollection"] else [])

let operations ~version entry =
  verbs ~version entry
  @ (if version>=8 && entry.subresource="" then ["apply-existing";"apply-missing"] else [])

let checks ~operation = match operation with
  | "apply-existing" -> ["patch"]
  | "apply-missing" -> ["patch";"create"]
  | verb -> [verb]

let object_state ~operation = match operation with
  | "apply-existing" -> Some "existing"
  | "apply-missing" -> Some "missing"
  | _ -> None

(* These classify authorization attributes, not names or namespaces in a body.
   Callers first check that the verb belongs to the entry's operation list. *)
let name_domain entry ~verb =
  if entry.subresource<>"" then "named"
  else match verb with
    | "create" | "deletecollection" -> "empty"
    | "list" | "watch" -> "empty-or-named"
    | _ -> "named"

let namespace_domain entry ~verb =
  if not entry.namespaced then "empty"
  else if entry.subresource="" && (verb="list" || verb="watch") then "empty-or-named"
  else "named"
