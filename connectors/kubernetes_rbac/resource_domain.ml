type t = { api_group : string; resource : string; namespaced : bool }

let core resource = {api_group="";resource;namespaced=true}
let legacy = [core "configmaps";core "secrets"]
let expanded = legacy @ [
  core "pods";core "services";core "endpoints";
  {api_group="apps";resource="deployments";namespaced=true};
  {api_group="discovery.k8s.io";resource="endpointslices";namespaced=true};
  {api_group="";resource="nodes";namespaced=false} ]

let for_version = function
  | 1 | 2 | 3 | 4 -> legacy
  | 5 -> expanded
  | _ -> invalid_arg "unsupported RBAC contract version"

let find ~version ~api_group ~resource =
  List.find_opt (fun entry -> entry.api_group=api_group && entry.resource=resource)
    (for_version version)

let kind entry =
  if entry.api_group="" then entry.resource else entry.resource ^ "." ^ entry.api_group

let of_kind ~version value =
  List.find_opt (fun entry -> kind entry=value) (for_version version)

let description entry =
  if entry.api_group="" then "core " ^ entry.resource
  else entry.resource ^ " in API group " ^ Printf.sprintf "%S" entry.api_group
