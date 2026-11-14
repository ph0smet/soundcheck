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

let coverage = [
  core "serviceaccounts";core "events";{(core "namespaces") with namespaced=false};
  core "persistentvolumeclaims";{(core "persistentvolumes") with namespaced=false};
  {api_group="events.k8s.io";resource="events";namespaced=true;subresource=""};
  {api_group="apps";resource="replicasets";namespaced=true;subresource=""};
  {api_group="apps";resource="statefulsets";namespaced=true;subresource=""};
  {api_group="apps";resource="daemonsets";namespaced=true;subresource=""};
  {api_group="batch";resource="jobs";namespaced=true;subresource=""};
  {api_group="batch";resource="cronjobs";namespaced=true;subresource=""};
  {api_group="coordination.k8s.io";resource="leases";namespaced=true;subresource=""};
  {api_group="networking.k8s.io";resource="ingresses";namespaced=true;subresource=""};
  {api_group="networking.k8s.io";resource="ingressclasses";namespaced=false;subresource=""};
  {api_group="storage.k8s.io";resource="storageclasses";namespaced=false;subresource=""} ]

(* Initial caller authorization only. Review API request bodies and response
   decisions do not supply the caller's identity or additional prerequisites. *)
let controllers = [
  {api_group="admissionregistration.k8s.io";resource="validatingwebhookconfigurations";namespaced=false;subresource=""};
  {api_group="admissionregistration.k8s.io";resource="mutatingwebhookconfigurations";namespaced=false;subresource=""};
  {api_group="apiextensions.k8s.io";resource="customresourcedefinitions";namespaced=false;subresource=""};
  {api_group="apiextensions.k8s.io";resource="customresourcedefinitions";namespaced=false;subresource="status"};
  {api_group="authorization.k8s.io";resource="subjectaccessreviews";namespaced=false;subresource=""};
  {api_group="authentication.k8s.io";resource="tokenreviews";namespaced=false;subresource=""} ]

let is_review entry = entry.subresource="" &&
  List.mem (entry.api_group,entry.resource)
    ["authorization.k8s.io","subjectaccessreviews";"authentication.k8s.io","tokenreviews"]

let custom ~api_group ~resource ~namespaced ~subresources =
  {api_group;resource;namespaced;subresource=""}
  :: List.map (fun subresource -> {api_group;resource;namespaced;subresource}) subresources

let is_namespace entry = entry.api_group="" && entry.resource="namespaces"

let for_version = function
  | 1 | 2 | 3 | 4 -> legacy
  | 5 | 6 -> expanded
  | 7 | 8 -> expanded @ subresources
  | 9 -> expanded @ subresources @ coverage
  | 10 -> expanded @ subresources @ coverage @ controllers
  | _ -> invalid_arg "unsupported RBAC contract version"

let find_in entries ~api_group ~resource ~subresource =
  List.find_opt (fun entry -> entry.api_group=api_group && entry.resource=resource && entry.subresource=subresource)
    entries

let find_subresource ~version = find_in (for_version version)

let find ~version ~api_group ~resource = find_subresource ~version ~api_group ~resource ~subresource:""

let combined_resource entry =
  entry.resource ^ (if entry.subresource="" then "" else "/" ^ entry.subresource)

let kind entry =
  let resource = combined_resource entry in
  if entry.api_group="" then resource else resource ^ "." ^ entry.api_group

let of_kind ~version value =
  List.find_opt (fun entry -> kind entry=value) (for_version version)

let of_kind_in entries value = List.find_opt (fun entry -> kind entry=value) entries

let description entry =
  let resource = combined_resource entry in
  if entry.api_group="" then "core " ^ resource
  else resource ^ " in API group " ^ Printf.sprintf "%S" entry.api_group

let verbs ~version entry =
  if version>=10 && is_review entry then ["create"]
  else if entry.subresource<>"" then match entry.subresource with
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
  @ (if version>=8 && List.mem entry expanded then ["apply-existing";"apply-missing"] else [])
  @ (if version>=9 && entry.api_group="" && entry.subresource=""
        && List.mem entry.resource ["services";"endpoints"]
     then ["update-existing";"update-missing"] else [])

let checks ~operation = match operation with
  | "apply-existing" -> ["patch"]
  | "apply-missing" -> ["patch";"create"]
  | "update-existing" -> ["update"]
  | "update-missing" -> ["update";"create"]
  | verb -> [verb]

let object_state ~operation = match operation with
  | "apply-existing" | "update-existing" -> Some "existing"
  | "apply-missing" | "update-missing" -> Some "missing"
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
  if is_namespace entry && not (List.mem verb ["list";"watch";"create";"deletecollection"])
  then "same-as-name"
  else if not entry.namespaced then "empty"
  else if entry.subresource="" && (verb="list" || verb="watch") then "empty-or-named"
  else "named"
