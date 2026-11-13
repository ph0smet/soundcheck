open Input

type entry = { api_group:string; resource:string; namespaced:bool; subresources:string list }
type t = entry list

let reserved_groups = ["";"apps";"batch";"extensions";"policy";"autoscaling";
  "coordination.k8s.io";"events.k8s.io";"networking.k8s.io";"storage.k8s.io";
  "discovery.k8s.io";"rbac.authorization.k8s.io";"authentication.k8s.io";
  "authorization.k8s.io";"apiextensions.k8s.io";"apiregistration.k8s.io";
  "admissionregistration.k8s.io";"certificates.k8s.io";"flowcontrol.apiserver.k8s.io";
  "node.k8s.io";"scheduling.k8s.io";"resource.k8s.io";"internal.apiserver.k8s.io"]

let parse path value =
  let values = arr path value in
  if List.length values > 64 then reject path "custom catalogue exceeds 64 base resources";
  let seen = Hashtbl.create 16 in
  List.mapi (fun index value ->
    let path = Printf.sprintf "%s[%d]" path index in
    let fields = obj path ["api_group";"resource";"scope";"subresources"] value in
    let api_group = string_field path "api_group" fields in
    if not (dns_subdomain api_group && String.contains api_group '.')
       || List.mem api_group reserved_groups then
      reject (path ^ ".api_group") "expected a custom DNS API group containing a dot; native API groups cannot be redefined";
    let resource = string_field path "resource" fields in
    if not (dns_label resource && resource.[0]>='a' && resource.[0]<='z') then
      reject (path ^ ".resource") "expected a lowercase DNS resource plural beginning with a letter";
    if Hashtbl.mem seen (api_group,resource) then reject path "duplicate custom resource or conflicting scope";
    Hashtbl.add seen (api_group,resource) ();
    let namespaced = match string_field path "scope" fields with
      | "Namespaced" -> true | "Cluster" -> false
      | _ -> reject (path ^ ".scope") "expected Namespaced or Cluster from independently reviewed API metadata" in
    let subresources = strings (path ^ ".subresources") (field path "subresources" fields) in
    if List.exists (fun value -> value<>"status" && value<>"scale") subresources then
      reject (path ^ ".subresources") "only explicitly selected status and scale are supported";
    let sorted = List.sort_uniq String.compare subresources in
    if List.length sorted <> List.length subresources then reject path "duplicate custom subresource";
    {api_group;resource;namespaced;subresources=sorted}) values
  |> List.sort (fun a b -> compare (a.api_group,a.resource) (b.api_group,b.resource))

let of_string source = protect (fun () -> parse "custom_resources" (Input.parse source))

let resources entries = List.concat_map (fun entry -> Resource_domain.custom
  ~api_group:entry.api_group ~resource:entry.resource ~namespaced:entry.namespaced
  ~subresources:entry.subresources) entries

let json entries = `A (List.map (fun entry -> `O [
  "api_group",`String entry.api_group;"resource",`String entry.resource;
  "scope",`String (if entry.namespaced then "Namespaced" else "Cluster");
  "subresources",`A (List.map (fun value -> `String value) entry.subresources)]) entries)
