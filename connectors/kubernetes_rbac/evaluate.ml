open Soundcheck_core
open Input

type request = { id:string; request:Ir.request }

let requests spec source = protect (fun () ->
  let operation_field = if Contract_spec.version spec>=8 then "operation" else "verb" in
  let seen = Hashtbl.create 16 in
  arr "requests" (parse source) |> List.mapi (fun index value ->
    let path = Printf.sprintf "requests[%d]" index in
    let fields = obj path ["id";"username";"groups";"namespace";"resource";"name";
                          operation_field;"apiGroup";"resourceRequest";"subresource"] value in
    let id = string_field path "id" fields |> nonempty path in
    if Hashtbl.mem seen id then reject path "duplicate request id";
    Hashtbl.add seen id ();
    let username = string_field path "username" fields in
    let groups = strings path (field path "groups" fields) |> List.sort String.compare in
    if not (List.exists (fun (identity : Identity.identity) ->
        identity.username = username && identity.groups = groups) (Contract_spec.identities spec))
    then reject path "username and exact groups must match the frozen context";
    let verb = string_field path operation_field fields in
    (* Classify the request before interpreting resource coordinates. URL
       controls carry empty group/resource strings and must keep the explicit
       non-resource boundary, rather than fail catalogue lookup first. *)
    let subresource = string_field path "subresource" fields in
    if Contract_spec.version spec<7 then require_equal path subresource "";
    (match field path "resourceRequest" fields with
     | `Bool true -> () | _ -> reject path "resourceRequest must be true");
    let api_group = string_field path "apiGroup" fields in
    let resource = string_field path "resource" fields in
    let entry = match Resource_domain.find_subresource ~version:(Contract_spec.version spec) ~api_group ~resource ~subresource with
      | Some entry -> entry
      | None when Contract_spec.version spec>=7 -> reject path "API group/resource/subresource triple is outside the contract's fixed RBAC catalogue"
      | None -> reject path "API group/resource pair is outside the contract's fixed RBAC resource catalogue" in
    let coordinates : Ir.object_request =
      {namespace=string_field path "namespace" fields;
       resource_kind=Resource_domain.kind entry;
       name=string_field path "name" fields} in
    let request : Ir.request =
      {principal=Ir.Authenticated username;action=verb;resource="";context=[];
       source=0l;host="";scheme="";sni="";object_request=Some coordinates} in
    if not (Ir.matches (Lower.domain spec) request) then reject path "request is outside the contract's RBAC request domain";
    {id;request}))

let decisions policy requests =
  `A (List.map (fun row ->
      let grants = Lower.granting_rules policy row.request in
      `O ["id",`String row.id;
          "decision",`String (if Ir.possibly_allows policy row.request then "Allow" else "NoOpinion");
          "grants",`A (List.map (fun s -> `String s) grants)]) requests)

(* Exercise the production core formula against concrete requests in one solver
   process. The reference runner checks every domain/decision answer and also
   calls Kubernetes on the same original manifest bytes. *)
let matrix_smt policy requests =
  let signature =
    "((path String) (method String) (is_anon Bool) (src_ip (_ BitVec 32)) (host String) (scheme String) (sni String) (principal_name String) (has_object_request Bool) (object_namespace String) (object_kind String) (object_name String))" in
  let buffer = Buffer.create 4096 in
  Buffer.add_string buffer "(set-option :timeout 5000)\n(set-logic ALL)\n";
  Buffer.add_string buffer (Printf.sprintf "(define-fun domain %s Bool %s)\n" signature (Smt_encode.cond policy.Ir.request_domain));
  Buffer.add_string buffer (Printf.sprintf "(define-fun allows %s Bool %s)\n" signature (Smt_encode.possibly_allowed_formula policy));
  List.iter (fun row ->
      let principal = match row.request.principal with Ir.Authenticated name -> name | _ -> assert false in
      let coordinates = Option.get row.request.object_request in
      let args = String.concat " " ["\"\"";Regex.smt_string row.request.action;"false";"#x00000000";"\"\"";"\"\"";"\"\"";
          Regex.smt_string principal;"true";Regex.smt_string coordinates.namespace;
          Regex.smt_string coordinates.resource_kind;Regex.smt_string coordinates.name] in
      Buffer.add_string buffer (Printf.sprintf "(simplify (domain %s))\n(simplify (allows %s))\n" args args)) requests;
  Buffer.contents buffer
