open Soundcheck_core

let dns_label =
  let alnum = Regex.Class (false,['a','z';'0','9']) in
  let middle = Regex.Class (false,['a','z';'0','9';'-','-']) in
  Regex.Concat [alnum;Regex.Opt (Regex.Concat [Regex.Star middle;alnum])]

let dns_name = Regex.Concat [dns_label;Regex.Star (Regex.Concat [Regex.Lit ".";dns_label])]

let legacy_domain spec =
  let resources = Resource_domain.for_version (Contract_spec.version spec) in
  let namespace = Ir.And [Ir.Object_matches (Ir.Object_namespace,dns_label);
                         Ir.Object_length_at_most (Ir.Object_namespace,63)] in
  let kind resources = Ir.Or (List.map (fun entry ->
    Ir.Object_is (Ir.Object_kind,Resource_domain.kind entry)) resources) in
  let namespace_for resources_namespace =
    if Contract_spec.version spec < 5 then resources_namespace
    else Ir.Or [
      Ir.And [kind (List.filter (fun entry -> entry.Resource_domain.namespaced) resources);resources_namespace];
      Ir.And [kind (List.filter (fun entry -> not entry.Resource_domain.namespaced) resources);
              Ir.Object_is (Ir.Object_namespace,"")]] in
  let named_namespace = namespace_for namespace in
  let collection_namespace = namespace_for (Ir.Or [Ir.Object_is (Ir.Object_namespace,"");namespace]) in
  let name = Ir.And [Ir.Object_matches (Ir.Object_name,dns_name);
                    Ir.Object_length_at_most (Ir.Object_name,253)] in
  let named_get = Ir.And [Ir.Method_is "get";named_namespace;name] in
  let reads = if Contract_spec.version spec = 1 then named_get else
      Ir.Or [named_get;
        Ir.And [Ir.Or [Ir.Method_is "list";Ir.Method_is "watch"];
                collection_namespace;
                Ir.Or [Ir.Object_is (Ir.Object_name,"");name]]] in
  let requests = if Contract_spec.version spec >= 3 then
      Ir.Or [reads;Ir.And [Ir.Or [Ir.Method_is "update";Ir.Method_is "patch";Ir.Method_is "delete"];
                          named_namespace;name]]
    else reads in
  let requests = if Contract_spec.version spec = 6 then
      Ir.Or [requests;
        Ir.And [Ir.Or [Ir.Method_is "create";Ir.Method_is "deletecollection"];
                named_namespace;Ir.Object_is (Ir.Object_name,"")]]
    else requests in
  Ir.And [Ir.Has_object_request;requests;
    Ir.Or (List.map (fun (identity : Identity.identity) -> Ir.Principal_is identity.username)
      (Contract_spec.identities spec));
    kind resources]

let domain spec =
  let version = Contract_spec.version spec in
  if version<7 then legacy_domain spec else
  let named coordinate regex length = Ir.And [Ir.Object_matches (coordinate,regex);
      Ir.Object_length_at_most (coordinate,length)] in
  let attribute coordinate nonempty = function
    | "named" -> nonempty
    | "empty" -> Ir.Object_is (coordinate,"")
    | "empty-or-named" -> Ir.Or [Ir.Object_is (coordinate,"");nonempty]
    | "same-as-name" -> Ir.And [nonempty;Ir.Object_equal (coordinate,Ir.Object_name)]
    | _ -> invalid_arg "unregistered RBAC attribute domain" in
  let namespace = named Ir.Object_namespace dns_label 63
  and name = named Ir.Object_name dns_name 253 in
  let operations entry = Resource_domain.operations ~version entry |> List.map (fun verb ->
      Ir.And [Ir.Method_is verb;
        attribute Ir.Object_namespace namespace (Resource_domain.namespace_domain entry ~verb);
        attribute Ir.Object_name name (Resource_domain.name_domain entry ~verb)]) in
  let who = Ir.Or (List.map (fun (identity : Identity.identity) -> Ir.Principal_is identity.username)
      (Contract_spec.identities spec)) in
  let objects = Ir.And [Ir.Has_object_request;who;
    Ir.Or (List.map (fun entry -> Ir.And [
      Ir.Object_is (Ir.Object_kind,Resource_domain.kind entry);Ir.Or (operations entry)])
      (Contract_spec.resources spec))] in
  (* Resource authorization has object coordinates, not an independent URL.
     Canonicalize the inactive path in this mixed domain just as the shared
     encoder canonicalizes inactive object coordinates for URL requests. *)
  if version>=9 then Ir.Or [Ir.And [objects;Ir.Path_exact ""];Ir.And [who;Url_domain.condition]] else objects

let wildcard_or values value = List.mem "*" values || List.mem value values

let resource_condition resources verbs (rule : Snapshot.resource_rule) =
  Ir.And [
      Ir.Or (List.filter_map (fun verb ->
          if wildcard_or rule.verbs verb then Some (Ir.Method_is verb) else None)
        verbs);
      Ir.Or (List.filter_map (fun (entry : Resource_domain.t) ->
          (* Kubernetes accepts exact combined resources, whole *, and an
             exact subresource after */. Parent/* is not a general glob. *)
          if wildcard_or rule.api_groups entry.api_group &&
             (wildcard_or rule.resources (Resource_domain.combined_resource entry)
              || (entry.subresource<>"" && List.mem ("*/" ^ entry.subresource) rule.resources))
          then Some (Ir.Object_is (Ir.Object_kind,Resource_domain.kind entry)) else None) resources);
      (match rule.resource_names with
       | [] -> Ir.True
       | names -> Ir.Or (List.filter_map (fun name ->
           if name = "" || Input.dns_subdomain name then Some (Ir.Object_is (Ir.Object_name,name)) else None) names))]

let rule_condition ~urls resources verbs = function
  | Snapshot.Resource rule -> resource_condition resources verbs rule
  | Snapshot.Non_resource rule ->
    if not urls then Ir.Or [] else Ir.And [Ir.Not Ir.Has_object_request;
      Ir.Or (List.filter_map (fun verb -> if wildcard_or rule.verbs verb
        then Some (Ir.Method_is verb) else None) Url_domain.methods);
      Ir.Or (List.map Url_domain.rule_condition rule.urls)]

let grant_id binding index =
  Printf.sprintf "%s -> %s/rules/%d" (Snapshot.binding_label binding) (Snapshot.role_label binding) index

(* The raw rules are exact additive Allow predicates. Specialize only their
   action coordinate; preserve caller and target constraints under every boolean
   connective. Named additional create must not use the standalone request
   domain, which correctly permits only an empty name for base collection POST. *)
let rec at_verb verb = function
  | Ir.Method_is value -> if verb=value then Ir.True else Ir.Or []
  | Ir.And conditions ->
    let conditions = List.map (at_verb verb) conditions in
    if List.mem (Ir.Or []) conditions then Ir.Or []
    else Ir.And (List.filter ((<>) Ir.True) conditions)
  | Ir.Or conditions ->
    let conditions = List.map (at_verb verb) conditions in
    if List.mem Ir.True conditions then Ir.True
    else Ir.Or (List.filter ((<>) (Ir.Or [])) conditions)
  | Ir.Not condition -> Ir.Not (at_verb verb condition)
  | condition -> condition

let allow_rule id match_ : Ir.rule =
  {id;match_;match_complete=true;guard=Ir.True;guard_complete=true;
   priority={comparable=true;key=[]};decision=Ir.Allow;
   rate_limited=false;targets_admin=false}

let policy spec snapshot : Ir.policy =
  let identities = Contract_spec.identities spec in
  let resources = Contract_spec.resources spec in
  let verbs = if Contract_spec.version spec >= 6 then ["get";"list";"watch";"update";"patch";"delete";"create";"deletecollection"]
    else if Contract_spec.version spec >= 3 then ["get";"list";"watch";"update";"patch";"delete"]
    else ["get";"list";"watch"] in
  let rules = Snapshot.grants snapshot |> List.concat_map (fun (grant : Snapshot.bound_grant) ->
      let binding = grant.binding in
      let who = Ir.Or (List.filter_map (fun (identity : Identity.identity) ->
          if List.exists (Snapshot.subject_matches identity) binding.subjects then
            Some (Ir.Principal_is identity.username) else None) identities) in
      let where = if binding.binding_kind = "RoleBinding" then
          Ir.Object_is (Ir.Object_namespace,binding.binding_namespace) else Ir.True in
      List.mapi (fun index rule ->
          allow_rule (grant_id binding index)
            (Ir.And [who;where;rule_condition ~urls:(Contract_spec.version spec>=9) resources verbs rule])) grant.bound_rules) in
  let rules = if Contract_spec.version spec<8 then rules else
    let native_grant verb = Ir.Or (List.map (fun (rule : Ir.rule) -> at_verb verb rule.match_) rules) in
    let derived = List.map (fun operation ->
        allow_rule ("conditional RBAC prerequisites: " ^ operation)
          (Ir.And (Ir.Method_is operation :: List.map native_grant (Resource_domain.checks ~operation))))
        (["apply-existing";"apply-missing"]
         @ if Contract_spec.version spec>=9 then ["update-existing";"update-missing"] else []) in
    rules @ derived in
  {request_domain=domain spec;rules;default=Ir.Deny}

let matching_grants policy request =
  policy.Ir.rules |> List.filter (Ir.selected policy request)
    |> List.map (fun (rule : Ir.rule) -> rule.id) |> List.sort_uniq String.compare

let authorization_checks policy request =
  if not (Ir.matches policy.Ir.request_domain request) then [] else
  Resource_domain.checks ~operation:request.Ir.action |> List.map (fun verb ->
    (* The enclosing operation domain is checked above. Deliberately replay the
       exact raw rules without the standalone verb's domain: additional create
       has a named target. Derived SSA rules cannot match native stage verbs. *)
    verb,matching_grants policy {request with action=verb})

let granting_rules policy request =
  if not (Ir.matches policy.Ir.request_domain request) then []
  else match Resource_domain.object_state ~operation:request.Ir.action with
    | None -> matching_grants policy request
    | Some _ ->
      let checks = authorization_checks policy request in
      if List.exists (fun (_,grants) -> grants=[]) checks then [] else
      List.concat_map (fun (verb,grants) -> List.map (fun id -> verb ^ ": " ^ id) grants) checks
