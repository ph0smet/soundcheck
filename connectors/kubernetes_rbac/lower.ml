open Soundcheck_core

let dns_label =
  let alnum = Regex.Class (false,['a','z';'0','9']) in
  let middle = Regex.Class (false,['a','z';'0','9';'-','-']) in
  Regex.Concat [alnum;Regex.Opt (Regex.Concat [Regex.Star middle;alnum])]

let dns_name = Regex.Concat [dns_label;Regex.Star (Regex.Concat [Regex.Lit ".";dns_label])]

let domain spec =
  let namespace = Ir.And [Ir.Object_matches (Ir.Object_namespace,dns_label);
                         Ir.Object_length_at_most (Ir.Object_namespace,63)] in
  let name = Ir.And [Ir.Object_matches (Ir.Object_name,dns_name);
                    Ir.Object_length_at_most (Ir.Object_name,253)] in
  let named_get = Ir.And [Ir.Method_is "get";namespace;name] in
  let reads = if Contract_spec.version spec = 1 then named_get else
      Ir.Or [named_get;
        Ir.And [Ir.Or [Ir.Method_is "list";Ir.Method_is "watch"];
                Ir.Or [Ir.Object_is (Ir.Object_namespace,"");namespace];
                Ir.Or [Ir.Object_is (Ir.Object_name,"");name]]] in
  let requests = if Contract_spec.version spec >= 3 then
      Ir.Or [reads;Ir.And [Ir.Or [Ir.Method_is "update";Ir.Method_is "patch";Ir.Method_is "delete"];
                          namespace;name]]
    else reads in
  Ir.And [Ir.Has_object_request;requests;
    Ir.Or (List.map (fun (identity : Identity.identity) -> Ir.Principal_is identity.username)
      (Contract_spec.identities spec));
    Ir.Or [Ir.Object_is (Ir.Object_kind,"configmaps");Ir.Object_is (Ir.Object_kind,"secrets")]]

let wildcard_or values value = List.mem "*" values || List.mem value values

let resource_condition verbs (rule : Snapshot.resource_rule) =
  if not (wildcard_or rule.api_groups "") then Ir.Or []
  else Ir.And [
      Ir.Or (List.filter_map (fun verb ->
          if wildcard_or rule.verbs verb then Some (Ir.Method_is verb) else None)
        verbs);
      Ir.Or (List.filter_map (fun kind ->
          if wildcard_or rule.resources kind then Some (Ir.Object_is (Ir.Object_kind,kind)) else None)
        ["configmaps";"secrets"]);
      (match rule.resource_names with
       | [] -> Ir.True
       | names -> Ir.Or (List.filter_map (fun name ->
           if name = "" || Input.dns_subdomain name then Some (Ir.Object_is (Ir.Object_name,name)) else None) names))]

let rule_condition verbs = function
  | Snapshot.Resource rule -> resource_condition verbs rule
  | Snapshot.Non_resource _ ->
    (* Every quantified request is a resource request. Keep this rule's source
       slot for trace IDs, but it cannot grant any request in that domain. *)
    Ir.Or []

let grant_id binding index =
  Printf.sprintf "%s -> %s/rules/%d" (Snapshot.binding_label binding) (Snapshot.role_label binding) index

let policy spec snapshot : Ir.policy =
  let identities = Contract_spec.identities spec in
  let verbs = if Contract_spec.version spec >= 3 then ["get";"list";"watch";"update";"patch";"delete"]
    else ["get";"list";"watch"] in
  let rules = Snapshot.grants snapshot |> List.concat_map (fun (grant : Snapshot.bound_grant) ->
      let binding = grant.binding in
      let who = Ir.Or (List.filter_map (fun (identity : Identity.identity) ->
          if List.exists (Snapshot.subject_matches identity) binding.subjects then
            Some (Ir.Principal_is identity.username) else None) identities) in
      let where = if binding.binding_kind = "RoleBinding" then
          Ir.Object_is (Ir.Object_namespace,binding.binding_namespace) else Ir.True in
      List.mapi (fun index rule : Ir.rule ->
          {id=grant_id binding index;
           match_=Ir.And [who;where;rule_condition verbs rule];
           match_complete=true;guard=Ir.True;guard_complete=true;
           priority={comparable=true;key=[]};decision=Ir.Allow;
           rate_limited=false;targets_admin=false}) grant.bound_rules) in
  {request_domain=domain spec;rules;default=Ir.Deny}

let granting_rules policy request =
  if not (Ir.matches policy.Ir.request_domain request) then []
  else policy.rules |> List.filter (Ir.selected policy request)
    |> List.map (fun (rule : Ir.rule) -> rule.id) |> List.sort_uniq String.compare
