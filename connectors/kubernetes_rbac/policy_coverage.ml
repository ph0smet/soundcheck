open Input
open Snapshot

type missing = { proposed_rule_index : int; atom_index : int; rule : Snapshot.rule }
type t = { covered : bool; atom_count : int; missing : missing list }

let max_values = 100_000
let max_bytes = 8 * 1024 * 1024
let max_atoms = 100_000
let max_comparison_units = 10_000_000
type budget = { mutable values : int; mutable bytes : int }
let budget () = { values = 0; bytes = 0 }

let checked_add path limit a b =
  if b > limit - a then reject path (Printf.sprintf "budget exceeds %d" limit);
  a + b

let checked_mul path limit a b =
  if a <> 0 && b > limit / a then reject path (Printf.sprintf "budget exceeds %d" limit);
  a * b

let value budget =
  budget.values <- checked_add "policy coverage input values" max_values budget.values 1

let string budget text =
  value budget;
  budget.bytes <- checked_add "policy coverage string bytes" max_bytes budget.bytes (String.length text)

let strings budget values = List.iter (string budget) values

let fields = function
  | Resource r -> [r.verbs; r.api_groups; r.resources; r.resource_names]
  | Non_resource r -> [r.verbs; r.urls]

let check_rule budget rule =
  value budget;
  List.iter (strings budget) (fields rule);
  let required label = function
    | [] -> reject "policy coverage rule" (label ^ " must not be empty")
    | _ -> () in
  match rule with
  | Resource r ->
      required "verbs" r.verbs;
      required "apiGroups" r.api_groups;
      required "resources" r.resources
  | Non_resource r -> required "verbs" r.verbs; required "nonResourceURLs" r.urls

let check_rules budget rules = List.iter (check_rule budget) rules

let scan_cost rules =
  (* Input validation bounds this sum below 36 million, including on 32-bit
     OCaml. Keep the full cost so zero atoms correctly require zero comparisons. *)
  List.fold_left (fun cost rule ->
    let bytes_and_values = List.fold_left (fun cost values ->
      List.fold_left (fun cost text -> cost + 1 + String.length text) cost values) 0 (fields rule) in
    cost + 16 + 4 * bytes_and_values) 0 rules

let check_comparisons rules count =
  ignore (checked_mul "policy coverage comparison units" max_comparison_units count (scan_cost rules))

let atom_count rule =
  let multiply = checked_mul "policy coverage proposed atoms" max_atoms in
  match rule with
  | Resource r ->
      multiply (multiply (multiply (List.length r.api_groups) (List.length r.resources))
        (List.length r.verbs)) (max 1 (List.length r.resource_names))
  | Non_resource r -> multiply (List.length r.urls) (List.length r.verbs)

let expanded_atom_bytes rule =
  let count = atom_count rule in
  let add = checked_add "policy coverage expanded atom string bytes" max_bytes in
  let multiply = checked_mul "policy coverage expanded atom string bytes" max_bytes in
  List.fold_left (fun total values ->
    if values = [] then total else
      let bytes = List.fold_left (fun bytes text -> bytes + String.length text) 0 values in
      add total (multiply bytes (count / List.length values))) 0 (fields rule)

let exact_or_all values requested =
  List.exists (fun value -> value = "*" || value = requested) values

let resource_matches values ~resource ~wildcard_subresource =
  List.exists (fun value -> value = "*" || value = resource ||
    match wildcard_subresource with Some wildcard -> value = wildcard | None -> false) values

let wildcard_suffix resource =
  match String.index_opt resource '/' with
  | None -> None
  | Some slash -> Some ("*/" ^ String.sub resource (slash + 1) (String.length resource - slash - 1))

let url_covers owner proposed =
  if owner = proposed then true
  else if not (String.ends_with ~suffix:"*" owner) then false
  else begin
    (* Kubernetes trims ALL trailing stars, retaining internal stars literally. *)
    let rec last_nonstar i = if i >= 0 && owner.[i] = '*' then last_nonstar (i - 1) else i in
    let prefix = String.sub owner 0 (1 + last_nonstar (String.length owner - 1)) in
    String.starts_with ~prefix proposed
  end

let resource_atom_covered owners ~verb ~api_group ~resource ~wildcard_subresource ~name =
  List.exists (function
    | Non_resource _ -> false
    | Resource owner ->
        exact_or_all owner.verbs verb && exact_or_all owner.api_groups api_group &&
        resource_matches owner.resources ~resource ~wildcard_subresource &&
        (match name with
         | None -> owner.resource_names = []
         | Some name -> owner.resource_names = [] || List.mem name owner.resource_names)) owners

let url_atom_covered owners ~verb ~url =
  List.exists (function
    | Resource _ -> false
    | Non_resource owner ->
        exact_or_all owner.verbs verb && List.exists (fun owned -> url_covers owned url) owner.urls) owners

let covers ~owner ~proposed = protect (fun () ->
  let budget = budget () in
  check_rules budget owner;
  check_rules budget proposed;
  let atom_count = List.fold_left (fun total rule ->
    checked_add "policy coverage proposed atoms" max_atoms total (atom_count rule)) 0 proposed in
  ignore (List.fold_left (fun total rule ->
    checked_add "policy coverage expanded atom string bytes" max_bytes total
      (expanded_atom_bytes rule)) 0 proposed);
  check_comparisons owner atom_count;
  let missing = ref [] in
  List.iteri (fun proposed_rule_index rule ->
    let atom_index = ref 0 in
    let emit covered rule =
      if not covered then missing := { proposed_rule_index; atom_index = !atom_index; rule } :: !missing;
      incr atom_index in
    match rule with
    | Resource r ->
        (* Compute slash suffixes once per source resource, before multiplying
           by groups, verbs and names. No Cartesian list is constructed. *)
        let resources = List.map (fun resource -> resource, wildcard_suffix resource) r.resources in
        List.iter (fun api_group -> List.iter (fun (resource, wildcard_subresource) ->
          List.iter (fun verb ->
            let atom name =
              let covered = resource_atom_covered owner ~verb ~api_group ~resource ~wildcard_subresource ~name in
              let resource_names = match name with None -> [] | Some name -> [name] in
              emit covered (Resource { verbs = [verb]; api_groups = [api_group]; resources = [resource]; resource_names }) in
            match r.resource_names with [] -> atom None | names -> List.iter (fun name -> atom (Some name)) names)
          r.verbs) resources) r.api_groups
    | Non_resource r ->
        List.iter (fun url -> List.iter (fun verb ->
          emit (url_atom_covered owner ~verb ~url) (Non_resource { verbs = [verb]; urls = [url] })) r.verbs) r.urls)
    proposed;
  let missing = List.rev !missing in
  { covered = missing = []; atom_count; missing })

let rules_for snapshot ~identity ~namespace = protect (fun () ->
  let budget = budget () in
  string budget identity.Identity.username;
  strings budget identity.groups;
  string budget namespace;
  let grants = Snapshot.grants snapshot in
  (* Validate before copying any selected rules. Repeated references count each
     time, bounding binding-by-rule multiplication even for unmatched callers. *)
  List.iter (fun grant ->
    value budget;
    let binding = grant.binding in
    strings budget [binding.binding_kind; binding.binding_namespace; binding.binding_name];
    (match binding.role_ref with Local_role name | Cluster_role name -> string budget name);
    List.iter (fun subject ->
      value budget;
      match subject with
      | User name | Group name -> string budget name
      | Service_account (namespace, name) -> strings budget [namespace; name]) binding.subjects;
    check_rules budget grant.bound_rules) grants;
  let group_cost = List.fold_left (fun cost group -> cost + 1 + String.length group) 0 identity.groups in
  let subject_cost = function
    | User name -> 16 + 4 * (1 + String.length name)
    | Group name -> 16 + 4 * (1 + String.length name + group_cost)
    | Service_account (namespace, name) ->
        16 + 4 * (2 + String.length namespace + String.length name + String.length "system:serviceaccount::") in
  ignore (List.fold_left (fun cost grant ->
    let binding = grant.binding in
    let applicable = binding.binding_kind = "ClusterRoleBinding" ||
      (namespace <> "" && binding.binding_kind = "RoleBinding" && binding.binding_namespace = namespace) in
    if not applicable then cost else
      List.fold_left (fun cost subject ->
        checked_add "policy coverage subject comparison units" max_comparison_units cost (subject_cost subject)) cost binding.subjects) 0 grants);
  let collect kind applicable acc =
    List.fold_left (fun acc grant ->
      let binding = grant.binding in
      if binding.binding_kind = kind && applicable binding &&
         List.exists (Snapshot.subject_matches identity) binding.subjects
      then List.rev_append grant.bound_rules acc else acc) acc grants in
  let reversed = collect "ClusterRoleBinding" (fun _ -> true) [] in
  let reversed = if namespace = "" then reversed else
    collect "RoleBinding" (fun binding -> binding.binding_namespace = namespace) reversed in
  List.rev reversed)

let granting_rules ~rules ~verb ~api_group ~resource ~subresource ~name = protect (fun () ->
  let budget = budget () in
  check_rules budget rules;
  strings budget [verb; api_group; resource; subresource; name];
  check_comparisons rules 1;
  let combined = if subresource = "" then resource else resource ^ "/" ^ subresource in
  let wildcard_subresource = if subresource = "" then None else Some ("*/" ^ subresource) in
  List.mapi (fun index -> function
    | Non_resource _ -> None
    | Resource rule ->
        if exact_or_all rule.verbs verb && exact_or_all rule.api_groups api_group &&
           resource_matches rule.resources ~resource:combined ~wildcard_subresource &&
           (rule.resource_names = [] || List.mem name rule.resource_names)
        then Some index else None) rules
  |> List.filter_map Fun.id)

let allows_resource ~rules ~verb ~api_group ~resource ~subresource ~name =
  Result.map (fun indices -> indices <> []) (granting_rules ~rules ~verb ~api_group ~resource ~subresource ~name)
