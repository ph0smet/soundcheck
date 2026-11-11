open Input

let subject_json = function
  | Snapshot.User name -> `O ["kind",`String "User";"name",`String name]
  | Group name -> `O ["kind",`String "Group";"name",`String name]
  | Service_account (namespace,name) -> `O ["kind",`String "ServiceAccount";
      "namespace",`String namespace;"name",`String name]

let identity bytes = `O ["sha256",`String (Soundcheck_core.Sha256.string bytes);
  "bytes",`Number (string_of_int (String.length bytes))]

let run ~snapshot ~contract =
  let ( let* ) = Result.bind in
  let* spec = Contract_spec.of_string contract in
  let* policy = Snapshot.of_string snapshot in
  let identities = Contract_spec.identities spec |> List.map (fun (identity : Identity.identity) ->
    let bindings = Snapshot.grants policy |> List.filter_map (fun (grant : Snapshot.bound_grant) ->
      let subjects = List.filter (Snapshot.subject_matches identity) grant.binding.subjects in
      if subjects=[] then None else Some (`O [
        "binding",`String (Snapshot.binding_label grant.binding);
        "role",`String (Snapshot.role_label grant.binding);
        "rule_count",`Number (string_of_int (List.length grant.bound_rules));
        "matching_subjects",`A (List.map subject_json subjects)])) in
    `O ["username",`String identity.username;"groups",`A (List.map (fun group -> `String group) identity.groups);
      "subject_matching_bindings",`A bindings]) in
  let canonical = Contract_spec.canonical spec in
  Ok (json (`O ["schema_version",`Number "1";"kind",`String "rbac-identity-inspection";
    "target_profile",`String (Assurance.id_for_version (Contract_spec.version spec));
    "snapshot",identity snapshot;"contract",identity contract;
    "contract_version",`Number (string_of_int (Contract_spec.version spec));
    "canonical_contract",`String canonical;
    "canonical_contract_sha256",`String (Soundcheck_core.Sha256.string canonical);
    "identity_source",`String "frozen-contract";"identities",`A identities;
    "snapshot_completeness_asserted_by_contract",`Bool true;
    "identity_authentication_established",`Bool false;"completeness_established",`Bool false;
    "authorization_evaluated",`Bool false;"verification_performed",`Bool false]))
