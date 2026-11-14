open Input

let strings xs = `A (List.map (fun x -> `String x) xs)
let number n = `Number (string_of_int n)
let matches entry group resource =
  (group="*" || group=entry.Resource_domain.api_group) &&
  (resource="*" || resource=Resource_domain.combined_resource entry ||
   (entry.subresource<>"" && resource="*/" ^ entry.subresource))

let run ~snapshot ~contract =
  let ( let* ) = Result.bind in
  let* spec = Contract_spec.of_string contract in
  let* rules = Snapshot.rule_inventory snapshot in
  protect (fun () ->
    let version = Contract_spec.version spec in
    let entries = Contract_spec.resources spec in
    let resource_json entry = `O [
      "api_group",`String entry.Resource_domain.api_group;
      "resource",`String entry.resource;"subresource",`String entry.subresource;
      "scope",`String (if entry.namespaced then "Namespaced" else "Cluster");
      "operations",strings (Resource_domain.operations ~version entry)] in
    let reference_count = ref 0 and association_count = ref 0 in
    let sources = List.map (fun (source : Snapshot.rule_source) ->
      let details = match source.rule with
        | Snapshot.Resource r ->
          let references = List.concat_map (fun group -> List.map (fun resource ->
            incr reference_count;
            if !reference_count>10000 then reject "coverage" "rule-reference review exceeds 10000 pairs";
            let matched = List.filter (fun entry -> matches entry group resource) entries in
            association_count := !association_count + List.length matched;
            if !association_count>100000 then reject "coverage" "review exceeds 100000 catalogue associations";
            `O ["api_group",`String group;"resource",`String resource;
              "reviewed_entries",strings (List.map Resource_domain.kind matched);
              "wildcard",`Bool (group="*" || resource="*" || String.starts_with ~prefix:"*/" resource);
              "outside_catalogue",`Bool (matched=[])]) r.resources) r.api_groups in
          ["request_kind",`String "resource";"verbs",strings r.verbs;
           "resource_names",strings r.resource_names;"references",`A references;
           "note",`String "Entry matching describes references only. Verb, namespace, name and identity restrictions still apply; wildcard grants can cover APIs outside the frozen catalogue."]
        | Non_resource r ->
          ["request_kind",`String "non_resource";"verbs",strings r.verbs;
           "non_resource_urls",strings r.urls;
           "non_resource_verification_enabled",`Bool (version>=9);
           "note",`String "Schemas 9 and later cover canonical non-resource paths and seven HTTP methods. Endpoint existence, escaped paths and other methods are not inferred."] in
      `O (["role",`String source.role_label;"item_index",number source.item_index;
           "rule_index",number source.rule_index;"referenced_by_binding",`Bool source.bound] @ details)) rules in
    let canonical = Contract_spec.canonical spec in
    json (`O ["schema_version",number 1;"kind",`String "rbac-coverage-review";
      "target_profile",`String (Assurance.id_for_version version);
      "contract_version",number version;
      "snapshot_sha256",`String (Soundcheck_core.Sha256.string snapshot);
      "canonical_contract_sha256",`String (Soundcheck_core.Sha256.string canonical);
      "custom_resources",Catalogue.json (Contract_spec.custom_resources spec);
      "reviewed_resource_entries",`A (List.map resource_json entries);
      "resource_operation_classes",number (List.fold_left (fun n entry ->
        n + List.length (Resource_domain.operations ~version entry)) 0 entries);
      "non_resource_methods",strings (if version>=9 then Url_domain.methods else []);
      "rule_sources",`A sources;
      "requirements_inferred",`Bool false;"authorization_evaluated",`Bool false;
      "verification_performed",`Bool false;"completeness_established",`Bool false;
      "limitations",strings ["Observed rule references are not access requirements.";
        "Unbound roles are included; binding references do not establish grants to reviewed identities.";
        "Wildcards quantify only the frozen catalogue during verification, never future APIs.";
        "Named Namespace authorization uses namespace equal to name; collection requests use an empty namespace.";
        "No claim about installed handlers, valid bodies, admission, controller effects or final API-server decisions."]]))
