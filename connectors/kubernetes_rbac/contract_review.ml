open Soundcheck_core

let run source =
  let ( let* ) = Result.bind in
  let* spec = Contract_spec.of_string source in
  let canonical = Contract_spec.canonical spec in
  let identities = Contract_spec.identities spec in
  let clauses = Contract_spec.clauses spec and changes = Contract_spec.changes spec in
  let required = List.length (List.filter (fun (c : Contract_spec.clause) -> c.kind=Must_allow) clauses) in
  let groups = List.fold_left (fun total (i : Identity.identity) -> total + List.length i.groups) 0 identities in
  let buffer = Buffer.create 1024 in
  let line format = Printf.ksprintf (fun value -> Buffer.add_string buffer value;Buffer.add_char buffer '\n') format in
  line "RBAC contract parsed (structure only; not a verification result).";
  line "Inhabitation, consistency, access and repair preservation have NOT been checked.";
  line "Contract schema: %d" (Contract_spec.version spec);
  line "Selected profile (information only): %s" (Assurance.id_for_version (Contract_spec.version spec));
  line "Raw artifact SHA-256: %s" (Sha256.string source);
  line "Canonical frozen-contract SHA-256: %s" (Sha256.string canonical);
  line "Artifact size: %d bytes; %d identities; %d group memberships; %d clauses (%d must_allow, %d must_not_grant); %d normalized approved-change scopes."
    (String.length source) (List.length identities) groups (List.length clauses) required
    (List.length clauses-required) (List.length changes);
  line "";
  if Contract_spec.version spec>=9 then begin
    line "Frozen resource catalogue: %d entries including explicit custom resources."
      (List.length (Contract_spec.resources spec));
    line "Custom API metadata: %s" (Input.json (Catalogue.json (Contract_spec.custom_resources spec)));
    line "Non-resource URL access and preservation are included within the profile's canonical path domain.";
    line "Named Namespace authorization attributes have namespace equal to target name; collection requests have empty namespace.";
    line "PUT and SSA are conditional prerequisites; a shared named-create grant can affect both operations.";
    line ""
  end;
  if Contract_spec.version spec>=10 then begin
    line "Controller APIs are cluster-scoped: webhook configurations, CRDs and CRD/status, SubjectAccessReview and TokenReview.";
    line "Review APIs allow only initial create with empty authorization name/namespace. Their body subjects, tokens and returned decisions are not the caller or an authorization guarantee.";
    line "Webhook/CRD access does not establish admission behavior, schema validity or successful effects.";
    line ""
  end;
  line "Declared identities (trusted input, not authentication findings):";
  List.iter (fun (identity : Identity.identity) ->
    line "  %S; groups: [%s]" identity.username
      (String.concat ", " (List.map (Printf.sprintf "%S") identity.groups))) identities;
  line "";
  line "Required and forbidden access (in contract order):";
  List.iteri (fun index clause -> line "  %d. %S: %s" (index+1)
    (Contract.name clause) (Contract.description clause)) (Contract_spec.to_contract spec).clauses;
  line "";
  line "Approved decision changes (separate from access requirements):";
  (match changes with
   | [] -> line "  None. Preserve every modeled decision for every frozen identity."
   | _ ->
     List.iteri (fun index scope -> line "  %d. %s" (index+1) (Contract_spec.describe_scope scope)) changes;
     line "  Only these request classes may change; candidate access requirements still apply inside them.";
     line "  Preserve all other modeled decisions for every frozen identity, including identities without clauses.");
  line "";
  if Contract_spec.version spec>=8 then begin
    line "Apply operations are conditional storage branches, not observations of object existence.";
    line "NoOpinion means at least one RBAC prerequisite lacks a grant, not final API-server denial.";
    line "Preservation compares aggregate operation decisions. Patch and apply-existing remain distinct scope classes."
  end else line "NoOpinion means no RBAC grant, not final API-server denial.";
  line "Snapshot completeness is asserted by the contract, not established here.";
  line "These counts describe the artifact, not measured authoring effort.";
  line "Review and freeze intent independently of candidate grants. Use rbac verify/compare for solver-backed results.";
  Ok (Buffer.contents buffer)
