open Soundcheck_core
module I = Input
let ( let* ) = Result.bind
type attributes = { verb : string; namespace : string; resource : string; name : string }
type check = { attributes : attributes; granting_rules : int list }
type authorization = {
  allowed : bool; initial : check; special : check option;
  coverage : Policy_coverage.t option; reason : string;
}
let profile_id = "kubernetes-rbac-v1.34-policy-change-v1"
let profile_json = I.json (`O ["schema_version",`Number "1";"id",`String profile_id;
  "kubernetes_version",`String "1.34.0";
  "authorization_method",`String "deterministic-native-rbac-policy-coverage";
  "scope",`String "One create or update-existing of Role, ClusterRole, RoleBinding or ClusterRoleBinding; original-snapshot authority only.";
  "assumptions",`A (List.map (fun x -> `String x) [
    "Complete static desired RBAC inventory and independently trusted caller groups.";
    "Original and proposed inventories differ only at the frozen target; update-existing changes its typed rules or subjects.";
    "No system:masters bypass actors, aggregate target, roleRef mutation, patch/apply/delete or create-on-update.";
    "No admission, concurrency, storage, successful mutation, runtime effects or composed authorization chain guarantee.";
    "Full native policy coverage retains unknown resource/verb/group strings. Nested access and preservation use the frozen requirements schema's domain.";
    "Executed analysis bounds: 100000 input values, 8 MiB input strings, 100000 proposed atoms, 8 MiB expanded atom strings, 10000000 comparison units; overflow returns unknown. Explicit authority skips policy coverage."])])

let profile_id_for_version = function
  | 1 -> profile_id | 2 -> "kubernetes-rbac-v1.34-policy-change-v2"
  | _ -> invalid_arg "unsupported policy-change version"
let profile_json_for_version = function
  | 1 -> profile_json
  | 2 -> I.json (`O ["schema_version",`Number "2";"id",`String (profile_id_for_version 2);
    "kubernetes_version",`String "1.34.0";
    "authorization_method",`String "deterministic-native-rbac-policy-coverage";
    "scope",`String "One create, update-existing or delete-existing of Role, ClusterRole, RoleBinding or ClusterRoleBinding; original-snapshot authority only.";
    "assumptions",`A (List.map (fun x -> `String x) [
      "Complete strict static inventories and independently trusted caller/groups. Only the frozen target may change.";
      "Create/update retain initial plus bind/escalate or full-policy coverage checks. Ordinary named delete-existing requires only its initial delete grant; no bind/escalate/coverage check applies.";
      "Delete-existing requires target presence before and absence afterward. Default DELETE options only; unsafe deletion, finalizers, owner references and deletion timestamps are unsupported.";
      "Deletion is conditional on complete successful visible removal. No admission, storage, garbage collection, concurrency, controller reconciliation, runtime effects or composed authorization-chain guarantee.";
      "No system:masters bypass actor, aggregate target, roleRef mutation, patch/apply, bulk deletion or create-on-update. Updates require a typed rule/subject change.";
      "Existing native-policy coverage bounds remain in force; overflow yields unknown. Access and preservation keep the nested schema's supported domain and all frozen identities."])])
  | _ -> invalid_arg "unsupported policy-change version"

let profile_human_for_version version =
  "RBAC policy changes ["^profile_id_for_version version^"] (Kubernetes v1.34.0)\n" ^
  (if version=1 then "One create/update-existing, authorized from the original snapshot, with final access and preservation.\n"
   else "One create/update-existing/delete-existing, authorized from the original snapshot, with final access and preservation. Ordinary delete requires only the named delete grant and assumes fully completed visible removal with default options.\n") ^
  "Complete strict inventories and trusted identities; no successful mutation, concurrency, admission or composed-authorizer guarantee.\n"

let object_key (v : Snapshot.object_view) = v.object_kind,v.object_namespace,v.object_name
let prepare spec ~before ~after =
  let* before_objects = Snapshot.object_views before in
  let* after_objects = Snapshot.object_views after in
  let target = Change_spec.target spec in
  let key = target.kind,target.namespace,target.name in
  let find xs = List.find_opt (fun v -> object_key v=key) xs in
  let original = find before_objects in
  let* proposed = match Change_spec.operation spec,original,find after_objects with
    | Delete_existing,Some v,None -> Ok v
    | Delete_existing,None,_ -> Error "delete-existing requires the frozen target to exist in the original inventory"
    | Delete_existing,_,Some _ -> Error "delete-existing requires the frozen target to be absent from the candidate"
    | _,_,Some v -> Ok v | _,_,None -> Error "candidate must contain the frozen target" in
  let* () = match Change_spec.operation spec,original with
    | Create,None | Update_existing,Some _ | Delete_existing,Some _ -> Ok ()
    | Create,Some _ -> Error "create requires the frozen target to be absent in the original inventory"
    | Update_existing,None -> Error "update-existing requires an original target; create-on-update is unsupported"
    | Delete_existing,None -> Error "delete-existing requires an original target" in
  let others xs = List.filter (fun v -> object_key v<>key) xs
    |> List.map (fun v -> object_key v,v.Snapshot.canonical_object)
    |> List.sort Stdlib.compare in
  let* () = if others before_objects=others after_objects then Ok ()
    else Error "only the frozen target may change; unrelated object bytes must agree after map-key normalization" in
  let* () = if proposed.aggregated || Option.fold ~none:false ~some:(fun v -> v.Snapshot.aggregated) original
    then Error "aggregate ClusterRole targets are outside the policy-change profile" else Ok () in
  let* () = match Change_spec.operation spec,original with
    | Delete_existing,_ -> Ok ()
    | _,None -> Ok ()
    | _,Some old -> (match old.object_spec,proposed.object_spec with
        | Binding_spec a,Binding_spec b when a.role_ref<>b.role_ref -> Error "binding roleRef is immutable; changing it is unsupported"
        | _ when old.object_spec=proposed.object_spec -> Error "update-existing requires a typed rule or subject change; no-op and metadata-only updates are unsupported"
        | _ -> Ok ()) in
  let* snapshot = Snapshot.of_string before in
  Ok (snapshot,before_objects,proposed)

let authorize spec ~before ~after =
  let* snapshot,original,proposed = prepare spec ~before ~after in
  let actor = Change_spec.actor spec and target = Change_spec.target spec in
  let* rules = Policy_coverage.rules_for snapshot ~identity:actor ~namespace:target.namespace in
  let check attributes =
    let* granting_rules = Policy_coverage.granting_rules ~rules ~verb:attributes.verb
      ~api_group:"rbac.authorization.k8s.io" ~resource:attributes.resource
      ~subresource:"" ~name:attributes.name in
    Ok {attributes;granting_rules} in
  let name = match Change_spec.operation spec with Create -> "" | Update_existing | Delete_existing -> target.name in
  let verb = match Change_spec.operation spec with Create -> "create" | Update_existing -> "update" | Delete_existing -> "delete" in
  let* initial = check {verb;namespace=target.namespace;resource=Change_spec.resource target;name} in
  if initial.granting_rules=[] then Ok {allowed=false;initial;special=None;coverage=None;
    reason=(if Change_spec.version spec=1 then "original RBAC does not grant the initial create/update request"
      else "original RBAC does not grant the initial "^verb^" request")}
  else if Change_spec.operation spec=Delete_existing then
    Ok {allowed=true;initial;special=None;coverage=None;
      reason="original RBAC grants the ordinary named delete request; bind/escalate and policy coverage are not deletion prerequisites"}
  else
    let* attrs,proposed_rules = match proposed.object_spec with
      | Role_spec proposed_rules -> Ok ({verb="escalate";namespace=target.namespace;
          resource=Change_spec.resource target;name},proposed_rules)
      | Binding_spec binding ->
        let kind,ns,name,resource = match binding.role_ref with
          | Local_role name -> "Role",target.namespace,name,"roles"
          | Cluster_role name -> "ClusterRole","",name,"clusterroles" in
        (match List.find_opt (fun v -> object_key v=(kind,ns,name)) original with
         | Some {object_spec=Role_spec proposed_rules;_} ->
           Ok ({verb="bind";namespace=target.namespace;resource;name},proposed_rules)
         | _ -> Error "binding roleRef must resolve in the original complete inventory") in
    let* special = check attrs in
    if special.granting_rules<>[] then Ok {allowed=true;initial;special=Some special;coverage=None;
      reason="original RBAC grants the initial request and explicit bind/escalate authority"}
    else
      let* coverage = Policy_coverage.covers ~owner:rules ~proposed:proposed_rules in
      Ok {allowed=coverage.covered;initial;special=Some special;coverage=Some coverage;
        reason=(if coverage.covered then "original RBAC grants the initial request and covers every proposed policy rule"
          else "proposed policy contains permissions not covered by the actor's original RBAC rules")}

let str x = `String x
let strings xs = `A (List.map str xs)
let number n = `Number (string_of_int n)
let optional f = function None -> `Null | Some x -> f x
let rule_json = function
  | Snapshot.Resource r -> `O ["verbs",strings r.verbs;"apiGroups",strings r.api_groups;
      "resources",strings r.resources;"resourceNames",strings r.resource_names]
  | Non_resource r -> `O ["verbs",strings r.verbs;"nonResourceURLs",strings r.urls]
let check_json (c : check) = `O ["attributes",`O ["verb",str c.attributes.verb;
  "api_group",str "rbac.authorization.k8s.io";"namespace",str c.attributes.namespace;
  "resource",str c.attributes.resource;"subresource",str "";"name",str c.attributes.name];
  "granting_rule_indices",`A (List.map number c.granting_rules)]
let authorization_value a = `O ["method",str "deterministic-native-rbac-policy-coverage";
  "allowed",`Bool a.allowed;"reason",str a.reason;"initial",check_json a.initial;
  "special",optional check_json a.special;
  "coverage",optional (fun (c : Policy_coverage.t) -> `O ["covered",`Bool c.covered;
    "atom_count",number c.atom_count;"missing",`A (List.map (fun (m : Policy_coverage.missing) ->
      `O ["proposed_rule_index",number m.proposed_rule_index;"atom_index",number m.atom_index;
        "rule",rule_json m.rule]) c.missing)]) a.coverage]
let authorization_json a = I.json (authorization_value a)

type outcome = Valid_change | Authorization_failed | Contract_failed | Out_of_scope_regression | Unknown
type t = { outcome : outcome; reason : string; spec : Change_spec.t option;
  before : string; after : string; z3 : string option;
  authorization : authorization option; comparison : Verify.comparison option }
type evaluation = {
  outcome : outcome; frozen_contract : string option;
  before_sha256 : string; after_sha256 : string;
  authorization_allowed : bool option; comparison : Verify.comparison option;
}
let evaluation (t : t) : evaluation = {
  outcome=t.outcome;frozen_contract=Option.map Change_spec.canonical t.spec;
  before_sha256=Sha256.string t.before;after_sha256=Sha256.string t.after;
  authorization_allowed=Option.map (fun a -> a.allowed) t.authorization;
  comparison=t.comparison;
}
let result_name = function Valid_change -> "valid_change" | Authorization_failed -> "authorization_failed"
  | Contract_failed -> "contract_failed" | Out_of_scope_regression -> "out_of_scope_regression" | Unknown -> "unknown"
let invalid_contract reason ~before ~after = {outcome=Unknown;reason;spec=None;before;after;z3=None;authorization=None;comparison=None}
let run ?z3 spec ~before ~after =
  let make outcome reason authorization comparison = {outcome;reason;spec=Some spec;before;after;z3;authorization;comparison} in
  match authorize spec ~before ~after with
  | Error reason -> make Unknown reason None None
  | Ok a when not a.allowed -> make Authorization_failed a.reason (Some a) None
  | Ok a ->
    let comparison = Verify.compare_with_trace ?z3 (Change_spec.requirements spec) ~before ~after in
    let outcome,reason = match comparison.report.result with
      | Proved -> Valid_change,"Authorization checks, frozen access requirements and modeled out-of-scope preservation passed."
      | Unknown reason -> Unknown,reason
      | _ -> (match comparison.candidate_report with
          | Some {result=Proved;_} -> Out_of_scope_regression,"Candidate changes a modeled permission outside the frozen approved scope."
          | _ -> Contract_failed,"Candidate does not satisfy the frozen access requirements.") in
    make outcome reason (Some a) (Some comparison)

let digest source = `O ["sha256",str (Sha256.string source);"bytes",number (String.length source)]
let version (t : t) = Option.fold ~none:1 ~some:Change_spec.version t.spec
let to_json (t : t) = I.json (`O ["schema_version",number (version t);"kind",str Change_spec.kind;
  "result",str (result_name t.outcome);"reason",str t.reason;
  "assurance",`O ["profile",str (profile_id_for_version (version t));"status",str (if t.outcome=Unknown then "unsupported_or_inconclusive" else "within_profile")];
  "frozen_spec",optional (fun spec -> `O ["schema_version",number (Change_spec.version spec);"kind",str Change_spec.kind;
    "canonical",str (Change_spec.canonical spec)]) t.spec;
  "inputs",`O ["before",digest t.before;"after",digest t.after];
  "authorization",optional authorization_value t.authorization;
  "verification",optional (fun (c : Verify.comparison) -> `O ["comparison_report",I.parse (Report.to_json c.report);
    "candidate_report",optional (fun r -> I.parse (Report.to_json r)) c.candidate_report]) t.comparison])
let to_human (t : t) = Printf.sprintf "rbac-policy-change %s [%s]\n%s\n%s"
  (result_name t.outcome) (profile_id_for_version (version t)) t.reason
  (match t.comparison with None -> "Access/preservation verification not executed.\n"
   | Some c -> Report.to_human c.report)
let exit_code (t : t) = match t.outcome with
  | Valid_change -> 0 | Unknown -> 4
  | Contract_failed -> (match t.comparison with Some {report={result=Vacuous;_};_}->5
      | Some {report={result=Inconsistent _;_};_}->6 | _->3)
  | _ -> 3

let evidence_files provenance t =
  let* spec = match t.spec with Some spec -> Ok spec | None -> Error "invalid change contract cannot produce frozen evidence" in
  let* nested = match t.comparison with
    | None -> Ok []
    | Some c ->
      let version = Contract_spec.version (Change_spec.requirements spec) in
      let profile : Evidence.profile = {id=Assurance.id_for_version version;json=Assurance.profile_json ~version ()} in
      let* bundle = Evidence.create_comparison ~before:t.before ~after:t.after ~profile ~provenance
        ~report:c.report ~candidate_report:c.candidate_report ~trace:c.trace in
      Ok (List.map (fun (path,data) -> "verification/"^path,data) (Evidence.files bundle)) in
  let files = ["contract.json",Change_spec.canonical spec^"\n";
    "profile.json",profile_json_for_version (Change_spec.version spec)^"\n";"report.json",to_json t^"\n"] @ nested in
  let manifest = I.json (`O ["schema_version",number (Change_spec.version spec);"kind",str "kubernetes-rbac-policy-change-evidence";
    "inputs",`O ["before",digest t.before;"after",digest t.after];
    "authorization_method",str "deterministic-native-rbac-policy-coverage";
    "verification",str (if t.comparison=None then "not_executed" else "see verification/manifest.json");
    "provenance",`O ["executable_sha256",str provenance.Evidence.executable_sha256;
      "ocaml_version",str provenance.ocaml_version;"z3_version",(match provenance.z3_version with
        | Ok value -> `O ["value",str value] | Error reason -> `O ["error",str reason])];
    "artifacts",`A (List.map (fun (path,data) -> `O ["path",str path;"sha256",str (Sha256.string data);
      "bytes",number (String.length data)]) files)]) in
  Ok (files @ ["manifest.json",manifest^"\n"])

let write_evidence ~directory t =
  let* provenance = Evidence.collect_provenance ?z3:t.z3 () in
  let* files = evidence_files provenance t in
  try
    Unix.mkdir directory 0o700;
    if t.comparison<>None then begin
      Unix.mkdir (Filename.concat directory "verification") 0o700;
      Unix.mkdir (Filename.concat directory "verification/queries") 0o700
    end;
    List.iter (fun (relative,data) ->
      let target = Filename.concat directory relative in
      let manifest = Filename.basename relative="manifest.json" in
      let path = if manifest then target^".tmp" else target in
      let channel = open_out_gen [Open_wronly;Open_creat;Open_excl;Open_binary] 0o600 path in
      Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () -> output_string channel data;close_out channel);
      if manifest then begin Unix.link path target;Unix.unlink path end) files;
    Ok ()
  with Sys_error reason -> Error reason
    | Unix.Unix_error (error,operation,path) -> Error (Printf.sprintf "%s(%s): %s" operation path (Unix.error_message error))
