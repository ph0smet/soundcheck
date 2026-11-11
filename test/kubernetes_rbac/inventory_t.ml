module K = Soundcheck_kubernetes_rbac
open K.Input
let checks = ref 0
let check label condition = incr checks; if not condition then failwith ("inventory: " ^ label)
let ok = function Ok value -> value | Error reason -> failwith reason
let field key = function `O fields -> List.assoc key fields | _ -> failwith "object expected"
let fields = function `O fields -> fields | _ -> failwith "object expected"
let array = function `A values -> values | _ -> failwith "array expected"
let set key value obj = `O ((key,value)::List.remove_assoc key (fields obj))
let remove key obj = `O (List.remove_assoc key (fields obj))
let contains text part =
  let rec loop index = index+String.length part <= String.length text &&
    (String.sub text index (String.length part)=part || loop (index+1)) in loop 0
let list items = `O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items]
let api = "rbac.authorization.k8s.io/v1"
let role ?(kind="Role") ?(ns="apps") name rules =
  `O ["apiVersion",`String api;"kind",`String kind;
    "metadata",`O (["name",`String name] @ if kind="Role" then ["namespace",`String ns] else []);
    "rules",`A rules]
let rule resource = `O ["apiGroups",`A [`String ""];"resources",`A [`String resource];"verbs",`A [`String "get"]]
let user name = `O ["kind",`String "User";"apiGroup",`String group;"name",`String name]
let group_subject name = `O ["kind",`String "Group";"apiGroup",`String group;"name",`String name]
let sa = `O ["kind",`String "ServiceAccount";"name",`String "app"]
let binding ?(kind="RoleBinding") ?(ns="apps") ?(role_kind="Role") name target subjects =
  `O ["apiVersion",`String api;"kind",`String kind;
    "metadata",`O (["name",`String name] @ if kind="RoleBinding" then ["namespace",`String ns] else []);
    "subjects",`A subjects;
    "roleRef",`O ["apiGroup",`String group;"kind",`String role_kind;"name",`String target]]
let local = role "reader" [rule "configmaps"]
let cluster = role ~kind:"ClusterRole" "shared" [rule "secrets"]
let local_binding = binding "local" "reader" [sa;user "alice";group_subject "operators"]
let cluster_binding = binding ~role_kind:"ClusterRole" "cluster" "shared" [group_subject "system:authenticated"]
let source ?(kind="supplied") ?(format="json") id path bytes =
  `O ["id",`String id;"path",`String path;"format",`String format;
    "sha256",`String (Soundcheck_core.Sha256.string bytes);"source_type",`String kind]
let plan sources = `O ["schema_version",`Number "1";"kind",`String "kubernetes-rbac-inventory";"sources",`A sources]
let assemble plan files = K.Inventory.assemble ~load:(fun path -> List.assoc path files) (json plan)
let failed label value = check label (Result.is_error value)
let snapshot = list [local_binding;local;cluster;cluster_binding]
let context groups = `O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
  "identities",`A [`O ["username",`String "system:serviceaccount:apps:app";"groups",`A (List.map (fun g -> `String g) groups)];
    `O ["username",`String "alice";"groups",`A [`String "operators";`String "system:authenticated"]]]]
let contract groups =
  let clause name kind resource = `O ["name",`String name;"kind",`String kind;
    "subject",`String "system:serviceaccount:apps:app";"namespace",`String "apps";
    "resource",`String resource;"names",`Null] in
  `O ["schema_version",`Number "1";"kind",`String "kubernetes-rbac-access";"context",context groups;
    "clauses",`A [clause "required-config" "must_allow" "configmaps";clause "no-secrets" "must_not_grant" "secrets"];
    "change_scope",`A []]

let () =
  let primary = json local_binding in
  let supplemental = json (list [local;cluster;cluster_binding]) in
  let a = source "application" "app.json" primary in
  let b = source ~kind:"bootstrap-reference" "supplement" "supplement.json" supplemental
    |> set "source_version" (`String "v1.34.0") in
  let files = ["app.json",primary;"supplement.json",supplemental] in
  let p = plan [a;b] in
  let reads = ref [] in
  let result = ok (K.Inventory.assemble ~load:(fun path -> reads:=path::!reads;List.assoc path files) (json p)) in
  check "sources loaded once in order" (List.rev !reads=["app.json";"supplement.json"]);
  check "all supplemental objects retained, including unrelated binding" (result.object_count=4 && parse result.snapshot=snapshot);
  check "union is a strict closed snapshot" (Result.is_ok (K.Snapshot.of_string result.snapshot));
  failed "single-source prepare still requires closure" (K.Prepare.of_manifest ~format:K.Manifest_input.Json primary);
  failed "strict verifier reader still requires closure" (K.Snapshot.of_string (json (list [local_binding])));
  check "fragment cannot hide unsupported rules" (Result.is_error (K.Prepare.fragment_of_manifest ~format:K.Manifest_input.Json
    (json (set "aggregationRule" (`O []) local))));
  let receipt = parse result.receipt in
  check "distinct inventory receipt" (field "kind" receipt=`String "rbac-inventory-assembly" && field "schema_version" receipt=`Number "1");
  check "plan bound exactly" (field "sha256" (field "plan" receipt)=`String (Soundcheck_core.Sha256.string (json p)));
  check "snapshot bound exactly including newline" (field "sha256" (field "snapshot" receipt)=`String (Soundcheck_core.Sha256.string result.snapshot));
  List.iter (fun key -> check (key ^ " is false") (field key receipt=`Bool false))
    ["verification_performed";"source_authenticity_established";"completeness_established"];
  check "bootstrap source remains an explicit assumption" (field "assumed_bootstrap_sources" receipt=`A [`String "supplement"]);
  let sources = array (field "sources" receipt) in
  check "version is caller-declared" (field "declared_source_version" (List.nth sources 1)=`String "v1.34.0");
  List.iteri (fun i source ->
    let normalization = field "normalization" source in
    let original = if i=0 then primary else supplemental in
    check "each source digest" (field "sha256" (field "input" normalization)=`String (Soundcheck_core.Sha256.string original));
    check "source is not a stand-alone snapshot receipt" (not (List.mem_assoc "snapshot" (fields normalization)))) sources;
  let objects = array (field "objects" receipt) in
  check "source-to-output order is explicit" (List.map (field "source_id") objects=
    [`String "application";`String "supplement";`String "supplement";`String "supplement"]);
  check "original nested location preserved" (field "source_path" (List.nth objects 3)=`String "documents[0].items[2]");
  check "deterministic repeated assembly" ((ok (assemble p files)).receipt=result.receipt);
  let reversed = ok (assemble (plan [b;a]) files) in
  check "source order reflected in snapshot and receipt" (reversed.snapshot<>result.snapshot && reversed.receipt<>result.receipt);
  check "source order does not change grants" (List.sort compare (K.Snapshot.grants (ok (K.Snapshot.of_string reversed.snapshot)))=
    List.sort compare (K.Snapshot.grants (ok (K.Snapshot.of_string result.snapshot))));
  failed "pin covers comments/whitespace too" (assemble p ["app.json",primary ^ "\n";"supplement.json",supplemental]);
  failed "source hash cannot be omitted" (assemble (plan [remove "sha256" a;b]) files);
  failed "bootstrap version required" (assemble (plan [a;remove "source_version" b]) files);
  failed "zero sources" (assemble (plan []) []);
  failed "duplicate source identifiers" (assemble (plan [a;set "id" (`String "application") b]) files);
  failed "unknown source field" (assemble (plan [set "snapshot_complete" (`Bool true) a;b]) files);
  failed "unknown plan field" (assemble (set "identity" (`O []) p) files);
  let loads = ref 0 in
  failed "bad later descriptor rejected before any read"
    (K.Inventory.assemble ~load:(fun _ -> incr loads;primary) (json (plan [a;set "format" (`String "auto") b])));
  check "no reads on invalid plan" (!loads=0);
  List.iter (fun (key,value) -> failed ("invalid descriptor " ^ key)
    (assemble (plan [set key value a;b]) files))
    ["id",`String "UPPER";"path",`String "bad\000path";"sha256",`String "abc";
     "source_type",`String "automatic";"namespace",`String "UPPER";"rbac_only",`String "true"];
  let duplicate = json (list [local_binding;local]) in
  failed "identical duplicate object across sources"
    (assemble (plan [source "a" "a" duplicate;source "b" "b" duplicate]) ["a",duplicate;"b",duplicate]);
  let refs = list [local_binding;binding ~ns:"other" "second" "reader" [user "alice"];cluster_binding] in
  let missing = ok (K.Snapshot.unresolved_references (json refs)) in
  check "all missing refs reported" (List.length missing=3);
  check "missing reference namespace and target are exact"
    (List.map (fun (r:K.Snapshot.missing_reference) -> r.binding_index,r.binding_label,r.role_label) missing=
      [0,"RoleBinding/apps/local","Role/apps/reader";1,"RoleBinding/other/second","Role/other/reader";
       2,"RoleBinding/apps/cluster","ClusterRole/shared"]);
  let bytes = json refs in
  let error = match assemble (plan [source "refs" "refs.json" bytes]) ["refs.json",bytes] with
    | Error reason -> reason | Ok _ -> failwith "unexpected resolved refs" in
  List.iter (fun text -> check ("diagnostic contains " ^ text) (contains error text))
    ["source refs documents[0].items[0]";"source refs documents[0].items[1]";
     "source refs documents[0].items[2]";"Role/other/reader";"ClusterRole/shared"];
  let yaml = {|apiVersion: rbac.authorization.k8s.io/v1
kind: RoleList
items:
  - metadata: {name: reader, uid: discarded}
    rules: [{apiGroups: [""], resources: [configmaps], verbs: [get]}]
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: app}
|} in
  let descriptor = source ~format:"yaml" "roles" "roles.yaml" yaml |> set "namespace" (`String "apps") |> set "rbac_only" (`Bool true) in
  let mixed = ok (assemble (plan [a;descriptor]) ["app.json",primary;"roles.yaml",yaml]) in
  check "mixed JSON/YAML and explicit namespace" (mixed.object_count=2);
  let normalized = field "normalization" (List.nth (array (field "sources" (parse mixed.receipt))) 1) in
  check "source defaults preserved" (List.length (array (field "defaulted_fields" normalized))=3);
  check "excluded non-RBAC accounted" (List.length (array (field "excluded_objects" normalized))=1);
  check "metadata removals use source paths" (field "removed_fields" normalized=`A [`String "documents[0].items[0].metadata.uid"]);
  failed "selection not silently enabled" (assemble (plan [a;remove "rbac_only" descriptor]) ["app.json",primary;"roles.yaml",yaml]);
  let with_extra_rules = list [local;cluster;local_binding;cluster_binding;
    role "empty" [];binding "empty-binding" "empty" [user "alice"];
    role "other-api" [`O ["apiGroups",`A [`String "authentication.k8s.io"];
      "resources",`A [`String "tokenreviews"];"verbs",`A [`String "create"]]];
    binding "other-api-binding" "other-api" [user "alice"]] |> json in
  let inspect groups = K.Inspect.run ~snapshot:with_extra_rules ~contract:(json (contract groups)) |> ok |> parse in
  let report = inspect [] in
  check "inspection protocol" (field "kind" report=`String "rbac-identity-inspection");
  List.iter (fun key -> check ("inspection " ^ key ^ " false") (field key report=`Bool false))
    ["verification_performed";"authorization_evaluated";"identity_authentication_established";"completeness_established"];
  check "completeness is only a contract assertion" (field "snapshot_completeness_asserted_by_contract" report=`Bool true);
  let identities = array (field "identities" report) in
  let workload = List.find (fun i -> field "username" i=`String "system:serviceaccount:apps:app") identities in
  check "no authentication/service-account groups inferred" (field "groups" workload=`A []);
  let matches identity = array (field "subject_matching_bindings" identity) in
  check "only exact SA subject matches for empty groups" (List.map (field "binding") (matches workload)=[`String "RoleBinding/apps/local"]);
  let alice = List.find (fun i -> field "username" i=`String "alice") identities in
  check "empty/out-of-domain rules remain visible as subject matches" (List.length (matches alice)=4);
  check "empty role is not labeled a grant" (field "rule_count" (List.nth (matches alice) 2)=`Number "0");
  check "multiple matching subjects retained" (List.length (array (field "matching_subjects" (List.hd (matches alice))))=2);
  let changed = inspect ["system:authenticated"] in
  check "contract group change changes canonical identity" (field "canonical_contract_sha256" changed<>field "canonical_contract_sha256" report);
  let workload2 = List.find (fun i -> field "username" i=`String "system:serviceaccount:apps:app") (array (field "identities" changed)) in
  check "explicit group adds matching binding" (List.length (matches workload2)=2);
  check "raw contract hash bound" (field "sha256" (field "contract" report)=`String (Soundcheck_core.Sha256.string (json (contract []))));
  check "raw snapshot hash bound" (field "sha256" (field "snapshot" report)=`String (Soundcheck_core.Sha256.string with_extra_rules));
  check "canonical hash recomputable" (match field "canonical_contract" report with `String c ->
    field "canonical_contract_sha256" report=`String (Soundcheck_core.Sha256.string c) | _ -> false);
  failed "inspection does not permit missing roles" (K.Inspect.run ~snapshot:(json refs) ~contract:(json (contract [])));
  failed "inspection does not permit incomplete context" (K.Inspect.run ~snapshot:with_extra_rules
    ~contract:(json (set "context" (set "snapshot_complete" (`Bool false) (context [])) (contract []))));
  Printf.printf "RBAC inventory and inspection: %d checks passed.\n" !checks
