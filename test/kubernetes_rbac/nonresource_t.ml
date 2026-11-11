module K = Soundcheck_kubernetes_rbac
open K.Input
open Soundcheck_core

let checks = ref 0
let check label condition = incr checks; if not condition then failwith ("nonresource: " ^ label)
let ok = function Ok value -> value | Error reason -> failwith reason
let fields = function `O fields -> fields | _ -> failwith "expected object"
let field name value = List.assoc name (fields value)
let array = function `A values -> values | _ -> failwith "expected array"
let set key value obj = `O ((key,value)::List.remove_assoc key (fields obj))
let remove key obj = `O (List.remove_assoc key (fields obj))
let rec normalize = function
  | `O fields -> `O (List.map (fun (k,v) -> k,normalize v) fields |> List.sort compare)
  | `A values -> `A (List.map normalize values)
  | value -> value
let strings values = `A (List.map (fun value -> `String value) values)
let snapshot items = `O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items]
let role ?(kind="ClusterRole") rules = `O ["apiVersion",`String api_version;"kind",`String kind;
  "metadata",`O (["name",`String "policy"] @ if kind="Role" then ["namespace",`String "apps"] else []);
  "rules",`A rules]
let binding ?(kind="ClusterRoleBinding") ?(role_kind="ClusterRole") () =
  `O ["apiVersion",`String api_version;"kind",`String kind;
    "metadata",`O (["name",`String "binding"] @ if kind="RoleBinding" then ["namespace",`String "apps"] else []);
    "subjects",`A [`O ["kind",`String "User";"apiGroup",`String group;"name",`String "alice"]];
    "roleRef",`O ["apiGroup",`String group;"kind",`String role_kind;"name",`String "policy"]]
let url urls = `O ["verbs",strings ["*"];"nonResourceURLs",strings urls]
let resource = `O ["verbs",strings ["*"];"apiGroups",strings [""];"resources",strings ["configmaps"]]
let bytes rules = json (snapshot [role rules;binding ()])
let supported value = Result.is_ok (K.Snapshot.of_string (json value))
let contract version =
  let clause name kind resource = `O (["name",`String name;"kind",`String kind;
    "subject",`String "alice";"namespace",`String "apps";"resource",`String resource;"names",`Null]
    @ if version=1 then [] else ["verb",`String "get"]) in
  json (`O ["schema_version",`Number (string_of_int version);"kind",`String "kubernetes-rbac-access";
    "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
      "identities",`A [`O ["username",`String "alice";"groups",strings []]]];
    "clauses",`A [clause "config-required" "must_allow" "configmaps";
      clause "secrets-not-granted" "must_not_grant" "secrets"];"change_scope",`A []])
let request ?(namespace="apps") ?(verb="get") ?(resource="configmaps") ?(name="settings") () =
  `O ["id",`String "probe";"username",`String "alice";"groups",strings [];"verb",`String verb;
    "apiGroup",`String "";"resource",`String resource;"namespace",`String namespace;"name",`String name;
    "subresource",`String "";"resourceRequest",`Bool true]
let grants spec source req =
  let policy = K.Lower.policy spec (ok (K.Snapshot.of_string source)) in
  let requests = K.Evaluate.requests spec (json (`A [req])) |> ok in
  let result = K.Evaluate.decisions policy requests in
  array result |> List.hd |> field "grants" |> array

let () =
  (* Literal validation expectations come from pinned ValidatePolicyRule:
     URL string syntax is not checked; array lengths select the native domain. *)
  List.iter (fun urls ->
    check "arbitrary native URL strings accepted" (supported (snapshot [role [url urls]])))
    [["*"];["/*"];["/version"];["/foo**"];["/foo*bar"];["version"];[""];["/x\000suffix"];["/版本"];["/x";"/x"]];
  List.iter (fun verb -> check "literal URL verb retained" (supported (snapshot [role [set "verbs" (strings [verb]) (url ["*"])]])))
    ["get";"GET";"";"custom";"get\000suffix"];
  List.iter (fun optional ->
    let rule = List.fold_left (fun rule key -> set key optional rule) (url ["*"]) ["apiGroups";"resources";"resourceNames"] in
    check "empty or null resource lists in URL rule" (supported (snapshot [role [rule]]))) [`A [];`Null];
  List.iter (fun value ->
    List.iter (fun kind -> check "empty URLs are still resource permissions"
      (supported (snapshot [role ~kind [set "nonResourceURLs" value resource]]))) ["Role";"ClusterRole"])
    [`A [];`Null];
  let invalid label rule = check label (not (supported (snapshot [role [rule]]))) in
  List.iter (fun key ->
    List.iter (fun value -> invalid ("mixed nonempty " ^ key) (set key value (url ["*"])))
      [strings [""];strings ["*"];strings ["secrets"]];
    List.iter (fun value -> invalid ("malformed unused " ^ key) (set key value (url ["*"])))
      [`String "";`Bool false;`A [`Null];`O []]) ["apiGroups";"resources";"resourceNames"];
  List.iter (fun value -> invalid "missing/empty verbs" (set "verbs" value (url ["*"]))) [`Null;`A [];`String "get"];
  invalid "absent verbs" (remove "verbs" (url ["*"]));
  List.iter (fun value -> invalid "malformed URLs" (set "nonResourceURLs" value (url ["*"])))
    [`String "*";`Number "1";`A [`Null];`A [`Number "0"]];
  invalid "unknown URL rule field" (set "future" `Null (url ["*"]));
  List.iter (fun value -> invalid "empty URL list cannot replace missing resource fields" (set "nonResourceURLs" value (url ["*"])))
    [`Null;`A []];
  check "unbound namespaced URL rule rejected" (not (supported (snapshot [role ~kind:"Role" [url ["*"]]])));
  check "RoleBinding to mixed ClusterRole is supported" (supported (snapshot [role [url ["*"];resource];binding ~kind:"RoleBinding" ()]));
  let baseline = bytes [resource] and mixed = bytes [url ["*"];resource;url ["/version"]] in
  List.iter (fun version ->
    let spec = ok (K.Contract_spec.of_string (contract version)) in
    let verified = K.Verify.run spec mixed in
    check "all existing contracts accept separated URL rules" (verified.result=Report.Proved);
    check "revised profile identifies new boundary" ((Option.get verified.assurance).profile=K.Assurance.id_for_version version
      && String.ends_with ~suffix:"-v2" (Option.get verified.assurance).profile);
    check "URL-only grants cannot satisfy resource must_allow" (match (K.Verify.run spec (bytes [url ["*"]])).result with
      | Report.Violated _ -> true | _ -> false);
    let compared = K.Verify.compare_with_trace spec ~before:baseline ~after:mixed in
    check "inserting URL rules preserves resource decisions" (compared.report.result=Report.Proved);
    let swapped = bytes [url ["/different"];resource] in
    check "changing URL policy is outside resource preservation"
      ((K.Verify.compare_with_trace spec ~before:mixed ~after:swapped).report.result=Report.Proved);
    check "original resource rule index preserved" (grants spec mixed (request ())=
      [`String "ClusterRoleBinding/binding -> ClusterRole/policy/rules/1"]);
    check "two resource slots separated by URL retain source indices"
      (grants spec (bytes [resource;url ["*"];resource]) (request ())=
        [`String "ClusterRoleBinding/binding -> ClusterRole/policy/rules/0";
         `String "ClusterRoleBinding/binding -> ClusterRole/policy/rules/2"]);
    check "URL wildcard supplies no secret grant" (grants spec mixed (request ~resource:"secrets" ())=[]);
    List.iter (fun empty ->
      let wildcard = resource |> set "resources" (strings ["*"]) |> set "nonResourceURLs" empty in
      let unsafe = bytes [url ["*"];wildcard] in
      check "resource wildcard is not erased by empty URL field" (grants spec unsafe (request ~resource:"secrets" ())<>[]);
      check "resource wildcard still violates safety" (match (K.Verify.run spec unsafe).result with Report.Violated _ -> true | _ -> false))
      [`A [];`Null];
    let local = json (snapshot [role [url ["*"];resource];binding ~kind:"RoleBinding" ()]) in
    check "local binding retains namespace scope" (grants spec local (request ())<>[] && grants spec local (request ~namespace:"other" ())=[]);
    let nonresource = request () |> set "resourceRequest" (`Bool false) in
    check "nonresource request adapter still rejects" (Result.is_error (K.Evaluate.requests spec (json (`A [nonresource]))));
    let inspection = K.Inspect.run ~snapshot:mixed ~contract:(contract version) |> ok |> parse in
    let subject_matches = field "identities" inspection |> array |> List.hd |> field "subject_matching_bindings" |> array in
    check "inspection counts every source rule" (field "rule_count" (List.hd subject_matches)=`Number "3");
    check "inspection does not evaluate URL authorization" (field "authorization_evaluated" inspection=`Bool false);
    let profile = parse (K.Assurance.profile_json ~version ()) in
    check "profile JSON schema unchanged" (field "schema_version" profile=`Number (if version=1 then "1" else "2"))) [1;2;3;4];
  let with_metadata = snapshot [(role [url ["*";"/x\000suffix"];resource] |> fun role ->
    set "metadata" (set "uid" (`String "bookkeeping") (field "metadata" role)) role);binding ()] in
  let source = json with_metadata in
  let expected = snapshot [role [url ["*";"/x\000suffix"];resource];binding ()] in
  let prepared = K.Prepare.of_string source |> ok in
  check "JSON preparation retains complete URL policy" (normalize (parse prepared.snapshot)=normalize expected);
  let manifest = K.Prepare.of_manifest ~format:K.Manifest_input.Json source |> ok |> K.Prepare.manifest_snapshot in
  check "manifest preparation retains complete URL policy" (normalize (parse manifest.snapshot)=normalize expected);
  let yaml = {|apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: discovery}
rules:
  - verbs: [get]
    nonResourceURLs: ["*", "/version"]
|} in
  let prepared_yaml = K.Prepare.of_manifest ~format:K.Manifest_input.Yaml yaml |> ok |> K.Prepare.manifest_snapshot in
  let item = field "items" (parse prepared_yaml.snapshot) |> array |> List.hd in
  check "YAML URL fields survive" (field "nonResourceURLs" (field "rules" item |> array |> List.hd)=strings ["*";"/version"]);
  let descriptor = `O ["id",`String "source";"path",`String "in.json";"format",`String "json";
    "sha256",`String (Sha256.string source);"source_type",`String "supplied"] in
  let plan = json (`O ["schema_version",`Number "1";"kind",`String "kubernetes-rbac-inventory";"sources",`A [descriptor]]) in
  let inventory = K.Inventory.assemble ~load:(fun _ -> source) plan |> ok in
  check "inventory retains URL rules" (normalize (parse inventory.snapshot)=normalize expected);
  check "inventory receipt binds full policy" (field "sha256" (field "snapshot" (parse inventory.receipt))=`String (Sha256.string inventory.snapshot));
  Printf.printf "RBAC nonresource coexistence: %d checks passed.\n" !checks
