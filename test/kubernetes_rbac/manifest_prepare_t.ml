module K = Soundcheck_kubernetes_rbac
module M = K.Manifest_input
open K.Input

let checks = ref 0
let check label value = incr checks; if not value then failwith ("manifest preparation: " ^ label)
let ok = function Ok value -> value | Error reason -> failwith reason
let fields = function `O fields -> fields | _ -> failwith "expected object"
let field name value = List.assoc name (fields value)
let array = function `A values -> values | _ -> failwith "expected array"
let set key value obj = `O ((key,value) :: List.remove_assoc key (fields obj))
let remove key obj = `O (List.remove_assoc key (fields obj))
let rec ordered = function
  | `O fields -> `O (List.sort compare (List.map (fun (k,v) -> k,ordered v) fields))
  | `A values -> `A (List.map ordered values) | v -> v
let api = "rbac.authorization.k8s.io/v1"
let role = `O ["apiVersion",`String api;"kind",`String "Role";
  "metadata",`O ["name",`String "reader";"namespace",`String "team-a"];
  "rules",`A [`O ["verbs",`A [`String "get";`String "list"];
    "apiGroups",`A [`String ""];"resources",`A [`String "configmaps"];"resourceNames",`A [`String "settings"]]]]
let binding = `O ["apiVersion",`String api;"kind",`String "RoleBinding";
  "metadata",`O ["name",`String "reader";"namespace",`String "team-a"];
  "subjects",`A [`O ["kind",`String "ServiceAccount";"name",`String "app"]];
  "roleRef",`O ["apiGroup",`String "rbac.authorization.k8s.io";"kind",`String "Role";"name",`String "reader"]]
let list ?(kind="List") items = `O ["apiVersion",`String (if kind="List" then "v1" else api);
  "kind",`String kind;"items",`A items]
let raw value = value |> remove "apiVersion" |> remove "kind"
let no_namespace obj = set "metadata" (remove "namespace" (field "metadata" obj)) obj
let workload = `O ["apiVersion",`String "apps/v1";"kind",`String "Deployment";
  "metadata",`O ["name",`String "app"];"spec",`O ["replicas",`Number "2"]]
let yaml_role = {|apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: reader
  namespace: team-a
rules:
  - verbs: [get, list]
    apiGroups: [""]
    resources: [configmaps]
    resourceNames: [settings]
|}
let prepare ?namespace ?rbac_only ?(format=M.Json) value =
  K.Prepare.of_manifest ~format ?namespace ?rbac_only value
let receipt value = parse (K.Prepare.manifest_receipt_json value)
let snapshot value = (K.Prepare.manifest_snapshot value).snapshot |> parse
let reject label ?namespace ?rbac_only ?format source =
  check label (Result.is_error (prepare ?namespace ?rbac_only ?format source))
let reject_json label ?namespace ?rbac_only value = reject label ?namespace ?rbac_only (json value)
let scalar token = protect (fun () -> M.parse M.Yaml ("value: " ^ token ^ "\n"))
let scalar_is token value = check ("scalar " ^ token)
  (scalar token = Ok [Some (`O ["value",value])])

let () =
  let source = yaml_role ^ "---\n" ^ json binding ^ "\n" in
  let prepared = ok (prepare ~format:M.Yaml source) in
  let expected = list [role;binding] in
  check "full stream retains role and binding" (ordered (snapshot prepared) = ordered expected);
  let grants = K.Snapshot.grants (ok (K.Snapshot.of_string (K.Prepare.manifest_snapshot prepared).snapshot)) in
  check "SA subject namespace uses effective RoleBinding namespace"
    (match grants with [{binding={subjects=[K.Snapshot.Service_account ("team-a","app")];_};_}] -> true | _ -> false);
  let r = receipt prepared in
  check "receipt schema 2" (field "schema_version" r = `Number "2");
  check "format and documents" (field "input_format" r = `String "yaml" && field "document_count" r = `Number "2");
  check "input hash exact bytes" (field "sha256" (field "input" r) = `String (Soundcheck_core.Sha256.string source));
  check "output hash exact bytes" (field "sha256" (field "snapshot" r) = `String (Soundcheck_core.Sha256.string (K.Prepare.manifest_snapshot prepared).snapshot));
  check "unconditional negative assurance" (field "verification_performed" r=`Bool false && field "completeness_established" r=`Bool false);
  check "receipt complete retained inventory" (field "retained_objects" r = `A [
    `O ["source_path",`String "documents[0]";"snapshot_index",`Number "0"];
    `O ["source_path",`String "documents[1]";"snapshot_index",`Number "1"]]);
  check "normalization deterministic" (K.Prepare.manifest_receipt_json prepared =
    K.Prepare.manifest_receipt_json (ok (prepare ~format:M.Yaml source)));
  check "default strict reader still rejects YAML" (Result.is_error (K.Prepare.of_string source));
  check "default strict reader still rejects single object" (Result.is_error (K.Prepare.of_string (json role)));
  let single = ok (prepare (json role)) in
  check "explicit JSON object" (ordered (snapshot single) = ordered (list [role]));
  List.iter (fun kind ->
    let base = if kind="Role" || kind="ClusterRole" then role else binding in
    let base = set "kind" (`String kind) base in
    let base = if String.starts_with ~prefix:"Cluster" kind then no_namespace base else base in
    let base = if kind="ClusterRoleBinding" then
      set "subjects" (`A [`O ["kind",`String "ServiceAccount";"name",`String "app";"namespace",`String "team-a"]])
        (set "roleRef" (set "kind" (`String "ClusterRole") (field "roleRef" base)) base) else base in
    let typed item = list ~kind:(kind ^ "List") [item] in
    let supporting = match kind with
      | "RoleBinding" -> [role]
      | "ClusterRoleBinding" -> [set "kind" (`String "ClusterRole") (no_namespace role)]
      | _ -> [] in
    let input item = list (supporting @ [typed item]) in
    let prepared = ok (prepare (json (input (raw base)))) in
    check (kind ^ " inferred GVK") (ordered (snapshot prepared) = ordered (list (supporting @ [base])));
    check (kind ^ " default paths recorded") (List.length (array (field "defaulted_fields" (receipt prepared))) = 2);
    check (kind ^ " explicit GVK") (Result.is_ok (prepare (json (input base))));
    check (kind ^ " empty GVK pair") (Result.is_ok (prepare (json (input (raw base |> set "kind" (`String "") |> set "apiVersion" (`String ""))))));
    List.iter (fun item -> reject_json (kind ^ " partial/conflicting type") (input item))
      [remove "kind" base;remove "apiVersion" base;set "kind" `Null base;
       set "kind" (`String "SomethingElse") base;set "apiVersion" (`String "v1") base]
  ) ["Role";"ClusterRole";"RoleBinding";"ClusterRoleBinding"];
  let typed = list ~kind:"RoleList" [raw (no_namespace role)] in
  let nested = list [typed;list ~kind:"RoleBindingList" [raw (no_namespace binding)];workload] in
  reject_json "projection must be explicit" ~namespace:"team-a" nested;
  let prepared = ok (prepare ~namespace:"team-a" ~rbac_only:true (json nested)) in
  check "typed/default/project normalization" (ordered (snapshot prepared) = ordered expected);
  let r = receipt prepared in
  check "defaulting context receipt" (field "namespace_context" r=`String "team-a" && field "selection" r=`String "rbac-only");
  check "each type and namespace default recorded" (List.length (array (field "defaulted_fields" r))=6);
  check "each wrapper recorded" (List.length (array (field "list_wrappers" r))=3);
  check "excluded object receipt" (field "excluded_objects" r=`A [`O ["source_path",`String "documents[0].items[2]";
    "apiVersion",`String "apps/v1";"kind",`String "Deployment"]]);
  check "excluded count" (K.Prepare.manifest_excluded_count prepared=1);
  let explicit = ok (prepare ~namespace:"elsewhere" (json expected)) in
  check "namespace defaults never override explicit namespaces" (ordered (snapshot explicit)=ordered expected);
  check "unused namespace still recorded" (field "namespace_context" (receipt explicit)=`String "elsewhere");
  let empty_ns = no_namespace role |> set "metadata" (set "namespace" (`String "") (field "metadata" role)) in
  check "explicit empty namespace default" (ordered (snapshot (ok (prepare ~namespace:"team-a" (json empty_ns))))=ordered (list [role]));
  reject_json "namespace requires context" (no_namespace role);
  reject_json "invalid namespace context" ~namespace:"UPPER" role;
  reject_json "null namespace is not absence" ~namespace:"team-a" (set "metadata" (set "namespace" `Null (field "metadata" role)) role);
  reject_json "cluster scoped namespace remains unsupported" ~namespace:"team-a" (set "kind" (`String "ClusterRole") role);
  reject_json "defaulting can expose duplicate identity" ~namespace:"team-a" (list [role;no_namespace role]);
  reject_json "no projected RBAC is an error" ~rbac_only:true workload;
  reject_json "empty List is not a selected inventory" (list []);
  reject_json "top-level array" (`A [role]);
  reject_json "generic items cannot infer GVK" (list [raw role]);
  reject_json "unresolved roleRef" binding;
  reject_json "unbound malformed URL rule still rejected" (set "rules" (`A [`O ["nonResourceURLs",`A [`String "*"]]]) role);
  reject_json "aggregation not removed" (set "aggregationRule" (`O []) role);
  List.iter (fun obj -> reject_json "RBAC cannot be projected away" ~rbac_only:true (list [role;obj]))
    [set "apiVersion" (`String "rbac.authorization.k8s.io/v1beta1") role;
     set "apiVersion" (`String "example.com/v1") role;
     set "kind" (`String "Rol") role;set "kind" (`String "Rolelist") role];
  List.iter (fun obj -> reject_json "unknown List cannot hide children" ~rbac_only:true (list [role;obj]))
    [set "apiVersion" (`String "v1") (list ~kind:"PodList" [role]);
     `O ["apiVersion",`String "example.com/v1";"kind",`String "BundleList";"items",`A [role]];
     `O ["apiVersion",`String "example.com/v1";"kind",`String "Bundle";"items",`A [role]];
     set "items" `Null workload];
  List.iter (fun metadata -> reject_json "nested pagination cannot disappear" (list [set "metadata" metadata typed]))
    [`O ["continue",`String "next"];`O ["remainingItemCount",`Number "1"];`Null;`O ["unknown",`String "value"]];
  let meta = field "metadata" role |> set "creationTimestamp" (`String "2026-11-10T10:11:12Z")
    |> set "generation" (`Number "9007199254740993") in
  let removed = ok (prepare (json (set "metadata" meta role))) |> receipt in
  check "source removal paths" (field "removed_fields" removed=`A [
    `String "documents[0].metadata.creationTimestamp";`String "documents[0].metadata.generation"]);
  List.iter (fun (key,value) -> reject_json "active lifecycle metadata rejected"
    (set "metadata" (set key value meta) role))
    ["managedFields",`A [`O []];"finalizers",`A [`String "cleanup"];
     "ownerReferences",`A [`O []];"deletionTimestamp",`String "2026-11-10T10:11:12Z"];
  List.iter (fun token -> scalar_is token (`Bool true)) ["y";"Y";"yes";"Yes";"YES";"true";"True";"TRUE";"on";"On";"ON"];
  List.iter (fun token -> scalar_is token (`Bool false)) ["n";"N";"no";"No";"NO";"false";"False";"FALSE";"off";"Off";"OFF"];
  List.iter (fun token -> scalar_is token `Null) ["";"~";"null";"Null";"NULL"];
  List.iter (fun token -> scalar_is token (`Number token)) ["0";"1";"-1";"9007199254740993";"9223372036854775807";"-9223372036854775808"];
  List.iter (fun token -> scalar_is token (`String token)) ["yeS";"TruE";"NULLify";"100m";"1Gi";"1.2.3";"system:masters";"2026-11-10";"2026-11-10T10:11:12Z"];
  List.iter (fun token ->
    check ("unsupported numeric " ^ token) (Result.is_error (scalar token));
    scalar_is ("\"" ^ token ^ "\"") (`String token))
    ["-0";"01";"+1";"1_000";"1__0";"1e3";".5";"1.";"0.1";"1E+4";"0x10";"0XFF";"0o10";"0b10";
     "0b-1";"0b+1";"0b_+_1";
     ".nan";".Inf";"-.inf";"+.INF";"9223372036854775808";"-9223372036854775809";"1000000000000000000000000000000000000"];
  scalar_is "'yes'" (`String "yes");scalar_is "|\n  yes" (`String "yes\n");
  scalar_is ">\n  a\n  b" (`String "a b\n");
  scalar_is "\"a\\\\0b\"" (`String "a\\0b");scalar_is "'a\\0b'" (`String "a\\0b");
  scalar_is "\"\\x5c0\"" (`String "\\0");scalar_is "\"\\u005cu0000\"" (`String "\\u0000");
  scalar_is "\"a\\\n  b\"" (`String "ab");
  List.iter (fun suffix -> reject "whole stream validated before projection" ~format:M.Yaml ~rbac_only:true (yaml_role ^ "---\n" ^ suffix))
    ["broken: [";"kind: Pod\nkind: Role\n";"value: &a [get]\n";"value: *a\n";"value: !!str yes\n";
     "value: {<<: {a: b}}\n";"value: {name: a, \"\\u006eame\": b}\n";
     "value: {yes: a}\n";"value: {12: a}\n";"value: {null: a}\n";
     "apiVersion: v1\nkind: Pod\nspec: {value: 0.1}\n";"value: \"a\\0b\"\n";"value: a\000b\n"];
  List.iter (fun escape -> List.iter (fun prefix ->
    let source = prefix ^ "value: \"before" ^ escape ^ "after\"\n" in
    check "NUL source spans, Unicode, BOM, CRLF" (Result.is_error (protect (fun () -> M.parse M.Yaml source))))
      ["";"# café 😀\n";"\239\187\191";"# comment\r\n"])
    ["\\0";"\\x00";"\\u0000";"\\U00000000"];
  check "UTF8 BOM safe quoted source" (protect (fun () -> M.parse M.Yaml "\239\187\191value: \"yes\"\n")=Ok [Some (`O ["value",`String "yes"])]);
  check "Unicode before escaped backslash" (protect (fun () -> M.parse M.Yaml "# café 😀\nvalue: \"a\\\\0b\"\n")=Ok [Some (`O ["value",`String "a\\0b"])]);
  List.iter (fun source -> check "quoted key and escaped quote NUL guards"
    (Result.is_error (protect (fun () -> M.parse M.Yaml source))))
    ["\"key\\0suffix\": value\n";"value: \"a\\\"b\\0suffix\"\n";
     "value: \"a\\\\\\0suffix\"\n";"value: \"a\\\n  b\\0suffix\"\n";
     "\239\187\191# café 😀\nvalue: \"a\\0suffix\"\n";
     "# before\194\133value: \"a\\0suffix\"\n";
     "# before\226\128\168value: \"a\\0suffix\"\n"];
  List.iter (fun escape -> check "invalid Unicode escape" (Result.is_error (scalar escape)))
    ["\"\\uD800\"";"\"\\uDC00\"";"\"\\U00110000\"";"\"\\u00ZZ\""];
  check "YAML 1.1 directive accepted" (Result.is_ok (prepare ~format:M.Yaml ("%YAML 1.1\n---\n" ^ yaml_role)));
  let native_metadata = String.concat "\n" ["apiVersion: rbac.authorization.k8s.io/v1";"kind: Role";
    "metadata:";"  name: reader";"  namespace: team-a";"  creationTimestamp: 2026-11-10T10:11:12Z";
    "  generation: 9007199254740993";"rules: []";""] in
  let native = ok (prepare ~format:M.Yaml native_metadata) in
  check "native YAML timestamp/large int metadata removed exactly" (field "removed_fields" (receipt native)=
    `A [`String "documents[0].metadata.creationTimestamp";`String "documents[0].metadata.generation"]);
  let documents count = "---\n" ^ String.concat "---\n" (List.init count (fun _ -> "# empty\n")) in
  check "document limit accepted" (Result.is_ok (protect (fun () -> M.parse M.Yaml (documents 4096))));
  check "document limit rejected" (Result.is_error (protect (fun () -> M.parse M.Yaml (documents 4097))));
  let nested count = String.make count '[' ^ "x" ^ String.make count ']' in
  check "nesting at limit" (Result.is_ok (protect (fun () -> M.parse M.Yaml (nested 128))));
  check "nesting above limit" (Result.is_error (protect (fun () -> M.parse M.Yaml (nested 129))));
  let many_nodes count = "[" ^ String.concat "," (List.init count (fun _ -> "x")) ^ "]" in
  check "node count at limit" (Result.is_ok (protect (fun () -> M.parse M.Yaml (many_nodes 249999))));
  check "node count above limit" (Result.is_error (protect (fun () -> M.parse M.Yaml (many_nodes 250000))));
  List.iter (fun source -> reject "unsupported encoding/directive/depth" ~format:M.Yaml source)
    ["\255\254a\000";"# \192\175\n" ^ yaml_role;"%YAML 1.2\n---\n" ^ yaml_role;
     "%YAML 1.3\n---\n" ^ yaml_role;"x: " ^ String.make 130 '[' ^ String.make 130 ']' ^ "\n"];
  let empty = ok (prepare ~format:M.Yaml ("---\n# empty\n---\n" ^ yaml_role ^ "---\n# trailing\n")) |> receipt in
  check "empty docs accounted" (field "empty_documents" empty=`A [`String "documents[0]";`String "documents[2]"]);
  let preamble = ok (prepare ~format:M.Yaml ("# preamble, not a document\n---\n" ^ yaml_role)) |> receipt in
  check "comments before first explicit document are a preamble" (field "document_count" preamble=`Number "1"
    && field "empty_documents" preamble=`A []);
  List.iter (fun value -> reject "explicit null/empty string document is not empty" ~format:M.Yaml
    (yaml_role ^ "---\n" ^ value ^ "\n")) ["null";"~";"\"\"";"[]"];
  reject "comment-only stream has no inventory" ~format:M.Yaml "# empty\n";
  reject "JSON never silently falls back to YAML" ~format:M.Json yaml_role;
  reject "JSON trailing document" (json role ^ "\n---\n" ^ json role);
  Printf.printf "RBAC manifest preparation: %d checks passed.\n" !checks
