module K = Soundcheck_kubernetes_rbac
open K.Input

let checks = ref 0
let check name yes = incr checks; if not yes then failwith ("bootstrap: " ^ name)
let ok = function Ok value -> value | Error reason -> failwith reason
let field name = function `O xs -> List.assoc name xs | _ -> failwith "object expected"
let array = function `A xs -> xs | _ -> failwith "array expected"
let fields = function `O xs -> xs | _ -> failwith "object expected"
let obj_list items = `O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items]
let hash bytes = Soundcheck_core.Sha256.string bytes
let metadata item = field "metadata" item
let name item = field "name" (metadata item)
let kind item = field "kind" item
let prepare packs = K.Bootstrap.prepare ~kubernetes_version:"1.34.0" ~packs
let failed label value = check label (Result.is_error value)
let contains text needle =
  let rec at i = i+String.length needle <= String.length text &&
    (String.sub text i (String.length needle)=needle || at (i+1)) in at 0
let source id file bytes source_type = `O ["id",`String id;"path",`String file;
  "format",`String "json";"sha256",`String (hash bytes);"source_type",`String source_type;
  "source_version",`String "1.34.0"]
let assemble application supplement =
  let plan = json (`O ["schema_version",`Number "1";"kind",`String "kubernetes-rbac-inventory";
    "sources",`A [source "application" "app.json" application "supplied";
      source "bootstrap" "bootstrap.json" supplement "bootstrap-reference"]]) in
  K.Inventory.assemble ~load:(function "app.json" -> application | "bootstrap.json" -> supplement | _ -> assert false) plan
let binding target = `O ["apiVersion",`String "rbac.authorization.k8s.io/v1";"kind",`String "RoleBinding";
  "metadata",`O ["name",`String "app-reader";"namespace",`String "apps"];
  "subjects",`A [`O ["kind",`String "ServiceAccount";"name",`String "frontend";"namespace",`String "apps"]];
  "roleRef",`O ["apiGroup",`String "rbac.authorization.k8s.io";"kind",`String "ClusterRole";"name",`String target]]
let extra_role name labels = `O ["apiVersion",`String "rbac.authorization.k8s.io/v1";"kind",`String "ClusterRole";
  "metadata",`O ["name",`String name;"labels",`O labels];
  "rules",`A [`O ["apiGroups",`A [`String ""];"resources",`A [`String "secrets"];"verbs",`A [`String "get"]]]]

let () =
  check "exact version" (K.Bootstrap.kubernetes_version="1.34.0");
  check "explicit four packs" (K.Bootstrap.available_packs=
    ["auth-delegator";"cluster-admin";"extension-apiserver-authentication-reader";"view"]);
  failed "no implicit all selection" (prepare []);
  List.iter (fun packs -> failed "invalid selection" (prepare packs))
    [["view";"view"];["cluster-admin";"view";"cluster-admin"];["unknown"];["*"];[""];["View"];
     ["view";"view";"view";"view";"view"]];
  List.iter (fun version -> failed ("unsupported version " ^ version)
    (K.Bootstrap.prepare ~kubernetes_version:version ~packs:["view"]))
    ["";"1.34";"v1.34.0";"1.34.1";"1.33.0";"latest"];
  for mask = 1 to 15 do
    let packs = List.mapi (fun index name -> index,name) K.Bootstrap.available_packs
      |> List.filter_map (fun (index,name) -> if mask land (1 lsl index)<>0 then Some name else None) in
    let result = ok (prepare packs) in
    let expected_count = List.length packs + if List.mem "view" packs then 1 else 0 in
    check "selected object count" (result.object_count=expected_count);
    let items = array (field "items" (parse result.snapshot)) in
    check "all selected objects are roles; no bindings inferred"
      (List.length items=expected_count && List.for_all (fun x -> List.mem (kind x) [`String "Role";`String "ClusterRole"]) items);
    check "strict closed snapshot" (Result.is_ok (K.Snapshot.of_string result.snapshot));
    check "single final newline" (String.ends_with ~suffix:"\n" result.snapshot && not (String.ends_with ~suffix:"\n\n" result.snapshot));
    let receipt = parse result.receipt in
    check "receipt protocol" (field "kind" receipt=`String "rbac-bootstrap-selection" && field "schema_version" receipt=`Number "1");
    check "selected packs explicit" (field "selected_packs" receipt=`A (List.map (fun p -> `String p) packs));
    check "exact output digest" (field "sha256" (field "snapshot" receipt)=`String (hash result.snapshot));
    check "exact output byte count" (field "bytes" (field "snapshot" receipt)=`Number (string_of_int (String.length result.snapshot)));
    check "reference digest" (field "sha256" (field "reference" receipt)=`String K.Bootstrap_data.sha256);
    check "upstream version/commit recorded" (field "module" (field "upstream" receipt)=`String "k8s.io/kubernetes@v1.34.0" &&
      field "commit" (field "upstream" receipt)=`String "f28b4c9efbca5c5c0af716d9f2d5702667ee8a45");
    check "relevant effective feature gate" (field "DynamicResourceAllocation" (field "configuration" receipt)=`Bool true);
    List.iter (fun key -> check (key ^ " is false") (field key receipt=`Bool false))
      ["verification_performed";"installed_state_observed";"identity_authentication_established";"completeness_established"];
    check "normalization output tied to receipt" (field "snapshot" (field "normalization" receipt)=field "snapshot" receipt);
    let twice = ok (prepare packs) in
    check "deterministic selection" (twice=result);
    let reverse = ok (prepare (List.rev packs)) in
    check "order cannot change policy" (reverse.snapshot=result.snapshot);
    check "requested order still recorded" (field "requested_packs" (parse reverse.receipt)=`A (List.map (fun p -> `String p) (List.rev packs)))
  done;
  let view = ok (prepare ["view"]) in
  let items = array (field "items" (parse view.snapshot)) in
  check "view is not flattened into an ordinary role" (List.mem_assoc "aggregationRule" (fields (List.hd items)));
  check "matching unbound contributor retained" (List.map name items=[`String "view";`String "system:aggregate-to-view"]);
  check "all materialized rule bytes retained" (field "rules" (List.hd items)=field "rules" (List.nth items 1));
  let objects = array (field "objects" (parse view.receipt)) in
  check "dependency selection explicit" (List.map (field "selection") objects=[`String "requested";`String "aggregation-dependency"]);
  let reader = ok (prepare ["extension-apiserver-authentication-reader"]) in
  check "native Role namespace retained" (field "namespace" (metadata (List.hd (array (field "items" (parse reader.snapshot)))))=`String "kube-system");
  let app = json (obj_list [binding "view"]) in
  let joined = ok (assemble app view.snapshot) in
  check "explicit inventory closes binding" (joined.object_count=3);
  let joined_items = array (field "items" (parse joined.snapshot)) in
  check "original supplied binding unchanged" (List.hd joined_items=binding "view");
  check "bootstrap roles unchanged after union" (List.tl joined_items=items);
  let before_hash = hash app and pack_hash = hash view.snapshot in
  ignore (assemble app view.snapshot);
  check "assembly inputs untouched" (hash app=before_hash && hash view.snapshot=pack_hash);
  failed "identical role is not silently deduplicated" (assemble (json (obj_list (binding "view"::items))) view.snapshot);
  failed "conflicting role is never overwritten" (assemble (json (obj_list [binding "view";extra_role "view" []])) view.snapshot);
  let extension = extra_role "app-view-extension" ["rbac.authorization.k8s.io/aggregate-to-view",`String "true"] in
  let stale = assemble (json (obj_list [binding "view";extension])) view.snapshot in
  check "new matching contributor invalidates bootstrap-only view materialization"
    (match stale with Error reason -> contains reason "aggregation" | Ok _ -> false);
  let unrelated = extra_role "unrelated" [] in
  check "unrelated roles retained" ((ok (assemble (json (obj_list [binding "view";unrelated])) view.snapshot)).object_count=4);
  failed "other missing roles are not automatically supplied" (assemble (json (obj_list [binding "cluster-admin"])) view.snapshot);
  check "native role metadata needs no removal"
    (array (field "removed_fields" (field "normalization" (parse view.receipt)))=[]);
  check "native role fields need no defaulting"
    (array (field "defaulted_fields" (field "normalization" (parse view.receipt)))=[]);
  Printf.printf "bootstrap packs: %d checks passed\n" !checks
