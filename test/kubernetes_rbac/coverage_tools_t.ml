module K = Soundcheck_kubernetes_rbac
module I = K.Input
let checks = ref 0
let check label v = incr checks; if not v then failwith label
let ok = function Ok v -> v | Error e -> failwith e
let field name = function `O fields -> List.assoc name fields | _ -> failwith name
let strings xs = `A (List.map (fun s -> `String s) xs)
let change name value = function `O fields -> `O ((name,value)::List.remove_assoc name fields) | _ -> failwith name
let version ?(name="v1") ?(served=true) ?(storage=true) subs =
  `O ["name",`String name;"served",`Bool served;"storage",`Bool storage;"subresources",subs]
let crd ?(scope="Namespaced") ?(group="example.test") ?(plural="widgets") versions =
  `O ["apiVersion",`String "apiextensions.k8s.io/v1";"kind",`String "CustomResourceDefinition";
      "metadata",`O ["name",`String (plural^"."^group)];
      "spec",`O ["group",`String group;"names",`O ["plural",`String plural;"kind",`String "Widget"];
        "scope",`String scope;"versions",`A versions]]
let status = `O ["status",`O []]
let scale = `O ["scale",`O ["specReplicasPath",`String ".spec.replicas";
  "statusReplicasPath",`String ".status.replicas"]]
let list items = `O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items]
let prepare ?(crd_only=false) input = K.Catalogue_prepare.run ~crd_only ~format:K.Manifest_input.Json (I.json input)
let reject label input = check label (Result.is_error (prepare input))
let source = crd [version status]
let contract = {|{"schema_version":9,"kind":"kubernetes-rbac-access","custom_resources":[{"api_group":"example.test","resource":"widgets","scope":"Namespaced","subresources":["status"]}],"context":{"schema_version":1,"snapshot_complete":true,"identities":[{"username":"app","groups":[]}]},"clauses":[{"name":"required","kind":"must_allow","request_kind":"resource","subject":"app","operation":"get","api_group":"","resource":"configmaps","subresource":"","namespace":"team-a","names":["settings"]},{"name":"forbidden","kind":"must_not_grant","request_kind":"non_resource","subject":"app","operation":"get","paths":{"exact":"/metrics"}}],"change_scope":[]}|}
let resource groups resources verbs = `O ["apiGroups",strings groups;"resources",strings resources;"verbs",strings verbs]
let role name rules = `O ["apiVersion",`String "rbac.authorization.k8s.io/v1";"kind",`String "ClusterRole";
  "metadata",`O ["name",`String name];"rules",`A rules]
let snapshot = I.json (list [role "unused" [resource ["example.test"] ["widgets";"widgets/status";"widgets/*"] ["get"]];
    role "wild" [resource ["*"] ["*"] ["*"];`O ["verbs",strings ["get"];"nonResourceURLs",strings ["/metrics"]]]])
let read path = let c=open_in_bin path in Fun.protect ~finally:(fun ()->close_in_noerr c)
  (fun ()->really_input_string c (in_channel_length c))
let write path text = let c=open_out_bin path in Fun.protect ~finally:(fun ()->close_out_noerr c) (fun ()->output_string c text)
let run binary args =
  let out=Filename.temp_file "coverage-tool-out" "" and err=Filename.temp_file "coverage-tool-err" "" in
  Fun.protect ~finally:(fun ()->List.iter Sys.remove [out;err]) (fun ()->
    let o=Unix.openfile out [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 and e=Unix.openfile err [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let pid=Unix.create_process binary (Array.of_list (binary::args)) Unix.stdin o e in
    Unix.close o;Unix.close e;let _,status=Unix.waitpid [] pid in
    (match status with Unix.WEXITED n->n|_->99),read out,read err)
let () =
  let prepared=prepare source |> ok in
  check "project exact metadata" (prepared.catalogue={|[{"api_group":"example.test","resource":"widgets","scope":"Namespaced","subresources":["status"]}]|} ^ "\n");
  let receipt=I.parse prepared.receipt in
  check "source hash" (field "source_sha256" receipt=`String (Soundcheck_core.Sha256.string (I.json source)));
  check "catalogue hash" (field "catalogue_sha256" receipt=`String (Soundcheck_core.Sha256.string prepared.catalogue));
  List.iter (fun key->check key (field key receipt=`Bool false))
    ["verification_performed";"requirements_inferred";"crd_schema_validated";"cluster_completeness_established"];
  check "list same" ((prepare (list [source]) |> ok).catalogue=prepared.catalogue);
  check "typed list same" ((prepare (list [source] |> change "kind" (`String "CustomResourceDefinitionList")
    |> change "apiVersion" (`String "apiextensions.k8s.io/v1")) |> ok).catalogue=prepared.catalogue);
  check "served same" ((prepare (crd [version ~name:"v2" ~storage:false status;version status]) |> ok).catalogue=prepared.catalogue);
  check "unserved does not add" ((prepare (crd [version status;version ~name:"v2" ~served:false ~storage:false scale]) |> ok).catalogue=prepared.catalogue);
  let pod=`O ["apiVersion",`String "v1";"kind",`String "Pod"] in
  reject "mixed needs opt in" (list [source;pod]);
  let selected=prepare ~crd_only:true (list [source;pod]) |> ok in
  check "exclusions counted" (selected.object_count=1 && selected.excluded_count=1);
  check "exclusions retained" (List.length (I.arr "excluded" (field "excluded_objects" (I.parse selected.receipt)))=1);
  List.iter (fun (label,input)->reject label input)
    ["duplicate CRD",list [source;source];"mismatched name",change "metadata" (`O ["name",`String "wrong"]) source;
     "native API group",crd ~group:"apps" [version status];"unknown scope",crd ~scope:"Unknown" [version status];
     "unsupported version",change "apiVersion" (`String "apiextensions.k8s.io/v1beta1") source;
     "no version",crd [];"no served",crd [version ~served:false status];
     "no storage",crd [version ~storage:false status];"two storage",crd [version status;version ~name:"v2" status];
     "duplicate version",crd [version status;version ~storage:false status];
     "conflicting availability",crd [version status;version ~name:"v2" ~storage:false scale];
     "unknown subresource",crd [version (`O ["exec",`O []])];
     "malformed status",crd [version (`O ["status",`Null])];
     "missing scale path",crd [version (`O ["scale",`O []])];
     "partial list",list [source] |> change "metadata" (`O ["continue",`String "next"]);
     "no CRD",list []];
  check "duplicate JSON key" (Result.is_error (K.Catalogue_prepare.run ~format:Json {|{"kind":"List","kind":"List"}|}));
  let yaml="apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.example.test\nspec:\n  group: example.test\n  names:\n    plural: widgets\n  scope: Namespaced\n  versions:\n  - name: v1\n    served: true\n    storage: true\n    subresources:\n      status: {}\n" in
  check "YAML metadata" ((K.Catalogue_prepare.run ~format:Yaml yaml |> ok).catalogue=prepared.catalogue);
  check "whole YAML stream" (Result.is_error (K.Catalogue_prepare.run ~format:Yaml (yaml^"---\nnull\n")));
  check "empty YAML doc recorded" (field "empty_document_count" (I.parse (K.Catalogue_prepare.run ~format:Yaml ("---\n---\n"^yaml) |> ok).receipt)=`Number "1");
  let spec=K.Contract_spec.of_string contract |> ok in
  let request : Soundcheck_core.Ir.request =
    {principal=Authenticated "app";action="get";resource="/unused";context=[];source=0l;host="";scheme="";sni="";
     object_request=Some {namespace="team-a";resource_kind="configmaps";name="settings"}} in
  check "resource path is absent in mixed domain"
    (not (Soundcheck_core.Ir.matches (K.Lower.domain spec) request));
  check "canonical resource request stays accepted"
    (Soundcheck_core.Ir.matches (K.Lower.domain spec) {request with resource=""});
  let report=K.Coverage.run ~snapshot ~contract |> ok |> I.parse in
  check "no verification" (field "verification_performed" report=`Bool false);
  check "frozen custom domain" (field "resource_operation_classes" report=`Number "234");
  let rules=I.arr "rule_sources" (field "rule_sources" report) in
  check "unbound included" (List.length rules=3 && List.for_all (fun row->field "referenced_by_binding" row=`Bool false) rules);
  let refs=I.arr "references" (field "references" (List.hd rules)) in
  check "literal subresource star not glob" (field "outside_catalogue" (List.nth refs 2)=`Bool true);
  check "custom status found" (field "reviewed_entries" (List.nth refs 1)=strings ["widgets/status.example.test"]);
  let wild=field "references" (List.nth rules 1) |> I.arr "references" |> List.hd in
  check "wildcard disclosed" (field "wildcard" wild=`Bool true);
  check "URL verification explicitly enabled" (field "non_resource_verification_enabled" (List.nth rules 2)=`Bool true);
  let excessive=I.json (list [role "excessive" [resource [""] (List.init 10001 (fun _->"pods")) ["get"]]]) in
  check "bounded reference diagnostics" (Result.is_error (K.Coverage.run ~snapshot:excessive ~contract));
  check "unknown snapshot fails" (Result.is_error (K.Coverage.run ~snapshot:"{}" ~contract));
  let binary=Sys.argv.(1) in
  let paths=List.init 4 (fun _->Filename.temp_file "coverage-cli" ".json") in
  Fun.protect ~finally:(fun ()->List.iter (fun path->if Sys.file_exists path then Sys.remove path) paths) (fun ()->
    let input=List.nth paths 0 and contract_path=List.nth paths 1 and snapshot_path=List.nth paths 2 and receipt_path=List.nth paths 3 in
    write input (I.json source);write contract_path contract;write snapshot_path snapshot;
    let code,output,_=run binary ["rbac";"catalogue";input;"--input-format";"json"] in
    check "CLI catalogue" (code=0 && output=prepared.catalogue);
    let code,output,_=run binary ["rbac";"catalogue";input;"--input-format";"json";"--receipt";receipt_path] in
    check "receipt overwrite refused before output" (code=1 && output="");
    Sys.remove receipt_path;
    let code,_,_=run binary ["rbac";"catalogue";input;"--input-format";"json";"--receipt";receipt_path] in
    check "receipt new file" (code=0 && String.trim (read receipt_path)=prepared.receipt);
    check "receipt private" ((Unix.stat receipt_path).Unix.st_perm land 0o077=0);
    let code,output,_=run binary ["rbac";"coverage";snapshot_path;"--contract";contract_path] in
    check "CLI coverage" (code=0 && I.parse output=report);
    let code,output,_=run binary ["rbac";"catalogue";input] in
    check "format explicit" (code=2 && output=""));
  Printf.printf "RBAC coverage workflows: %d checks passed\n" !checks
