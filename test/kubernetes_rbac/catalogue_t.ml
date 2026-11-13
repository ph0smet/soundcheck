module K = Soundcheck_kubernetes_rbac
let checks = ref 0
let check label value = incr checks; if not value then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason
let parse = K.Catalogue.of_string
let row ?(group="example.test") ?(resource="widgets") ?(scope="Namespaced") ?(subs="[]") () =
  Printf.sprintf {|{"api_group":%S,"resource":%S,"scope":%S,"subresources":%s}|} group resource scope subs
let () =
  let old = K.Resource_domain.for_version 8 and expanded = K.Resource_domain.for_version 9 in
  check "old catalogue fixed" (List.length old=16);
  check "expanded catalogue fixed" (List.length expanded=31);
  check "all old entries retained" (List.for_all (fun e -> List.mem e expanded) old);
  check "old operation count" (List.fold_left (fun n e -> n+List.length (K.Resource_domain.operations ~version:8 e)) 0 old=99);
  check "new operation count" (List.fold_left (fun n e -> n+List.length (K.Resource_domain.operations ~version:9 e)) 0 expanded=223);
  let expected = ["","serviceaccounts",true;"","events",true;"","namespaces",false;
    "","persistentvolumeclaims",true;"","persistentvolumes",false;
    "events.k8s.io","events",true;"apps","replicasets",true;
    "apps","statefulsets",true;"apps","daemonsets",true;
    "batch","jobs",true;"batch","cronjobs",true;
    "coordination.k8s.io","leases",true;"networking.k8s.io","ingresses",true;
    "networking.k8s.io","ingressclasses",false;"storage.k8s.io","storageclasses",false] in
  List.iter (fun (api_group,resource,namespaced) ->
    let entry = Option.get (K.Resource_domain.find ~version:9 ~api_group ~resource) in
    check "independent scope metadata" (entry.namespaced=namespaced);
    check "new entries are initial only" (K.Resource_domain.operations ~version:9 entry=["get";"list";"watch";"update";"patch";"delete";"create";"deletecollection"]);
    check "no legacy widening" (K.Resource_domain.find ~version:8 ~api_group ~resource=None)) expected;
  let ns=Option.get (K.Resource_domain.find ~version:9 ~api_group:"" ~resource:"namespaces") in
  List.iter (fun verb -> check "named Namespace relationship" (K.Resource_domain.namespace_domain ns ~verb="same-as-name")) ["get";"update";"patch";"delete"];
  List.iter (fun verb -> check "Namespace collection namespace" (K.Resource_domain.namespace_domain ns ~verb="empty")) ["list";"watch";"create";"deletecollection"];
  check "empty custom catalogue" (K.Catalogue.resources (parse "[]" |> ok)=[]);
  let source="["^row ~subs:{|["status","scale"]|} ()^"]" in
  let parsed=parse source |> ok in
  let entries=K.Catalogue.resources parsed in
  check "explicit subresources" (List.length entries=3);
  List.iter (fun e ->
    check "custom scope frozen" e.K.Resource_domain.namespaced;
    check "custom no automatic SSA" (not (List.mem "apply-missing" (K.Resource_domain.operations ~version:9 e)))) entries;
  let canonical=K.Input.json (K.Catalogue.json parsed) in
  check "catalogue canonical roundtrip" (K.Input.json (K.Catalogue.json (parse canonical |> ok))=canonical);
  check "subresource order normalized" (canonical=K.Input.json (K.Catalogue.json (parse ("["^row ~subs:{|["scale","status"]|} ()^"]") |> ok)));
  List.iter (fun invalid -> check "invalid catalogue rejected" (Result.is_error (parse invalid)))
    ["null";"{}";"[{}]";"["^row ()^","^row ()^"]";
     "["^row ()^","^row ~scope:"Cluster" ()^"]";
     "["^row ~group:"rbac.authorization.k8s.io" ~resource:"roles" ()^"]";
     "["^row ~group:"apps" ()^"]";"["^row ~group:"" ()^"]";
     "["^row ~group:"*.test" ()^"]";"["^row ~resource:"*/status" ()^"]";
     "["^row ~resource:"9widgets" ()^"]";"["^row ~resource:"Widgets" ()^"]";
     "["^row ~scope:"cluster" ()^"]";"["^row ~subs:{|["status","status"]|} ()^"]";
     "["^row ~subs:{|["finalizers"]|} ()^"]";
     "["^row ~subs:{|["*"]|} ()^"]";
     "["^String.concat "," (List.init 65 (fun i -> row ~resource:("items"^string_of_int i) ()))^"]"];
  check "at limit accepted" (Result.is_ok (parse ("["^String.concat "," (List.init 64 (fun i -> row ~resource:("items"^string_of_int i) ()))^"]")));
  Printf.printf "RBAC frozen catalogue: %d checks passed\n" !checks
