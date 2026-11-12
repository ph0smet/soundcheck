open Soundcheck_core
module K = Soundcheck_kubernetes_rbac
module I = K.Input

let checks = ref 0
let check label yes = incr checks; if not yes then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason
let strings xs = `A (List.map (fun x -> `String x) xs)
let set key value fields = (key,value) :: List.remove_assoc key fields
let resources = [
  "","configmaps","configmaps",false; "","secrets","secrets",false;
  "","pods","pods",false; "","services","services",false;
  "","endpoints","endpoints",false; "","nodes","nodes",true;
  "apps","deployments","deployments.apps",false;
  "discovery.k8s.io","endpointslices","endpointslices.discovery.k8s.io",false]
let writes = ["create";"deletecollection"]
let empty = `O ["empty",`Bool true]
let scope ?(subject="app") ?(verb="get") ?(group="") ?(resource="configmaps")
    ?(ns=`String "team-a") ?(names=strings ["settings"]) () =
  ["subject",`String subject;"verb",`String verb;"api_group",`String group;
   "resource",`String resource;"namespace",ns;"names",names]
let contract ?(version=6) ?(allow=scope ())
    ?(deny=scope ~resource:"secrets" ~names:`Null ()) ?(changes=[]) () =
  let fields xs = if version=1 then List.remove_assoc "verb" (List.remove_assoc "api_group" xs)
    else if version<5 then List.remove_assoc "api_group" xs else xs in
  `O ["schema_version",`Number (string_of_int version);"kind",`String K.Contract_spec.kind;
    "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
      "identities",`A [`O ["username",`String "app";"groups",strings ["operators"]];
                       `O ["username",`String "unused";"groups",strings []]]];
    "clauses",`A [
      `O (["name",`String "required";"kind",`String "must_allow"] @ fields allow);
      `O (["name",`String "forbidden";"kind",`String "must_not_grant"] @ fields deny)];
    "change_scope",`A (List.map (fun xs -> `O (fields xs)) changes)]
let parse value = K.Contract_spec.of_string (I.json value)
let spec value = ok (parse value)
let rule ?(verbs=["*"]) ?(groups=[""]) ?(names=[]) resources =
  `O ["verbs",strings verbs;"apiGroups",strings groups;"resources",strings resources;
      "resourceNames",strings names]
let grant ?(binding="ClusterRoleBinding") ?(role="ClusterRole") ?(subject="app") name rules =
  let api="rbac.authorization.k8s.io" in
  let metadata kind = `O (["name",`String name] @
    if kind="Role" || kind="RoleBinding" then ["namespace",`String "team-a"] else []) in
  [`O ["apiVersion",`String (api^"/v1");"kind",`String role;"metadata",metadata role;"rules",`A rules];
   `O ["apiVersion",`String (api^"/v1");"kind",`String binding;"metadata",metadata binding;
     "roleRef",`O ["apiGroup",`String api;"kind",`String role;"name",`String name];
     "subjects",`A [`O ["kind",`String "User";"apiGroup",`String api;"name",`String subject]]]]
let snapshot items = I.json (`O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items])
let policy s source = K.Lower.policy s (ok (K.Snapshot.of_string source))
let request ?(subject="app") kind verb namespace name : Ir.request =
  {principal=Authenticated subject;action=verb;resource="";context=[];source=0l;host="";scheme="";sni="";
   object_request=Some {namespace;resource_kind=kind;name}}
let request_json ?(groups=["operators"]) ?(subresource="") ?(resource_request=true)
    group resource verb namespace name =
  `O ["id",`String "request";"username",`String "app";"groups",strings groups;
    "apiGroup",`String group;"resource",`String resource;"verb",`String verb;
    "namespace",`String namespace;"name",`String name;
    "subresource",`String subresource;"resourceRequest",`Bool resource_request]
let evaluate s row = K.Evaluate.requests s (I.json (`A [row]))
let outcome = function Report.Proved -> "proved" | Violated _ -> "violated"
  | Vacuous -> "vacuous" | Inconsistent _ -> "inconsistent" | Unknown _ -> "unknown"
let from_ce (ce:Report.counterexample) =
  let c=Option.get ce.object_request in request ~subject:ce.principal c.resource_kind ce.action c.namespace c.name
let verify label s source expected =
  let report=K.Verify.run s source in
  check (label^" verdict") (outcome report.result=expected);
  check (label^" frozen identity") (report.frozen_spec=Some (K.Contract_spec.frozen_spec s));
  (match report.result with
   | Report.Violated ce ->
     let p=policy s source and r=from_ce ce in
     let clause=List.find (fun c -> Contract.name c=(Option.get report.clause).name)
       (K.Contract_spec.to_contract s).clauses in
     check (label^" witness obligation") (Witness.clause p clause r);
     check (label^" empty authorization name") ((Option.get ce.object_request).name="");
     check (label^" grant provenance") (ce.granting_rules=K.Lower.granting_rules p r)
   | _ -> ()); report
let compare label s before after expected =
  let result=K.Verify.compare_with_trace s ~before ~after in
  check (label^" verdict") (outcome result.report.result=expected);
  check (label^" candidate contract independently proved")
    ((Option.get result.candidate_report).result=Report.Proved);
  (match result.report.result with
   | Report.Violated ce ->
     check (label^" preservation phase") ((Option.get result.report.clause).kind=Report.Must_preserve);
     check (label^" outside approved scope")
       (Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes s))
          (policy s before) (policy s after) (from_ce ce));
     check (label^" newly covered verb and empty name")
       (List.mem ce.action writes && (Option.get ce.object_request).name="")
   | _ -> ()); result.report

let () =
  (* These hashes were captured from a separately built untouched 133ead8 CLI,
     before schema 6. They protect public profiles as well as canonical sorting. *)
  List.iter (fun (version,hash) -> check "old profile bytes stay frozen"
    (Sha256.string (K.Assurance.profile_json ~version ())=hash)) [
    1,"31230a9fb3e62798f74e50b77eb61fb7554d8c9dbd511c1b7f2370a395f07b3b";
    2,"bdaa6e06babb84cbf69fe060bc84ea030b3528ef9f8b0e57548b1c9cc4ac4455";
    3,"de7842a1f531b9b87b408689fd0e94a9c3cf15edd58cbb0b50c98c9975e35d03";
    4,"dc66d39ebc0986f216671974f4da636cf5ad511c0f7d998701c5b4f6815d67e7";
    5,"33702f3193261a8f6b6150291135b23ca3e38280f708b4bf30c47167e90f9af7"];
  let old=ok (K.Contract_spec.of_string {|{
    "schema_version":5,"kind":"kubernetes-rbac-access",
    "context":{"schema_version":1,"snapshot_complete":true,"identities":[
      {"username":"unused","groups":[]},{"username":"app","groups":["z","a"]}]},
    "clauses":[
      {"name":"required","kind":"must_allow","subject":"app","verb":"list",
       "namespace":{"include":["team-b","team-a"]},"api_group":"apps","resource":"deployments",
       "names":{"exclude":["z","a"],"include_empty":true}},
      {"name":"forbidden","kind":"must_not_grant","subject":"app","verb":"delete",
       "namespace":null,"api_group":"","resource":"nodes",
       "names":{"exclude":["node-b","node-a"],"include_empty":false}}],
    "change_scope":[
      {"subject":"unused","verb":"watch","namespace":null,"api_group":"discovery.k8s.io",
       "resource":"endpointslices","names":{"empty":true}},
      {"subject":"app","verb":"patch","namespace":{"exclude":["team-b","team-a"]},
       "api_group":"apps","resource":"deployments","names":["z","a"]},
      {"subject":"app","verb":"patch","namespace":{"exclude":["team-a","team-b"]},
       "api_group":"apps","resource":"deployments","names":["a","z"]}]
  }|}) in
  check "compound schema-5 frozen identity is unchanged"
    (Sha256.string (K.Contract_spec.canonical old)="d275b5a1f6f37c2dfe044e0a846515e55bb47fcb38e3908844b58f83e29e7d3a"
     && List.length (K.Contract_spec.changes old)=2);
  let s=spec (contract ()) in
  check "schema 6 has an explicit assurance profile"
    (K.Assurance.id_for_version 6="kubernetes-rbac-v1.34-collection-write-v1");
  List.iter (fun version ->
    let old=spec (contract ~version ()) in
    List.iter (fun verb ->
      check "old domains do not silently acquire collection writes"
        (not (Ir.matches (K.Lower.domain old) (request "configmaps" verb "team-a" "")));
      check "old concrete adapters reject collection writes"
        (Result.is_error (evaluate old (request_json "" "configmaps" verb "team-a" "")));
      if version>=2 then check "old contracts reject new verbs"
        (Result.is_error (parse (contract ~version ~allow:(scope ~verb ~names:`Null ()) ())))) writes)
    [1;2;3;4;5];
  List.iter (fun (group,raw,kind,cluster) ->
    List.iter (fun verb ->
      List.iter (fun ns -> List.iter (fun name ->
        let allowed_ns=if cluster then ns="" else List.mem ns ["team-a";"team-b"] in
        let expected=allowed_ns && name="" in
        check "collection writes have exactly the approved name and namespace domain"
          (Ir.matches (K.Lower.domain s) (request kind verb ns name)=expected);
        check "concrete request validation uses the same bounded domain"
          (Result.is_ok (evaluate s (request_json group raw verb ns name))=expected))
        ["";"settings"]) ["team-a";"team-b";"";"Bad"];
      let ns=if cluster then `Null else `String "team-a" in
      List.iter (fun names -> check "both approved empty-name authoring forms parse"
        (Result.is_ok (parse (contract ~allow:(scope ~verb ~group ~resource:raw ~ns ~names ()) ()))))
        [`Null;empty]) writes) resources;
  let before=spec (contract ~version:5 ()) in
  List.iter (fun (_,_,kind,cluster) ->
    List.iter (fun verb -> List.iter (fun ns -> List.iter (fun name ->
      check "all existing request domains retain their meaning"
        (Ir.matches (K.Lower.domain before) (request kind verb ns name)=
         Ir.matches (K.Lower.domain s) (request kind verb ns name))) ["";"settings"])
      (if cluster then ["";"team-a"] else ["";"team-a"]))
      ["get";"list";"watch";"update";"patch";"delete"]) resources;
  List.iter (fun verb ->
    let selected=scope ~verb ~resource:"pods" ~names:`Null () in
    let invalid=[selected |> List.remove_assoc "api_group";
      selected |> set "names" (strings ["worker"]);
      selected |> set "names" (strings [""]);
      selected |> set "names" (strings []);
      selected |> set "names" (`O ["empty",`Bool false]);
      selected |> set "names" (`O ["exclude",strings [];"include_empty",`Bool true]);
      selected |> set "names" (`O ["exclude",strings ["worker"];"include_empty",`Bool false]);
      selected |> set "namespace" `Null;
      selected |> set "namespace" (`String "");
      selected |> set "resource" (`String "pods/status");
      selected |> set "resource" (`String "namespaces");
      selected |> set "api_group" (`String "apps");
      selected |> set "resource" (`String "nodes")] in
    List.iter (fun selected ->
      check "unsafe collection-write clause authoring fails closed"
        (Result.is_error (parse (contract ~allow:selected ())));
      check "unsafe collection-write approved changes fail closed"
        (Result.is_error (parse (contract ~changes:[selected] ())))) invalid;
    List.iter (fun ns -> check "Node collection-write scopes cannot inherit namespace selectors"
      (Result.is_error (parse (contract ~allow:(scope ~verb ~resource:"nodes" ~ns ~names:empty ()) ()))))
      [`String "team-a";`O ["include",strings ["team-a"]];`O ["exclude",strings []]];
    let included=scope ~verb ~resource:"pods" ~names:empty ~ns:(`O ["include",strings ["team-b";"team-a"]]) () in
    let excluded=scope ~verb ~resource:"pods" ~names:`Null ~ns:(`O ["exclude",strings ["team-b"]]) () in
    let selected=spec (contract ~allow:included ~changes:[excluded;excluded] ()) in
    check "new verbs preserve namespace selector normalization"
      (List.length (K.Contract_spec.changes selected)=1 &&
       K.Contract_spec.canonical selected=K.Contract_spec.canonical
         (ok (K.Contract_spec.of_string (K.Contract_spec.canonical selected))));
    check "namespace include selects the Cartesian request class"
      (Ir.matches (Contract.request_class (List.hd (K.Contract_spec.to_contract selected).clauses))
        (request "pods" verb "team-b" ""));
    check "namespace complement excludes empty and listed namespace"
      (Ir.matches (K.Contract_spec.approved_changes selected) (request "pods" verb "future" "") &&
       not (Ir.matches (K.Contract_spec.approved_changes selected) (request "pods" verb "team-b" "")) &&
       not (Ir.matches (K.Contract_spec.approved_changes selected) (request "pods" verb "" "")))) writes;
  List.iter (fun row -> check "unmodeled concrete request dimensions fail closed"
    (Result.is_error (evaluate s row))) [
      request_json ~subresource:"status" "" "pods" "create" "team-a" "";
      request_json ~resource_request:false "" "" "create" "" "";
      request_json ~groups:[] "" "pods" "create" "team-a" "";
      request_json "apps" "deployments.apps" "create" "team-a" "";
      request_json "" "pods" "bind" "team-a" "";
      request_json "example.com" "widgets" "create" "team-a" ""];
  (* Literal expectations follow Kubernetes RuleAllows and ResourceNameMatches:
     names are compared exactly, including the unusual valid empty string. *)
  let cases=[
    "unrestricted",grant "all" [rule ~groups:["*"] ["*"]],(fun _ _ _ -> true);
    "empty resourceNames",grant "empty" [rule ~groups:["*"] ~names:[""] ["*"]],(fun _ _ _ -> true);
    "named resourceNames",grant "named" [rule ~groups:["*"] ~names:["worker"] ["*"]],(fun _ _ _ -> false);
    "literal star resourceNames",grant "star" [rule ~groups:["*"] ~names:["*"] ["*"]],(fun _ _ _ -> false);
    "named delete is distinct",grant "delete" [rule ~groups:["*"] ~verbs:["delete"] ["*"]],(fun _ _ _ -> false);
    "create only",grant "create" [rule ~groups:["*"] ~verbs:["create"] ["*"]],(fun _ verb _ -> verb="create");
    "apps group",grant "apps" [rule ~groups:["apps"] ["*"]],(fun group _ _ -> group="apps");
    "RoleBinding to ClusterRole",grant ~binding:"RoleBinding" "local" [rule ~groups:["*"] ["*"]],(fun _ _ ns -> ns="team-a");
    "RoleBinding to Role",grant ~role:"Role" ~binding:"RoleBinding" "local" [rule ~groups:["*"] ["*"]],(fun _ _ ns -> ns="team-a");
    "additive empty-name grant",grant "named" [rule ~groups:["*"] ~names:["worker"] ["*"]] @
      grant "empty" [rule ~groups:["*"] ~names:["";"worker"] ["*"]],(fun _ _ _ -> true)] in
  List.iter (fun (label,items,wanted) ->
    let p=policy s (snapshot items) in
    List.iter (fun (group,_,kind,cluster) -> List.iter (fun verb ->
      List.iter (fun ns -> let r=request kind verb ns "" in
        check (label^" exact initial RBAC decision")
          (Ir.possibly_allows p r=wanted group verb ns && Ir.definitely_allows p r=wanted group verb ns))
        (if cluster then [""] else ["team-a";"team-b"])) writes) resources) cases;
  let required=scope ~verb:"create" ~resource:"pods" ~names:`Null ()
  and forbidden=scope ~verb:"deletecollection" ~resource:"pods" ~names:empty () in
  let workload=spec (contract ~allow:required ~deny:forbidden ~changes:[forbidden] ()) in
  let create=grant ~role:"Role" ~binding:"RoleBinding" "create" [rule ~verbs:["create"] ["pods"]]
  and bulk=grant ~role:"Role" ~binding:"RoleBinding" "bulk" [rule ~verbs:["deletecollection"] ["pods"]] in
  ignore (verify "required creation works" workload (snapshot create) "proved");
  ignore (verify "name-constrained creation is not functional" workload
    (snapshot (grant ~binding:"RoleBinding" "named" [rule ~verbs:["create"] ~names:["worker"] ["pods"]])) "violated");
  ignore (verify "explicit empty-name creation works" workload
    (snapshot (grant ~binding:"RoleBinding" "empty" [rule ~verbs:["create"] ~names:[""] ["pods"]])) "proved");
  let denied=verify "deny-all is not a repair" workload (snapshot []) "violated" in
  check "missing functionality identifies create" (match denied.result with Violated ce -> ce.action="create" | _ -> false);
  let unsafe=verify "bulk deletion violates safety" workload (snapshot (create @ bulk)) "violated" in
  check "bulk deletion is lifted without a fabricated object name"
    (match unsafe.result with Violated ce -> ce.action="deletecollection" && (Option.get ce.object_request).name="" | _ -> false);
  ignore (verify "named deletion alone does not violate bulk-deletion scope" workload
    (snapshot (create @ grant ~binding:"RoleBinding" "named-delete" [rule ~verbs:["delete"] ["pods"]])) "proved");
  ignore (compare "authorized repair preserves required create" workload (snapshot (create @ bulk)) (snapshot create) "proved");
  let overlap=spec (contract ~allow:required ~deny:(scope ~verb:"create" ~resource:"pods" ~names:empty ()) ()) in
  ignore (verify "null and empty authoring classes overlap" overlap (snapshot create) "inconsistent");
  let common=grant "read" [rule ~verbs:["get"] ~names:["settings"] ["configmaps"]] in
  List.iter (fun verb -> List.iter (fun (group,raw,kind,cluster) ->
    let binding=if cluster then "ClusterRoleBinding" else "RoleBinding" in
    let extra=grant ~binding ~subject:"unused" "secondary" [rule ~groups:[group] ~verbs:[verb] [raw]] in
    let before=snapshot (common @ extra) and after=snapshot common in
    ignore (compare "schema 5 preserves its smaller verb domain" (spec (contract ~version:5 ())) before after "proved");
    let report=compare "schema 6 preserves unmentioned identities and resources" s before after "violated" in
    check "preservation witness retains exact resource and identity"
      (match report.result with Violated ce -> ce.principal="unused" && (Option.get ce.object_request).resource_kind=kind | _ -> false);
    let change=scope ~subject:"unused" ~verb ~group ~resource:raw
      ~ns:(if cluster then `Null else `String "team-a") ~names:empty () in
    ignore (compare "explicit collection-write scope permits its exact change"
      (spec (contract ~changes:[change] ())) before after "proved"))
    ["","pods","pods",false;"","nodes","nodes",true;"apps","deployments","deployments.apps",false]) writes;
  Printf.printf "RBAC collection writes: %d checks passed\n" !checks
