open Soundcheck_core
module K = Soundcheck_kubernetes_rbac
module I = K.Input

let checks = ref 0
let check label yes = incr checks; if not yes then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason
let strings xs = `A (List.map (fun x -> `String x) xs)
let set key value fields = (key,value) :: List.remove_assoc key fields
let contains source part =
  let rec loop i = i+String.length part<=String.length source &&
    (String.sub source i (String.length part)=part || loop (i+1)) in loop 0
(* Independently enumerated from the approved Kubernetes v1.34 REST routes.
   Apply branches are operations, never literal RBAC verbs. *)
let bases = [
  "","configmaps","configmaps",false; "","secrets","secrets",false;
  "","pods","pods",false; "","services","services",false;
  "","endpoints","endpoints",false; "","nodes","nodes",true;
  "apps","deployments","deployments.apps",false;
  "discovery.k8s.io","endpointslices","endpointslices.discovery.k8s.io",false]
let subresources = [
  "","pods","log","pods/log",false,["get"];
  "","pods","exec","pods/exec",false,["get";"create"];
  "","serviceaccounts","token","serviceaccounts/token",false,["create"];
  "","pods","status","pods/status",false,["get";"update";"patch"];
  "","services","status","services/status",false,["get";"update";"patch"];
  "","nodes","status","nodes/status",true,["get";"update";"patch"];
  "apps","deployments","status","deployments/status.apps",false,["get";"update";"patch"];
  "apps","deployments","scale","deployments/scale.apps",false,["get";"update";"patch"]]
let native = ["get";"list";"watch";"update";"patch";"delete";"create";"deletecollection"]
let apply = ["apply-existing";"apply-missing"]
let scope ?(subject="app") ?(operation="get") ?(group="") ?(resource="configmaps")
    ?(subresource="") ?(ns=`String "team-a") ?(names=strings ["settings"]) () =
  ["subject",`String subject;"operation",`String operation;"api_group",`String group;
   "resource",`String resource;"subresource",`String subresource;"namespace",ns;"names",names]
let contract ?(version=8) ?(allow=scope ())
    ?(deny=scope ~resource:"secrets" ~names:`Null ()) ?(changes=[]) () =
  let fields xs = if version>=8 then xs else
    let xs=set "verb" (List.assoc "operation" xs) (List.remove_assoc "operation" xs) in
    let xs=if version<7 then List.remove_assoc "subresource" xs else xs in
    let xs=if version<5 then List.remove_assoc "api_group" xs else xs in
    if version=1 then List.remove_assoc "verb" xs else xs in
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
let grant ?(binding="ClusterRoleBinding") ?(role="ClusterRole") ?(ns="team-a")
    ?(subject="app") ?(subject_kind="User") name rules =
  let api="rbac.authorization.k8s.io" in
  let metadata kind = `O (["name",`String name] @
    if kind="Role" || kind="RoleBinding" then ["namespace",`String ns] else []) in
  [`O ["apiVersion",`String (api^"/v1");"kind",`String role;"metadata",metadata role;"rules",`A rules];
   `O ["apiVersion",`String (api^"/v1");"kind",`String binding;"metadata",metadata binding;
     "roleRef",`O ["apiGroup",`String api;"kind",`String role;"name",`String name];
     "subjects",`A [`O ["kind",`String subject_kind;"apiGroup",`String api;"name",`String subject]]]]
let snapshot items = I.json (`O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items])
let policy s source = K.Lower.policy s (ok (K.Snapshot.of_string source))
let request ?(subject="app") kind operation namespace name : Ir.request =
  {principal=Authenticated subject;action=operation;resource="";context=[];source=0l;host="";scheme="";sni="";
   object_request=Some {namespace;resource_kind=kind;name}}
let request_json ?(version=8) ?(groups=["operators"]) ?(subresource="")
    group resource operation namespace name =
  `O ["id",`String "request";"username",`String "app";"groups",strings groups;
    "apiGroup",`String group;"resource",`String resource;
    (if version>=8 then "operation" else "verb"),`String operation;
    "namespace",`String namespace;"name",`String name;
    "subresource",`String subresource;"resourceRequest",`Bool true]
let evaluate s row = K.Evaluate.requests s (I.json (`A [row]))
let outcome = function Report.Proved -> "proved" | Violated _ -> "violated"
  | Vacuous -> "vacuous" | Inconsistent _ -> "inconsistent" | Unknown _ -> "unknown"
let from_ce (ce:Report.counterexample) =
  let c=Option.get ce.object_request in request ~subject:ce.principal c.resource_kind ce.action c.namespace c.name
let verify label s source expected =
  let report=K.Verify.run s source in
  check (label^" verdict: expected "^expected^", got "^outcome report.result) (outcome report.result=expected);
  check (label^" frozen identity") (report.frozen_spec=Some (K.Contract_spec.frozen_spec s));
  (match report.result with
   | Report.Violated ce ->
     let p=policy s source and r=from_ce ce in
     let clause=List.find (fun c -> Contract.name c=(Option.get report.clause).name)
       (K.Contract_spec.to_contract s).clauses in
     check (label^" witness obligation") (Witness.clause p clause r);
     check (label^" request belongs to frozen domain") (Ir.matches (K.Lower.domain s) r);
     check (label^" grant provenance") (ce.granting_rules=K.Lower.granting_rules p r)
   | _ -> ()); report
let compare_result label s before after expected =
  let result=K.Verify.compare_with_trace s ~before ~after in
  check (label^" verdict: expected "^expected^", got "^outcome result.report.result) (outcome result.report.result=expected);
  check (label^" candidate contract independently proved")
    ((Option.get result.candidate_report).result=Report.Proved);
  (match result.report.result with
   | Report.Violated ce ->
     check (label^" preservation phase") ((Option.get result.report.clause).kind=Report.Must_preserve);
     check (label^" outside approved scope")
       (Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes s))
          (policy s before) (policy s after) (from_ce ce));
     check (label^" frozen-domain witness") (Ir.matches (K.Lower.domain s) (from_ce ce))
   | _ -> ()); result.report

let () =
  (* Captured with build-only CLI operations from untouched 0373c86 before
     schema-8 implementation. These are bytes, not regenerated expectations. *)
  let goldens = [
    1,"31230a9fb3e62798f74e50b77eb61fb7554d8c9dbd511c1b7f2370a395f07b3b","ce687f59c4d72e580a711a817abe9706e21a171361a1ee7827b9fa2aa3e0c0ce";
    2,"bdaa6e06babb84cbf69fe060bc84ea030b3528ef9f8b0e57548b1c9cc4ac4455","30571c71ff44e50fcbbb24d23b2659103dca0f543ca0763280eab50a607ff2e0";
    3,"de7842a1f531b9b87b408689fd0e94a9c3cf15edd58cbb0b50c98c9975e35d03","1e4ecd33131a38586e3de24efc68c53136cd89453781214fde73f65c840d84c8";
    4,"dc66d39ebc0986f216671974f4da636cf5ad511c0f7d998701c5b4f6815d67e7","c5a8c730b1c80380f16faedf9aa8171427813e3ab5adbb733ed3a6b61f9ea217";
    5,"33702f3193261a8f6b6150291135b23ca3e38280f708b4bf30c47167e90f9af7","a0eb6c69ef273f92115967fffaad4fa2d6ec9967bda54e58f790adea65bf126e";
    6,"ea4f7e094c800f68fe02703828bc2a03a02269e3cfc855a622af296ad77050b3","12a37fe551ae1fadeeb5c3b90e893d7df432044777a42c8c3ee3d343b1dbabcb";
    7,"c8020f0402c9677c995a7aea4d3fcbf4033d43355e6bb4242e6a124426412bd9","79a3c9939d24a03a3e5787b69a3e31c855c190dd0820c7d82310d7522dd41b59"] in
  List.iter (fun (version,profile_hash,canonical_hash) ->
    check "legacy assurance profile bytes frozen" (Sha256.string (K.Assurance.profile_json ~version ())=profile_hash);
    let old=spec (contract ~version ()) in
    check "legacy canonical bytes frozen" (Sha256.string (K.Contract_spec.canonical old)=canonical_hash);
    List.iter (fun operation ->
      (* V1 has no operation selector at all. Keep an explicit verb field in
         this rejection input instead of silently generating ordinary v1 get. *)
      let unsupported = match contract ~version:(max 2 version) ~allow:(scope ~operation ()) () with
        | `O fields -> `O (set "schema_version" (`Number (string_of_int version)) fields)
        | _ -> assert false in
      check "old contracts reject apply operations" (Result.is_error (parse unsupported));
      check "old domains cannot acquire apply branches" (not (Ir.matches (K.Lower.domain old) (request "configmaps" operation "team-a" "settings")));
      check "old concrete adapter cannot acquire apply branches"
        (Result.is_error (evaluate old (request_json ~version "" "configmaps" operation "team-a" "settings")))) apply;
    let row=request_json "" "configmaps" "get" "team-a" "settings" in
    check "old concrete inputs reject operation key" (Result.is_error (evaluate old row))) goldens;
  let s=spec (contract ()) and old=spec (contract ~version:7 ()) in
  check "schema8 explicit assurance" (K.Assurance.id_for_version 8="kubernetes-rbac-v1.34-apply-v1");
  check "schema8 payload lacks required schema9 fields" (Result.is_error (parse (contract ~version:9 ())));
  let identity operation=K.Contract_spec.canonical (spec (contract ~allow:(scope ~operation ()) ())) in
  check "frozen identity distinguishes raw patch and both hypothetical apply branches"
    (List.length (List.sort_uniq String.compare (List.map identity ["patch";"apply-existing";"apply-missing"]))=3);
  let full=snapshot (grant "native" [rule ~groups:["*"] ["*"]]) in
  let old_policy=policy old full and new_policy=policy s full in
  List.iter (fun (_,_,kind,_) -> List.iter (fun operation -> List.iter (fun ns -> List.iter (fun name ->
    check "all old base request classes retain their domain"
      (Ir.matches (K.Lower.domain old) (request kind operation ns name)=
       Ir.matches (K.Lower.domain s) (request kind operation ns name));
    let r=request kind operation ns name in
    check "legacy native decisions and provenance remain unchanged in schema8"
      (Ir.possibly_allows old_policy r=Ir.possibly_allows new_policy r &&
       K.Lower.granting_rules old_policy r=K.Lower.granting_rules new_policy r)) ["";"worker";"Bad";"*"])
    ["";"team-a";"future";"Bad"]) native) bases;
  List.iter (fun (group,raw,sub,kind,cluster,operations) ->
    List.iter (fun operation -> List.iter (fun ns -> List.iter (fun name ->
      check "all old subresource request classes retain their domain"
        (Ir.matches (K.Lower.domain old) (request kind operation ns name)=
         Ir.matches (K.Lower.domain s) (request kind operation ns name))) ["";"worker";"Bad"])
      ["";"team-a";"Bad"]) operations;
    List.iter (fun operation ->
      check "apply is not accepted on subresources"
        (Result.is_error (parse (contract ~allow:(scope ~group ~resource:raw ~subresource:sub ~operation
          ~ns:(if cluster then `Null else `String "team-a") ()) ())));
      check "subresource concrete apply fails closed"
        (Result.is_error (evaluate s (request_json ~subresource:sub group raw operation
          (if cluster then "" else "team-a") "worker")))) apply) subresources;
  List.iter (fun (group,raw,kind,cluster) -> List.iter (fun operation ->
    List.iter (fun ns -> List.iter (fun name ->
      let expected=(if cluster then ns="" else List.mem ns ["team-a";"future"]) && List.mem name ["worker";"future"] in
      let r=request kind operation ns name in
      check "exact named base SSA domain" (Ir.matches (K.Lower.domain s) r=expected);
      let rows=evaluate s (request_json group raw operation ns name) in
      check "concrete SSA requests share exact domain" (Result.is_ok rows=expected);
      if expected then check "concrete operation survives lowering" ((List.hd (ok rows)).request=r))
      ["";"worker";"future";"Bad";"*"]) ["";"team-a";"future";"Bad"];
    let selected=scope ~operation ~group ~resource:raw ~ns:(if cluster then `Null else `String "team-a") () in
    List.iter (fun names -> check "apply accepts named selectors"
      (Result.is_ok (parse (contract ~allow:(set "names" names selected) ~changes:[set "names" names selected] ()))))
      [`Null;strings ["worker";"future"];`O ["exclude",strings ["worker"];"include_empty",`Bool false]];
    List.iter (fun invalid ->
      check "invalid apply clause rejected" (Result.is_error (parse (contract ~allow:invalid ())));
      check "invalid apply change scope rejected" (Result.is_error (parse (contract ~changes:[invalid] ()))))
      [List.remove_assoc "operation" selected;set "operation" `Null selected;
       set "verb" (`String "patch") selected;set "operation" (`String "apply") selected;
       set "operation" (`String "*") selected;List.remove_assoc "api_group" selected;
       List.remove_assoc "subresource" selected;set "subresource" `Null selected;
       set "names" (`O ["empty",`Bool true]) selected;set "names" (strings [""]) selected;
       set "names" (`O ["exclude",strings [];"include_empty",`Bool true]) selected;
       set "namespace" (`String "") selected];
    List.iter (fun ns -> check "apply namespace selectors follow base scope"
      (Result.is_ok (parse (contract ~allow:(set "namespace" ns selected) ()))=not cluster))
      [`O ["include",strings ["team-a";"team-b"]];`O ["exclude",strings ["team-a"]]];
    check "only Node apply accepts null namespace"
      (Result.is_ok (parse (contract ~allow:(set "namespace" `Null selected) ()))=cluster)) apply) bases;
  List.iter (fun row -> check "schema8 concrete input requires operation and trusted identity"
    (Result.is_error (evaluate s row))) [
      request_json ~version:7 "" "configmaps" "patch" "team-a" "settings";
      request_json ~groups:[] "" "configmaps" "apply-missing" "team-a" "settings";
      (match request_json "" "configmaps" "apply-existing" "team-a" "settings" with
       | `O xs -> `O (set "verb" (`String "patch") xs) | _ -> assert false)];
  let selected=scope ~operation:"apply-missing" ~ns:(`O ["include",strings ["team-b";"team-a"]])
    ~names:(`O ["exclude",strings ["z";"a"];"include_empty",`Bool false]) () in
  let scoped=spec (contract ~changes:[selected;selected] ()) in
  check "canonical normalizes apply scope without changing operation"
    (List.length (K.Contract_spec.changes scoped)=1 &&
     K.Contract_spec.canonical scoped=K.Contract_spec.canonical (ok (K.Contract_spec.of_string (K.Contract_spec.canonical scoped))));
  let condition=K.Contract_spec.approved_changes scoped in
  List.iter (fun (operation,ns,name,expected) -> check "approval selects one hypothetical branch only"
    (Ir.matches condition (request "configmaps" operation ns name)=expected)) [
    "apply-missing","team-a","other",true;"apply-missing","team-b","other",true;
    "apply-missing","team-c","other",false;"apply-missing","team-a","a",false;
    "apply-existing","team-a","other",false;"patch","team-a","other",false;
    "create","team-a","",false;"apply-missing","team-a","",false];
  (* Two independent native authorization calls at identical coordinates.
     A cross-resource/namespace/name/identity join must never produce Allow. *)
  List.iter (fun (group,raw,kind,cluster) ->
    let ns=if cluster then "" else "team-a" in
    let ptag=grant "patch-stage" [rule ~groups:[group] ~verbs:["patch"] ~names:["worker"] [raw]]
    and ctag=grant "create-stage" [rule ~groups:[group] ~verbs:["create"] ~names:["worker"] [raw]] in
    let cases=["neither",[],false,false;"patch",ptag,true,false;"create",ctag,false,false;
      "separate roles",ptag@ctag,true,true;
      "wildcard native verbs",grant "wild" [rule ~groups:[group] ~names:["worker"] [raw]],true,true;
      "fake apply verbs",grant "fake" [rule ~groups:[group] ~verbs:apply ~names:["worker"] [raw]],false,false;
      "verb globs are literal",grant "fake-globs" [rule ~groups:[group] ~verbs:["apply-*";"patch*";"create*"] [raw]],false,false;
      "wrong create resource",ptag@grant "wrong" [rule ~groups:[group] ~verbs:["create"] ["other-resources"]],true,false;
      "wrong create name",ptag@grant "wrong" [rule ~groups:[group] ~verbs:["create"] ~names:["other"] [raw]],true,false;
      "empty create name",ptag@grant "wrong" [rule ~groups:[group] ~verbs:["create"] ~names:[""] [raw]],true,false;
      "star create name literal",ptag@grant "wrong" [rule ~groups:[group] ~verbs:["create"] ~names:["*"] [raw]],true,false;
      "wrong create group",ptag@grant "wrong" [rule ~groups:["wrong.example"] ~verbs:["create"] [raw]],true,false;
      "other create subject",ptag@grant ~subject:"unused" "wrong" [rule ~groups:[group] ~verbs:["create"] [raw]],true,false;
      "group create grant",ptag@grant ~subject:"operators" ~subject_kind:"Group" "group" [rule ~groups:[group] ~verbs:["create"] ~names:["worker"] [raw]],true,true;
      "foreign namespace create",ptag@grant ~binding:"RoleBinding" ~ns:"team-b" "wrong" [rule ~groups:[group] ~verbs:["create"] [raw]],true,false] in
    List.iter (fun (label,items,existing,missing) ->
      let p=policy s (snapshot items) in
      List.iter (fun (operation,expected) -> let r=request kind operation ns "worker" in
        check (label^" compound native decision")
          (Ir.possibly_allows p r=expected && Ir.definitely_allows p r=expected);
        let provenance=K.Lower.granting_rules p r in
        if expected then begin
          check "successful apply lists patch stage" (List.exists (String.starts_with ~prefix:"patch: ") provenance);
          check "only missing apply lists create stage"
            (List.exists (String.starts_with ~prefix:"create: ") provenance=(operation="apply-missing"));
          check "every successful source belongs to a required native stage"
            (List.for_all (fun source -> String.starts_with ~prefix:"patch: " source ||
              (operation="apply-missing" && String.starts_with ~prefix:"create: " source)) provenance)
        end else check "partial compound grants are not reported as a successful operation" (provenance=[]))
        ["apply-existing",existing;"apply-missing",missing];
      (* The empty-string control deliberately grants ordinary POST but cannot
         grant SSA's named create. All other rows restrict/omit that grant. *)
      check (label ^ " distinguishes named SSA from empty collection create")
        (Ir.possibly_allows p (request kind "create" ns "")=(label="empty create name"))) cases;
    let local=policy s (snapshot (grant ~role:"Role" ~binding:"RoleBinding" "local"
      [rule ~groups:[group] ~verbs:["patch";"create"] ~names:["worker"] [raw]])) in
    check "local role cannot authorize cluster-scoped Node apply"
      (Ir.possibly_allows local (request kind "apply-missing" ns "worker")=not cluster)) bases;
  let required=scope ~operation:"apply-missing" ()
  and forbidden=scope ~operation:"apply-missing" ~resource:"pods" ~names:(strings ["worker"]) () in
  let workflow=spec (contract ~allow:required ~deny:forbidden ~changes:[forbidden] ()) in
  let required_patch=grant "required-patch" [rule ~verbs:["patch"] ~names:["settings"] ["configmaps"]]
  and required_create=grant "required-create" [rule ~verbs:["create"] ~names:["settings"] ["configmaps"]]
  and forbidden_patch=grant "forbidden-patch" [rule ~verbs:["patch"] ~names:["worker"] ["pods"]]
  and forbidden_create=grant "forbidden-create" [rule ~verbs:["create"] ~names:["worker"] ["pods"]] in
  let complete=required_patch@required_create in
  ignore (verify "both stages satisfy must_allow" workflow (snapshot complete) "proved");
  List.iter (fun (label,items,missing) ->
    let report=verify label workflow (snapshot items) "violated" in
    check "failed compound witness keeps operation and identifies missing checks"
      (match report.result with Report.Violated ce -> ce.action="apply-missing" && ce.granting_rules=[]
        && List.for_all (contains ce.note) missing | _ -> false))
    ["partial patch is insufficient",required_patch,["create"];
     "partial create is insufficient",required_create,["patch"];
     "deny all is not a repair",[],["patch";"create"]];
  ignore (verify "must_not_grant forbids conjunction, not patch" workflow (snapshot (complete@forbidden_patch)) "proved");
  ignore (verify "must_not_grant forbids conjunction, not create" workflow (snapshot (complete@forbidden_create)) "proved");
  ignore (verify "both stages violate must_not_grant" workflow (snapshot (complete@forbidden_patch@forbidden_create)) "violated");
  ignore (compare_result "global grant removal exceeds team-a-only change scope" workflow
    (snapshot (complete@forbidden_patch@forbidden_create)) (snapshot (complete@forbidden_patch)) "violated");
  let local_patch=grant ~binding:"RoleBinding" "local-patch"
      [rule ~verbs:["patch"] ~names:["worker"] ["pods"]]
  and local_create=grant ~binding:"RoleBinding" "local-create"
      [rule ~verbs:["create"] ~names:["worker"] ["pods"]] in
  ignore (compare_result "local repair removes only named create stage" workflow
    (snapshot (complete@local_patch@local_create)) (snapshot (complete@local_patch)) "proved");
  let common=grant "common" [rule ~verbs:["get"] ~names:["settings"] ["configmaps"]]
  and extra_patch=grant ~subject:"unused" "extra-patch" [rule ~verbs:["patch"] ~names:["worker"] ["pods"]]
  and extra_create=grant ~subject:"unused" "extra-create" [rule ~verbs:["create"] ~names:["worker"] ["pods"]] in
  let change operation=scope ~subject:"unused" ~operation ~resource:"pods" ~names:(strings ["worker"])
    ~ns:(`O ["exclude",strings []]) () in
  let before=snapshot (common@extra_patch@extra_create) in
  let missing_report=compare_result "unmentioned identity and absent apply clause still preserve missing branch" s
    before (snapshot (common@extra_patch)) "violated" in
  check "only missing branch changed" (match missing_report.result with Violated ce ->
    ce.principal="unused" && ce.action="apply-missing" | _ -> false);
  let without_create=snapshot (common@extra_patch) in
  let existing_report=compare_result "patch approval does not silently approve apply-existing"
    (spec (contract ~changes:[change "patch"] ())) without_create (snapshot common) "violated" in
  check "existing branch independently preserved" (match existing_report.result with Violated ce ->
    ce.action="apply-existing" && ce.principal="unused" | _ -> false);
  let missing_report=compare_result "existing approval does not silently approve missing branch"
    (spec (contract ~changes:[change "patch";change "apply-existing"] ()))
    before (snapshot (common@extra_create)) "violated" in
  check "missing branch remains outside sibling approval" (match missing_report.result with Violated ce ->
    ce.action="apply-missing" | _ -> false);
  ignore (compare_result "aggregate NoOpinion preserved while components swap inside approved classes"
    (spec (contract ~changes:[change "patch";change "apply-existing"] ()))
    without_create (snapshot (common@extra_create)) "proved");
  let redundant=grant ~subject:"unused" "redundant" [rule ~verbs:["patch";"create"] ~names:["worker"] ["pods"]] in
  ignore (compare_result "preservation checks decisions, not individual rule provenance" s
    (snapshot (common@extra_patch@extra_create@redundant)) before "proved");
  Printf.printf "RBAC apply operations: %d checks passed\n" !checks
