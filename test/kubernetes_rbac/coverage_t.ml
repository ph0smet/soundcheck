open Soundcheck_core
module K = Soundcheck_kubernetes_rbac
module I = K.Input

let checks=ref 0
let check label yes=incr checks;if not yes then failwith label
let ok=function Ok x->x|Error e->failwith e
let strings xs=`A (List.map (fun x->`String x) xs)
let set k v xs=(k,v)::List.remove_assoc k xs
let field k=function `O xs->List.assoc k xs|_->failwith ("expected object: "^k)
let arr k value=I.arr k (field k value)
let modify k f=function `O xs->`O (set k (f (List.assoc k xs)) xs)|_->assert false
let resource ?(subject="app") ?(op="get") ?(group="") ?(raw="configmaps")
    ?(sub="") ?(ns=`String "team-a") ?(names=strings ["settings"]) () =
  ["request_kind",`String "resource";"subject",`String subject;"operation",`String op;
   "api_group",`String group;"resource",`String raw;"subresource",`String sub;"namespace",ns;"names",names]
let url ?(subject="app") ?(op="get") ?(selector="exact") path =
  ["request_kind",`String "non_resource";"subject",`String subject;"operation",`String op;
   "paths",`O [selector,`String path]]
let custom ?(group="acme.example") ?(raw="widgets") ?(scope="Namespaced") ?(subs=[]) () =
  `O ["api_group",`String group;"resource",`String raw;"scope",`String scope;"subresources",strings subs]
let customs=[custom ~subs:["status";"scale"] ();custom ~group:"platform.example" ~raw:"clusters" ~scope:"Cluster" ()]
let contract ?(version=9) ?(catalogue=customs) ?(allow=resource ())
    ?(deny=resource ~raw:"secrets" ~names:`Null ()) ?(changes=[]) () =
  let scope fields=if version>=9 then fields else
    let fields=List.remove_assoc "request_kind" fields in
    let fields=if version>=8 then fields else set "verb" (List.assoc "operation" fields) (List.remove_assoc "operation" fields) in
    let fields=if version<7 then List.remove_assoc "subresource" fields else fields in
    let fields=if version<5 then List.remove_assoc "api_group" fields else fields in
    if version=1 then List.remove_assoc "verb" fields else fields in
  `O (["schema_version",`Number (string_of_int version);"kind",`String "kubernetes-rbac-access";
    "context",`O ["schema_version",`Number "1";"snapshot_complete",`Bool true;
      "identities",`A [`O ["username",`String "app";"groups",strings ["operators"]];
                       `O ["username",`String "unused";"groups",strings []]]];
    "clauses",`A [`O (["name",`String "required";"kind",`String "must_allow"]@scope allow);
                  `O (["name",`String "forbidden";"kind",`String "must_not_grant"]@scope deny)];
    "change_scope",`A (List.map (fun row->`O (scope row)) changes)]
    @ if version>=9 then ["custom_resources",`A catalogue] else [])
let parse v=K.Contract_spec.of_string (I.json v)
let spec v=ok (parse v)
let rule ?(verbs=["*"]) ?(groups=[""]) ?(names=[]) resources =
  `O ["verbs",strings verbs;"apiGroups",strings groups;"resources",strings resources;"resourceNames",strings names]
let url_rule ?(verbs=["*"]) paths=`O ["verbs",strings verbs;"nonResourceURLs",strings paths]
let grant ?(binding="ClusterRoleBinding") ?(role="ClusterRole") ?(ns="team-a")
    ?(subject="app") ?(subject_kind="User") name rules =
  let api="rbac.authorization.k8s.io" in
  let metadata kind=`O (["name",`String name]@if kind="Role" || kind="RoleBinding" then ["namespace",`String ns] else []) in
  [`O ["apiVersion",`String (api^"/v1");"kind",`String role;"metadata",metadata role;"rules",`A rules];
   `O ["apiVersion",`String (api^"/v1");"kind",`String binding;"metadata",metadata binding;
     "roleRef",`O ["apiGroup",`String api;"kind",`String role;"name",`String name];
     "subjects",`A [`O ["kind",`String subject_kind;"apiGroup",`String api;"name",`String subject]]]]
let snapshot items=I.json (`O ["apiVersion",`String "v1";"kind",`String "List";"items",`A items])
let policy s source=K.Lower.policy s (ok (K.Snapshot.of_string source))
let req ?(subject="app") kind op ns name : Ir.request =
  {principal=Authenticated subject;action=op;resource="";context=[];source=0l;host="";scheme="";sni="";
   object_request=Some {namespace=ns;resource_kind=kind;name}}
let url_req ?(subject="app") op path : Ir.request =
  {principal=Authenticated subject;action=op;resource=path;context=[];source=0l;host="";scheme="";sni="";object_request=None}
let eval_resource ?(group="") ?(sub="") raw op ns name =
  `O ["id",`String "r";"username",`String "app";"groups",strings ["operators"];
      "operation",`String op;"apiGroup",`String group;"resource",`String raw;
      "subresource",`String sub;"namespace",`String ns;"name",`String name;"resourceRequest",`Bool true]
let eval_url op path=`O ["id",`String "u";"username",`String "app";"groups",strings ["operators"];
                       "operation",`String op;"resourceRequest",`Bool false;"path",`String path]
let evaluate s row=K.Evaluate.requests s (I.json (`A [row]))
let outcome=function Report.Proved->"proved"|Violated _->"violated"|Vacuous->"vacuous"|Inconsistent _->"inconsistent"|Unknown _->"unknown"
let from_ce (ce:Report.counterexample) : Ir.request =
  {principal=Authenticated ce.principal;action=ce.action;resource=ce.path;context=[];source=0l;
   host="";scheme="";sni="";object_request=ce.object_request}
let verify label s source expected =
  let r=K.Verify.run s source in
  check (label^": expected "^expected^", got "^outcome r.result) (outcome r.result=expected);
  check (label^" frozen identity") (r.frozen_spec=Some (K.Contract_spec.frozen_spec s));
  (match r.result with Report.Violated ce ->
     let p=policy s source in
     let clause=List.find (fun c->Contract.name c=(Option.get r.clause).name) (K.Contract_spec.to_contract s).clauses in
     check (label^" valid witness") (Witness.clause p clause (from_ce ce));
     check (label^" source grants") (ce.granting_rules=K.Lower.granting_rules p (from_ce ce))
   |_->());r
let compare_result label s before after expected =
  let result=K.Verify.compare_with_trace s ~before ~after in
  check (label^": expected "^expected^", got "^outcome result.report.result) (outcome result.report.result=expected);
  check (label^" candidate proved") ((Option.get result.candidate_report).result=Report.Proved);
  (match result.report.result with Report.Violated ce ->
     check (label^" preservation phase") ((Option.get result.report.clause).kind=Report.Must_preserve);
     check (label^" validated outside-scope difference")
       (Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes s))
          (policy s before) (policy s after) (from_ce ce))
   |_->());result.report
let needed=grant "needed" [rule ~verbs:["get"] ~names:["settings"] ["configmaps"]]

(* Frozen from baseline 5b6aa9c with CLI profile/check-contract only, before
   schema-9 implementation. Exact inputs/reviews remain in the local receipt. *)
let legacy_goldens=[
  1,"31230a9fb3e62798f74e50b77eb61fb7554d8c9dbd511c1b7f2370a395f07b3b","ce687f59c4d72e580a711a817abe9706e21a171361a1ee7827b9fa2aa3e0c0ce";
  2,"bdaa6e06babb84cbf69fe060bc84ea030b3528ef9f8b0e57548b1c9cc4ac4455","30571c71ff44e50fcbbb24d23b2659103dca0f543ca0763280eab50a607ff2e0";
  3,"de7842a1f531b9b87b408689fd0e94a9c3cf15edd58cbb0b50c98c9975e35d03","1e4ecd33131a38586e3de24efc68c53136cd89453781214fde73f65c840d84c8";
  4,"dc66d39ebc0986f216671974f4da636cf5ad511c0f7d998701c5b4f6815d67e7","c5a8c730b1c80380f16faedf9aa8171427813e3ab5adbb733ed3a6b61f9ea217";
  5,"33702f3193261a8f6b6150291135b23ca3e38280f708b4bf30c47167e90f9af7","a0eb6c69ef273f92115967fffaad4fa2d6ec9967bda54e58f790adea65bf126e";
  6,"ea4f7e094c800f68fe02703828bc2a03a02269e3cfc855a622af296ad77050b3","12a37fe551ae1fadeeb5c3b90e893d7df432044777a42c8c3ee3d343b1dbabcb";
  7,"c8020f0402c9677c995a7aea4d3fcbf4033d43355e6bb4242e6a124426412bd9","79a3c9939d24a03a3e5787b69a3e31c855c190dd0820c7d82310d7522dd41b59";
  8,"06293f84d64c3f2a277ab303c7802df9394e70296024714d68a17d27ecfc6a57","cad32098b458a96488cce53ed4505054a02d38c356ce418ce4ff8149639a88cd"]
let native=["get";"list";"watch";"create";"update";"patch";"delete";"deletecollection"]
(* Independent approved catalogue, not read from Resource_domain. *)
let added=[
  "","serviceaccounts",false;"","events",false;"","namespaces",true;
  "","persistentvolumeclaims",false;"","persistentvolumes",true;
  "events.k8s.io","events",false;"apps","replicasets",false;
  "apps","statefulsets",false;"apps","daemonsets",false;
  "batch","jobs",false;"batch","cronjobs",false;
  "coordination.k8s.io","leases",false;"networking.k8s.io","ingresses",false;
  "networking.k8s.io","ingressclasses",true;"storage.k8s.io","storageclasses",true]
let kind group raw=raw^(if group="" then "" else "."^group)

let legacy_and_catalogue () =
  List.iter (fun (version,ph,ch)->
    let old=spec (contract ~version ()) in
    check "legacy profile bytes frozen" (Sha256.string (K.Assurance.profile_json ~version ())=ph);
    check "legacy canonical bytes frozen" (Sha256.string (K.Contract_spec.canonical old)=ch);
    List.iter (fun (group,raw,_) ->
      check "legacy domain does not gain catalogue entries"
        (not (Ir.matches (K.Lower.domain old) (req (kind group raw) "get" "team-a" "settings")))) added;
    check "legacy domain does not gain URL requests" (not (Ir.matches (K.Lower.domain old) (url_req "get" "/version")));
    check "legacy domain does not gain conditional PUT"
      (not (Ir.matches (K.Lower.domain old) (req "services" "update-missing" "team-a" "settings")))) legacy_goldens;
  let s=spec (contract ()) in
  let profile=I.parse (K.Assurance.profile_json ~version:9 ()) in
  check "new profile identity" (K.Assurance.id_for_version 9="kubernetes-rbac-v1.34-static-coverage-v1");
  check "profile JSON6" (field "schema_version" profile=`Number "6" && field "contract_schema_version" profile=`Number "9");
  let domains=arr "resource_domains" profile in
  check "fixed catalogue has31entries" (List.length domains=31);
  check "fixed catalogue has223classes" (List.fold_left (fun n row->n+List.length (arr "operations" row)) 0 domains=223);
  let full=policy s (snapshot (grant "all" [rule ~groups:["*"] ["*"]])) in
  let old=spec (contract ~version:8 ()) in
  let old_full=policy old (snapshot (grant "all" [rule ~groups:["*"] ["*"]])) in
  let previous=["configmaps";"secrets";"pods";"services";"endpoints";"nodes";
    "deployments.apps";"endpointslices.discovery.k8s.io";"pods/log";"pods/exec";
    "serviceaccounts/token";"pods/status";"services/status";"nodes/status";
    "deployments/status.apps";"deployments/scale.apps"] in
  List.iter (fun kind->List.iter (fun op->List.iter (fun ns->List.iter (fun name->
    let r=req kind op ns name in
    check "schema9 retains every old request-domain decision"
      (Ir.matches (K.Lower.domain old) r=Ir.matches (K.Lower.domain s) r);
    check "schema9 retains every old native/SSA grant decision"
      (Ir.possibly_allows old_full r=Ir.possibly_allows full r);
    check "schema9 retains old source-grant explanations"
      (K.Lower.granting_rules old_full r=K.Lower.granting_rules full r))
      ["";"settings"]) ["";"team-a"]) (native@["apply-existing";"apply-missing"])) previous;
  List.iter (fun (group,raw,cluster)->List.iter (fun op->
    List.iter (fun ns->List.iter (fun name->
      let collection=List.mem op ["create";"deletecollection"] and read=List.mem op ["list";"watch"] in
      let expected=if raw="namespaces" && group="" then
          if collection then ns="" && name="" else if read then ns="" else ns<>"" && ns=name
        else (if cluster then ns="" else read || ns<>"") && (if collection then name="" else read || name<>"") in
      let r=req (kind group raw) op ns name in
      check ("new domain "^raw^"/"^op) (Ir.matches (K.Lower.domain s) r=expected);
      check ("new wildcard grant "^raw^"/"^op) (Ir.possibly_allows full r=expected);
      check "concrete adapter agrees with independent endpoint domain"
        (Result.is_ok (evaluate s (eval_resource ~group raw op ns name))=expected))
      ["";"team-a";"other"]) ["";"team-a";"other"];
    let ns=if raw="namespaces" then (if List.mem op ["list";"watch";"create";"deletecollection"] then `Null else `String "team-a")
      else if cluster then `Null else `String "team-a" in
    let names=if List.mem op ["create";"deletecollection"] then `Null else strings ["team-a"] in
    check "new resource clause accepted" (Result.is_ok (parse (contract ~allow:(resource ~op ~group ~raw ~ns ~names ()) ())))) native;
    List.iter (fun op->check "new resource cannot acquire compound operations"
      (Result.is_error (parse (contract ~allow:(resource ~op ~group ~raw ~ns:(if cluster then `Null else `String "team-a") ()) ()))))
      ["apply-existing";"apply-missing";"update-existing";"update-missing"];
    check "new resource cannot acquire unlisted status endpoint"
      (Result.is_error (parse (contract ~allow:(resource ~group ~raw ~sub:"status" ~ns:(if cluster then `Null else `String "team-a") ()) ())))) added;
  check "future schema fails closed" (Result.is_error (parse (contract ~version:10 ())))

let strict_contracts_and_customs () =
  let value=contract () in
  let reject label value=check label (Result.is_error (parse value)) in
  let reject_scope scope=reject "invalid clause" (contract ~allow:scope ());reject "invalid change scope" (contract ~changes:[scope] ()) in
  (match value with `O xs->reject "catalogue is explicit" (`O (List.remove_assoc "custom_resources" xs))|_->assert false);
  List.iter (fun scope->reject_scope scope)
    [List.remove_assoc "request_kind" (resource ());set "request_kind" (`String "url") (resource ());
     set "verb" (`String "get") (resource ());set "paths" (`O ["exact",`String "/version"]) (resource ());
     set "resource" (`String "pods") (url "/version");set "namespace" `Null (url "/version");
     set "names" `Null (url "/version");set "api_group" (`String "") (url "/version");
     set "subresource" (`String "") (url "/version");set "verb" (`String "get") (url "/version");
     set "paths" (`O ["exact",`String "/version";"prefix",`String "/"]) (url "/version");
     set "paths" (`String "/version") (url "/version")];
  List.iter (fun rows->reject "invalid custom catalogue" (contract ~catalogue:rows ()))
    [[custom ();custom ()];[custom ();custom ~scope:"Cluster" ()];
     [custom ~group:"" ()];[custom ~group:"apps" ()];[custom ~group:"networking.k8s.io" ()];
     [custom ~scope:"namespaced" ()];[custom ~subs:["status";"status"] ()];
     [custom ~subs:["exec"] ()];[custom ~raw:"Widgets" ()];[custom ~raw:"widgets/status" ()];
     [custom ~raw:"*" ()];[custom ~group:"UPPER.example" ()];[custom ~group:"bad/group" ()];
     [custom ~raw:"" ()];[custom ~group:"bad group" ()];
     [modify "scope" (fun _->`Bool true) (custom ())];
     [`O (("verbs",strings ["*"])::(match custom () with `O xs->xs|_->assert false))];
     List.init 65 (fun i->custom ~raw:("resources"^string_of_int i) ())];
  check "bounded catalogue permits64entries"
    (Result.is_ok (parse (contract ~catalogue:(List.init 64 (fun i->custom ~raw:("resources"^string_of_int i) ())) ())));
  let s=spec value and reordered=spec (contract ~catalogue:[List.nth customs 1;custom ~subs:["scale";"status"] ()] ()) in
  check "catalogue order normalized" (K.Contract_spec.canonical s=K.Contract_spec.canonical reordered);
  let different=spec (contract ~catalogue:[custom ~scope:"Cluster" ~subs:["status";"scale"] ();List.nth customs 1] ()) in
  check "catalogue scope is frozen identity" (K.Contract_spec.canonical s<>K.Contract_spec.canonical different);
  check "catalogue narrowing changes frozen identity" (K.Contract_spec.canonical s<>K.Contract_spec.canonical (spec (contract ~catalogue:[] ())));
  List.iter (fun (group,raw,ns,sub,ops)->List.iter (fun op->
    let scope=resource ~op ~group ~raw ~sub ~ns:(if ns="" then `Null else `String ns)
      ~names:(if List.mem op ["create";"deletecollection"] then `Null else strings ["settings"]) () in
    check "custom operation clause accepted" (Result.is_ok (parse (contract ~allow:scope ())));
    let name=if List.mem op ["create";"deletecollection"] then "" else "settings" in
    check "custom concrete input accepted" (Result.is_ok (evaluate s (eval_resource ~group ~sub raw op ns name)))) ops)
    ["acme.example","widgets","team-a","",native;
     "acme.example","widgets","team-a","status",["get";"update";"patch"];
     "acme.example","widgets","team-a","scale",["get";"update";"patch"];
     "platform.example","clusters","","",native];
  List.iter (fun scope->reject_scope scope)
    [resource ~group:"acme.example" ~raw:"widgets" ~op:"apply-missing" ();
     resource ~group:"acme.example" ~raw:"widgets" ~op:"update-missing" ();
     resource ~group:"acme.example" ~raw:"widgets" ~sub:"scale" ~op:"create" ();
     resource ~group:"acme.example" ~raw:"widgets" ~sub:"log" ();
     resource ~group:"platform.example" ~raw:"clusters" ~sub:"status" ~ns:`Null ();
     resource ~group:"other.example" ~raw:"widgets" ();
     resource ~group:"acme.example" ~raw:"widgets.acme.example" ()];
  let p=policy s (snapshot (grant ~binding:"RoleBinding" "local" [rule ~groups:["*"] ["*"]])) in
  check "custom namespaced RoleBinding applies" (Ir.possibly_allows p (req "widgets.acme.example" "get" "team-a" "settings"));
  check "custom RoleBinding stays local" (not (Ir.possibly_allows p (req "widgets.acme.example" "get" "other" "settings")));
  check "custom cluster entry ignores namespaced binding" (not (Ir.possibly_allows p (req "clusters.platform.example" "get" "" "settings")));
  let candidate=I.parse (snapshot needed) |> modify "items" (fun x->x) in
  let candidate=match candidate with `O xs->`O (set "custom_resources" (`A []) xs)|_->assert false in
  check "candidate cannot supply a substitute catalogue" (Result.is_error (K.Snapshot.of_string (I.json candidate)))

let namespace_cases () =
  let s=spec (contract ()) in
  let p=policy s (snapshot (grant ~binding:"RoleBinding" "local-ns" [rule ["namespaces"]])) in
  check "named Namespace uses same-namespace RoleBinding" (Ir.possibly_allows p (req "namespaces" "get" "team-a" "team-a"));
  check "Namespace attributes must agree" (not (Ir.matches (K.Lower.domain s) (req "namespaces" "get" "team-a" "other")));
  check "named Namespace is not ordinary cluster tuple" (not (Ir.matches (K.Lower.domain s) (req "namespaces" "get" "" "team-a")));
  List.iter (fun op->List.iter (fun name->check "Namespace collection ignores RoleBinding"
    (not (Ir.possibly_allows p (req "namespaces" op "" name)))) ["";"team-a"]) ["list";"watch"];
  List.iter (fun op->check "Namespace empty-name collection is supported"
    (Ir.matches (K.Lower.domain s) (req "namespaces" op "" ""))) ["create";"deletecollection"];
  let dotted="a.b" and long=String.make 64 'a' in
  List.iter (fun name->check "named Namespace label bound"
    (not (Ir.matches (K.Lower.domain s) (req "namespaces" "get" name name)))) [dotted;long];
  check "Namespace selector name uses collection effective-name bound"
    (Ir.matches (K.Lower.domain s) (req "namespaces" "list" "" dotted));
  let a=resource ~raw:"namespaces" ~ns:(`String "team-a") ~names:(strings ["team-a"]) () in
  let contract_=spec (contract ~allow:a ()) in
  ignore (verify "Namespace named functionality" contract_ (snapshot (grant ~binding:"RoleBinding" "local-ns" [rule ~verbs:["get"] ["namespaces"]])) "proved");
  let impossible=spec (contract ~allow:(resource ~raw:"namespaces" ~names:(strings ["other"]) ()) ()) in
  ignore (verify "Namespace cross-coordinate class is vacuous" impossible (snapshot []) "vacuous")

let url_cases () =
  let s=spec (contract ()) in
  let valid=["/";"/version";"/healthz/ping";"/readyz/";"/.well-known/openid-configuration";
    "/a_B-~.c";"/api";"/api/";"/api/v1";"/api/v1/";"/apis";"/apis/apps";
    "/apis/apps/v1";"/apis/apps/v1/";"/API/v1/pods";"/apiXYZ/v1/pods";"/apisXYZ/apps/v1/resources"] in
  let invalid=["";"relative";"//";"/a//b";"/a/./b";"/a/../b";"/.";"/..";"/a%2fb";
    "/a?x=1";"/a#fragment";"/a b";"/caf\xc3\xa9";"/a\x00b";"/api/v1/pods";"/apis/apps/v1/deployments"] in
  let methods=["get";"head";"post";"put";"patch";"delete";"options"] in
  List.iter (fun op->List.iter (fun path->
    check "valid URL request domain" (Ir.matches (K.Lower.domain s) (url_req op path));
    check "valid URL evaluator" (Result.is_ok (evaluate s (eval_url op path)));
    check "valid exact URL clause" (Result.is_ok (parse (contract ~allow:(url ~op path) ())))) valid) methods;
  List.iter (fun path->
    check "invalid/resource URL outside domain" (not (Ir.matches (K.Lower.domain s) (url_req "get" path)));
    check "invalid/resource URL evaluator rejected" (Result.is_error (evaluate s (eval_url "get" path)));
    check "invalid/resource exact URL selector rejected" (Result.is_error (parse (contract ~allow:(url path) ())))) invalid;
  List.iter (fun op->
    check "URL operation is explicit HTTP verb" (Result.is_error (parse (contract ~allow:(url ~op "/version") ())));
    check "unsupported URL method rejected by evaluator" (Result.is_error (evaluate s (eval_url op "/version"))))
    ["GET";"list";"watch";"create";"trace";"connect";"*"];
  let only_url=policy s (snapshot (grant "urls" [url_rule ["*"]])) in
  let only_resource=policy s (snapshot (grant "resources" [rule ~groups:["*"] ["*"]])) in
  check "URL wildcard cannot grant resource" (not (Ir.possibly_allows only_url (req "configmaps" "get" "team-a" "settings")));
  check "resource wildcard cannot grant URL" (not (Ir.possibly_allows only_resource (url_req "get" "/version")));
  let local=policy s (snapshot (grant ~binding:"RoleBinding" "local-url" [url_rule ["*"]])) in
  check "namespaced binding cannot grant nonresource" (not (Ir.possibly_allows local (url_req "get" "/version")));
  List.iter (fun (pattern,path,expected)->
    let p=policy s (snapshot (grant "literal" [url_rule ~verbs:["get"] [pattern]])) in
    check ("native URL match "^pattern^" -> "^path) (Ir.possibly_allows p (url_req "get" path)=expected);
    check "HEAD does not alias GET" (not (Ir.possibly_allows p (url_req "head" path))))
    ["/healthz","/healthz",true;"/healthz","/healthz/",false;
     "/healthz*","/healthzXYZ",true;"/healthz/**","/healthz/ping",true;
     "/healthz/**","/healthz",false;"/healthz***","/healthz",true;
     "*","/version",true;"**","/version",true;
     "/hea*lthz","/healthz",false;"/hea*lthz*","/healthz",false;
     "healthz*","/healthz",false;"/healthz?x*","/healthz",false;
     "","/",false;"/HEALTHZ*","/healthz",false];
  let base=eval_url "get" "/version" in
  List.iter (fun (key,value)->check "mixed URL evaluation fields rejected"
    (Result.is_error (evaluate s (modify key (fun _->value) (match base with `O xs->`O (set key value xs)|_->assert false)))))
    ["apiGroup",`String "";"resource",`String "";"subresource",`String "";"namespace",`String "";"name",`String "";"verb",`String "get"];
  check "resource evaluator rejects URL field"
    (Result.is_error (evaluate s (match eval_resource "configmaps" "get" "team-a" "settings" with
      |`O xs->`O (set "path" (`String "/version") xs)|_->assert false)));
  check "URL evaluator groups are immutable" (Result.is_error (evaluate s (modify "groups" (fun _->strings []) base)));
  let us=spec (contract ~allow:(url "/healthz") ~deny:(url "/metrics") ()) in
  let good=snapshot (grant "health" [url_rule ~verbs:["get"] ["/healthz*"]]) in
  ignore (verify "URL paired functionality" us good "proved");
  let bad=snapshot (grant "urls" [url_rule ~verbs:["get"] ["/healthz*";"/metrics"]]) in
  let r=verify "URL counterexample" us bad "violated" in
  check "URL witness has path and no object coordinates"
    (match r.result with Violated ce->ce.object_request=None && ce.path="/metrics"|_->false);
  let impossible=spec (contract ~allow:(url ~selector:"prefix" "/api/v1/pods") ()) in
  ignore (verify "resource-only prefix is vacuous" impossible (snapshot []) "vacuous")

let compound_and_preservation () =
  let s=spec (contract ()) in
  List.iter (fun raw->List.iter (fun update->List.iter (fun create->
    let objects=(if update then grant ~binding:"RoleBinding" "up" [rule ~verbs:["update"] ~names:["settings"] [raw]] else [])@
      (if create then grant ~binding:"RoleBinding" "cr" [rule ~verbs:["create"] ~names:["settings"] [raw]] else []) in
    let p=policy s (snapshot objects) in
    check "PUT existing requires update" (Ir.possibly_allows p (req raw "update-existing" "team-a" "settings")=update);
    check "PUT missing requires both same-target grants" (Ir.possibly_allows p (req raw "update-missing" "team-a" "settings")=(update && create));
    check "named extra create is not collection POST" (not (Ir.possibly_allows p (req raw "create" "team-a" "")));
    check "PUT grant target does not bleed" (not (Ir.possibly_allows p (req raw "update-missing" "team-a" "other")))) [false;true]) [false;true]) ["services";"endpoints"];
  let allow=resource ~raw:"services" ~op:"update-existing" () and deny=resource ~raw:"services" ~op:"update-missing" () in
  let us=spec (contract ~allow ~deny ()) in
  let update=grant ~binding:"RoleBinding" "update" [rule ~verbs:["update"] ~names:["settings"] ["services"]] in
  let create=grant ~binding:"RoleBinding" "create" [rule ~verbs:["create"] ~names:["settings"] ["services"]] in
  ignore (verify "update without create meets paired PUT requirement" us (snapshot update) "proved");
  ignore (verify "both grants violate missing-object prohibition" us (snapshot (update@create)) "violated");
  List.iter (fun (tag,extra)->
    let before=snapshot (needed@extra) and after=snapshot needed in
    let report=compare_result ("preserve unmentioned "^tag) s before after "violated" in
    check "unmentioned frozen identity retained" (match report.result with Violated ce->ce.principal="unused"|_->false))
    ["builtin",grant ~subject:"unused" "lease" [rule ~groups:["coordination.k8s.io"] ~verbs:["get"] ["leases"]];
     "custom",grant ~subject:"unused" "custom" [rule ~groups:["acme.example"] ~verbs:["get"] ["widgets"]];
     "URL",grant ~subject:"unused" "url" [url_rule ~verbs:["get"] ["/metrics"]]];
  let patch=grant ~binding:"RoleBinding" "patch" [rule ~verbs:["patch"] ~names:["settings"] ["services"]] in
  let before=snapshot (needed@update@patch@create) and after=snapshot (needed@update@patch) in
  let change=resource ~raw:"services" ~op:"update-missing" () in
  let one=spec (contract ~changes:[change] ()) in
  let report=compare_result "PUT scope cannot silently include SSA" one before after "violated" in
  check "SSA coupled witness" (match report.result with Violated ce->ce.action="apply-missing"|_->false);
  let both=spec (contract ~changes:[change;resource ~raw:"services" ~op:"apply-missing" ()] ()) in
  ignore (compare_result "both compound classes explicitly approved" both before after "proved");
  let alias=spec (contract ~changes:[resource ~raw:"services" ~op:"update-existing" ()] ()) in
  let report=compare_result "update aliases stay distinct" alias (snapshot needed) (snapshot (needed@update)) "violated" in
  check "raw update outside alias scope" (match report.result with Violated ce->ce.action="update"|_->false);
  let no_stage=snapshot needed and stage_only=snapshot (needed@create) in
  ignore (compare_result "unusable named-create stage is not an operation change" s no_stage stage_only "proved");
  let urls=grant "health" [url_rule ~verbs:["get"] ["/healthz"]] in
  let before=snapshot (needed@urls) and after=snapshot needed in
  let wrong=spec (contract ~changes:[resource ~op:"get" ~names:`Null ()] ()) in
  ignore (compare_result "resource scope cannot approve URL loss" wrong before after "violated");
  let right=spec (contract ~changes:[url "/healthz"] ()) in
  ignore (compare_result "exact URL loss separately approved" right before after "proved")

let () =
  legacy_and_catalogue ();
  strict_contracts_and_customs ();
  namespace_cases ();
  url_cases ();
  compound_and_preservation ();
  Printf.printf "RBAC coverage: %d checks passed\n" !checks
